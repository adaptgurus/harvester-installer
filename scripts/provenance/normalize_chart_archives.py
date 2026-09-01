#!/usr/bin/env python3
"""Rewrite Helm .tgz archives into a deterministic, safety-checked form."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import posixpath
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Iterable

ALLOWED_TYPES = {
    tarfile.REGTYPE,
    tarfile.AREGTYPE,
    tarfile.DIRTYPE,
    tarfile.SYMTYPE,
    tarfile.LNKTYPE,
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_member_name(name: str) -> str:
    if not name or "\x00" in name or name.startswith("/"):
        raise ValueError(f"unsafe archive member name: {name!r}")
    normalized = posixpath.normpath(name)
    if normalized in {"", ".", ".."} or normalized.startswith("../"):
        raise ValueError(f"unsafe archive member path: {name!r}")
    return normalized


def safe_link_target(member_name: str, target: str) -> str:
    if not target or "\x00" in target or target.startswith("/"):
        raise ValueError(f"unsafe link target for {member_name!r}: {target!r}")
    parent = PurePosixPath(member_name).parent
    resolved = posixpath.normpath(str(parent / target))
    if resolved == ".." or resolved.startswith("../"):
        raise ValueError(f"link escapes chart root for {member_name!r}: {target!r}")
    return target


def read_members(path: Path) -> list[tuple[tarfile.TarInfo, bytes | None]]:
    records: list[tuple[tarfile.TarInfo, bytes | None]] = []
    seen: set[str] = set()
    with tarfile.open(path, mode="r:gz") as archive:
        for original in archive.getmembers():
            name = safe_member_name(original.name)
            if name in seen:
                raise ValueError(f"duplicate archive member: {name}")
            seen.add(name)
            if original.type not in ALLOWED_TYPES:
                raise ValueError(f"unsupported archive member type for {name!r}")
            data: bytes | None = None
            if original.isfile():
                extracted = archive.extractfile(original)
                if extracted is None:
                    raise ValueError(f"cannot read regular file member: {name}")
                data = extracted.read()
                if len(data) != original.size:
                    raise ValueError(f"short read for archive member: {name}")
            elif original.issym() or original.islnk():
                safe_link_target(name, original.linkname)
            clone = tarfile.TarInfo(name=name)
            clone.type = original.type
            clone.mode = original.mode & 0o7777
            clone.linkname = original.linkname
            clone.size = len(data) if data is not None else 0
            records.append((clone, data))
    if not records:
        raise ValueError(f"chart archive is empty: {path}")
    if not any(info.name.endswith("/Chart.yaml") or info.name == "Chart.yaml" for info, _ in records):
        raise ValueError(f"chart archive has no Chart.yaml: {path}")
    return records


def normalized_bytes(path: Path, epoch: int) -> bytes:
    records = read_members(path)
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, compresslevel=9, mtime=epoch) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for info, data in sorted(records, key=lambda item: item[0].name):
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = epoch
                info.pax_headers = {}
                archive.addfile(info, io.BytesIO(data) if data is not None else None)
    return buffer.getvalue()


def normalize(path: Path, epoch: int) -> dict[str, object]:
    before = sha256_file(path)
    data = normalized_bytes(path, epoch)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, path.stat().st_mode & 0o777)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    after = sha256_file(path)
    return {
        "path": path.as_posix(),
        "sha256_before": before,
        "sha256": after,
        "bytes": path.stat().st_size,
        "changed": before != after,
    }


def chart_paths(values: Iterable[Path]) -> list[Path]:
    found: set[Path] = set()
    for value in values:
        if value.is_dir():
            found.update(path for path in value.rglob("*.tgz") if path.is_file())
        elif value.is_file() and value.suffix == ".tgz":
            found.add(value)
        else:
            raise ValueError(f"chart path does not exist or is not a .tgz archive: {value}")
    if not found:
        raise ValueError("no .tgz chart archives were found")
    return sorted(found)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--source-date-epoch", type=int)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)

    epoch = args.source_date_epoch
    if epoch is None:
        raw_epoch = os.environ.get("SOURCE_DATE_EPOCH", "0")
        try:
            epoch = int(raw_epoch)
        except ValueError as exc:
            parser.error(f"SOURCE_DATE_EPOCH is not an integer: {raw_epoch!r}")
    if epoch < 0:
        parser.error("source date epoch must not be negative")

    try:
        results = [normalize(path, epoch) for path in chart_paths(args.paths)]
    except (OSError, tarfile.TarError, ValueError) as exc:
        parser.exit(1, f"ERROR: {exc}\n")

    report = {
        "schema": "layersentry.deterministic-chart-normalization/v1",
        "source_date_epoch": epoch,
        "chart_count": len(results),
        "charts": results,
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for item in results:
        print(f"{item['sha256']}  {item['path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
