#!/usr/bin/env python3
"""Build a deterministic chart-lock candidate from verified chart archives."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]*$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


class CandidateError(ValueError):
    """Raised when chart evidence is incomplete or inconsistent."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CandidateError(f"{label} must be an object")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise CandidateError(f"{label} must be an array")
    return value


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CandidateError(f"file does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise CandidateError(f"invalid JSON in {path}: {exc}") from exc


def yaml_scalar(value: str) -> str:
    value = value.strip()
    if not value:
        raise CandidateError("empty Chart.yaml scalar")
    if value[0] == value[-1:] and value[0] in {"'", '"'}:
        if value[0] == "'":
            return value[1:-1].replace("''", "'")
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise CandidateError(f"invalid quoted Chart.yaml scalar: {value!r}") from exc
        if not isinstance(parsed, str):
            raise CandidateError(f"Chart.yaml scalar is not a string: {value!r}")
        return parsed
    return value.split(" #", 1)[0].strip()


def chart_metadata(path: Path) -> tuple[str, str]:
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            members = []
            for member in archive.getmembers():
                pure = PurePosixPath(member.name)
                if pure.is_absolute() or ".." in pure.parts:
                    raise CandidateError(f"unsafe member path in {path.name}: {member.name!r}")
                if member.isfile() and len(pure.parts) == 2 and pure.name == "Chart.yaml":
                    members.append(member)
            if len(members) != 1:
                raise CandidateError(
                    f"{path.name} must contain exactly one root chart Chart.yaml; found {len(members)}"
                )
            extracted = archive.extractfile(members[0])
            if extracted is None:
                raise CandidateError(f"cannot read Chart.yaml from {path.name}")
            text = extracted.read().decode("utf-8")
    except (OSError, tarfile.TarError, UnicodeDecodeError) as exc:
        raise CandidateError(f"cannot inspect chart archive {path}: {exc}") from exc

    values: dict[str, str] = {}
    for raw in text.splitlines():
        if not raw or raw[0].isspace() or raw.lstrip().startswith("#") or ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        key = key.strip()
        if key in {"name", "version"}:
            values[key] = yaml_scalar(value)
    if not values.get("name") or not values.get("version"):
        raise CandidateError(f"{path.name} Chart.yaml is missing top-level name or version")
    return values["name"], values["version"]


def load_source_checksums(path: Path) -> dict[str, dict[str, Any]]:
    try:
        handle = path.open("r", encoding="utf-8", newline="")
    except FileNotFoundError as exc:
        raise CandidateError(f"source checksum evidence does not exist: {path}") from exc
    with handle:
        reader = csv.DictReader(handle, delimiter="\t")
        required = {"id", "url", "archive", "sha256", "bytes"}
        if set(reader.fieldnames or []) != required:
            raise CandidateError(
                f"source checksum TSV columns must be {sorted(required)}; got {reader.fieldnames}"
            )
        records: dict[str, dict[str, Any]] = {}
        for row_number, row in enumerate(reader, 2):
            item_id = (row.get("id") or "").strip()
            if not item_id or item_id in records:
                raise CandidateError(f"invalid or duplicate source id on TSV row {row_number}: {item_id!r}")
            checksum = (row.get("sha256") or "").strip()
            if not SHA256_RE.fullmatch(checksum):
                raise CandidateError(f"invalid source SHA-256 on TSV row {row_number}")
            try:
                size = int((row.get("bytes") or "").strip())
            except ValueError as exc:
                raise CandidateError(f"invalid source byte count on TSV row {row_number}") from exc
            if size <= 0:
                raise CandidateError(f"source byte count must be positive on TSV row {row_number}")
            records[item_id] = {
                "url": (row.get("url") or "").strip(),
                "archive": (row.get("archive") or "").strip(),
                "sha256": checksum,
                "bytes": size,
            }
    return records


def source_string(source: dict[str, Any]) -> str:
    kind = source.get("kind")
    if kind == "url":
        url = str(source.get("url", ""))
        if not url.startswith("https://") or "releases/latest" in url.lower():
            raise CandidateError(f"chart source URL is not immutable HTTPS: {url!r}")
        return url
    if kind == "git":
        repository = str(source.get("repository", ""))
        commit = str(source.get("commit", ""))
        path = str(source.get("path", ""))
        if not repository.startswith("https://github.com/") or not repository.endswith(".git"):
            raise CandidateError(f"unexpected Git chart source repository: {repository!r}")
        if not COMMIT_RE.fullmatch(commit):
            raise CandidateError(f"Git chart source is not pinned by exact commit: {commit!r}")
        pure = PurePosixPath(path)
        if pure.is_absolute() or not path or ".." in pure.parts:
            raise CandidateError(f"unsafe Git chart source path: {path!r}")
        return f"git+{repository}@{commit}#{path}"
    raise CandidateError(f"unsupported chart source kind: {kind!r}")


def build_candidate(
    plan_path: Path,
    charts_dir: Path,
    source_checksums_path: Path,
    normalization_report_path: Path,
    source_commit: str,
    source_date_epoch: int,
) -> dict[str, Any]:
    if not COMMIT_RE.fullmatch(source_commit):
        raise CandidateError("LayerSentry source commit must be exactly 40 lowercase hex characters")
    if source_date_epoch < 0:
        raise CandidateError("source date epoch must not be negative")

    plan = require_dict(load_json(plan_path), "plan")
    if plan.get("schema") != "layersentry.chart-source-plan/v1":
        raise CandidateError("unsupported chart source plan schema")
    source_locks = require_dict(plan.get("source_locks"), "source_locks")
    harvester_lock = require_dict(source_locks.get("harvester"), "source_locks.harvester")
    addons_lock = require_dict(source_locks.get("addons"), "source_locks.addons")
    for label, lock in (("harvester", harvester_lock), ("addons", addons_lock)):
        if not COMMIT_RE.fullmatch(str(lock.get("commit", ""))):
            raise CandidateError(f"source_locks.{label}.commit is not immutable")

    source_checksums = load_source_checksums(source_checksums_path)
    normalization = require_dict(load_json(normalization_report_path), "normalization report")
    if normalization.get("schema") != "layersentry.deterministic-chart-normalization/v1":
        raise CandidateError("unexpected chart normalization report schema")
    if normalization.get("source_date_epoch") != source_date_epoch:
        raise CandidateError("normalization source date epoch does not match requested epoch")
    normalized_by_archive: dict[str, dict[str, Any]] = {}
    for raw in require_list(normalization.get("charts"), "normalization.charts"):
        item = require_dict(raw, "normalization chart")
        archive = Path(str(item.get("path", ""))).name
        if not archive or archive in normalized_by_archive:
            raise CandidateError(f"invalid or duplicate normalization archive: {archive!r}")
        normalized_by_archive[archive] = item

    plan_charts = require_list(plan.get("charts"), "charts")
    if not plan_charts:
        raise CandidateError("chart source plan is empty")
    entries: list[dict[str, Any]] = []
    expected_archives: set[str] = set()
    expected_source_ids: set[str] = set()
    seen_ids: set[str] = set()
    for index, raw in enumerate(plan_charts):
        item = require_dict(raw, f"charts[{index}]")
        item_id = str(item.get("id", ""))
        name = str(item.get("name", ""))
        version = str(item.get("version", ""))
        archive = str(item.get("archive", ""))
        if not item_id or item_id in seen_ids:
            raise CandidateError(f"missing or duplicate chart id: {item_id!r}")
        seen_ids.add(item_id)
        if not name or not VERSION_RE.fullmatch(version) or version.lower() in {"latest", "head"}:
            raise CandidateError(f"invalid chart identity for {item_id!r}")
        if Path(archive).name != archive or not archive.endswith(".tgz"):
            raise CandidateError(f"invalid archive name for {item_id!r}: {archive!r}")
        if archive in expected_archives:
            raise CandidateError(f"duplicate chart archive in plan: {archive}")
        expected_archives.add(archive)

        chart_path = charts_dir / archive
        if not chart_path.is_file():
            raise CandidateError(f"expected chart archive is missing: {chart_path}")
        actual_name, actual_version = chart_metadata(chart_path)
        if actual_name != name or actual_version != version:
            raise CandidateError(
                f"{archive} metadata mismatch: expected {name} {version}, got {actual_name} {actual_version}"
            )
        checksum = sha256_file(chart_path)
        normalized = normalized_by_archive.get(archive)
        if normalized is None:
            raise CandidateError(f"normalization report is missing {archive}")
        if normalized.get("sha256") != checksum:
            raise CandidateError(f"normalization checksum mismatch for {archive}")
        if normalized.get("bytes") != chart_path.stat().st_size:
            raise CandidateError(f"normalization byte count mismatch for {archive}")

        source = require_dict(item.get("source"), f"charts[{index}].source")
        entry: dict[str, Any] = {
            "id": item_id,
            "name": name,
            "version": version,
            "archive": archive,
            "source": source_string(source),
            "sha256": checksum,
            "bytes": chart_path.stat().st_size,
            "transformations": require_list(item.get("transformations"), f"charts[{index}].transformations"),
        }
        if source.get("kind") == "url":
            expected_source_ids.add(item_id)
            evidence = source_checksums.get(item_id)
            if evidence is None:
                raise CandidateError(f"source checksum evidence is missing for {item_id}")
            if evidence["url"] != source.get("url") or evidence["archive"] != archive:
                raise CandidateError(f"source checksum identity mismatch for {item_id}")
            entry["source_sha256"] = evidence["sha256"]
            entry["source_bytes"] = evidence["bytes"]
        entries.append(entry)

    actual_archives = {path.name for path in charts_dir.glob("*.tgz") if path.is_file()}
    if actual_archives != expected_archives:
        missing = sorted(expected_archives - actual_archives)
        extra = sorted(actual_archives - expected_archives)
        raise CandidateError(f"chart archive set mismatch; missing={missing}, extra={extra}")
    if set(source_checksums) != expected_source_ids:
        missing = sorted(expected_source_ids - set(source_checksums))
        extra = sorted(set(source_checksums) - expected_source_ids)
        raise CandidateError(f"source checksum set mismatch; missing={missing}, extra={extra}")
    if set(normalized_by_archive) != expected_archives:
        missing = sorted(expected_archives - set(normalized_by_archive))
        extra = sorted(set(normalized_by_archive) - expected_archives)
        raise CandidateError(f"normalization archive set mismatch; missing={missing}, extra={extra}")

    candidate: dict[str, Any] = {
        "schema": "layersentry.chart-lock-candidate/v1",
        "source_commit": source_commit,
        "source_date_epoch": source_date_epoch,
        "plan_sha256": sha256_file(plan_path),
        "source_checksums_sha256": sha256_file(source_checksums_path),
        "harvester_commit": harvester_lock["commit"],
        "addons_commit": addons_lock["commit"],
        "chart_count": len(entries),
        "all_sources_verified": True,
        "all_archives_normalized": True,
        "charts": entries,
    }
    return candidate


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--charts-dir", required=True, type=Path)
    parser.add_argument("--source-checksums", required=True, type=Path)
    parser.add_argument("--normalization-report", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        candidate = build_candidate(
            args.plan,
            args.charts_dir,
            args.source_checksums,
            args.normalization_report,
            args.source_commit,
            args.source_date_epoch,
        )
    except CandidateError as exc:
        print(f"ERROR: {exc}")
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(candidate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"CHART LOCK CANDIDATE: PASS ({candidate['chart_count']} charts)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
