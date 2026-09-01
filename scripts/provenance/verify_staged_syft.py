#!/usr/bin/env python3
"""Verify that a staged Syft executable matches the immutable provenance-lock entry."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Iterable

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EXPECTED = {
    "id": "syft-linux-amd64",
    "name": "syft",
    "version": "v1.51.1",
    "source": (
        "https://github.com/anchore/syft/releases/download/"
        "v1.51.1/syft_1.51.1_linux_amd64.tar.gz"
    ),
    "sha256": "8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3",
    "bytes": 29203595,
}


class VerificationError(ValueError):
    """Raised when the staged Syft binary is not the locked tool."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_lock(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise VerificationError(f"provenance lock does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise VerificationError(f"invalid JSON in provenance lock: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema") != "layersentry.provenance-lock/v1":
        raise VerificationError("unsupported provenance lock")
    return value


def verify(lock_path: Path, binary: Path) -> dict[str, Any]:
    lock = load_lock(lock_path)
    tools = lock.get("toolchain_artifacts")
    if not isinstance(tools, list):
        raise VerificationError("provenance lock toolchain_artifacts is not an array")
    matches = [
        item
        for item in tools
        if isinstance(item, dict) and item.get("id") == EXPECTED["id"]
    ]
    if len(matches) != 1:
        raise VerificationError(
            f"provenance lock must contain exactly one {EXPECTED['id']!r} entry; "
            f"found {len(matches)}"
        )
    entry = matches[0]
    for field, expected in EXPECTED.items():
        if entry.get(field) != expected:
            raise VerificationError(
                f"locked Syft field {field!r} is {entry.get(field)!r}; expected {expected!r}"
            )
    binary_sha256 = str(entry.get("binary_sha256", ""))
    binary_bytes = entry.get("binary_bytes")
    if not SHA256_RE.fullmatch(binary_sha256):
        raise VerificationError("locked Syft binary_sha256 is invalid")
    if not isinstance(binary_bytes, int) or binary_bytes <= 0:
        raise VerificationError("locked Syft binary_bytes is invalid")

    binary = binary.resolve()
    if not binary.is_file():
        raise VerificationError(f"staged Syft binary does not exist: {binary}")
    if not os.access(binary, os.X_OK):
        raise VerificationError(f"staged Syft binary is not executable: {binary}")
    actual_sha256 = sha256_file(binary)
    actual_bytes = binary.stat().st_size
    if actual_sha256 != binary_sha256:
        raise VerificationError(
            f"staged Syft SHA-256 {actual_sha256} does not equal locked {binary_sha256}"
        )
    if actual_bytes != binary_bytes:
        raise VerificationError(
            f"staged Syft byte count {actual_bytes} does not equal locked {binary_bytes}"
        )

    environment = dict(os.environ)
    environment["SYFT_CHECK_FOR_APP_UPDATE"] = "false"
    proc = subprocess.run(
        [str(binary), "version"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        env=environment,
    )
    if proc.returncode != 0:
        raise VerificationError(
            f"staged Syft version command failed with {proc.returncode}: {proc.stdout.strip()}"
        )
    if not re.search(r"(^|[^0-9])1\.51\.1([^0-9]|$)", proc.stdout):
        raise VerificationError(
            f"staged Syft does not report version 1.51.1: {proc.stdout.strip()}"
        )

    return {
        "schema": "layersentry.staged-tool-verification/v1",
        "id": entry["id"],
        "version": entry["version"],
        "source": entry["source"],
        "archive_sha256": entry["sha256"],
        "binary_path": str(binary),
        "binary_sha256": actual_sha256,
        "binary_bytes": actual_bytes,
        "version_output": proc.stdout.strip(),
        "verified": True,
    }


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = verify(args.lock, args.binary)
    except VerificationError as exc:
        print(f"ERROR: {exc}")
        return 1
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("STAGED SYFT VERIFICATION: PASS")
    print(f"binary_sha256={report['binary_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
