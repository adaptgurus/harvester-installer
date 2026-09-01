#!/usr/bin/env python3
"""Review a checksum-locked Syft binary and merge it into the incomplete provenance lock."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Iterable

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
UNRESOLVED_ID = "syft-sbom-generator"
EXPECTED = {
    "schema": "layersentry.locked-tool/v1",
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
EXPECTED_MANIFEST = {
    "source": (
        "https://github.com/anchore/syft/releases/download/"
        "v1.51.1/syft_1.51.1_checksums.txt"
    ),
    "sha256": "105346699e7cb694afa37a21e2386432df6278c99f71331c24b1e0bb0f38cc75",
    "bytes": 2690,
}


class ReviewError(ValueError):
    """Raised when locked Syft evidence cannot be accepted."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReviewError(f"{label} does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ReviewError(f"invalid JSON in {label} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReviewError(f"{label} must contain a JSON object")
    return value


def atomic_json_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def validate_descriptor(path: Path) -> dict[str, Any]:
    descriptor = load_object(path, "locked Syft descriptor")
    for field, expected in EXPECTED.items():
        if descriptor.get(field) != expected:
            raise ReviewError(
                f"locked Syft descriptor field {field!r} is {descriptor.get(field)!r}; "
                f"expected {expected!r}"
            )
    manifest = descriptor.get("checksums_manifest")
    if not isinstance(manifest, dict):
        raise ReviewError("locked Syft checksums_manifest must be an object")
    for field, expected in EXPECTED_MANIFEST.items():
        if manifest.get(field) != expected:
            raise ReviewError(
                f"locked Syft manifest field {field!r} is {manifest.get(field)!r}; "
                f"expected {expected!r}"
            )
    release = descriptor.get("release")
    if not isinstance(release, dict):
        raise ReviewError("locked Syft release metadata must be an object")
    if release.get("repository") != "https://github.com/anchore/syft.git":
        raise ReviewError("locked Syft release repository is not approved")
    if release.get("tag") != EXPECTED["version"] or release.get("immutable") is not True:
        raise ReviewError("locked Syft release tag is not exact and immutable")
    if release.get("release_id") != 377988884 or release.get("asset_id") != 532610151:
        raise ReviewError("locked Syft release or asset ID does not match reviewed metadata")
    if "releases/latest" in str(descriptor.get("source", "")).lower():
        raise ReviewError("locked Syft descriptor uses a latest-release endpoint")
    return descriptor


def validate_validation(
    validation_path: Path, descriptor_path: Path, descriptor: dict[str, Any]
) -> dict[str, Any]:
    validation = load_object(validation_path, "locked Syft validation report")
    if validation.get("schema") != "layersentry.locked-tool-validation/v1":
        raise ReviewError("unsupported locked Syft validation schema")
    comparisons = {
        "id": descriptor["id"],
        "version": descriptor["version"],
        "source": descriptor["source"],
        "archive_sha256": descriptor["sha256"],
        "archive_bytes": descriptor["bytes"],
        "descriptor_sha256": sha256_file(descriptor_path),
        "version_verified": True,
        "official_checksum_manifest_verified": True,
        "archive_safety_verified": True,
    }
    for field, expected in comparisons.items():
        if validation.get(field) != expected:
            raise ReviewError(
                f"locked Syft validation field {field!r} is {validation.get(field)!r}; "
                f"expected {expected!r}"
            )
    binary_sha256 = str(validation.get("binary_sha256", ""))
    if not SHA256_RE.fullmatch(binary_sha256):
        raise ReviewError("locked Syft binary SHA-256 is invalid")
    binary_bytes = validation.get("binary_bytes")
    if not isinstance(binary_bytes, int) or binary_bytes <= 0:
        raise ReviewError("locked Syft binary byte count is invalid")
    return validation


def toolchain_entry(
    descriptor: dict[str, Any], validation: dict[str, Any]
) -> dict[str, Any]:
    return {
        "id": descriptor["id"],
        "name": descriptor["name"],
        "version": descriptor["version"],
        "source": descriptor["source"],
        "sha256": descriptor["sha256"],
        "bytes": descriptor["bytes"],
        "binary_sha256": validation["binary_sha256"],
        "binary_bytes": validation["binary_bytes"],
        "release": descriptor["release"],
        "checksums_manifest": descriptor["checksums_manifest"],
    }


def review(
    descriptor_path: Path,
    validation_path: Path,
    lock_path: Path,
    source_commit: str,
    apply: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not COMMIT_RE.fullmatch(source_commit):
        raise ReviewError("review source commit must be exactly 40 lowercase hex characters")
    descriptor = validate_descriptor(descriptor_path)
    validation = validate_validation(validation_path, descriptor_path, descriptor)
    entry = toolchain_entry(descriptor, validation)

    lock = load_object(lock_path, "provenance lock")
    if lock.get("schema") != "layersentry.provenance-lock/v1":
        raise ReviewError("unsupported provenance lock schema")
    if lock.get("lock_status") != "incomplete":
        raise ReviewError("Syft review may only update an incomplete provenance lock")
    identity = lock.get("release_identity")
    if not isinstance(identity, dict):
        raise ReviewError("provenance lock release identity is missing")
    if identity.get("product", {}).get("version") != "v1.0":
        raise ReviewError("provenance lock does not identify LayerSentry v1.0")
    if identity.get("embedded_platform", {}).get("version") != "v1.8.2":
        raise ReviewError("provenance lock does not identify Harvester v1.8.2")

    tools = lock.get("toolchain_artifacts")
    unresolved = lock.get("unresolved")
    if not isinstance(tools, list) or not isinstance(unresolved, list):
        raise ReviewError("provenance lock toolchain_artifacts/unresolved section is invalid")

    same_id = [
        item for item in tools if isinstance(item, dict) and item.get("id") == entry["id"]
    ]
    unresolved_present = any(
        isinstance(item, dict) and item.get("id") == UNRESOLVED_ID
        for item in unresolved
    )
    if len(same_id) > 1:
        raise ReviewError("provenance lock contains duplicate Syft toolchain entries")
    if same_id and same_id[0] != entry:
        raise ReviewError("existing Syft toolchain entry conflicts with reviewed evidence")
    if not unresolved_present and not same_id:
        raise ReviewError("Syft unresolved marker is absent but no accepted Syft entry exists")

    new_tools = [
        dict(item)
        for item in tools
        if not (isinstance(item, dict) and item.get("id") == entry["id"])
    ]
    new_tools.append(entry)
    new_tools.sort(key=lambda item: str(item.get("id", "")))

    new_unresolved = [
        item
        for item in unresolved
        if not (isinstance(item, dict) and item.get("id") == UNRESOLVED_ID)
    ]

    updated = dict(lock)
    updated["toolchain_artifacts"] = new_tools
    updated["unresolved"] = new_unresolved
    updated["reviewed_syft_tool"] = {
        "status": "syft-reviewed-lock-still-incomplete",
        "source_commit": source_commit,
        "descriptor_sha256": sha256_file(descriptor_path),
        "validation_sha256": sha256_file(validation_path),
        "id": entry["id"],
        "version": entry["version"],
        "archive_sha256": entry["sha256"],
        "binary_sha256": entry["binary_sha256"],
    }

    remaining_ids = sorted(
        str(item.get("id"))
        for item in new_unresolved
        if isinstance(item, dict) and item.get("id")
    )
    report = {
        "schema": "layersentry.locked-tool-review/v1",
        "source_commit": source_commit,
        "id": entry["id"],
        "version": entry["version"],
        "descriptor_sha256": sha256_file(descriptor_path),
        "validation_sha256": sha256_file(validation_path),
        "archive_sha256": entry["sha256"],
        "binary_sha256": entry["binary_sha256"],
        "removed_unresolved_id": UNRESOLVED_ID,
        "remaining_unresolved_count": len(new_unresolved),
        "remaining_unresolved_ids": remaining_ids,
        "lock_status": "incomplete",
        "production_lock_complete": False,
        "release_approved": False,
        "applied": apply,
    }
    if apply:
        atomic_json_write(lock_path, updated)
    return updated, report


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--descriptor", required=True, type=Path)
    parser.add_argument("--validation", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        _, report = review(
            args.descriptor,
            args.validation,
            args.lock,
            args.source_commit,
            args.apply,
        )
    except ReviewError as exc:
        print(f"ERROR: {exc}")
        return 1
    atomic_json_write(args.report, report)
    action = "APPLIED" if args.apply else "DRY-RUN"
    print(
        f"LOCKED SYFT REVIEW: {action} "
        f"({report['remaining_unresolved_count']} unresolved inputs remain)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
