#!/usr/bin/env python3
"""Review immutable builder/toolchain evidence and merge it into the incomplete lock."""
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
OCI_REF_RE = re.compile(
    r"^ghcr\.io/adaptgurus/layersentry-full-offline-builder@sha256:[0-9a-f]{64}$"
)
BUILDER_IMAGE_ID = "layersentry-full-offline-builder"
BUILDER_REPOSITORY = "ghcr.io/adaptgurus/layersentry-full-offline-builder"
UNRESOLVED_IDS = {
    "layersentry-full-offline-builder-image",
    "build-toolchain",
}
TOOL_IDS = {
    "layersentry-builder-go",
    "layersentry-builder-docker-client",
    "layersentry-builder-docker-daemon",
    "layersentry-builder-docker-buildx",
    "layersentry-builder-python3",
    "layersentry-builder-git",
    "layersentry-builder-curl",
    "layersentry-builder-wget",
    "layersentry-builder-yq",
    "layersentry-builder-jq",
    "layersentry-builder-helm",
    "layersentry-builder-syft",
    "layersentry-builder-xorriso",
    "layersentry-builder-mksquashfs",
    "layersentry-builder-zstd",
    "layersentry-builder-tar",
    "layersentry-builder-gzip",
    "layersentry-builder-sha256sum",
    "layersentry-builder-sha512sum",
    "layersentry-builder-mcopy",
    "layersentry-builder-mkfs-vfat",
    "layersentry-builder-rsync",
    "layersentry-builder-patch",
    "layersentry-builder-awk",
    "layersentry-builder-sed",
}
META_ARTIFACT_IDS = {
    "layersentry-builder-oci-manifest",
    "layersentry-builder-rpm-inventory",
    "layersentry-builder-source-contract",
    "layersentry-builder-dockerfile",
}
EXPECTED_ARTIFACT_IDS = TOOL_IDS | META_ARTIFACT_IDS


class ReviewError(ValueError):
    """Raised when builder/toolchain evidence cannot be accepted."""


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
        raise ReviewError(f"invalid JSON in {label}: {exc}") from exc
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


def validate_candidate(
    candidate: dict[str, Any], source_commit: str
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not COMMIT_RE.fullmatch(source_commit):
        raise ReviewError("review source commit must be exactly 40 lowercase hex characters")
    expected_alias = f"{BUILDER_REPOSITORY}:source-{source_commit}"
    comparisons = {
        "schema": "layersentry.builder-toolchain-candidate/v1",
        "source_commit": source_commit,
        "platform": "linux/amd64",
        "release_approved": False,
        "tool_count": len(TOOL_IDS),
    }
    for field, expected in comparisons.items():
        if candidate.get(field) != expected:
            raise ReviewError(
                f"candidate field {field!r} is {candidate.get(field)!r}; expected {expected!r}"
            )

    identity = candidate.get("release_identity")
    if identity != {
        "product": "LayerSentry v1.0",
        "embedded_platform": "Harvester v1.8.2",
    }:
        raise ReviewError("candidate release identity is not LayerSentry v1.0 / Harvester v1.8.2")
    for field in ("rootfs_layer_count", "source_input_count"):
        value = candidate.get(field)
        if not isinstance(value, int) or value <= 0:
            raise ReviewError(f"candidate {field} is not a positive integer")
    if candidate["source_input_count"] < 9:
        raise ReviewError("candidate source-input contract is unexpectedly small")

    image = candidate.get("builder_image")
    if not isinstance(image, dict):
        raise ReviewError("candidate builder_image is not an object")
    if image.get("id") != BUILDER_IMAGE_ID:
        raise ReviewError("candidate builder image has an unexpected ID")
    ref = str(image.get("ref", ""))
    if not OCI_REF_RE.fullmatch(ref):
        raise ReviewError("candidate builder image is not an exact approved GHCR digest")
    if image.get("aliases") != [expected_alias]:
        raise ReviewError("candidate builder alias is not bound to the exact source commit")

    raw_artifacts = candidate.get("toolchain_artifacts")
    if not isinstance(raw_artifacts, list):
        raise ReviewError("candidate toolchain_artifacts is not an array")
    if len(raw_artifacts) != len(EXPECTED_ARTIFACT_IDS):
        raise ReviewError(
            f"candidate contains {len(raw_artifacts)} toolchain artifacts; "
            f"expected {len(EXPECTED_ARTIFACT_IDS)}"
        )

    seen: set[str] = set()
    reviewed: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_artifacts):
        if not isinstance(raw, dict):
            raise ReviewError(f"candidate toolchain_artifacts[{index}] is not an object")
        item_id = str(raw.get("id", ""))
        if not item_id or item_id in seen:
            raise ReviewError(f"candidate contains a missing or duplicate artifact ID: {item_id!r}")
        seen.add(item_id)
        version = str(raw.get("version", ""))
        source = str(raw.get("source", ""))
        checksum = str(raw.get("sha256", ""))
        if not version or version.lower() in {"latest", "head", "main", "master"}:
            raise ReviewError(f"candidate artifact {item_id!r} has a floating version")
        if not source or "releases/latest" in source.lower() or ":latest" in source.lower():
            raise ReviewError(f"candidate artifact {item_id!r} has a mutable source")
        if not SHA256_RE.fullmatch(checksum):
            raise ReviewError(f"candidate artifact {item_id!r} has an invalid SHA-256")
        if item_id in {"layersentry-builder-source-contract", "layersentry-builder-dockerfile"}:
            if source_commit not in source:
                raise ReviewError(f"candidate artifact {item_id!r} is not bound to the source commit")
        elif ref not in source:
            raise ReviewError(f"candidate artifact {item_id!r} is not bound to the builder digest")
        reviewed.append(dict(raw))

    if seen != EXPECTED_ARTIFACT_IDS:
        raise ReviewError(
            "candidate artifact IDs differ from reviewed set; "
            f"missing={sorted(EXPECTED_ARTIFACT_IDS - seen)}, "
            f"extra={sorted(seen - EXPECTED_ARTIFACT_IDS)}"
        )
    reviewed.sort(key=lambda item: item["id"])
    return dict(image), reviewed


def review(
    candidate_path: Path,
    lock_path: Path,
    source_commit: str,
    apply: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    candidate = load_object(candidate_path, "builder/toolchain candidate")
    reviewed_image, reviewed_artifacts = validate_candidate(candidate, source_commit)

    lock = load_object(lock_path, "provenance lock")
    if lock.get("schema") != "layersentry.provenance-lock/v1":
        raise ReviewError("unsupported provenance lock schema")
    if lock.get("lock_status") != "incomplete":
        raise ReviewError("builder review may only update an incomplete provenance lock")
    identity = lock.get("release_identity")
    if not isinstance(identity, dict):
        raise ReviewError("provenance lock release identity is missing")
    if identity.get("product", {}).get("version") != "v1.0":
        raise ReviewError("provenance lock does not identify LayerSentry v1.0")
    if identity.get("embedded_platform", {}).get("version") != "v1.8.2":
        raise ReviewError("provenance lock does not identify Harvester v1.8.2")

    images = lock.get("container_images")
    artifacts = lock.get("toolchain_artifacts")
    unresolved = lock.get("unresolved")
    if not isinstance(images, list) or not isinstance(artifacts, list) or not isinstance(unresolved, list):
        raise ReviewError("provenance lock image/toolchain/unresolved sections are invalid")

    unresolved_ids = {
        str(item.get("id"))
        for item in unresolved
        if isinstance(item, dict) and item.get("id")
    }
    missing_markers = UNRESOLVED_IDS - unresolved_ids
    if missing_markers:
        raise ReviewError(
            "builder/toolchain unresolved marker is absent; refusing to replace an established lock: "
            f"{sorted(missing_markers)}"
        )

    image_by_id: dict[str, dict[str, Any]] = {}
    for raw in images:
        if not isinstance(raw, dict):
            raise ReviewError("provenance lock image entry is not an object")
        item_id = str(raw.get("id", ""))
        if not item_id or item_id in image_by_id:
            raise ReviewError(f"provenance lock contains a missing or duplicate image ID: {item_id!r}")
        image_by_id[item_id] = dict(raw)
    existing_image = image_by_id.get(BUILDER_IMAGE_ID)
    if existing_image is not None and existing_image != reviewed_image:
        raise ReviewError("an existing builder image conflicts with reviewed evidence")
    image_by_id[BUILDER_IMAGE_ID] = reviewed_image

    artifact_by_id: dict[str, dict[str, Any]] = {}
    for raw in artifacts:
        if not isinstance(raw, dict):
            raise ReviewError("provenance lock toolchain artifact is not an object")
        item_id = str(raw.get("id", ""))
        if not item_id or item_id in artifact_by_id:
            raise ReviewError(
                f"provenance lock contains a missing or duplicate toolchain artifact ID: {item_id!r}"
            )
        artifact_by_id[item_id] = dict(raw)
    for entry in reviewed_artifacts:
        existing = artifact_by_id.get(entry["id"])
        if existing is not None and existing != entry:
            raise ReviewError(
                f"existing toolchain artifact {entry['id']!r} conflicts with reviewed evidence"
            )
        artifact_by_id[entry["id"]] = entry

    new_unresolved = [
        item
        for item in unresolved
        if not (isinstance(item, dict) and item.get("id") in UNRESOLVED_IDS)
    ]
    updated = dict(lock)
    updated["container_images"] = [image_by_id[item_id] for item_id in sorted(image_by_id)]
    updated["toolchain_artifacts"] = [
        artifact_by_id[item_id] for item_id in sorted(artifact_by_id)
    ]
    updated["unresolved"] = new_unresolved
    updated["reviewed_builder_toolchain"] = {
        "status": "immutable-builder-and-toolchain-reviewed-lock-still-incomplete",
        "source_commit": source_commit,
        "candidate_sha256": sha256_file(candidate_path),
        "builder_ref": reviewed_image["ref"],
        "builder_alias": reviewed_image["aliases"][0],
        "platform": candidate["platform"],
        "rootfs_layer_count": candidate["rootfs_layer_count"],
        "tool_count": candidate["tool_count"],
        "toolchain_artifact_count": len(reviewed_artifacts),
        "source_input_count": candidate["source_input_count"],
    }

    remaining_ids = sorted(
        str(item.get("id"))
        for item in new_unresolved
        if isinstance(item, dict) and item.get("id")
    )
    report = {
        "schema": "layersentry.builder-toolchain-lock-review/v1",
        "source_commit": source_commit,
        "candidate_sha256": sha256_file(candidate_path),
        "builder_ref": reviewed_image["ref"],
        "tool_count": candidate["tool_count"],
        "toolchain_artifact_count": len(reviewed_artifacts),
        "removed_unresolved_ids": sorted(UNRESOLVED_IDS),
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
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        _, report = review(
            args.candidate,
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
        f"BUILDER TOOLCHAIN LOCK REVIEW: {action} "
        f"({report['toolchain_artifact_count']} artifacts; "
        f"{report['remaining_unresolved_count']} unresolved groups remain)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
