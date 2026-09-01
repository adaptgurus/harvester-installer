#!/usr/bin/env python3
"""Review generated Harvester images and complete the LayerSentry dependency lock."""
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
OCI_REF_RE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
UNRESOLVED_ID = "harvester-offline-image-set"
SOURCE_COMPONENT = "layersentry-offline-image-set-build"
SOURCE_REPOSITORY = "https://github.com/adaptgurus/harvester-installer.git"

EXPECTED_IMAGES = {
    "layersentry-generated-harvester-cluster-repo": {
        "runtime_alias": "docker.io/rancher/harvester-cluster-repo:v1.0",
        "repository": "ghcr.io/adaptgurus/layersentry-harvester-cluster-repo",
    },
    "layersentry-generated-harvester-installer": {
        "runtime_alias": "docker.io/rancher/harvester-installer:v1.0",
        "repository": "ghcr.io/adaptgurus/layersentry-harvester-installer",
    },
    "layersentry-generated-harvester-os": {
        "runtime_alias": "docker.io/rancher/harvester-os:v1.0",
        "repository": "ghcr.io/adaptgurus/layersentry-harvester-os",
    },
}
EXPECTED_SOURCE_INPUTS = {
    "package/harvester-repo/Dockerfile",
    "package/harvester-installer/Dockerfile",
    "package/harvester-os/Dockerfile",
    "scripts/build",
    "scripts/build-bundle",
    "scripts/default",
    "scripts/package-harvester-repo",
    "scripts/package-harvester-installer",
    "scripts/package-harvester-os",
    "scripts/lib/image",
    "scripts/provenance/collect_offline_image_set_evidence.sh",
    "scripts/provenance/review_offline_image_set.py",
    "scripts/provenance/verify_offline_image_set_binding.py",
    "scripts/provenance/prepare_finalizer_iso_evidence.sh",
    "tests/test_offline_image_set_lock.py",
    ".github/workflows/layersentry-v1.0-offline-image-set-lock.yml",
}


class ReviewError(ValueError):
    """Raised when image-set evidence cannot be accepted."""


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


def require_sha256(value: Any, field: str) -> str:
    text = str(value or "")
    if not SHA256_RE.fullmatch(text):
        raise ReviewError(f"{field} must be exactly 64 lowercase hexadecimal characters")
    return text


def validate_candidate(
    candidate: dict[str, Any], source_commit: str, build_run_id: int
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not COMMIT_RE.fullmatch(source_commit):
        raise ReviewError("review source commit must be exactly 40 lowercase hex characters")
    if not isinstance(build_run_id, int) or build_run_id <= 0:
        raise ReviewError("review build run ID must be a positive integer")

    expected_scalars = {
        "schema": "layersentry.offline-image-set-candidate/v1",
        "source_commit": source_commit,
        "build_run_id": build_run_id,
        "dependency_lock_complete": False,
        "installed": False,
        "runtime_qualified": False,
        "release_approved": False,
    }
    for field, expected in expected_scalars.items():
        if candidate.get(field) != expected:
            raise ReviewError(
                f"candidate field {field!r} is {candidate.get(field)!r}; expected {expected!r}"
            )
    if not COMMIT_RE.fullmatch(str(candidate.get("source_tree", ""))):
        raise ReviewError("candidate source_tree must be an exact Git tree ID")
    if candidate.get("release_identity") != {
        "product": "LayerSentry v1.0",
        "embedded_platform": "Harvester v1.8.2",
    }:
        raise ReviewError("candidate release identity is not LayerSentry v1.0 / Harvester v1.8.2")

    raw_images = candidate.get("images")
    if not isinstance(raw_images, list) or len(raw_images) != len(EXPECTED_IMAGES):
        raise ReviewError(
            f"candidate must contain exactly {len(EXPECTED_IMAGES)} generated images"
        )
    images: dict[str, dict[str, Any]] = {}
    reviewed_images: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_images):
        if not isinstance(raw, dict):
            raise ReviewError(f"candidate images[{index}] is not an object")
        image_id = str(raw.get("id", ""))
        if not image_id or image_id in images:
            raise ReviewError(f"candidate contains a missing or duplicate image ID: {image_id!r}")
        images[image_id] = raw

    if set(images) != set(EXPECTED_IMAGES):
        raise ReviewError(
            "candidate generated-image IDs differ from reviewed set; "
            f"missing={sorted(set(EXPECTED_IMAGES) - set(images))}, "
            f"extra={sorted(set(images) - set(EXPECTED_IMAGES))}"
        )

    for image_id in sorted(EXPECTED_IMAGES):
        raw = images[image_id]
        expected = EXPECTED_IMAGES[image_id]
        runtime_alias = expected["runtime_alias"]
        source_alias = (
            f"{expected['repository']}:source-{source_commit}-run-{build_run_id}"
        )
        if raw.get("aliases") != [runtime_alias, source_alias]:
            raise ReviewError(f"candidate aliases for {image_id!r} are not source/run bound")
        ref = str(raw.get("ref", ""))
        if not OCI_REF_RE.fullmatch(ref) or not ref.startswith(expected["repository"] + "@sha256:"):
            raise ReviewError(f"candidate ref for {image_id!r} is not an approved immutable GHCR digest")
        if raw.get("platform") != "linux/amd64":
            raise ReviewError(f"candidate platform for {image_id!r} is not linux/amd64")
        require_sha256(raw.get("config_digest"), f"images[{image_id!r}].config_digest")
        rootfs = raw.get("rootfs_diff_ids")
        if not isinstance(rootfs, list) or not rootfs:
            raise ReviewError(f"candidate image {image_id!r} has no rootfs diff IDs")
        for layer in rootfs:
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(layer)):
                raise ReviewError(f"candidate image {image_id!r} has an invalid rootfs diff ID")
        if not isinstance(raw.get("size_bytes"), int) or raw["size_bytes"] <= 0:
            raise ReviewError(f"candidate image {image_id!r} has an invalid size")
        if not isinstance(raw.get("runtime_config"), dict):
            raise ReviewError(f"candidate image {image_id!r} has no runtime config")
        sbom = raw.get("sbom")
        if not isinstance(sbom, dict):
            raise ReviewError(f"candidate image {image_id!r} has no SBOM metadata")
        if sbom.get("format") != "SPDX JSON":
            raise ReviewError(f"candidate image {image_id!r} SBOM is not SPDX JSON")
        require_sha256(sbom.get("sha256"), f"images[{image_id!r}].sbom.sha256")
        if not isinstance(sbom.get("bytes"), int) or sbom["bytes"] <= 0:
            raise ReviewError(f"candidate image {image_id!r} SBOM is empty")
        if not isinstance(sbom.get("package_count"), int) or sbom["package_count"] < 0:
            raise ReviewError(f"candidate image {image_id!r} SBOM package count is invalid")
        reviewed_images.append(dict(raw))

    raw_inputs = candidate.get("source_inputs")
    if not isinstance(raw_inputs, list):
        raise ReviewError("candidate source_inputs is not an array")
    source_inputs: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(raw_inputs):
        if not isinstance(raw, dict):
            raise ReviewError(f"candidate source_inputs[{index}] is not an object")
        path = str(raw.get("path", ""))
        if not path or path in source_inputs or Path(path).is_absolute() or ".." in Path(path).parts:
            raise ReviewError(f"candidate contains an invalid or duplicate source path: {path!r}")
        if not isinstance(raw.get("bytes"), int) or raw["bytes"] <= 0:
            raise ReviewError(f"candidate source input {path!r} has an invalid byte count")
        require_sha256(raw.get("sha256"), f"source_inputs[{path!r}].sha256")
        source_inputs[path] = dict(raw)
    if set(source_inputs) != EXPECTED_SOURCE_INPUTS:
        raise ReviewError(
            "candidate source-input set differs from reviewed contract; "
            f"missing={sorted(EXPECTED_SOURCE_INPUTS - set(source_inputs))}, "
            f"extra={sorted(set(source_inputs) - EXPECTED_SOURCE_INPUTS)}"
        )

    image_lists = candidate.get("image_lists")
    if not isinstance(image_lists, dict):
        raise ReviewError("candidate image_lists is not an object")
    files = image_lists.get("files")
    if not isinstance(files, list) or not files:
        raise ReviewError("candidate image-list file inventory is empty")
    if image_lists.get("file_count") != len(files):
        raise ReviewError("candidate image-list file count is inconsistent")
    if not isinstance(image_lists.get("observed_alias_count"), int) or image_lists["observed_alias_count"] < 100:
        raise ReviewError("candidate observed image-alias count is unexpectedly small")
    require_sha256(image_lists.get("aggregate_sha256"), "image_lists.aggregate_sha256")
    seen_list_paths: set[str] = set()
    for index, raw in enumerate(files):
        if not isinstance(raw, dict):
            raise ReviewError(f"candidate image_lists.files[{index}] is not an object")
        path = str(raw.get("path", ""))
        if not path.startswith("image-lists/") or path in seen_list_paths:
            raise ReviewError(f"candidate image-list path is invalid or duplicated: {path!r}")
        seen_list_paths.add(path)
        require_sha256(raw.get("sha256"), f"image_lists.files[{path!r}].sha256")
        if not isinstance(raw.get("bytes"), int) or raw["bytes"] <= 0:
            raise ReviewError(f"candidate image-list {path!r} is empty")
        if not isinstance(raw.get("entry_count"), int) or raw["entry_count"] <= 0:
            raise ReviewError(f"candidate image-list {path!r} has no entries")

    iso = candidate.get("iso_candidate")
    if not isinstance(iso, dict):
        raise ReviewError("candidate iso_candidate is not an object")
    if iso.get("path") != "dist/artifacts/harvester-v1.0-amd64.iso":
        raise ReviewError("candidate ISO path is unexpected")
    if not isinstance(iso.get("bytes"), int) or iso["bytes"] < 1024 * 1024 * 1024:
        raise ReviewError("candidate ISO is unexpectedly small")
    require_sha256(iso.get("sha256"), "iso_candidate.sha256")
    sha512 = str(iso.get("sha512", ""))
    if not re.fullmatch(r"[0-9a-f]{128}", sha512):
        raise ReviewError("iso_candidate.sha512 is invalid")

    reviewed_images.sort(key=lambda item: item["id"])
    reviewed = {
        "status": "generated-images-reviewed-dependency-lock-complete-runtime-gates-pending",
        "build_source_commit": source_commit,
        "build_source_tree": candidate["source_tree"],
        "build_run_id": build_run_id,
        "candidate_sha256": "",
        "images": reviewed_images,
        "source_inputs": [source_inputs[path] for path in sorted(source_inputs)],
        "image_lists": dict(image_lists),
        "iso_candidate": dict(iso),
        "dependency_lock_complete": True,
        "installed": False,
        "runtime_qualified": False,
        "airgap_qualified": False,
        "release_approved": False,
    }
    return reviewed_images, reviewed


def review(
    candidate_path: Path,
    lock_path: Path,
    source_commit: str,
    build_run_id: int,
    apply: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    candidate = load_object(candidate_path, "offline image-set candidate")
    reviewed_images, reviewed = validate_candidate(
        candidate, source_commit, build_run_id
    )
    reviewed["candidate_sha256"] = sha256_file(candidate_path)

    lock = load_object(lock_path, "provenance lock")
    if lock.get("schema") != "layersentry.provenance-lock/v1":
        raise ReviewError("unsupported provenance lock schema")
    if lock.get("lock_status") != "incomplete":
        raise ReviewError("offline image-set review may only update an incomplete lock")
    unresolved = lock.get("unresolved")
    images = lock.get("container_images")
    sources = lock.get("source_locks")
    if not isinstance(unresolved, list) or not isinstance(images, list) or not isinstance(sources, list):
        raise ReviewError("provenance lock image/source/unresolved sections are invalid")
    unresolved_ids = [
        str(item.get("id"))
        for item in unresolved
        if isinstance(item, dict) and item.get("id")
    ]
    if unresolved_ids != [UNRESOLVED_ID]:
        raise ReviewError(
            f"offline image-set review requires exactly [{UNRESOLVED_ID!r}] unresolved; "
            f"found {unresolved_ids!r}"
        )

    image_by_id: dict[str, dict[str, Any]] = {}
    alias_to_id: dict[str, str] = {}
    for raw in images:
        if not isinstance(raw, dict):
            raise ReviewError("provenance lock image entry is not an object")
        image_id = str(raw.get("id", ""))
        if not image_id or image_id in image_by_id:
            raise ReviewError(f"provenance lock contains a missing or duplicate image ID: {image_id!r}")
        image_by_id[image_id] = dict(raw)
        for alias in raw.get("aliases", []):
            alias_to_id[str(alias)] = image_id

    for entry in reviewed_images:
        image_id = entry["id"]
        if image_id in image_by_id:
            raise ReviewError(f"generated image {image_id!r} is already locked")
        for alias in entry["aliases"]:
            if alias in alias_to_id:
                raise ReviewError(
                    f"generated runtime alias {alias!r} already belongs to {alias_to_id[alias]!r}"
                )
        image_by_id[image_id] = {
            "id": image_id,
            "aliases": list(entry["aliases"]),
            "ref": entry["ref"],
        }

    source_by_component: dict[str, dict[str, Any]] = {}
    for raw in sources:
        if not isinstance(raw, dict):
            raise ReviewError("provenance lock source entry is not an object")
        component = str(raw.get("component", ""))
        if not component or component in source_by_component:
            raise ReviewError(
                f"provenance lock contains a missing or duplicate source component: {component!r}"
            )
        source_by_component[component] = dict(raw)
    if SOURCE_COMPONENT in source_by_component:
        raise ReviewError("offline image-set build source is already locked")
    source_by_component[SOURCE_COMPONENT] = {
        "component": SOURCE_COMPONENT,
        "repository": SOURCE_REPOSITORY,
        "commit": source_commit,
        "version_label": "v1.0",
    }

    updated = dict(lock)
    updated["container_images"] = [
        image_by_id[image_id] for image_id in sorted(image_by_id)
    ]
    updated["source_locks"] = [
        source_by_component[component] for component in sorted(source_by_component)
    ]
    updated["unresolved"] = []
    updated["lock_status"] = "complete"
    updated["reviewed_offline_image_set"] = reviewed

    report = {
        "schema": "layersentry.offline-image-set-lock-review/v1",
        "build_source_commit": source_commit,
        "build_run_id": build_run_id,
        "candidate_sha256": reviewed["candidate_sha256"],
        "generated_image_count": len(reviewed_images),
        "generated_image_refs": {
            entry["id"]: entry["ref"] for entry in reviewed_images
        },
        "observed_alias_count": reviewed["image_lists"]["observed_alias_count"],
        "iso_sha256": reviewed["iso_candidate"]["sha256"],
        "removed_unresolved_id": UNRESOLVED_ID,
        "remaining_unresolved_count": 0,
        "remaining_unresolved_ids": [],
        "lock_status": "complete",
        "dependency_lock_complete": True,
        "installed": False,
        "runtime_qualified": False,
        "airgap_qualified": False,
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
    parser.add_argument("--build-run-id", required=True, type=int)
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
            args.build_run_id,
            args.apply,
        )
    except ReviewError as exc:
        print(f"ERROR: {exc}")
        return 1
    atomic_json_write(args.report, report)
    action = "APPLIED" if args.apply else "DRY-RUN"
    print(
        f"OFFLINE IMAGE-SET LOCK REVIEW: {action} "
        f"({report['generated_image_count']} images; lock complete; runtime gates pending)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
