#!/usr/bin/env python3
"""Review a source-bound LayerSentry controller image and merge its immutable lock."""
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
    r"^ghcr\.io/adaptgurus/layersentry-controller@sha256:[0-9a-f]{64}$"
)
SOURCE_REPOSITORY = "https://github.com/adaptgurus/harvester-installer.git"
IMAGE_REPOSITORY = "ghcr.io/adaptgurus/layersentry-controller"
IMAGE_ID = "layersentry-controller"
SOURCE_COMPONENT = "layersentry-controller"
VERSION = "v1.0.0"
UNRESOLVED_ID = "layersentry-controller-image"
EXPECTED_SOURCE_INPUTS = {
    "go.mod",
    "cmd/layersentry-controller/main.go",
    "cmd/layersentry-controller/main_test.go",
    "package/layersentry-controller/Dockerfile",
    "package/layersentry-controller/README.md",
    "scripts/build-layersentry-controller",
    "scripts/default",
    "scripts/images/harvester-additional-images.txt",
    "scripts/provenance/review_controller_image.py",
    "scripts/provenance/verify_controller_binding.py",
    "tests/test_controller_image_lock.py",
    ".github/workflows/layersentry-v1.0-controller-lock.yml",
}


class ReviewError(ValueError):
    """Raised when controller evidence cannot be accepted."""


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


def validate_checksum(value: Any, field: str) -> str:
    text = str(value or "")
    if not SHA256_RE.fullmatch(text):
        raise ReviewError(f"{field} must be exactly 64 lowercase hexadecimal characters")
    return text


def validate_candidate(
    candidate: dict[str, Any], source_commit: str
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if not COMMIT_RE.fullmatch(source_commit):
        raise ReviewError("review source commit must be exactly 40 lowercase hex characters")
    expected_aliases = [
        f"{IMAGE_REPOSITORY}:{VERSION}",
        f"{IMAGE_REPOSITORY}:source-{source_commit}",
    ]
    expected_scalars = {
        "schema": "layersentry.controller-image-candidate/v1",
        "source_commit": source_commit,
        "version": VERSION,
        "platform": "linux/amd64",
        "runtime_user": "65532:65532",
        "bundled": True,
        "installed": False,
        "runtime_qualified": False,
        "release_approved": False,
    }
    for field, expected in expected_scalars.items():
        if candidate.get(field) != expected:
            raise ReviewError(
                f"candidate field {field!r} is {candidate.get(field)!r}; expected {expected!r}"
            )
    build_epoch = candidate.get("build_epoch")
    if not isinstance(build_epoch, int) or build_epoch <= 0:
        raise ReviewError("candidate build_epoch must be a positive Unix timestamp")
    if candidate.get("release_identity") != {
        "product": "LayerSentry v1.0",
        "embedded_platform": "Harvester v1.8.2",
    }:
        raise ReviewError("candidate release identity is not LayerSentry v1.0 / Harvester v1.8.2")

    image = candidate.get("controller_image")
    if not isinstance(image, dict):
        raise ReviewError("candidate controller_image is not an object")
    if image.get("id") != IMAGE_ID:
        raise ReviewError("candidate controller image has an unexpected ID")
    if image.get("aliases") != expected_aliases:
        raise ReviewError("candidate controller aliases are not the reviewed version/source pair")
    image_ref = str(image.get("ref", ""))
    if not OCI_REF_RE.fullmatch(image_ref):
        raise ReviewError("candidate controller image is not an exact approved GHCR digest")

    binary = candidate.get("binary")
    if not isinstance(binary, dict):
        raise ReviewError("candidate binary is not an object")
    if binary.get("path") != "layersentry-controller-linux-amd64":
        raise ReviewError("candidate binary path is unexpected")
    if not isinstance(binary.get("bytes"), int) or binary["bytes"] <= 0:
        raise ReviewError("candidate binary byte count is not positive")
    validate_checksum(binary.get("sha256"), "binary.sha256")

    config_digest = validate_checksum(
        candidate.get("image_config_digest"), "image_config_digest"
    )
    rootfs = candidate.get("rootfs_diff_ids")
    if (
        not isinstance(rootfs, list)
        or len(rootfs) != 1
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(rootfs[0]))
    ):
        raise ReviewError("scratch controller image must contain exactly one valid rootfs diff ID")
    if candidate.get("entrypoint") != ["/usr/local/bin/layersentry-controller"]:
        raise ReviewError("candidate controller entrypoint is unexpected")
    if candidate.get("cmd") != ["--listen", "0.0.0.0:9443"]:
        raise ReviewError("candidate controller command is unexpected")

    labels = candidate.get("image_labels")
    if not isinstance(labels, dict):
        raise ReviewError("candidate image_labels is not an object")
    expected_labels = {
        "org.opencontainers.image.version": VERSION,
        "org.opencontainers.image.revision": source_commit,
        "org.opencontainers.image.created": str(build_epoch),
        "io.layersentry.product": "LayerSentry",
        "io.layersentry.product-version": "v1.0",
        "io.layersentry.embedded-platform": "Harvester",
        "io.layersentry.embedded-platform-version": "v1.8.2",
        "io.layersentry.lifecycle": "BUNDLED_NOT_INSTALLED",
        "io.layersentry.runtime-qualified": "false",
        "io.layersentry.release-approved": "false",
    }
    for key, expected in expected_labels.items():
        if labels.get(key) != expected:
            raise ReviewError(
                f"candidate image label {key!r} is {labels.get(key)!r}; expected {expected!r}"
            )

    raw_inputs = candidate.get("source_inputs")
    if not isinstance(raw_inputs, list):
        raise ReviewError("candidate source_inputs is not an array")
    source_inputs: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(raw_inputs):
        if not isinstance(raw, dict):
            raise ReviewError(f"candidate source_inputs[{index}] is not an object")
        path = str(raw.get("path", ""))
        if not path or path in source_inputs or path.startswith("/") or ".." in Path(path).parts:
            raise ReviewError(f"candidate contains an invalid or duplicate source path: {path!r}")
        if not isinstance(raw.get("bytes"), int) or raw["bytes"] <= 0:
            raise ReviewError(f"candidate source input {path!r} has an invalid byte count")
        validate_checksum(raw.get("sha256"), f"source_inputs[{path!r}].sha256")
        source_inputs[path] = dict(raw)
    if set(source_inputs) != EXPECTED_SOURCE_INPUTS:
        raise ReviewError(
            "candidate source-input set differs from reviewed contract; "
            f"missing={sorted(EXPECTED_SOURCE_INPUTS - set(source_inputs))}, "
            f"extra={sorted(set(source_inputs) - EXPECTED_SOURCE_INPUTS)}"
        )

    sbom = candidate.get("sbom")
    if not isinstance(sbom, dict):
        raise ReviewError("candidate SBOM metadata is not an object")
    if sbom.get("path") != "controller-sbom.spdx.json" or sbom.get("format") != "SPDX JSON":
        raise ReviewError("candidate SBOM path or format is unexpected")
    if not isinstance(sbom.get("bytes"), int) or sbom["bytes"] <= 0:
        raise ReviewError("candidate SBOM byte count is not positive")
    validate_checksum(sbom.get("sha256"), "sbom.sha256")

    reviewed = {
        "status": "immutable-controller-image-reviewed-lock-still-incomplete",
        "source_commit": source_commit,
        "version": VERSION,
        "build_epoch": build_epoch,
        "candidate_sha256": "",
        "image_ref": image_ref,
        "image_config_digest": config_digest,
        "rootfs_diff_ids": list(rootfs),
        "binary_sha256": binary["sha256"],
        "binary_bytes": binary["bytes"],
        "runtime_user": candidate["runtime_user"],
        "entrypoint": candidate["entrypoint"],
        "cmd": candidate["cmd"],
        "image_labels": dict(sorted(labels.items())),
        "source_inputs": [source_inputs[path] for path in sorted(source_inputs)],
        "sbom": dict(sbom),
        "bundled": True,
        "installed": False,
        "runtime_qualified": False,
        "release_approved": False,
    }
    source_lock = {
        "component": SOURCE_COMPONENT,
        "repository": SOURCE_REPOSITORY,
        "commit": source_commit,
        "version_label": VERSION,
    }
    return dict(image), source_lock, reviewed


def review(
    candidate_path: Path,
    lock_path: Path,
    source_commit: str,
    apply: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    candidate = load_object(candidate_path, "controller candidate")
    reviewed_image, reviewed_source, reviewed = validate_candidate(candidate, source_commit)
    reviewed["candidate_sha256"] = sha256_file(candidate_path)

    lock = load_object(lock_path, "provenance lock")
    if lock.get("schema") != "layersentry.provenance-lock/v1":
        raise ReviewError("unsupported provenance lock schema")
    if lock.get("lock_status") != "incomplete":
        raise ReviewError("controller review may only update an incomplete provenance lock")
    identity = lock.get("release_identity")
    if not isinstance(identity, dict):
        raise ReviewError("provenance lock release identity is missing")
    if identity.get("product", {}).get("version") != "v1.0":
        raise ReviewError("provenance lock does not identify LayerSentry v1.0")
    if identity.get("embedded_platform", {}).get("version") != "v1.8.2":
        raise ReviewError("provenance lock does not identify Harvester v1.8.2")

    images = lock.get("container_images")
    sources = lock.get("source_locks")
    unresolved = lock.get("unresolved")
    if not isinstance(images, list) or not isinstance(sources, list) or not isinstance(unresolved, list):
        raise ReviewError("provenance lock image/source/unresolved sections are invalid")
    unresolved_ids = {
        str(item.get("id"))
        for item in unresolved
        if isinstance(item, dict) and item.get("id")
    }
    if UNRESOLVED_ID not in unresolved_ids:
        raise ReviewError(
            "controller unresolved marker is absent; refusing to replace an established lock"
        )

    image_by_id: dict[str, dict[str, Any]] = {}
    for raw in images:
        if not isinstance(raw, dict):
            raise ReviewError("provenance lock image entry is not an object")
        item_id = str(raw.get("id", ""))
        if not item_id or item_id in image_by_id:
            raise ReviewError(f"provenance lock contains a missing or duplicate image ID: {item_id!r}")
        image_by_id[item_id] = dict(raw)
    existing_image = image_by_id.get(IMAGE_ID)
    if existing_image is not None and existing_image != reviewed_image:
        raise ReviewError("an existing controller image conflicts with reviewed evidence")
    image_by_id[IMAGE_ID] = reviewed_image

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
    existing_source = source_by_component.get(SOURCE_COMPONENT)
    if existing_source is not None and existing_source != reviewed_source:
        raise ReviewError("an existing controller source lock conflicts with reviewed evidence")
    source_by_component[SOURCE_COMPONENT] = reviewed_source

    new_unresolved = [
        item
        for item in unresolved
        if not (isinstance(item, dict) and item.get("id") == UNRESOLVED_ID)
    ]
    updated = dict(lock)
    updated["container_images"] = [image_by_id[item_id] for item_id in sorted(image_by_id)]
    updated["source_locks"] = [
        source_by_component[component] for component in sorted(source_by_component)
    ]
    updated["unresolved"] = new_unresolved
    updated["reviewed_controller_image"] = reviewed

    remaining_ids = sorted(
        str(item.get("id"))
        for item in new_unresolved
        if isinstance(item, dict) and item.get("id")
    )
    report = {
        "schema": "layersentry.controller-image-lock-review/v1",
        "source_commit": source_commit,
        "candidate_sha256": reviewed["candidate_sha256"],
        "image_ref": reviewed_image["ref"],
        "binary_sha256": reviewed["binary_sha256"],
        "image_config_digest": reviewed["image_config_digest"],
        "removed_unresolved_id": UNRESOLVED_ID,
        "remaining_unresolved_count": len(new_unresolved),
        "remaining_unresolved_ids": remaining_ids,
        "lock_status": "incomplete",
        "bundled": True,
        "installed": False,
        "runtime_qualified": False,
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
        f"CONTROLLER IMAGE LOCK REVIEW: {action} "
        f"({report['image_ref']}; {report['remaining_unresolved_count']} unresolved groups remain)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
