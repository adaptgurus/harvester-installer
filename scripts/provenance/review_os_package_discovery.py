#!/usr/bin/env python3
"""Review Harvester OS/package evidence and merge it into the incomplete lock."""
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
UNRESOLVED_ID = "harvester-os-and-package-inputs"
EXPECTED_ALIAS = "docker.io/rancher/harvester-os:v1.8-20260806"
EXPECTED_REF = (
    "docker.io/rancher/harvester-os@sha256:"
    "d437600ddc5e809cd22d9a6ddfc3c10328ac88440cef2930aa73aaf36b4178b4"
)
EXPECTED_IMAGE_ID = "docker-io-rancher-harvester-os"
EXPECTED_PACKAGE_IDS = {
    "harvester-base-os-oci-manifest",
    "harvester-base-os-rootfs-layer-set",
    "harvester-base-os-rpm-inventory",
    "harvester-base-os-kernel",
    "harvester-base-os-initrd",
    "harvester-base-os-firmware-inventory",
    "harvester-base-os-package-repositories",
    "harvester-base-os-elemental",
    "harvester-base-os-dracut",
    "harvester-base-os-release-metadata",
    "layersentry-harvester-os-overlay",
}


class ReviewError(ValueError):
    """Raised when OS/package evidence cannot be accepted."""


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
    candidate: dict[str, Any], plan_path: Path, source_commit: str
) -> list[dict[str, Any]]:
    if not COMMIT_RE.fullmatch(source_commit):
        raise ReviewError("review source commit must be exactly 40 lowercase hex characters")
    if candidate.get("schema") != "layersentry.os-package-lock-candidate/v1":
        raise ReviewError("unsupported OS/package candidate schema")
    comparisons = {
        "source_commit": source_commit,
        "plan_sha256": sha256_file(plan_path),
        "platform": "linux/amd64",
        "base_os_alias": EXPECTED_ALIAS,
        "base_os_ref": EXPECTED_REF,
        "all_inputs_verified": True,
        "production_lock_complete": False,
        "release_approved": False,
    }
    for field, expected in comparisons.items():
        if candidate.get(field) != expected:
            raise ReviewError(
                f"candidate field {field!r} is {candidate.get(field)!r}; expected {expected!r}"
            )
    if not COMMIT_RE.fullmatch(str(candidate.get("overlay_tree", ""))):
        raise ReviewError("candidate overlay tree is not an exact Git tree")
    for field in (
        "rootfs_layer_count",
        "rpm_package_count",
        "firmware_record_count",
        "firmware_regular_file_count",
        "repository_record_count",
    ):
        value = candidate.get(field)
        if not isinstance(value, int) or value <= 0:
            raise ReviewError(f"candidate {field} is not a positive integer")
    if candidate["rpm_package_count"] < 50:
        raise ReviewError("candidate RPM inventory is unexpectedly small")

    evidence = candidate.get("evidence")
    if not isinstance(evidence, dict) or len(evidence) < 8:
        raise ReviewError("candidate evidence manifest is incomplete")
    for name, raw in evidence.items():
        if not isinstance(raw, dict):
            raise ReviewError(f"candidate evidence {name!r} is not an object")
        if raw.get("file") != name:
            raise ReviewError(f"candidate evidence {name!r} has mismatched file identity")
        if not SHA256_RE.fullmatch(str(raw.get("sha256", ""))):
            raise ReviewError(f"candidate evidence {name!r} has invalid SHA-256")
        if not isinstance(raw.get("bytes"), int) or raw["bytes"] <= 0:
            raise ReviewError(f"candidate evidence {name!r} has invalid byte count")

    packages = candidate.get("packages")
    if not isinstance(packages, list) or len(packages) != len(EXPECTED_PACKAGE_IDS):
        raise ReviewError("candidate does not contain the complete reviewed package-input set")
    seen: set[str] = set()
    reviewed: list[dict[str, Any]] = []
    for index, raw in enumerate(packages):
        if not isinstance(raw, dict):
            raise ReviewError(f"candidate packages[{index}] is not an object")
        item_id = str(raw.get("id", ""))
        if not item_id or item_id in seen:
            raise ReviewError(f"candidate contains missing or duplicate package id: {item_id!r}")
        seen.add(item_id)
        version = str(raw.get("version", ""))
        source = str(raw.get("source", ""))
        checksum = str(raw.get("sha256", ""))
        if not version or version.lower() in {"latest", "head", "main", "master"}:
            raise ReviewError(f"candidate package {item_id!r} has a floating version")
        if not source or "latest" in source.lower() or ":latest" in source.lower():
            raise ReviewError(f"candidate package {item_id!r} has a mutable source")
        if not SHA256_RE.fullmatch(checksum):
            raise ReviewError(f"candidate package {item_id!r} has invalid SHA-256")
        if item_id.startswith("harvester-base-os-") and EXPECTED_REF not in source:
            raise ReviewError(f"candidate package {item_id!r} is not bound to the base OS digest")
        if item_id == "layersentry-harvester-os-overlay" and source_commit not in source:
            raise ReviewError("LayerSentry OS overlay is not bound to the reviewed source commit")
        reviewed.append(dict(raw))
    if seen != EXPECTED_PACKAGE_IDS:
        raise ReviewError(
            f"candidate package IDs differ from reviewed set; missing={sorted(EXPECTED_PACKAGE_IDS - seen)}, "
            f"extra={sorted(seen - EXPECTED_PACKAGE_IDS)}"
        )
    reviewed.sort(key=lambda item: item["id"])
    return reviewed


def review(
    candidate_path: Path,
    plan_path: Path,
    lock_path: Path,
    source_commit: str,
    apply: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    plan = load_object(plan_path, "OS input plan")
    if plan.get("schema") != "layersentry.os-package-input-plan/v1":
        raise ReviewError("unsupported OS input plan schema")
    candidate = load_object(candidate_path, "OS/package candidate")
    reviewed_packages = validate_candidate(candidate, plan_path, source_commit)

    lock = load_object(lock_path, "provenance lock")
    if lock.get("schema") != "layersentry.provenance-lock/v1":
        raise ReviewError("unsupported provenance lock schema")
    if lock.get("lock_status") != "incomplete":
        raise ReviewError("OS/package review may only update an incomplete provenance lock")
    identity = lock.get("release_identity")
    if not isinstance(identity, dict):
        raise ReviewError("provenance lock release identity is missing")
    if identity.get("product", {}).get("version") != "v1.0":
        raise ReviewError("provenance lock does not identify LayerSentry v1.0")
    if identity.get("embedded_platform", {}).get("version") != "v1.8.2":
        raise ReviewError("provenance lock does not identify Harvester v1.8.2")

    images = lock.get("container_images")
    packages = lock.get("packages")
    unresolved = lock.get("unresolved")
    if not isinstance(images, list) or not isinstance(packages, list) or not isinstance(unresolved, list):
        raise ReviewError("provenance lock image/package/unresolved sections are invalid")
    image_matches = [
        item
        for item in images
        if isinstance(item, dict) and item.get("id") == EXPECTED_IMAGE_ID
    ]
    if len(image_matches) != 1:
        raise ReviewError("provenance lock does not contain exactly one Harvester base OS image")
    image = image_matches[0]
    if image.get("ref") != EXPECTED_REF or EXPECTED_ALIAS not in image.get("aliases", []):
        raise ReviewError("provenance lock Harvester base OS image conflicts with reviewed evidence")

    existing_by_id: dict[str, dict[str, Any]] = {}
    for raw in packages:
        if not isinstance(raw, dict):
            raise ReviewError("provenance lock package entry is not an object")
        item_id = str(raw.get("id", ""))
        if not item_id or item_id in existing_by_id:
            raise ReviewError(f"provenance lock contains missing or duplicate package id: {item_id!r}")
        existing_by_id[item_id] = dict(raw)
    for entry in reviewed_packages:
        existing = existing_by_id.get(entry["id"])
        if existing is not None and existing != entry:
            raise ReviewError(f"existing package input {entry['id']!r} conflicts with reviewed evidence")
        existing_by_id[entry["id"]] = entry

    unresolved_present = any(
        isinstance(item, dict) and item.get("id") == UNRESOLVED_ID
        for item in unresolved
    )
    if not unresolved_present and not EXPECTED_PACKAGE_IDS.issubset(existing_by_id):
        raise ReviewError("OS/package unresolved marker is absent but reviewed inputs are incomplete")
    new_unresolved = [
        item
        for item in unresolved
        if not (isinstance(item, dict) and item.get("id") == UNRESOLVED_ID)
    ]

    updated = dict(lock)
    updated["packages"] = [existing_by_id[item_id] for item_id in sorted(existing_by_id)]
    updated["unresolved"] = new_unresolved
    updated["reviewed_os_package_inputs"] = {
        "status": "os-package-inputs-reviewed-lock-still-incomplete",
        "source_commit": source_commit,
        "candidate_sha256": sha256_file(candidate_path),
        "plan_sha256": sha256_file(plan_path),
        "base_os_alias": EXPECTED_ALIAS,
        "base_os_ref": EXPECTED_REF,
        "package_input_count": len(reviewed_packages),
        "rpm_package_count": candidate["rpm_package_count"],
        "firmware_record_count": candidate["firmware_record_count"],
        "overlay_tree": candidate["overlay_tree"],
    }

    remaining_ids = sorted(
        str(item.get("id"))
        for item in new_unresolved
        if isinstance(item, dict) and item.get("id")
    )
    report = {
        "schema": "layersentry.os-package-lock-review/v1",
        "source_commit": source_commit,
        "candidate_sha256": sha256_file(candidate_path),
        "plan_sha256": sha256_file(plan_path),
        "base_os_ref": EXPECTED_REF,
        "package_input_count": len(reviewed_packages),
        "rpm_package_count": candidate["rpm_package_count"],
        "firmware_record_count": candidate["firmware_record_count"],
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
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
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
            args.plan,
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
        f"OS PACKAGE LOCK REVIEW: {action} "
        f"({report['package_input_count']} inputs; "
        f"{report['remaining_unresolved_count']} unresolved groups remain)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
