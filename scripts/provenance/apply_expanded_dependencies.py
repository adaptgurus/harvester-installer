#!/usr/bin/env python3
"""Append the reviewed LayerSentry storage/security dependencies to the lock.

This is an additive, fail-closed promotion. Existing chart, image and source
records are never rewritten or removed, and the lock remains incomplete with
harvester-offline-image-set as the sole unresolved generated input.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
OCI_RE = re.compile(r"^([^\s@]+)@sha256:([0-9a-f]{64})$")

NFS_COMMIT = "57ba72f46ca0864b16e9523ee71e88878c0a5c48"
NFS_REPOSITORY = "https://github.com/kubernetes-csi/csi-driver-nfs.git"
NFS_VERSION = "v4.12.0"
NEUVECTOR_COMMIT = "501b8f0e5213f2d1f4e1f904892fe86f7fb7e45b"
NEUVECTOR_REPOSITORY = "https://github.com/neuvector/neuvector-helm.git"
NEUVECTOR_VERSION = "v2.10.3"
UNRESOLVED_ID = "harvester-offline-image-set"
APPROVED_NEW_PREFIXES = (
    "docker.io/neuvector/",
    "registry.k8s.io/sig-storage/",
)


class ExpansionError(ValueError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise ExpansionError(f"cannot load {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ExpansionError(f"{label} must be a JSON object")
    return value


def canonical_alias(value: str) -> str:
    value = value.strip()
    if not value:
        return value
    first = value.split("/", 1)[0]
    if "/" not in value or ("." not in first and ":" not in first and first != "localhost"):
        return f"docker.io/{value}"
    return value


def read_aliases(path: Path) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        value = canonical_alias(value)
        if value.lower().endswith(":latest") or "@sha256:" in value:
            raise ExpansionError(f"expanded alias {path}:{line_no} is invalid: {value}")
        if ":" not in value.rsplit("/", 1)[-1]:
            raise ExpansionError(f"expanded alias lacks an explicit tag: {value}")
        if value in seen:
            raise ExpansionError(f"duplicate expanded alias: {value}")
        if not value.startswith(APPROVED_NEW_PREFIXES):
            raise ExpansionError(f"expanded alias is outside approved registries: {value}")
        seen.add(value)
        values.append(value)
    if not values:
        raise ExpansionError("expanded alias list is empty")
    return sorted(values)


def chart_metadata(path: Path) -> tuple[str, str]:
    try:
        with tarfile.open(path, "r:gz") as archive:
            candidates = []
            for member in archive.getmembers():
                pure = PurePosixPath(member.name)
                if pure.is_absolute() or ".." in pure.parts:
                    raise ExpansionError(f"unsafe chart member path: {member.name!r}")
                if member.isfile() and len(pure.parts) == 2 and pure.name == "Chart.yaml":
                    candidates.append(member)
            if len(candidates) != 1:
                raise ExpansionError(f"{path.name} has {len(candidates)} root Chart.yaml files")
            extracted = archive.extractfile(candidates[0])
            if extracted is None:
                raise ExpansionError(f"cannot read Chart.yaml from {path.name}")
            text = extracted.read().decode("utf-8")
    except (tarfile.TarError, OSError, UnicodeDecodeError) as exc:
        raise ExpansionError(f"cannot inspect chart {path}: {exc}") from exc
    values: dict[str, str] = {}
    for raw in text.splitlines():
        if not raw or raw[0].isspace() or raw.lstrip().startswith("#") or ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        if key.strip() in {"name", "version"}:
            values[key.strip()] = value.strip().strip("'\"")
    return values.get("name", ""), values.get("version", "")


def validate_candidate(candidate: dict[str, Any], aliases: list[str], source_commit: str) -> list[dict[str, Any]]:
    if candidate.get("schema") != "layersentry.container-image-lock-candidate/v1":
        raise ExpansionError("expanded image candidate has an unexpected schema")
    if candidate.get("source_commit") != source_commit:
        raise ExpansionError("expanded image candidate source commit mismatch")
    if candidate.get("complete") is not True or candidate.get("unresolved_alias_count") != 0:
        raise ExpansionError("expanded image candidate is not complete")
    if candidate.get("resolver") != "docker buildx imagetools inspect":
        raise ExpansionError("expanded image candidate used an unapproved resolver")
    if candidate.get("alias_count") != len(aliases) or candidate.get("resolved_alias_count") != len(aliases):
        raise ExpansionError("expanded image candidate alias count mismatch")

    entries = candidate.get("container_images")
    if not isinstance(entries, list) or not entries:
        raise ExpansionError("expanded image candidate is empty")
    alias_map: dict[str, str] = {}
    reviewed: list[dict[str, Any]] = []
    ids: set[str] = set()
    for raw in entries:
        if not isinstance(raw, dict):
            raise ExpansionError("expanded image candidate contains a non-object entry")
        image_id = str(raw.get("id", ""))
        ref = str(raw.get("ref", ""))
        match = OCI_RE.fullmatch(ref)
        if not image_id or image_id in ids or match is None:
            raise ExpansionError(f"invalid expanded image record: {raw!r}")
        ids.add(image_id)
        repository = match.group(1)
        if not repository.startswith(APPROVED_NEW_PREFIXES):
            raise ExpansionError(f"expanded image repository is not approved: {repository}")
        raw_aliases = raw.get("aliases")
        if not isinstance(raw_aliases, list) or not raw_aliases:
            raise ExpansionError(f"expanded image {image_id} has no aliases")
        normalized = sorted(canonical_alias(str(item)) for item in raw_aliases)
        for alias in normalized:
            previous = alias_map.get(alias)
            if previous and previous != ref:
                raise ExpansionError(f"expanded alias maps to multiple refs: {alias}")
            alias_map[alias] = ref
        reviewed.append({"id": image_id, "ref": ref, "aliases": normalized})
    if set(alias_map) != set(aliases):
        raise ExpansionError("expanded image candidate does not exactly cover the approved alias list")
    return sorted(reviewed, key=lambda item: item["id"])


def expected_charts(charts_dir: Path, nfs_source: Path) -> list[dict[str, Any]]:
    specs = [
        {
            "id": "layersentry-csi-nfs",
            "name": "csi-driver-nfs",
            "version": "4.12.0",
            "archive": "csi-driver-nfs-4.12.0.tgz",
            "source": (
                "https://raw.githubusercontent.com/kubernetes-csi/csi-driver-nfs/"
                f"{NFS_COMMIT}/charts/v4.12.0/csi-driver-nfs-4.12.0.tgz"
            ),
            "transformations": ["deterministic-archive-normalization"],
            "source_sha256": sha256_file(nfs_source),
            "source_bytes": nfs_source.stat().st_size,
        },
        {
            "id": "layersentry-runtime-security",
            "name": "core",
            "version": "2.10.3",
            "archive": "core-2.10.3.tgz",
            "source": f"git+{NEUVECTOR_REPOSITORY}@{NEUVECTOR_COMMIT}#charts/core",
            "transformations": [
                "scripts/layersentry/prepare-runtime-security-chart.py",
                "deterministic-archive-normalization",
            ],
        },
        {
            "id": "layersentry-runtime-security-crd",
            "name": "crd",
            "version": "2.10.3",
            "archive": "crd-2.10.3.tgz",
            "source": f"git+{NEUVECTOR_REPOSITORY}@{NEUVECTOR_COMMIT}#charts/crd",
            "transformations": ["deterministic-archive-normalization"],
        },
    ]
    entries: list[dict[str, Any]] = []
    for spec in specs:
        path = charts_dir / spec["archive"]
        if not path.is_file():
            raise ExpansionError(f"expanded chart is missing: {path}")
        actual_name, actual_version = chart_metadata(path)
        if (actual_name, actual_version) != (spec["name"], spec["version"]):
            raise ExpansionError(
                f"expanded chart metadata mismatch for {path.name}: "
                f"{actual_name} {actual_version}"
            )
        entry = dict(spec)
        entry["sha256"] = sha256_file(path)
        entry["bytes"] = path.stat().st_size
        entries.append(entry)
    return entries


def source_lock(component: str, repository: str, commit: str, version: str) -> dict[str, Any]:
    return {
        "component": component,
        "repository": repository,
        "commit": commit,
        "version_label": version,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--aliases", required=True, type=Path)
    parser.add_argument("--charts-dir", required=True, type=Path)
    parser.add_argument("--nfs-source-archive", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--chart-source-date-epoch", required=True, type=int)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    if not COMMIT_RE.fullmatch(args.source_commit):
        raise SystemExit("ERROR: LayerSentry source commit is invalid")
    try:
        lock = load_object(args.lock, "provenance lock")
        if lock.get("schema") != "layersentry.provenance-lock/v1" or lock.get("lock_status") != "incomplete":
            raise ExpansionError("expanded dependencies require an incomplete provenance lock")
        unresolved = lock.get("unresolved")
        if not isinstance(unresolved, list):
            raise ExpansionError("provenance lock unresolved section is not an array")
        unresolved_ids = [item.get("id") for item in unresolved if isinstance(item, dict)]
        if unresolved_ids != [UNRESOLVED_ID]:
            raise ExpansionError(
                f"expanded dependencies require exactly {UNRESOLVED_ID!r} unresolved; "
                f"found {unresolved_ids}"
            )

        aliases = read_aliases(args.aliases)
        candidate = load_object(args.candidate, "expanded image candidate")
        new_images = validate_candidate(candidate, aliases, args.source_commit)
        new_charts = expected_charts(args.charts_dir, args.nfs_source_archive)

        existing_images = lock.get("container_images")
        existing_charts = lock.get("charts")
        existing_sources = lock.get("source_locks")
        if not isinstance(existing_images, list) or not existing_images:
            raise ExpansionError("existing reviewed image lock is missing")
        if not isinstance(existing_charts, list) or len(existing_charts) < 13:
            raise ExpansionError("existing reviewed chart lock is missing")
        if not isinstance(existing_sources, list):
            raise ExpansionError("existing source lock section is invalid")

        existing_alias_to_ref: dict[str, str] = {}
        existing_image_ids: set[str] = set()
        for raw in existing_images:
            if not isinstance(raw, dict):
                raise ExpansionError("existing image lock contains invalid entry")
            existing_image_ids.add(str(raw.get("id", "")))
            ref = str(raw.get("ref", ""))
            for alias in raw.get("aliases") or []:
                existing_alias_to_ref[canonical_alias(str(alias))] = ref

        appended_images: list[dict[str, Any]] = []
        for image in new_images:
            if image["id"] in existing_image_ids:
                existing = next(item for item in existing_images if item.get("id") == image["id"])
                if existing != image:
                    raise ExpansionError(f"new image id conflicts with existing lock: {image['id']}")
                continue
            overlaps = [alias for alias in image["aliases"] if alias in existing_alias_to_ref]
            for alias in overlaps:
                if existing_alias_to_ref[alias] != image["ref"]:
                    raise ExpansionError(f"existing alias digest changed during expansion: {alias}")
            if overlaps and len(overlaps) != len(image["aliases"]):
                raise ExpansionError(f"expanded image partially overlaps an existing image: {image['id']}")
            if not overlaps:
                appended_images.append(image)

        existing_chart_ids = {str(item.get("id", "")) for item in existing_charts if isinstance(item, dict)}
        for chart in new_charts:
            if chart["id"] in existing_chart_ids:
                existing = next(item for item in existing_charts if item.get("id") == chart["id"])
                if existing != chart:
                    raise ExpansionError(f"expanded chart conflicts with existing lock: {chart['id']}")
                raise ExpansionError(f"expanded chart already exists; refusing ambiguous rerun: {chart['id']}")

        wanted_sources = [
            source_lock("kubernetes-csi-driver-nfs", NFS_REPOSITORY, NFS_COMMIT, NFS_VERSION),
            source_lock("neuvector-helm", NEUVECTOR_REPOSITORY, NEUVECTOR_COMMIT, NEUVECTOR_VERSION),
        ]
        source_by_component = {
            str(item.get("component", "")): item
            for item in existing_sources
            if isinstance(item, dict) and item.get("component")
        }
        appended_sources: list[dict[str, Any]] = []
        for source in wanted_sources:
            previous = source_by_component.get(source["component"])
            if previous is not None:
                if previous != source:
                    raise ExpansionError(f"source lock conflict for {source['component']}")
            else:
                appended_sources.append(source)

        updated = dict(lock)
        updated["container_images"] = sorted(
            [dict(item) for item in existing_images] + appended_images,
            key=lambda item: str(item.get("id", "")),
        )
        updated["charts"] = sorted(
            [dict(item) for item in existing_charts] + new_charts,
            key=lambda item: str(item.get("id", "")),
        )
        updated["source_locks"] = [dict(item) for item in existing_sources] + appended_sources
        updated["unresolved"] = [dict(item) for item in unresolved]
        updated["reviewed_expanded_dependencies"] = {
            "status": "storage-security-reviewed-lock-still-incomplete",
            "source_commit": args.source_commit,
            "chart_source_date_epoch": args.chart_source_date_epoch,
            "chart_ids": [item["id"] for item in new_charts],
            "image_aliases": aliases,
            "new_image_refs": len(appended_images),
            "nfs_csi": {"version": NFS_VERSION, "commit": NFS_COMMIT},
            "runtime_security": {
                "upstream": "NeuVector",
                "chart_version": NEUVECTOR_VERSION,
                "app_version": "5.5.3",
                "commit": NEUVECTOR_COMMIT,
                "prime_enabled": False,
                "online_cve_updater_enabled": False,
            },
            "release_approved": False,
        }

        if updated["unresolved"] != lock["unresolved"]:
            raise ExpansionError("expanded dependency review attempted to change unresolved inputs")
        if updated.get("lock_status") != "incomplete":
            raise ExpansionError("expanded dependency review attempted to complete the lock")

        report = {
            "schema": "layersentry.expanded-dependency-review/v1",
            "source_commit": args.source_commit,
            "existing_chart_count": len(existing_charts),
            "expanded_chart_count": len(new_charts),
            "final_chart_count": len(updated["charts"]),
            "existing_image_ref_count": len(existing_images),
            "appended_image_ref_count": len(appended_images),
            "final_image_ref_count": len(updated["container_images"]),
            "alias_count": len(aliases),
            "remaining_unresolved_ids": unresolved_ids,
            "lock_status": "incomplete",
            "release_approved": False,
            "applied": args.apply,
        }
        if args.apply:
            atomic_write(args.lock, updated)
        atomic_write(args.report, report)
        print(
            "EXPANDED DEPENDENCY REVIEW: PASS "
            f"({len(new_charts)} charts, {len(appended_images)} new image refs, lock incomplete)"
        )
        return 0
    except ExpansionError as exc:
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
