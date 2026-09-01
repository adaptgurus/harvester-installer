#!/usr/bin/env python3
"""Review deterministic chart evidence and merge it into the incomplete provenance lock."""
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
EXPECTED_HARVESTER_COMMIT = "5320dfa6770f63406750e7c64b24ed87c543e6ad"
EXPECTED_ADDONS_COMMIT = "f60d73d894e00f18d5e11cd21a301ed1b016631c"
UNRESOLVED_ID = "embedded-helm-chart-set"


class ReviewError(ValueError):
    """Raised when chart evidence cannot be promoted into the lock."""


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


def planned_source(source: dict[str, Any]) -> str:
    kind = source.get("kind")
    if kind == "url":
        return str(source.get("url", ""))
    if kind == "git":
        return (
            f"git+{source.get('repository', '')}@{source.get('commit', '')}"
            f"#{source.get('path', '')}"
        )
    raise ReviewError(f"unsupported planned chart source kind: {kind!r}")


def validate_candidate(
    candidate: dict[str, Any],
    plan: dict[str, Any],
    expected_source_commit: str,
    expected_plan_sha256: str,
) -> list[dict[str, Any]]:
    if not COMMIT_RE.fullmatch(expected_source_commit):
        raise ReviewError("expected source commit must be exactly 40 lowercase hex characters")
    if candidate.get("schema") != "layersentry.chart-lock-candidate/v1":
        raise ReviewError("unsupported chart-lock candidate schema")
    if candidate.get("source_commit") != expected_source_commit:
        raise ReviewError(
            f"candidate source commit {candidate.get('source_commit')!r} does not equal "
            f"review source {expected_source_commit!r}"
        )
    if candidate.get("harvester_commit") != EXPECTED_HARVESTER_COMMIT:
        raise ReviewError("candidate Harvester commit is not the approved v1.8.2 commit")
    if candidate.get("addons_commit") != EXPECTED_ADDONS_COMMIT:
        raise ReviewError("candidate add-ons commit is not the approved v1.8.2 commit")
    if not SHA256_RE.fullmatch(expected_plan_sha256):
        raise ReviewError("reviewed chart source plan SHA-256 is invalid")
    if candidate.get("plan_sha256") != expected_plan_sha256:
        raise ReviewError("candidate plan checksum does not match the reviewed chart source plan")
    if candidate.get("all_sources_verified") is not True:
        raise ReviewError("candidate does not prove all source downloads")
    if candidate.get("all_archives_normalized") is not True:
        raise ReviewError("candidate does not prove deterministic archive normalization")

    planned = plan.get("charts")
    charts = candidate.get("charts")
    if not isinstance(planned, list) or not planned:
        raise ReviewError("reviewed chart source plan is empty")
    if not isinstance(charts, list) or len(charts) != len(planned):
        raise ReviewError("candidate chart count does not match the reviewed plan")
    if candidate.get("chart_count") != len(planned):
        raise ReviewError("candidate chart_count does not match its chart list")

    planned_by_id: dict[str, dict[str, Any]] = {}
    for raw in planned:
        if not isinstance(raw, dict):
            raise ReviewError("chart plan entry is not an object")
        item_id = str(raw.get("id", ""))
        if not item_id or item_id in planned_by_id:
            raise ReviewError(f"invalid or duplicate chart plan id: {item_id!r}")
        planned_by_id[item_id] = raw

    reviewed: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in charts:
        if not isinstance(raw, dict):
            raise ReviewError("candidate chart entry is not an object")
        item_id = str(raw.get("id", ""))
        if not item_id or item_id in seen:
            raise ReviewError(f"invalid or duplicate candidate chart id: {item_id!r}")
        seen.add(item_id)
        expected = planned_by_id.get(item_id)
        if expected is None:
            raise ReviewError(f"candidate contains unplanned chart: {item_id}")
        comparisons = {
            "name": expected.get("name"),
            "version": expected.get("version"),
            "archive": expected.get("archive"),
            "source": planned_source(expected.get("source", {})),
            "transformations": expected.get("transformations"),
        }
        for field, wanted in comparisons.items():
            if raw.get(field) != wanted:
                raise ReviewError(
                    f"candidate chart {item_id!r} field {field!r} is {raw.get(field)!r}; "
                    f"expected {wanted!r}"
                )
        checksum = str(raw.get("sha256", ""))
        if not SHA256_RE.fullmatch(checksum):
            raise ReviewError(f"candidate chart {item_id!r} has invalid embedded SHA-256")
        if not isinstance(raw.get("bytes"), int) or raw["bytes"] <= 0:
            raise ReviewError(f"candidate chart {item_id!r} has invalid embedded byte count")
        source = expected.get("source", {})
        if source.get("kind") == "url":
            if not SHA256_RE.fullmatch(str(raw.get("source_sha256", ""))):
                raise ReviewError(f"candidate chart {item_id!r} has invalid source SHA-256")
            if not isinstance(raw.get("source_bytes"), int) or raw["source_bytes"] <= 0:
                raise ReviewError(f"candidate chart {item_id!r} has invalid source byte count")
        elif "source_sha256" in raw or "source_bytes" in raw:
            raise ReviewError(f"Git-source chart {item_id!r} must not claim a source archive checksum")
        reviewed.append(dict(raw))

    if seen != set(planned_by_id):
        missing = sorted(set(planned_by_id) - seen)
        raise ReviewError(f"candidate is missing planned charts: {missing}")
    return reviewed


def validate_review(
    candidate_path: Path,
    plan_path: Path,
    lock_path: Path,
    expected_source_commit: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    candidate = load_object(candidate_path, "chart-lock candidate")
    plan = load_object(plan_path, "chart source plan")
    candidate = dict(candidate)
    expected_plan_sha = sha256_file(plan_path)
    charts = validate_candidate(
        candidate, plan, expected_source_commit, expected_plan_sha
    )

    lock = load_object(lock_path, "provenance lock")
    if lock.get("schema") != "layersentry.provenance-lock/v1":
        raise ReviewError("unsupported provenance lock schema")
    if lock.get("lock_status") != "incomplete":
        raise ReviewError("chart review may only update an incomplete provenance lock")
    identity = lock.get("release_identity", {})
    if identity.get("product", {}).get("version") != "v1.0":
        raise ReviewError("provenance lock does not identify LayerSentry v1.0")
    if identity.get("embedded_platform", {}).get("version") != "v1.8.2":
        raise ReviewError("provenance lock does not identify Harvester v1.8.2")
    unresolved = lock.get("unresolved")
    if not isinstance(unresolved, list):
        raise ReviewError("provenance lock unresolved section is not an array")
    unresolved_ids = [item.get("id") for item in unresolved if isinstance(item, dict)]
    if UNRESOLVED_ID not in unresolved_ids:
        existing = lock.get("charts")
        if existing != charts:
            raise ReviewError(
                "embedded chart unresolved marker is absent but lock charts do not match candidate"
            )
    return lock, candidate


def review(
    candidate_path: Path,
    plan_path: Path,
    lock_path: Path,
    expected_source_commit: str,
    apply: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    lock, candidate = validate_review(
        candidate_path, plan_path, lock_path, expected_source_commit
    )
    charts = [dict(item) for item in candidate["charts"]]
    old_unresolved = lock["unresolved"]
    new_unresolved = [
        item
        for item in old_unresolved
        if not (isinstance(item, dict) and item.get("id") == UNRESOLVED_ID)
    ]
    updated = dict(lock)
    updated["charts"] = charts
    updated["unresolved"] = new_unresolved
    updated["reviewed_chart_discovery"] = {
        "status": "charts-reviewed-lock-still-incomplete",
        "source_commit": expected_source_commit,
        "chart_count": len(charts),
        "candidate_sha256": sha256_file(candidate_path),
        "plan_sha256": sha256_file(plan_path),
        "harvester_commit": candidate["harvester_commit"],
        "addons_commit": candidate["addons_commit"],
        "source_date_epoch": candidate["source_date_epoch"],
    }

    remaining_ids = {
        item.get("id") for item in new_unresolved if isinstance(item, dict)
    }
    report = {
        "schema": "layersentry.chart-lock-review/v1",
        "source_commit": expected_source_commit,
        "candidate_sha256": sha256_file(candidate_path),
        "plan_sha256": sha256_file(plan_path),
        "chart_count": len(charts),
        "removed_unresolved_id": UNRESOLVED_ID,
        "remaining_unresolved_count": len(new_unresolved),
        "remaining_unresolved_ids": sorted(str(item) for item in remaining_ids if item),
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
        f"CHART LOCK REVIEW: {action} ({report['chart_count']} charts, "
        f"{report['remaining_unresolved_count']} unresolved inputs remain)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
