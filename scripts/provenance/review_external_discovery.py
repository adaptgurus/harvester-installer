#!/usr/bin/env python3
"""Review and merge external image discovery into an incomplete provenance lock.

The command is intentionally fail-closed. It validates discovery integrity,
registry scope, alias coverage, and exact source identity. --apply may populate
reviewed external inputs, but it cannot mark the production lock complete.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OCI_REF_RE = re.compile(r"^([^\s@]+)@sha256:([0-9a-f]{64})$")
ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

APPROVED_REPOSITORY_PREFIXES = (
    "docker.io/aquasec/",
    "docker.io/kubeovn/",
    "docker.io/longhornio/",
    "docker.io/rancher/",
    "ghcr.io/k8snetworkplumbingwg/",
    "registry.k8s.io/descheduler/",
    "registry.k8s.io/sig-storage/",
    "registry.suse.com/bci/",
    "registry.suse.com/suse/",
)
EXPECTED_SOURCE_COMMITS = {
    "harvester": "5320dfa6770f63406750e7c64b24ed87c543e6ad",
    "harvester_addons": "f60d73d894e00f18d5e11cd21a301ed1b016631c",
}
RESOLVED_UNRESOLVED_IDS = {
    "trivy-scanner-image",
    "bci-evidence-verifier-image",
}
EXTERNAL_IMAGE_SET_ID = "harvester-offline-image-set"


class Review:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)

    def warn(self, message: str) -> None:
        self.warnings.append(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path, result: Review) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        result.error(f"required file does not exist: {path}")
        return {}
    except json.JSONDecodeError as exc:
        result.error(f"invalid JSON in {path}: {exc}")
        return {}
    if not isinstance(value, dict):
        result.error(f"{path} must contain a top-level JSON object")
        return {}
    return value


def canonical_alias(value: str) -> str:
    value = value.strip()
    if not value:
        return value
    first = value.split("/", 1)[0]
    if "/" not in value or ("." not in first and ":" not in first and first != "localhost"):
        return f"docker.io/{value}"
    return value


def repository_without_tag(alias: str) -> str:
    alias = canonical_alias(alias)
    if "@" in alias:
        return alias.split("@", 1)[0]
    slash = alias.rfind("/")
    colon = alias.rfind(":")
    if colon > slash:
        return alias[:colon]
    return alias


def validate_alias(alias: str) -> str | None:
    if not alias or any(ch.isspace() for ch in alias):
        return "is empty or contains whitespace"
    lower = alias.lower()
    if lower.endswith(":latest"):
        return "uses forbidden :latest"
    if re.search(r"(?:^|[-:/.])head(?:$|[-:/.])", lower):
        return "uses a forbidden head-derived tag"
    if "@sha256:" in alias:
        return None
    last = alias.rsplit("/", 1)[-1]
    if ":" not in last or not last.rsplit(":", 1)[1]:
        return "does not contain an explicit tag or digest"
    return None


def read_aliases(path: Path, result: Review) -> set[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        result.error(f"alias inventory does not exist: {path}")
        return set()
    aliases: set[str] = set()
    for number, raw in enumerate(lines, 1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        value = canonical_alias(value)
        problem = validate_alias(value)
        if problem:
            result.error(f"{path}:{number}: {value!r} {problem}")
            continue
        aliases.add(value)
    if not aliases:
        result.error("source alias inventory is empty")
    return aliases


def validate_discovery(
    candidate: dict[str, Any],
    failures: dict[str, Any],
    discovery: dict[str, Any],
    aliases: set[str],
    source_commit: str,
    result: Review,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if candidate.get("schema") != "layersentry.container-image-lock-candidate/v1":
        result.error("candidate schema is not layersentry.container-image-lock-candidate/v1")
    if candidate.get("source_commit") != source_commit:
        result.error("candidate source_commit does not match the approved discovery source")
    if candidate.get("complete") is not True:
        result.error("candidate is not marked complete")
    if candidate.get("review_required") is not True:
        result.error("candidate must remain review_required")
    if candidate.get("resolver") != "docker buildx imagetools inspect":
        result.error("candidate was not produced by the approved Buildx resolver")

    expected_count = len(aliases)
    if candidate.get("alias_count") != expected_count:
        result.error(
            f"candidate alias_count is {candidate.get('alias_count')!r}; expected {expected_count}"
        )
    if candidate.get("resolved_alias_count") != expected_count:
        result.error("candidate did not resolve every unique source alias")
    if candidate.get("unresolved_alias_count") != 0:
        result.error("candidate contains unresolved aliases")

    if failures.get("schema") != "layersentry.container-image-resolution-failures/v1":
        result.error("failure report has an unexpected schema")
    if failures.get("source_commit") != source_commit:
        result.error("failure report source_commit mismatch")
    if failures.get("failure_count") != 0 or failures.get("failures") not in ([], None):
        result.error("failure report is not empty")

    if discovery.get("schema") != "layersentry.provenance-discovery/v1":
        result.error("input discovery has an unexpected schema")
    if discovery.get("source_commit") != source_commit:
        result.error("input discovery source_commit mismatch")
    if discovery.get("release_approved") is not False:
        result.error("discovery must not claim release approval")
    if discovery.get("review_required") is not True:
        result.error("input discovery must remain review_required")
    if discovery.get("source_commits") != EXPECTED_SOURCE_COMMITS:
        result.error("input discovery source commits differ from the approved Harvester locks")

    raw_entries = candidate.get("container_images")
    if not isinstance(raw_entries, list) or not raw_entries:
        result.error("candidate container_images must be a non-empty array")
        raw_entries = []

    seen_ids: set[str] = set()
    seen_refs: set[str] = set()
    alias_to_ref: dict[str, str] = {}
    reviewed_entries: list[dict[str, Any]] = []
    registries: Counter[str] = Counter()

    for index, raw in enumerate(raw_entries):
        if not isinstance(raw, dict):
            result.error(f"container_images[{index}] must be an object")
            continue
        image_id = str(raw.get("id", ""))
        ref = str(raw.get("ref", ""))
        raw_aliases = raw.get("aliases")

        if not ID_RE.fullmatch(image_id):
            result.error(f"container_images[{index}].id is invalid: {image_id!r}")
        elif image_id in seen_ids:
            result.error(f"duplicate image id: {image_id}")
        seen_ids.add(image_id)

        match = OCI_REF_RE.fullmatch(ref)
        if not match:
            result.error(f"container image {image_id or index!r} has invalid OCI ref: {ref!r}")
            continue
        repository = match.group(1)
        if ref in seen_refs:
            result.error(f"duplicate immutable image ref: {ref}")
        seen_refs.add(ref)
        if not repository.startswith(APPROVED_REPOSITORY_PREFIXES):
            result.error(f"repository is outside the approved registry scope: {repository}")
        registry = repository.split("/", 1)[0]
        registries[registry] += 1

        if not isinstance(raw_aliases, list) or not raw_aliases:
            result.error(f"container image {image_id or index!r} has no aliases")
            continue

        normalized_aliases: list[str] = []
        local_seen: set[str] = set()
        for alias_index, raw_alias in enumerate(raw_aliases):
            alias = canonical_alias(str(raw_alias))
            problem = validate_alias(alias)
            if problem:
                result.error(
                    f"container_images[{index}].aliases[{alias_index}] {alias!r} {problem}"
                )
                continue
            if alias in local_seen:
                result.error(f"container image {image_id!r} repeats alias {alias!r}")
            local_seen.add(alias)
            if repository_without_tag(alias) != repository:
                result.error(
                    f"alias repository mismatch: {alias!r} cannot map to {repository!r}"
                )
            previous = alias_to_ref.get(alias)
            if previous and previous != ref:
                result.error(f"alias {alias!r} maps to multiple immutable refs")
            alias_to_ref[alias] = ref
            normalized_aliases.append(alias)

        reviewed_entries.append(
            {"id": image_id, "ref": ref, "aliases": sorted(normalized_aliases)}
        )

    candidate_aliases = set(alias_to_ref)
    missing = sorted(aliases - candidate_aliases)
    unexpected = sorted(candidate_aliases - aliases)
    if missing:
        result.error(f"{len(missing)} source aliases are absent from the candidate: {missing[:10]}")
    if unexpected:
        result.error(
            f"{len(unexpected)} candidate aliases are absent from the source inventory: "
            f"{unexpected[:10]}"
        )

    raw_tools = discovery.get("verified_tool_artifacts")
    if not isinstance(raw_tools, list) or not raw_tools:
        result.error("verified_tool_artifacts must be a non-empty array")
        raw_tools = []
    reviewed_tools: list[dict[str, Any]] = []
    tool_ids: set[str] = set()
    for index, raw in enumerate(raw_tools):
        if not isinstance(raw, dict):
            result.error(f"verified_tool_artifacts[{index}] must be an object")
            continue
        tool_id = str(raw.get("id", ""))
        version = str(raw.get("version", ""))
        source = str(raw.get("source", ""))
        checksum = str(raw.get("sha256", ""))
        if not tool_id or tool_id in tool_ids:
            result.error(f"invalid or duplicate tool id: {tool_id!r}")
        tool_ids.add(tool_id)
        if not version or version.lower() in {"latest", "head", "main", "master"}:
            result.error(f"tool {tool_id!r} has a floating or empty version")
        if not source or "releases/latest" in source.lower():
            result.error(f"tool {tool_id!r} has an invalid source URL")
        if not SHA256_RE.fullmatch(checksum):
            result.error(f"tool {tool_id!r} has an invalid SHA-256")
        reviewed_tools.append(
            {"id": tool_id, "version": version, "source": source, "sha256": checksum}
        )

    return sorted(reviewed_entries, key=lambda item: item["id"]), sorted(
        reviewed_tools, key=lambda item: item["id"]
    )


def merge_lock(
    lock: dict[str, Any],
    images: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    source_commit: str,
    candidate_sha256: str,
    alias_sha256: str,
    review_report: str,
    result: Review,
) -> dict[str, Any]:
    if lock.get("schema") != "layersentry.provenance-lock/v1":
        result.error("target lock has an unexpected schema")
        return lock
    if lock.get("lock_status") != "incomplete":
        result.error("reviewed discovery may only be merged into an incomplete lock")
        return lock

    existing_images = lock.get("container_images")
    if existing_images not in ([], images):
        result.error("target lock already contains a different container image set")
        return lock
    existing_tools = lock.get("toolchain_artifacts")
    if not isinstance(existing_tools, list):
        result.error("target lock toolchain_artifacts is not an array")
        return lock

    by_tool_id: dict[str, dict[str, Any]] = {}
    for raw in existing_tools:
        if not isinstance(raw, dict) or not raw.get("id"):
            result.error("target lock contains an invalid toolchain artifact")
            continue
        by_tool_id[str(raw["id"])] = raw
    for tool in tools:
        previous = by_tool_id.get(str(tool["id"]))
        if previous is not None and previous != tool:
            result.error(f"toolchain artifact conflict for {tool['id']!r}")
        by_tool_id[str(tool["id"])] = tool

    unresolved = lock.get("unresolved")
    if not isinstance(unresolved, list):
        result.error("target lock unresolved section is not an array")
        return lock

    remaining: list[dict[str, Any]] = []
    removed: set[str] = set()
    saw_external_set = False
    for raw in unresolved:
        if not isinstance(raw, dict):
            result.error("target lock contains a non-object unresolved entry")
            continue
        item = dict(raw)
        item_id = str(item.get("id", ""))
        if item_id in RESOLVED_UNRESOLVED_IDS:
            removed.add(item_id)
            continue
        if item_id == EXTERNAL_IMAGE_SET_ID:
            saw_external_set = True
            item["external_registry_aliases_locked"] = len(
                {alias for image in images for alias in image["aliases"]}
            )
            item["external_registry_refs_locked"] = len(images)
            item["reviewed_discovery_source_commit"] = source_commit
            item["review_report"] = review_report
            item["required_resolution"] = (
                "External registry aliases are digest-locked. Capture and verify locally "
                "generated harvester-cluster-repo, installer and OS image identities in "
                "the deterministic build evidence, then prove final ISO image-list coverage."
            )
        remaining.append(item)

    if removed != RESOLVED_UNRESOLVED_IDS:
        result.error(
            "target lock did not contain both expected resolved image blockers: "
            f"found {sorted(removed)}"
        )
    if not saw_external_set:
        result.error(f"target lock is missing unresolved item {EXTERNAL_IMAGE_SET_ID!r}")
    if not remaining:
        result.error("merge would incorrectly remove every unresolved release input")

    updated = dict(lock)
    updated["container_images"] = images
    updated["toolchain_artifacts"] = sorted(by_tool_id.values(), key=lambda item: item["id"])
    updated["unresolved"] = remaining
    updated["reviewed_discovery"] = {
        "source_commit": source_commit,
        "image_candidate_sha256": candidate_sha256,
        "image_alias_inventory_sha256": alias_sha256,
        "image_alias_count": len({alias for image in images for alias in image["aliases"]}),
        "immutable_image_ref_count": len(images),
        "review_report": review_report,
        "status": "external-inputs-reviewed-lock-still-incomplete",
    }
    updated["lock_status"] = "incomplete"
    return updated


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--failures", required=True, type=Path)
    parser.add_argument("--aliases", required=True, type=Path)
    parser.add_argument("--input-discovery", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    result = Review()
    if not COMMIT_RE.fullmatch(args.source_commit):
        result.error("--source-commit must be an exact lowercase 40-hex commit")

    candidate = load_json(args.candidate, result)
    failures = load_json(args.failures, result)
    discovery = load_json(args.input_discovery, result)
    lock = load_json(args.lock, result)
    aliases = read_aliases(args.aliases, result)

    images, tools = validate_discovery(
        candidate, failures, discovery, aliases, args.source_commit, result
    )

    candidate_sha256 = sha256_file(args.candidate) if args.candidate.is_file() else ""
    alias_sha256 = sha256_file(args.aliases) if args.aliases.is_file() else ""
    report_rel = args.report.as_posix()

    updated_lock = lock
    if args.apply and not result.errors:
        updated_lock = merge_lock(
            lock,
            images,
            tools,
            args.source_commit,
            candidate_sha256,
            alias_sha256,
            report_rel,
            result,
        )

    report = {
        "schema": "layersentry.external-image-review/v1",
        "eligible_for_incomplete_lock_merge": not result.errors,
        "applied": bool(args.apply and not result.errors),
        "source_commit": args.source_commit,
        "candidate_sha256": candidate_sha256,
        "alias_inventory_sha256": alias_sha256,
        "alias_count": len(aliases),
        "immutable_image_ref_count": len(images),
        "verified_tool_artifact_count": len(tools),
        "approved_repository_prefixes": list(APPROVED_REPOSITORY_PREFIXES),
        "errors": result.errors,
        "warnings": result.warnings,
        "release_approved": False,
        "production_lock_complete": False,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    for warning in result.warnings:
        print(f"WARNING: {warning}", file=sys.stderr)
    for error in result.errors:
        print(f"ERROR: {error}", file=sys.stderr)
    if result.errors:
        print(f"EXTERNAL INPUT REVIEW: FAIL ({len(result.errors)} error(s))", file=sys.stderr)
        return 1

    if args.apply:
        args.lock.write_text(
            json.dumps(updated_lock, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(
            f"EXTERNAL INPUT REVIEW: PASS; merged {len(images)} immutable refs "
            f"covering {len(aliases)} aliases; lock remains incomplete"
        )
    else:
        print(
            f"EXTERNAL INPUT REVIEW: PASS; {len(images)} immutable refs cover "
            f"{len(aliases)} aliases; no lock change performed"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
