#!/usr/bin/env python3
"""Fail-closed LayerSentry v1.0 / Harvester v1.8.2 provenance verifier.

This verifier deliberately distinguishes:
  * the LayerSentry product release,
  * the embedded Harvester platform release,
  * immutable dependency locks, and
  * the runtime LayerSentry Git commit captured by CI.

It has no third-party Python dependencies.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable

COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OCI_DIGEST_RE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
ACTION_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@([0-9a-f]{40})$")

EXPECTED_SOURCE_COMMITS = {
    "harvester-installer-upstream-baseline": "89d375137831667e22c729e4ca04e8fe2c6ac1bc",
    "harvester-core": "5320dfa6770f63406750e7c64b24ed87c543e6ad",
    "harvester-addons": "f60d73d894e00f18d5e11cd21a301ed1b016631c",
}
EXPECTED_CORRECTIVE_BASE = "ce3b8b4c2ce263325615c513d56edcbfd8476b98"
INVALID_INSTALLER_BASE = "49e533b1afbaaa08f0611090a4c09f2a6c6098ed"
STALE_SOURCE_COMMIT = "a104eab8cc5eca42b7ef002fc96561a21be3f163"

REQUIRED_REPO_SCRIPTS = (
    "scripts/provenance/verify_lock.py",
    "scripts/provenance/normalize_image_list.py",
    "scripts/provenance/verify_image_coverage.py",
    "scripts/provenance/prepare-release-evidence.sh",
    "scripts/prepare-production-iso-evidence.sh",
    "scripts/qualify-production-iso-evidence.sh",
)

BUILD_SCAN_FILES = (
    ".github/workflows/layersentry-production-bootstrap.yml",
    ".github/workflows/layersentry-production-iso.yml",
    ".github/workflows/layersentry-build-evidence.yml",
    ".github/workflows/layersentry-full-offline-iso.yml",
    "scripts/build",
    "scripts/build-bundle",
    "scripts/package-harvester-os",
    "scripts/lib/addon",
)

EXPENSIVE_MARKERS = (
    "build-production-iso",
    "build-bundle",
    "package-harvester-os",
    "docker pull",
    "docker build",
    "docker run",
    "podman pull",
    "podman build",
    "aws s3 cp",
    "make ",
)


class Validation:
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


def run_git(repo: Path, *args: str) -> tuple[int, str]:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return proc.returncode, proc.stdout.strip()


def ensure_dict(value: Any, path: str, result: Validation) -> dict[str, Any]:
    if not isinstance(value, dict):
        result.error(f"{path} must be an object")
        return {}
    return value


def ensure_list(value: Any, path: str, result: Validation) -> list[Any]:
    if not isinstance(value, list):
        result.error(f"{path} must be an array")
        return []
    return value


def validate_release_identity(lock: dict[str, Any], result: Validation) -> None:
    identity = ensure_dict(lock.get("release_identity"), "release_identity", result)
    product = ensure_dict(identity.get("product"), "release_identity.product", result)
    platform = ensure_dict(
        identity.get("embedded_platform"), "release_identity.embedded_platform", result
    )

    expected = {
        "product.name": (product.get("name"), "LayerSentry"),
        "product.version": (product.get("version"), "v1.0"),
        "embedded_platform.name": (platform.get("name"), "Harvester"),
        "embedded_platform.version": (platform.get("version"), "v1.8.2"),
    }
    for field, (actual, wanted) in expected.items():
        if actual != wanted:
            result.error(f"release_identity.{field} must be {wanted!r}; got {actual!r}")

    if product.get("version") == platform.get("version"):
        result.error("LayerSentry product version and embedded Harvester version are conflated")

    product_ns = str(product.get("artifact_namespace", ""))
    platform_ns = str(platform.get("artifact_namespace", ""))
    if product_ns != "layersentry/v1.0":
        result.error("product artifact_namespace must be 'layersentry/v1.0'")
    if platform_ns != "harvester/v1.8.2":
        result.error("embedded platform artifact_namespace must be 'harvester/v1.8.2'")


def validate_product_source(lock: dict[str, Any], result: Validation) -> None:
    source = ensure_dict(lock.get("product_source"), "product_source", result)
    if source.get("repository") != "https://github.com/adaptgurus/harvester-installer.git":
        result.error("product_source.repository is not the approved LayerSentry repository")
    if source.get("required_branch") != "layersentry-v1.0-dev":
        result.error("product_source.required_branch must be 'layersentry-v1.0-dev'")
    base = source.get("audited_corrective_base_commit")
    if base != EXPECTED_CORRECTIVE_BASE:
        result.error(
            "product_source.audited_corrective_base_commit must be the verified ce3b8b4... base"
        )
    if source.get("final_commit_capture") != "runtime-git-head":
        result.error("product_source.final_commit_capture must be 'runtime-git-head'")


def validate_source_locks(lock: dict[str, Any], result: Validation) -> None:
    entries = ensure_list(lock.get("source_locks"), "source_locks", result)
    seen: set[str] = set()
    by_component: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(entries):
        entry = ensure_dict(raw, f"source_locks[{index}]", result)
        component = str(entry.get("component", ""))
        if not component:
            result.error(f"source_locks[{index}].component is required")
            continue
        if component in seen:
            result.error(f"duplicate source lock component: {component}")
        seen.add(component)
        by_component[component] = entry
        commit = str(entry.get("commit", ""))
        if not COMMIT_RE.fullmatch(commit):
            result.error(f"source lock {component!r} does not contain an exact 40-hex commit")
        repository = str(entry.get("repository", ""))
        if not repository.startswith("https://github.com/") or not repository.endswith(".git"):
            result.error(f"source lock {component!r} has an unexpected repository URL")
        if any(token in commit.lower() for token in ("head", "main", "master", "refs/heads")):
            result.error(f"source lock {component!r} contains a mutable Git reference")

    for component, expected_commit in EXPECTED_SOURCE_COMMITS.items():
        entry = by_component.get(component)
        if entry is None:
            result.error(f"missing required source lock: {component}")
        elif entry.get("commit") != expected_commit:
            result.error(
                f"source lock {component!r} must resolve to {expected_commit}; "
                f"got {entry.get('commit')!r}"
            )


def validate_actions(lock: dict[str, Any], result: Validation) -> None:
    actions = ensure_list(lock.get("ci_actions"), "ci_actions", result)
    if not actions:
        result.error("ci_actions must not be empty")
    seen: set[str] = set()
    for index, raw in enumerate(actions):
        entry = ensure_dict(raw, f"ci_actions[{index}]", result)
        uses = str(entry.get("uses", ""))
        match = ACTION_RE.fullmatch(uses)
        if not match:
            result.error(
                f"ci_actions[{index}].uses must pin owner/repository@<40-hex-commit>; got {uses!r}"
            )
            continue
        action_name = uses.rsplit("@", 1)[0]
        if action_name in seen:
            result.error(f"duplicate CI action lock: {action_name}")
        seen.add(action_name)


def validate_images(lock: dict[str, Any], result: Validation) -> None:
    images = ensure_list(lock.get("container_images"), "container_images", result)
    seen: set[str] = set()
    for index, raw in enumerate(images):
        entry = ensure_dict(raw, f"container_images[{index}]", result)
        image_id = str(entry.get("id", ""))
        ref = str(entry.get("ref", ""))
        if not image_id:
            result.error(f"container_images[{index}].id is required")
        elif image_id in seen:
            result.error(f"duplicate container image id: {image_id}")
        seen.add(image_id)
        if not OCI_DIGEST_RE.fullmatch(ref):
            result.error(
                f"container image {image_id or index!r} must use repository@sha256:<64-hex>; got {ref!r}"
            )
        lower = ref.lower()
        if ":latest" in lower or re.search(r"(?:^|[-:/.])head(?:$|[-:/.@])", lower):
            result.error(f"container image {image_id or index!r} contains latest/head")

        aliases = entry.get("aliases")
        if not isinstance(aliases, list) or not aliases:
            result.error(f"container image {image_id or index!r} must list at least one runtime alias")
            continue
        alias_seen: set[str] = set()
        for alias_index, raw_alias in enumerate(aliases):
            alias = str(raw_alias).strip()
            if not alias or any(ch.isspace() for ch in alias):
                result.error(
                    f"container_images[{index}].aliases[{alias_index}] is empty or contains whitespace"
                )
                continue
            if alias in alias_seen:
                result.error(f"container image {image_id or index!r} contains duplicate alias {alias!r}")
            alias_seen.add(alias)
            alias_lower = alias.lower()
            if alias_lower.endswith(":latest") or re.search(
                r"(?:^|[-:/.])head(?:$|[-:/.])", alias_lower
            ):
                result.error(f"container image {image_id or index!r} has forbidden alias {alias!r}")
            if "@sha256:" not in alias:
                last_segment = alias.rsplit("/", 1)[-1]
                if ":" not in last_segment or not last_segment.rsplit(":", 1)[1]:
                    result.error(
                        f"container image {image_id or index!r} alias {alias!r} has no explicit tag or digest"
                    )


def validate_checksum_section(
    lock: dict[str, Any], section: str, result: Validation, *, require_version: bool
) -> None:
    entries = ensure_list(lock.get(section), section, result)
    seen: set[str] = set()
    for index, raw in enumerate(entries):
        entry = ensure_dict(raw, f"{section}[{index}]", result)
        entry_id = str(entry.get("id", ""))
        if not entry_id:
            result.error(f"{section}[{index}].id is required")
        elif entry_id in seen:
            result.error(f"duplicate {section} id: {entry_id}")
        seen.add(entry_id)
        checksum = str(entry.get("sha256", ""))
        if not SHA256_RE.fullmatch(checksum):
            result.error(f"{section}[{index}].sha256 must be exactly 64 lowercase hex characters")
        if require_version:
            version = str(entry.get("version", ""))
            if not version or version.lower() in {"latest", "head", "main", "master"}:
                result.error(f"{section}[{index}].version must be immutable and non-floating")
        source = str(entry.get("source", ""))
        if not source:
            result.error(f"{section}[{index}].source is required")
        if "releases/latest" in source.lower():
            result.error(f"{section}[{index}].source uses a latest-release endpoint")


def validate_policy(lock: dict[str, Any], result: Validation) -> None:
    policy = ensure_dict(lock.get("policy"), "policy", result)
    required_true = (
        "require_complete_lock_before_build",
        "require_oci_digest_for_every_image",
        "require_sha256_for_charts_packages_and_tools",
        "require_exact_commit_for_git_sources",
        "require_exact_commit_for_ci_actions",
        "forbid_tag_only_images",
        "forbid_latest",
        "forbid_head_images",
        "forbid_branch_git_refs",
        "forbid_floating_chart_versions",
        "forbid_override_bypass",
        "promotion_requires_source_build_provenance_deployment_sha_equality",
    )
    for key in required_true:
        if policy.get(key) is not True:
            result.error(f"policy.{key} must be true")


def active_line(line: str) -> str:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return ""
    # Remove an unquoted trailing YAML/shell comment conservatively.
    if " #" in line:
        line = line.split(" #", 1)[0]
    return line


def scan_file(path: Path, rel: str, result: Validation, locked_actions: set[str]) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        result.error(f"cannot scan non-UTF-8 build file: {rel}")
        return

    lines = text.splitlines()
    for number, raw in enumerate(lines, 1):
        line = active_line(raw)
        if not line:
            continue
        lower = line.lower()

        if INVALID_INSTALLER_BASE in line:
            result.error(f"{rel}:{number}: references nonexistent installer base {INVALID_INSTALLER_BASE}")
        if STALE_SOURCE_COMMIT in line:
            result.error(f"{rel}:{number}: references stale LayerSentry source commit {STALE_SOURCE_COMMIT}")
        if "releases/latest" in lower:
            result.error(f"{rel}:{number}: downloads from a mutable latest-release endpoint")
        if re.search(r"\bruns-on:\s*ubuntu-latest\b", lower):
            result.error(f"{rel}:{number}: artifact/gate workflow uses mutable ubuntu-latest runner")
        if re.search(r"\bapt-get\s+(?:update|install)\b", lower):
            result.error(f"{rel}:{number}: workflow dynamically mutates the build toolchain with apt-get")
        if re.search(r"(?:^|[^a-z0-9])[^\s'\"]*:latest(?:[^a-z0-9]|$)", lower):
            result.error(f"{rel}:{number}: contains a :latest image/artifact reference")
        head_derived = re.search(
            r"(?:^|[-:/.${}_])(?:v?\d+(?:\.\d+)*-)?head(?:$|[-:/.${}_])",
            lower,
        )
        if head_derived:
            # Git's symbolic HEAD and FETCH_HEAD are immutable once the checked-out
            # commit is bound and verified. Do not confuse those control-plane
            # tokens with a floating image/artifact tag such as v1.8-head.
            safe_git_head = re.search(
                r"\bgit\b.*\b(?:rev-parse|checkout|show|diff|merge-base|reset|log)\b"
                r".*\b(?:fetch_head|head)\b",
                lower,
            )
            if not safe_git_head:
                result.error(f"{rel}:{number}: contains a head-derived image/artifact reference")
        if re.search(r"\bgit\s+clone\b.*(?:\s-b\s|--branch(?:=|\s))", line):
            result.error(f"{rel}:{number}: clones by tag/branch instead of fetching an exact commit")

        uses_match = re.search(r"\buses:\s*([^\s#]+)", line)
        if uses_match:
            uses = uses_match.group(1).strip("'\"")
            if uses.startswith("./"):
                continue
            if uses.startswith("docker://"):
                image = uses[len("docker://") :]
                if not OCI_DIGEST_RE.fullmatch(image):
                    result.error(f"{rel}:{number}: Docker action is not pinned by OCI digest: {uses}")
            elif not ACTION_RE.fullmatch(uses):
                result.error(f"{rel}:{number}: GitHub Action is not pinned to a 40-hex commit: {uses}")
            elif uses not in locked_actions:
                result.error(f"{rel}:{number}: pinned GitHub Action is absent from the provenance lock: {uses}")

    if rel.startswith(".github/workflows/") and any(
        marker in text for marker in EXPENSIVE_MARKERS
    ):
        gate_pos = text.find("scripts/provenance/verify_lock.py")
        marker_positions = [text.find(marker) for marker in EXPENSIVE_MARKERS if text.find(marker) >= 0]
        first_expensive = min(marker_positions) if marker_positions else -1
        if gate_pos < 0:
            result.error(f"{rel}: expensive workflow has no fast provenance gate")
        elif first_expensive >= 0 and gate_pos > first_expensive:
            result.error(f"{rel}: provenance gate occurs after an expensive/networked build operation")


def scan_repository(repo: Path, result: Validation, lock: dict[str, Any]) -> None:
    for required in REQUIRED_REPO_SCRIPTS:
        if not (repo / required).is_file():
            result.error(f"required provenance/evidence script is missing: {required}")

    candidates: set[Path] = set()
    for rel in BUILD_SCAN_FILES:
        path = repo / rel
        if path.is_file():
            candidates.add(path)

    workflow_dir = repo / ".github" / "workflows"
    if workflow_dir.is_dir():
        for pattern in ("*layersentry*.yml", "*layersentry*.yaml"):
            candidates.update(workflow_dir.glob(pattern))

    if not candidates:
        result.error("no LayerSentry workflow or build files were found for provenance scanning")
        return

    locked_actions = {
        str(entry.get("uses", ""))
        for entry in lock.get("ci_actions", [])
        if isinstance(entry, dict)
    }
    for path in sorted(candidates):
        scan_file(path, path.relative_to(repo).as_posix(), result, locked_actions)

    expected_commit_usage = {
        "scripts/build": (EXPECTED_SOURCE_COMMITS["harvester-core"], EXPECTED_SOURCE_COMMITS["harvester-addons"]),
        "scripts/build-bundle": (EXPECTED_SOURCE_COMMITS["harvester-core"], EXPECTED_SOURCE_COMMITS["harvester-addons"]),
        "scripts/package-harvester-os": (EXPECTED_SOURCE_COMMITS["harvester-addons"],),
    }
    for relative, commits in expected_commit_usage.items():
        path = repo / relative
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for commit in commits:
            if commit not in text:
                result.error(f"{relative}: immutable source commit {commit} is not consumed by the build path")

    addon_loader = repo / "scripts/lib/addon"
    if addon_loader.is_file():
        addon_text = addon_loader.read_text(encoding="utf-8")
        if 'fetch --depth 1 origin "${commit}"' not in addon_text:
            result.error("scripts/lib/addon: add-on acquisition does not fetch the exact supplied commit")
        if re.search(r"\bbranch=(?:main|master)\b", addon_text):
            result.error("scripts/lib/addon: mutable default branch remains enabled")


def verify_git_context(repo: Path, lock: dict[str, Any], result: Validation) -> dict[str, str]:
    context: dict[str, str] = {}
    rc, inside = run_git(repo, "rev-parse", "--is-inside-work-tree")
    if rc != 0 or inside != "true":
        result.error(f"repo root is not a Git work tree: {repo}")
        return context

    rc, head = run_git(repo, "rev-parse", "HEAD")
    if rc != 0 or not COMMIT_RE.fullmatch(head):
        result.error("unable to resolve exact repository HEAD")
        return context
    context["source_commit"] = head

    source = ensure_dict(lock.get("product_source"), "product_source", result)
    base = str(source.get("audited_corrective_base_commit", ""))
    if COMMIT_RE.fullmatch(base):
        rc, output = run_git(repo, "merge-base", "--is-ancestor", base, head)
        if rc != 0:
            result.error(
                f"current source commit {head} is not descended from audited corrective base {base}: {output}"
            )

    rc, branch = run_git(repo, "symbolic-ref", "--short", "-q", "HEAD")
    if rc == 0 and branch:
        context["source_branch"] = branch
        required_branch = str(source.get("required_branch", ""))
        if branch != required_branch:
            result.error(f"current branch is {branch!r}; required branch is {required_branch!r}")
    else:
        # Detached HEAD is expected in GitHub Actions. Validate the advertised ref where available.
        advertised = os.environ.get("GITHUB_REF_NAME", "")
        if advertised:
            context["source_branch"] = advertised
            event_name = os.environ.get("GITHUB_EVENT_NAME", "")
            required_branch = str(source.get("required_branch", ""))
            if event_name != "pull_request" and advertised != required_branch:
                result.error(
                    f"detached checkout advertises ref {advertised!r}; required branch is {required_branch!r}"
                )

    github_sha = os.environ.get("GITHUB_SHA", "")
    if github_sha:
        if not COMMIT_RE.fullmatch(github_sha):
            result.error("GITHUB_SHA is not an exact lowercase 40-hex commit")
        elif github_sha != head:
            result.error(f"GITHUB_SHA {github_sha} does not equal checked-out HEAD {head}")

    return context


def validate_lock(lock_path: Path, require_complete: bool, repo_root: Path | None, scan: bool) -> tuple[Validation, dict[str, Any]]:
    result = Validation()
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        result.error(f"lock file does not exist: {lock_path}")
        return result, {}
    except json.JSONDecodeError as exc:
        result.error(f"invalid JSON in lock file: {exc}")
        return result, {}

    if not isinstance(lock, dict):
        result.error("top-level lock value must be an object")
        return result, {}

    if lock.get("schema") != "layersentry.provenance-lock/v1":
        result.error("schema must be 'layersentry.provenance-lock/v1'")

    status = lock.get("lock_status")
    if status not in {"incomplete", "complete"}:
        result.error("lock_status must be either 'incomplete' or 'complete'")

    validate_release_identity(lock, result)
    validate_product_source(lock, result)
    validate_source_locks(lock, result)
    validate_actions(lock, result)
    validate_images(lock, result)
    validate_checksum_section(lock, "charts", result, require_version=True)
    validate_checksum_section(lock, "packages", result, require_version=True)
    validate_checksum_section(lock, "toolchain_artifacts", result, require_version=True)
    validate_policy(lock, result)

    unresolved = ensure_list(lock.get("unresolved"), "unresolved", result)
    unresolved_ids: set[str] = set()
    for index, raw in enumerate(unresolved):
        entry = ensure_dict(raw, f"unresolved[{index}]", result)
        item_id = str(entry.get("id", ""))
        if not item_id:
            result.error(f"unresolved[{index}].id is required")
        elif item_id in unresolved_ids:
            result.error(f"duplicate unresolved id: {item_id}")
        unresolved_ids.add(item_id)
        if not entry.get("kind") or not entry.get("required_resolution"):
            result.error(f"unresolved[{index}] must contain kind and required_resolution")

    if status == "complete" and unresolved:
        result.error("lock_status is complete but unresolved entries remain")

    if require_complete:
        if status != "complete":
            result.error("provenance lock is not complete; the full-offline build remains blocked")
        if unresolved:
            result.error(f"provenance lock has {len(unresolved)} unresolved input(s)")
        for section in ("container_images", "charts", "packages", "toolchain_artifacts"):
            value = lock.get(section)
            if not isinstance(value, list) or not value:
                result.error(f"complete lock must contain at least one entry in {section}")

    git_context: dict[str, str] = {}
    if repo_root is not None:
        git_context = verify_git_context(repo_root, lock, result)
        if scan:
            scan_repository(repo_root, result, lock)

    report: dict[str, Any] = {
        "schema": "layersentry.provenance-gate-report/v1",
        "eligible_for_full_offline_build": not result.errors and status == "complete" and not unresolved,
        "lock_file": str(lock_path),
        "lock_sha256": sha256_file(lock_path) if lock_path.is_file() else None,
        "lock_status": status,
        "errors": result.errors,
        "warnings": result.warnings,
        "git_context": git_context,
        "release_identity": lock.get("release_identity"),
    }
    return result, report


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lock_file", type=Path)
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="Fail unless the lock is marked complete, has no unresolved entries, and has all required sections.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        help="Validate the checked-out Git commit/ancestry against the audited corrective base.",
    )
    parser.add_argument(
        "--scan-build-inputs",
        action="store_true",
        help="Scan LayerSentry workflows/build scripts for mutable refs and gate ordering. Requires --repo-root.",
    )
    parser.add_argument("--report", type=Path, help="Write a machine-readable gate report.")
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    if args.scan_build_inputs and args.repo_root is None:
        print("ERROR: --scan-build-inputs requires --repo-root", file=sys.stderr)
        return 2

    result, report = validate_lock(
        args.lock_file.resolve(),
        require_complete=args.require_complete,
        repo_root=args.repo_root.resolve() if args.repo_root else None,
        scan=args.scan_build_inputs,
    )

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    for warning in result.warnings:
        print(f"WARNING: {warning}", file=sys.stderr)
    for error in result.errors:
        print(f"ERROR: {error}", file=sys.stderr)

    if result.errors:
        print(f"PROVENANCE GATE: FAIL ({len(result.errors)} error(s))", file=sys.stderr)
        return 1

    print("PROVENANCE GATE: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
