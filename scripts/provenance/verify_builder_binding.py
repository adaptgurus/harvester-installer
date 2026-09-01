#!/usr/bin/env python3
"""Verify the immutable LayerSentry builder, toolchain and production launcher binding."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Iterable

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
BUILDER_REF_RE = re.compile(
    r"^ghcr\.io/adaptgurus/layersentry-full-offline-builder@sha256:[0-9a-f]{64}$"
)
BUILDER_ALIAS_RE = re.compile(
    r"^ghcr\.io/adaptgurus/layersentry-full-offline-builder:source-([0-9a-f]{40})$"
)
BUILDER_IMAGE_ID = "layersentry-full-offline-builder"
BASE_IMAGE = (
    "registry.suse.com/bci/golang@sha256:"
    "fa2dced84848f4e961e22f2b7d353d5df29fccba96c7b68c56b1bf495ac5dea1"
)
ADDONS_COMMIT = "f60d73d894e00f18d5e11cd21a301ed1b016631c"
RESOLVED_MARKERS = {
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


class Validation:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)


def load_object(path: Path, label: str, result: Validation) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        result.error(f"{label} does not exist: {path}")
        return {}
    except json.JSONDecodeError as exc:
        result.error(f"invalid JSON in {label}: {exc}")
        return {}
    if not isinstance(value, dict):
        result.error(f"{label} must contain a JSON object")
        return {}
    return value


def read_text(repo: Path, relative: str, result: Validation) -> str:
    path = repo / relative
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        result.error(f"required builder path is missing: {relative}")
    except UnicodeDecodeError:
        result.error(f"required builder path is not UTF-8: {relative}")
    return ""


def validate_lock(lock: dict[str, Any], result: Validation) -> tuple[str, str]:
    if lock.get("schema") != "layersentry.provenance-lock/v1":
        result.error("unsupported provenance lock schema")
    images = lock.get("container_images")
    artifacts = lock.get("toolchain_artifacts")
    unresolved = lock.get("unresolved")
    if not isinstance(images, list):
        result.error("container_images must be an array")
        images = []
    if not isinstance(artifacts, list):
        result.error("toolchain_artifacts must be an array")
        artifacts = []
    if not isinstance(unresolved, list):
        result.error("unresolved must be an array")
        unresolved = []

    image_matches = [
        item
        for item in images
        if isinstance(item, dict) and item.get("id") == BUILDER_IMAGE_ID
    ]
    builder_ref = ""
    source_commit = ""
    if len(image_matches) != 1:
        result.error(
            f"provenance lock must contain exactly one {BUILDER_IMAGE_ID!r} image; "
            f"found {len(image_matches)}"
        )
    else:
        image = image_matches[0]
        builder_ref = str(image.get("ref", ""))
        if not BUILDER_REF_RE.fullmatch(builder_ref):
            result.error("builder image is not pinned to the approved GHCR SHA-256 digest")
        aliases = image.get("aliases")
        if not isinstance(aliases, list) or len(aliases) != 1:
            result.error("builder image must have exactly one source-commit alias")
        else:
            match = BUILDER_ALIAS_RE.fullmatch(str(aliases[0]))
            if not match:
                result.error("builder image alias is not source-<40-hex-commit>")
            else:
                source_commit = match.group(1)

    artifact_by_id: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(artifacts):
        if not isinstance(raw, dict):
            result.error(f"toolchain_artifacts[{index}] is not an object")
            continue
        item_id = str(raw.get("id", ""))
        if not item_id or item_id in artifact_by_id:
            result.error(f"missing or duplicate toolchain artifact ID: {item_id!r}")
            continue
        artifact_by_id[item_id] = raw
    missing = EXPECTED_ARTIFACT_IDS - artifact_by_id.keys()
    if missing:
        result.error(f"builder/toolchain lock is missing required artifacts: {sorted(missing)}")

    for item_id in sorted(EXPECTED_ARTIFACT_IDS & artifact_by_id.keys()):
        item = artifact_by_id[item_id]
        version = str(item.get("version", ""))
        source = str(item.get("source", ""))
        checksum = str(item.get("sha256", ""))
        if not version or version.lower() in {"latest", "head", "main", "master"}:
            result.error(f"toolchain artifact {item_id!r} has a floating version")
        if not source or "releases/latest" in source.lower() or ":latest" in source.lower():
            result.error(f"toolchain artifact {item_id!r} has a mutable source")
        if not SHA256_RE.fullmatch(checksum):
            result.error(f"toolchain artifact {item_id!r} has an invalid SHA-256")
        if item_id in {"layersentry-builder-source-contract", "layersentry-builder-dockerfile"}:
            if source_commit and source_commit not in source:
                result.error(f"toolchain artifact {item_id!r} is not bound to the builder source commit")
        elif builder_ref and builder_ref not in source:
            result.error(f"toolchain artifact {item_id!r} is not bound to the builder digest")

    unresolved_ids = {
        str(item.get("id"))
        for item in unresolved
        if isinstance(item, dict) and item.get("id")
    }
    still_unresolved = RESOLVED_MARKERS & unresolved_ids
    if still_unresolved:
        result.error(
            "builder/toolchain evidence exists but unresolved markers remain: "
            f"{sorted(still_unresolved)}"
        )

    reviewed = lock.get("reviewed_builder_toolchain")
    if not isinstance(reviewed, dict):
        result.error("reviewed_builder_toolchain metadata is missing")
    else:
        if reviewed.get("builder_ref") != builder_ref:
            result.error("reviewed builder metadata does not match the locked builder ref")
        if reviewed.get("source_commit") != source_commit:
            result.error("reviewed builder metadata does not match the source-commit alias")
        if reviewed.get("tool_count") != len(TOOL_IDS):
            result.error("reviewed builder metadata has an unexpected tool count")
        if reviewed.get("toolchain_artifact_count") != len(EXPECTED_ARTIFACT_IDS):
            result.error("reviewed builder metadata has an unexpected artifact count")

    return builder_ref, source_commit


def validate_repository(repo: Path, result: Validation) -> None:
    dockerfile = read_text(repo, "Dockerfile.dapper", result)
    from_lines = [
        line.split(None, 1)[1].strip()
        for line in dockerfile.splitlines()
        if line.strip().upper().startswith("FROM ")
    ]
    if from_lines != [BASE_IMAGE]:
        result.error(f"Dockerfile.dapper must have exactly one pinned base image: {BASE_IMAGE}")
    required_dockerfile_tokens = (
        "ARG BUILDX_VERSION=v0.36.1",
        "ARG BUILDX_SHA256=48af8a397ebd60178778bf63611dbcebe5f5e7a9be90eb9147b24b9587455778",
        "ARG SYFT_VERSION=v1.51.1",
        "ARG SYFT_SHA256=8fcb33017a0dc1058298c923c436d19dfa68ae93968e0b423248542e3afb9fc3",
        "COPY scripts/provenance/locked_builder_entrypoint.sh",
        'ENTRYPOINT ["/usr/local/bin/layersentry-builder-entrypoint"]',
    )
    for token in required_dockerfile_tokens:
        if token not in dockerfile:
            result.error(f"Dockerfile.dapper is missing required immutable builder token: {token}")
    for forbidden in (
        "zypper addrepo",
        "download.opensuse.org",
        "DAPPER_DOCKER_SOCKET",
        "/run/containerd/containerd.sock",
        "ubuntu-latest",
    ):
        if forbidden.lower() in dockerfile.lower():
            result.error(f"Dockerfile.dapper contains forbidden production builder input: {forbidden}")

    test_script = read_text(repo, "scripts/test", result)
    if ADDONS_COMMIT not in test_script:
        result.error("scripts/test does not consume the exact Harvester add-ons commit")
    if not re.search(
        r"load_and_source_addon[^\n]+\$\{?ADDONS_COMMIT\}?",
        test_script,
    ):
        result.error("scripts/test does not pass ADDONS_COMMIT to the exact-source loader")
    if re.search(r"load_and_source_addon[^\n]+(?:\s|['\"])v1\.8(?:\s|['\"]|$)", test_script):
        result.error("scripts/test still consumes the mutable Harvester add-ons v1.8 branch")

    launcher = read_text(repo, "scripts/provenance/run_locked_builder.sh", result)
    for token in (
        'item.get("id") == "layersentry-full-offline-builder"',
        "docker pull --platform linux/amd64",
        "--privileged",
        "LAYERSENTRY_START_DOCKER_DAEMON",
        "GITHUB_WORKSPACE=$workspace",
    ):
        if token not in launcher:
            result.error(f"locked builder launcher is missing required token: {token}")
    if re.search(r"-v\s+[^\n]*:/var/run/docker\.sock", launcher):
        result.error("locked builder launcher mounts a host path over /var/run/docker.sock")
    if "DAPPER_DOCKER_SOCKET" in launcher or "/run/containerd/containerd.sock" in launcher:
        result.error("locked builder launcher inherits a host container runtime socket")

    entrypoint = read_text(repo, "scripts/provenance/locked_builder_entrypoint.sh", result)
    for token in (
        "dockerd",
        "--host=unix:///var/run/docker.sock",
        "--data-root=/var/lib/docker",
        "docker buildx version",
    ):
        if token not in entrypoint:
            result.error(f"locked builder entrypoint is missing required internal-daemon token: {token}")

    workflow = read_text(
        repo, ".github/workflows/layersentry-v1.0-full-offline-iso.yml", result
    )
    for token in (
        "packages: read",
        "scripts/provenance/verify_builder_binding.py",
        "scripts/provenance/run_locked_builder.sh ./scripts/default",
        "scripts/provenance/run_locked_builder.sh --no-daemon",
        "docker login ghcr.io",
    ):
        if token not in workflow:
            result.error(f"full-offline workflow is missing locked-builder binding: {token}")
    for forbidden in (
        "make default",
        "docker build -f Dockerfile.dapper",
        "docker build . -f Dockerfile.dapper",
    ):
        if forbidden in workflow:
            result.error(f"full-offline workflow bypasses the locked builder: {forbidden}")

    builder_workflow = read_text(
        repo, ".github/workflows/layersentry-v1.0-builder-toolchain-lock.yml", result
    )
    for token in (
        "packages: write",
        "docker build --pull --no-cache --platform linux/amd64",
        "scripts/provenance/collect_builder_toolchain_evidence.sh",
        "scripts/provenance/review_builder_toolchain.py",
        "scripts/provenance/verify_builder_binding.py",
    ):
        if token not in builder_workflow:
            result.error(f"builder-lock workflow is missing required control: {token}")


def verify(lock_path: Path, repo_root: Path) -> tuple[Validation, dict[str, Any]]:
    result = Validation()
    lock = load_object(lock_path, "provenance lock", result)
    builder_ref, source_commit = validate_lock(lock, result)
    validate_repository(repo_root, result)
    report = {
        "schema": "layersentry.builder-binding-verification/v1",
        "lock": str(lock_path),
        "repo_root": str(repo_root),
        "builder_ref": builder_ref,
        "builder_source_commit": source_commit,
        "required_tool_count": len(TOOL_IDS),
        "required_artifact_count": len(EXPECTED_ARTIFACT_IDS),
        "error_count": len(result.errors),
        "errors": result.errors,
        "verified": not result.errors,
    }
    return result, report


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    result, report = verify(args.lock, args.repo_root)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result.errors:
        for error in result.errors:
            print(f"ERROR: {error}")
        print(f"BUILDER BINDING: FAIL ({len(result.errors)} errors)")
        return 1
    print("BUILDER BINDING: PASS")
    print(f"builder_ref={report['builder_ref']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
