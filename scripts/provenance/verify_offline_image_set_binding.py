#!/usr/bin/env python3
"""Verify the completed generated-image lock and its finalizer build binding."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Iterable

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
OCI_REF_RE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
SOURCE_COMPONENT = "layersentry-offline-image-set-build"
SOURCE_REPOSITORY = "https://github.com/adaptgurus/harvester-installer.git"
PINNED_CLUSTER_REPO_BASE = (
    "registry.suse.com/bci/bci-base@sha256:"
    "ad95af6d4b236fa9854b30fc156984456c83dc7dd51684e200844e721861f542"
)
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


class Validation:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def error(self, message: str) -> None:
        self.errors.append(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def run_git(repo: Path, *args: str) -> tuple[int, str]:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return proc.returncode, proc.stdout.strip()


def validate_lock(
    lock: dict[str, Any], repo_root: Path, result: Validation
) -> tuple[str, int]:
    if lock.get("schema") != "layersentry.provenance-lock/v1":
        result.error("unsupported provenance lock schema")
    if lock.get("lock_status") != "complete":
        result.error("provenance lock is not complete")
    unresolved = lock.get("unresolved")
    if unresolved != []:
        result.error("completed offline image-set lock must have no unresolved entries")

    sources = lock.get("source_locks")
    images = lock.get("container_images")
    reviewed = lock.get("reviewed_offline_image_set")
    if not isinstance(sources, list):
        result.error("source_locks must be an array")
        sources = []
    if not isinstance(images, list):
        result.error("container_images must be an array")
        images = []
    if not isinstance(reviewed, dict):
        result.error("reviewed_offline_image_set metadata is missing")
        reviewed = {}

    source_matches = [
        item
        for item in sources
        if isinstance(item, dict) and item.get("component") == SOURCE_COMPONENT
    ]
    source_commit = ""
    if len(source_matches) != 1:
        result.error(
            f"provenance lock must contain exactly one {SOURCE_COMPONENT!r} source lock"
        )
    else:
        source = source_matches[0]
        source_commit = str(source.get("commit", ""))
        if source.get("repository") != SOURCE_REPOSITORY:
            result.error("offline image-set source repository is unexpected")
        if not COMMIT_RE.fullmatch(source_commit):
            result.error("offline image-set source commit is invalid")
        if source.get("version_label") != "v1.0":
            result.error("offline image-set source version is not v1.0")

    image_by_id: dict[str, dict[str, Any]] = {}
    for raw in images:
        if not isinstance(raw, dict):
            continue
        image_id = str(raw.get("id", ""))
        if image_id in image_by_id:
            result.error(f"duplicate container image ID: {image_id!r}")
        image_by_id[image_id] = raw

    build_run_id = reviewed.get("build_run_id")
    if not isinstance(build_run_id, int) or build_run_id <= 0:
        result.error("reviewed offline image-set build_run_id is invalid")
        build_run_id = 0
    reviewed_images = reviewed.get("images")
    if not isinstance(reviewed_images, list):
        result.error("reviewed offline image-set image evidence is missing")
        reviewed_images = []
    reviewed_by_id = {
        str(item.get("id")): item
        for item in reviewed_images
        if isinstance(item, dict) and item.get("id")
    }

    for image_id, expected in EXPECTED_IMAGES.items():
        entry = image_by_id.get(image_id)
        evidence = reviewed_by_id.get(image_id)
        if entry is None:
            result.error(f"missing generated image lock: {image_id}")
            continue
        if evidence is None:
            result.error(f"missing reviewed generated-image evidence: {image_id}")
            continue
        source_alias = (
            f"{expected['repository']}:source-{source_commit}-run-{build_run_id}"
        )
        expected_aliases = [expected["runtime_alias"], source_alias]
        if entry.get("aliases") != expected_aliases:
            result.error(f"generated image {image_id!r} aliases are unexpected")
        ref = str(entry.get("ref", ""))
        if (
            not OCI_REF_RE.fullmatch(ref)
            or not ref.startswith(expected["repository"] + "@sha256:")
        ):
            result.error(f"generated image {image_id!r} ref is not an immutable approved GHCR digest")
        if evidence.get("aliases") != entry.get("aliases") or evidence.get("ref") != ref:
            result.error(f"reviewed evidence for {image_id!r} differs from the image lock")
        if evidence.get("platform") != "linux/amd64":
            result.error(f"reviewed evidence for {image_id!r} is not linux/amd64")
        if not SHA256_RE.fullmatch(str(evidence.get("config_digest", ""))):
            result.error(f"reviewed evidence for {image_id!r} has invalid config digest")
        rootfs = evidence.get("rootfs_diff_ids")
        if not isinstance(rootfs, list) or not rootfs:
            result.error(f"reviewed evidence for {image_id!r} has no rootfs diff IDs")
        elif any(
            not re.fullmatch(r"sha256:[0-9a-f]{64}", str(layer))
            for layer in rootfs
        ):
            result.error(f"reviewed evidence for {image_id!r} has invalid rootfs diff IDs")
        sbom = evidence.get("sbom")
        if not isinstance(sbom, dict) or not SHA256_RE.fullmatch(str(sbom.get("sha256", ""))):
            result.error(f"reviewed evidence for {image_id!r} has invalid SBOM metadata")

    if set(reviewed_by_id) != set(EXPECTED_IMAGES):
        result.error("reviewed generated-image set differs from the required three images")

    comparisons = {
        "status": "generated-images-reviewed-dependency-lock-complete-runtime-gates-pending",
        "build_source_commit": source_commit,
        "dependency_lock_complete": True,
        "installed": False,
        "runtime_qualified": False,
        "airgap_qualified": False,
        "release_approved": False,
    }
    for field, expected in comparisons.items():
        if reviewed.get(field) != expected:
            result.error(
                f"reviewed_offline_image_set.{field} is {reviewed.get(field)!r}; expected {expected!r}"
            )
    if not COMMIT_RE.fullmatch(str(reviewed.get("build_source_tree", ""))):
        result.error("reviewed offline image-set source tree is invalid")
    if not SHA256_RE.fullmatch(str(reviewed.get("candidate_sha256", ""))):
        result.error("reviewed offline image-set candidate checksum is invalid")

    iso = reviewed.get("iso_candidate")
    if not isinstance(iso, dict):
        result.error("reviewed offline image-set ISO metadata is missing")
    else:
        if iso.get("path") != "dist/artifacts/harvester-v1.0-amd64.iso":
            result.error("reviewed offline image-set ISO path is unexpected")
        if not isinstance(iso.get("bytes"), int) or iso.get("bytes", 0) < 1024**3:
            result.error("reviewed offline image-set ISO size is unexpectedly small")
        if not SHA256_RE.fullmatch(str(iso.get("sha256", ""))):
            result.error("reviewed offline image-set ISO SHA-256 is invalid")
        if not re.fullmatch(r"[0-9a-f]{128}", str(iso.get("sha512", ""))):
            result.error("reviewed offline image-set ISO SHA-512 is invalid")

    source_inputs = reviewed.get("source_inputs")
    if not isinstance(source_inputs, list) or not source_inputs:
        result.error("reviewed offline image-set source-input contract is missing")
        source_inputs = []
    seen_paths: set[str] = set()
    for index, raw in enumerate(source_inputs):
        if not isinstance(raw, dict):
            result.error(f"reviewed source_inputs[{index}] is not an object")
            continue
        relative = str(raw.get("path", ""))
        checksum = str(raw.get("sha256", ""))
        expected_bytes = raw.get("bytes")
        if (
            not relative
            or relative in seen_paths
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
        ):
            result.error(f"reviewed source path is invalid or duplicated: {relative!r}")
            continue
        seen_paths.add(relative)
        path = repo_root / relative
        if not path.is_file():
            result.error(f"reviewed image-set source input is missing: {relative}")
            continue
        if not SHA256_RE.fullmatch(checksum):
            result.error(f"reviewed image-set source checksum is invalid: {relative}")
        elif sha256_file(path) != checksum:
            result.error(f"current image-set source input differs from reviewed evidence: {relative}")
        if not isinstance(expected_bytes, int) or path.stat().st_size != expected_bytes:
            result.error(f"current image-set source input byte count differs: {relative}")

    if source_commit:
        rc, output = run_git(repo_root, "merge-base", "--is-ancestor", source_commit, "HEAD")
        if rc != 0:
            result.error(
                "locked image-set build source is not an ancestor of current HEAD: "
                + output
            )
    return source_commit, build_run_id


def validate_repository(repo: Path, result: Validation) -> None:
    dockerfile_path = repo / "package/harvester-repo/Dockerfile"
    try:
        dockerfile = dockerfile_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        result.error("cluster-repository Dockerfile is missing")
        dockerfile = ""
    from_lines = [
        line.split(None, 1)[1].strip()
        for line in dockerfile.splitlines()
        if line.strip().upper().startswith("FROM ")
    ]
    if from_lines != [PINNED_CLUSTER_REPO_BASE]:
        result.error(
            "cluster-repository Dockerfile must use exactly the approved SUSE BCI digest"
        )
    if "registry.suse.com/bci/bci-base:16.0" in dockerfile:
        result.error("cluster-repository Dockerfile still contains the mutable BCI tag")

    workflow_path = repo / ".github/workflows/layersentry-v1.0-offline-image-set-lock.yml"
    try:
        workflow = workflow_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        result.error("offline image-set finalizer workflow is missing")
        workflow = ""
    for token in (
        "runs-on: ubuntu-24.04",
        "scripts/provenance/verify_lock.py",
        "scripts/provenance/run_locked_builder.sh",
        "scripts/default",
        "collect_offline_image_set_evidence.sh",
        "review_offline_image_set.py",
        "verify_offline_image_set_binding.py",
        "verify_image_coverage.py",
        "prepare_finalizer_iso_evidence.sh",
        "git commit -m \"chore(provenance): complete Harvester offline image-set lock\"",
    ):
        if token not in workflow:
            result.error(f"offline image-set workflow is missing required control: {token}")
    for forbidden in ("ubuntu-latest", "apt-get", ":latest"):
        if forbidden in workflow:
            result.error(f"offline image-set workflow contains forbidden input: {forbidden}")


def verify(lock_path: Path, repo_root: Path) -> tuple[Validation, dict[str, Any]]:
    result = Validation()
    lock = load_object(lock_path, "provenance lock", result)
    source_commit, build_run_id = validate_lock(lock, repo_root, result)
    validate_repository(repo_root, result)
    report = {
        "schema": "layersentry.offline-image-set-binding-verification/v1",
        "lock": str(lock_path),
        "repo_root": str(repo_root),
        "build_source_commit": source_commit,
        "build_run_id": build_run_id,
        "generated_image_count": len(EXPECTED_IMAGES),
        "dependency_lock_complete": not result.errors,
        "installed": False,
        "runtime_qualified": False,
        "airgap_qualified": False,
        "release_approved": False,
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
    args.report.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if result.errors:
        for error in result.errors:
            print(f"ERROR: {error}")
        print(f"OFFLINE IMAGE-SET BINDING: FAIL ({len(result.errors)} errors)")
        return 1
    print("OFFLINE IMAGE-SET BINDING: PASS")
    print(f"build_source_commit={source_commit if (source_commit := report['build_source_commit']) else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
