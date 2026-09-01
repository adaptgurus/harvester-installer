#!/usr/bin/env python3
"""Verify the locked LayerSentry controller and its offline ISO integration."""
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
OCI_REF_RE = re.compile(
    r"^ghcr\.io/adaptgurus/layersentry-controller@sha256:[0-9a-f]{64}$"
)
SOURCE_REPOSITORY = "https://github.com/adaptgurus/harvester-installer.git"
IMAGE_REPOSITORY = "ghcr.io/adaptgurus/layersentry-controller"
IMAGE_ID = "layersentry-controller"
SOURCE_COMPONENT = "layersentry-controller"
VERSION = "v1.0.0"
UNRESOLVED_ID = "layersentry-controller-image"
RUNTIME_ALIAS = f"{IMAGE_REPOSITORY}:{VERSION}"


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


def read_text(repo: Path, relative: str, result: Validation) -> str:
    path = repo / relative
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        result.error(f"required controller path is missing: {relative}")
    except UnicodeDecodeError:
        result.error(f"required controller path is not UTF-8: {relative}")
    return ""


def validate_lock(
    lock: dict[str, Any], repo_root: Path, result: Validation
) -> tuple[str, str]:
    if lock.get("schema") != "layersentry.provenance-lock/v1":
        result.error("unsupported provenance lock schema")
    if lock.get("lock_status") not in {"incomplete", "complete"}:
        result.error("provenance lock status is neither incomplete nor complete")

    sources = lock.get("source_locks")
    images = lock.get("container_images")
    unresolved = lock.get("unresolved")
    reviewed = lock.get("reviewed_controller_image")
    if not isinstance(sources, list):
        result.error("source_locks must be an array")
        sources = []
    if not isinstance(images, list):
        result.error("container_images must be an array")
        images = []
    if not isinstance(unresolved, list):
        result.error("unresolved must be an array")
        unresolved = []
    if not isinstance(reviewed, dict):
        result.error("reviewed_controller_image metadata is missing")
        reviewed = {}

    source_matches = [
        item
        for item in sources
        if isinstance(item, dict) and item.get("component") == SOURCE_COMPONENT
    ]
    image_matches = [
        item
        for item in images
        if isinstance(item, dict) and item.get("id") == IMAGE_ID
    ]
    source_commit = ""
    image_ref = ""
    if len(source_matches) != 1:
        result.error(
            f"provenance lock must contain exactly one controller source lock; found {len(source_matches)}"
        )
    else:
        source = source_matches[0]
        source_commit = str(source.get("commit", ""))
        if source.get("repository") != SOURCE_REPOSITORY:
            result.error("controller source lock has an unexpected repository")
        if not COMMIT_RE.fullmatch(source_commit):
            result.error("controller source lock does not contain an exact commit")
        if source.get("version_label") != VERSION:
            result.error("controller source lock does not contain version v1.0.0")

    expected_aliases = [RUNTIME_ALIAS, f"{IMAGE_REPOSITORY}:source-{source_commit}"]
    if len(image_matches) != 1:
        result.error(
            f"provenance lock must contain exactly one controller image; found {len(image_matches)}"
        )
    else:
        image = image_matches[0]
        image_ref = str(image.get("ref", ""))
        if not OCI_REF_RE.fullmatch(image_ref):
            result.error("controller image is not pinned to the approved GHCR SHA-256 digest")
        if image.get("aliases") != expected_aliases:
            result.error("controller image aliases are not the expected version/source pair")

    unresolved_ids = {
        str(item.get("id"))
        for item in unresolved
        if isinstance(item, dict) and item.get("id")
    }
    if UNRESOLVED_ID in unresolved_ids:
        result.error("controller image evidence exists but the unresolved marker remains")

    comparisons = {
        "source_commit": source_commit,
        "version": VERSION,
        "image_ref": image_ref,
        "runtime_user": "65532:65532",
        "entrypoint": ["/usr/local/bin/layersentry-controller"],
        "cmd": ["--listen", "0.0.0.0:9443"],
        "bundled": True,
        "installed": False,
        "runtime_qualified": False,
        "release_approved": False,
    }
    for field, expected in comparisons.items():
        if reviewed.get(field) != expected:
            result.error(
                f"reviewed_controller_image.{field} is {reviewed.get(field)!r}; expected {expected!r}"
            )
    for field in ("candidate_sha256", "image_config_digest", "binary_sha256"):
        if not SHA256_RE.fullmatch(str(reviewed.get(field, ""))):
            result.error(f"reviewed_controller_image.{field} is not a valid SHA-256")
    if not isinstance(reviewed.get("binary_bytes"), int) or reviewed.get("binary_bytes", 0) <= 0:
        result.error("reviewed controller binary byte count is not positive")
    if not isinstance(reviewed.get("build_epoch"), int) or reviewed.get("build_epoch", 0) <= 0:
        result.error("reviewed controller build epoch is not positive")
    rootfs = reviewed.get("rootfs_diff_ids")
    if (
        not isinstance(rootfs, list)
        or len(rootfs) != 1
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(rootfs[0]))
    ):
        result.error("reviewed controller rootfs diff IDs are invalid")

    source_inputs = reviewed.get("source_inputs")
    if not isinstance(source_inputs, list) or not source_inputs:
        result.error("reviewed controller source-input contract is missing")
        source_inputs = []
    seen_paths: set[str] = set()
    for index, raw in enumerate(source_inputs):
        if not isinstance(raw, dict):
            result.error(f"reviewed controller source_inputs[{index}] is not an object")
            continue
        relative = str(raw.get("path", ""))
        checksum = str(raw.get("sha256", ""))
        expected_bytes = raw.get("bytes")
        if not relative or relative in seen_paths or Path(relative).is_absolute() or ".." in Path(relative).parts:
            result.error(f"reviewed controller source path is invalid or duplicated: {relative!r}")
            continue
        seen_paths.add(relative)
        path = repo_root / relative
        if not path.is_file():
            result.error(f"reviewed controller source input is missing: {relative}")
            continue
        if not SHA256_RE.fullmatch(checksum):
            result.error(f"reviewed controller source input has invalid checksum: {relative}")
        elif sha256_file(path) != checksum:
            result.error(f"current controller source input differs from reviewed evidence: {relative}")
        if not isinstance(expected_bytes, int) or path.stat().st_size != expected_bytes:
            result.error(f"current controller source input byte count differs: {relative}")

    sbom = reviewed.get("sbom")
    if not isinstance(sbom, dict):
        result.error("reviewed controller SBOM metadata is missing")
    else:
        if sbom.get("format") != "SPDX JSON" or sbom.get("path") != "controller-sbom.spdx.json":
            result.error("reviewed controller SBOM path or format is unexpected")
        if not SHA256_RE.fullmatch(str(sbom.get("sha256", ""))):
            result.error("reviewed controller SBOM checksum is invalid")
        if not isinstance(sbom.get("bytes"), int) or sbom.get("bytes", 0) <= 0:
            result.error("reviewed controller SBOM byte count is not positive")

    if source_commit:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "merge-base", "--is-ancestor", source_commit, "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            result.error("locked controller source commit is not an ancestor of current HEAD")
    return source_commit, image_ref


def validate_repository(repo: Path, source_commit: str, result: Validation) -> None:
    source = read_text(repo, "cmd/layersentry-controller/main.go", result)
    source_test = read_text(repo, "cmd/layersentry-controller/main_test.go", result)
    dockerfile = read_text(repo, "package/layersentry-controller/Dockerfile", result)
    build_script = read_text(repo, "scripts/build-layersentry-controller", result)
    default_script = read_text(repo, "scripts/default", result)
    image_list = read_text(repo, "scripts/images/harvester-additional-images.txt", result)
    workflow = read_text(
        repo, ".github/workflows/layersentry-v1.0-controller-lock.yml", result
    )

    for forbidden in ("os/exec", "exec.Command", "syscall.Exec", "plugin.Open", "unsafe.Pointer"):
        if forbidden in source:
            result.error(f"controller source contains prohibited execution mechanism: {forbidden}")
    for required in (
        'controllerMode          = "bootstrap-validation"',
        'MutatingOperations: false',
        'ShellExecution:     false',
        '"BUNDLED_NOT_INSTALLED"',
        '"/v1/validate/platform-settings"',
        "DisallowUnknownFields",
        "http.MaxBytesReader",
        "time/tzdata",
    ):
        if required not in source:
            result.error(f"controller source is missing required safety contract: {required}")
    if source.count("http.MethodPost") != 1:
        result.error("controller source must expose exactly one POST route, the read-only validator")
    if "AIRGAP settings without a registry mirror were accepted" not in source_test:
        result.error("controller tests do not prove the AIRGAP mirror invariant")

    lines = [line.strip() for line in dockerfile.splitlines() if line.strip()]
    if not lines or lines[0] != "FROM scratch":
        result.error("controller runtime image must use FROM scratch")
    for required in (
        "USER 65532:65532",
        'ENTRYPOINT ["/usr/local/bin/layersentry-controller"]',
        'CMD ["--listen", "0.0.0.0:9443"]',
        'io.layersentry.lifecycle="BUNDLED_NOT_INSTALLED"',
        'io.layersentry.runtime-qualified="false"',
        'io.layersentry.release-approved="false"',
    ):
        if required not in dockerfile:
            result.error(f"controller Dockerfile is missing required control: {required}")
    for forbidden in ("RUN ", "ADD ", "apk ", "apt-get ", "zypper ", "curl ", "wget "):
        if forbidden in dockerfile:
            result.error(f"scratch controller Dockerfile contains prohibited runtime construction: {forbidden}")

    for required in (
        "--candidate",
        "--from-lock",
        "CGO_ENABLED=0 GOOS=linux GOARCH=amd64",
        "-trimpath",
        "-buildvcs=false",
        "-buildid=",
        "--network=none",
        "--provenance=false",
        "--sbom=false",
        "docker push",
        "source_inputs",
        "current controller rebuild script differs from reviewed source input",
    ):
        if required not in build_script:
            result.error(f"controller build script is missing required deterministic control: {required}")
    if "latest" in build_script.lower():
        result.error("controller build script contains a floating latest reference")

    if image_list.splitlines().count(RUNTIME_ALIAS) != 1:
        result.error("Harvester additional image list must contain the controller runtime alias exactly once")
    build_position = default_script.find("bash ./build-layersentry-controller --from-lock")
    bundle_position = default_script.find("./build-bundle")
    if build_position < 0 or bundle_position < 0 or build_position >= bundle_position:
        result.error("default build does not rebuild the locked controller before bundle creation")
    if "export USE_LOCAL_IMAGES=layersentry-provenance-lock" not in default_script:
        result.error("default build does not force locally rebuilt controller image reuse")
    if "verify_controller_binding.py" not in default_script:
        result.error("default build does not revalidate controller binding before expensive work")

    for required in (
        "packages: write",
        "scripts/provenance/run_locked_builder.sh",
        "scripts/build-layersentry-controller --candidate",
        "scripts/provenance/review_controller_image.py",
        "scripts/provenance/verify_controller_binding.py",
        "remaining_unresolved_ids",
        "harvester-offline-image-set",
        "git commit -m \"chore(provenance): lock LayerSentry controller image [skip ci]\"",
    ):
        if required not in workflow:
            result.error(f"controller lock workflow is missing required control: {required}")

    if source_commit and f"source-{source_commit}" in image_list:
        result.error("runtime image list contains a source-specific alias instead of the stable version alias")


def verify(lock_path: Path, repo_root: Path) -> tuple[Validation, dict[str, Any]]:
    result = Validation()
    lock = load_object(lock_path, "provenance lock", result)
    source_commit, image_ref = validate_lock(lock, repo_root, result)
    validate_repository(repo_root, source_commit, result)
    report = {
        "schema": "layersentry.controller-binding-verification/v1",
        "lock": str(lock_path),
        "repo_root": str(repo_root),
        "source_commit": source_commit,
        "image_ref": image_ref,
        "runtime_alias": RUNTIME_ALIAS,
        "error_count": len(result.errors),
        "errors": result.errors,
        "bundled": True,
        "installed": False,
        "runtime_qualified": False,
        "release_approved": False,
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
        print(f"CONTROLLER BINDING: FAIL ({len(result.errors)} errors)")
        return 1
    print("CONTROLLER BINDING: PASS")
    print(f"source_commit={report['source_commit']}")
    print(f"image_ref={report['image_ref']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
