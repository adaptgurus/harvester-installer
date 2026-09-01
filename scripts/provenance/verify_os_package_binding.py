#!/usr/bin/env python3
"""Verify that the Harvester OS build consumes the locked amd64 base image."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable

EXPECTED_ALIAS = "docker.io/rancher/harvester-os:v1.8-20260806"
EXPECTED_REF = (
    "docker.io/rancher/harvester-os@sha256:"
    "d437600ddc5e809cd22d9a6ddfc3c10328ac88440cef2930aa73aaf36b4178b4"
)
EXPECTED_IMAGE_ID = "docker-io-rancher-harvester-os"
EXPECTED_WHARFIE_VERSION = "v0.6.8"
EXPECTED_WHARFIE_SHA256 = (
    "e6b5d27e5b5815ece828e3d2f4012ccec1e40dceb4e639815d6cdbc0f22e2fa8"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class BindingError(ValueError):
    """Raised when the source tree is not bound to the reviewed OS inputs."""


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
        raise BindingError(f"{label} does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise BindingError(f"invalid JSON in {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise BindingError(f"{label} must contain a JSON object")
    return value


def verify(plan_path: Path, lock_path: Path, repo_root: Path) -> dict[str, Any]:
    plan = load_object(plan_path, "OS input plan")
    lock = load_object(lock_path, "provenance lock")
    if plan.get("schema") != "layersentry.os-package-input-plan/v1":
        raise BindingError("unsupported OS input plan schema")
    if lock.get("schema") != "layersentry.provenance-lock/v1":
        raise BindingError("unsupported provenance lock schema")
    if plan.get("platform") != "linux/amd64" or plan.get("architecture") != "amd64":
        raise BindingError("OS input plan must target linux/amd64")

    base = plan.get("base_os_image")
    if not isinstance(base, dict):
        raise BindingError("OS input plan base_os_image must be an object")
    expected_base = {
        "id": EXPECTED_IMAGE_ID,
        "alias": EXPECTED_ALIAS,
        "ref": EXPECTED_REF,
        "digest": EXPECTED_REF.rsplit("@", 1)[1],
        "version": "v1.8-20260806",
    }
    for field, expected in expected_base.items():
        if base.get(field) != expected:
            raise BindingError(
                f"OS input plan base_os_image.{field} is {base.get(field)!r}; "
                f"expected {expected!r}"
            )

    images = lock.get("container_images")
    if not isinstance(images, list):
        raise BindingError("provenance lock container_images must be an array")
    matches = [
        item
        for item in images
        if isinstance(item, dict) and item.get("id") == EXPECTED_IMAGE_ID
    ]
    if len(matches) != 1:
        raise BindingError(
            f"provenance lock must contain exactly one {EXPECTED_IMAGE_ID!r}; "
            f"found {len(matches)}"
        )
    image = matches[0]
    if image.get("ref") != EXPECTED_REF:
        raise BindingError("provenance lock Harvester OS digest does not match reviewed input")
    aliases = image.get("aliases")
    if not isinstance(aliases, list) or EXPECTED_ALIAS not in aliases:
        raise BindingError("provenance lock does not retain the reviewed Harvester OS alias")

    tools = lock.get("toolchain_artifacts")
    if not isinstance(tools, list):
        raise BindingError("provenance lock toolchain_artifacts must be an array")
    wharfie = [
        item
        for item in tools
        if isinstance(item, dict) and item.get("id") == "wharfie-amd64"
    ]
    if len(wharfie) != 1:
        raise BindingError("provenance lock must contain exactly one wharfie-amd64 entry")
    if wharfie[0].get("version") != EXPECTED_WHARFIE_VERSION:
        raise BindingError("Wharfie version does not match the OS Dockerfile input")
    if wharfie[0].get("sha256") != EXPECTED_WHARFIE_SHA256:
        raise BindingError("Wharfie checksum does not match the OS Dockerfile input")

    package_script = repo_root / "scripts/package-harvester-os"
    dockerfile = repo_root / "package/harvester-os/Dockerfile"
    package_text = package_script.read_text(encoding="utf-8")
    dockerfile_text = dockerfile.read_text(encoding="utf-8")
    required_script_fragments = (
        f'BASE_OS_IMAGE="{EXPECTED_REF}"',
        'docker image inspect "${BASE_OS_IMAGE}" >/dev/null',
        "docker build --pull=false",
    )
    for fragment in required_script_fragments:
        if fragment not in package_text:
            raise BindingError(f"scripts/package-harvester-os is missing {fragment!r}")
    if EXPECTED_ALIAS in package_text:
        raise BindingError("scripts/package-harvester-os still contains the mutable base OS tag")
    if re.search(r"docker\s+build\s+--pull(?:\s|\\|$)", package_text):
        raise BindingError("scripts/package-harvester-os still requests a mutable pull")
    if "FROM ${BASE_OS_IMAGE}" not in dockerfile_text:
        raise BindingError("Harvester OS Dockerfile does not consume BASE_OS_IMAGE")
    if re.search(r"\b(?:zypper|apt-get|apt|apk|dnf|yum)\s+", dockerfile_text):
        raise BindingError("Harvester OS Dockerfile mutates packages after the locked base image")
    if f"ARG WHARFIE_VERSION={EXPECTED_WHARFIE_VERSION}" not in dockerfile_text:
        raise BindingError("Harvester OS Dockerfile Wharfie version is not locked")
    if f"ARG WHARFIE_SUM_amd64={EXPECTED_WHARFIE_SHA256}" not in dockerfile_text:
        raise BindingError("Harvester OS Dockerfile Wharfie checksum is not locked")

    overlay = plan.get("source_controlled_overlay")
    if not isinstance(overlay, dict) or not isinstance(overlay.get("paths"), list):
        raise BindingError("OS input plan source_controlled_overlay is invalid")
    missing_paths = [
        path for path in overlay["paths"] if not (repo_root / str(path)).exists()
    ]
    if missing_paths:
        raise BindingError(f"source-controlled OS overlay paths are missing: {missing_paths}")

    digest = EXPECTED_REF.rsplit("sha256:", 1)[1]
    if not SHA256_RE.fullmatch(digest):
        raise BindingError("reviewed Harvester OS digest is malformed")
    return {
        "schema": "layersentry.os-package-binding-report/v1",
        "base_os_alias": EXPECTED_ALIAS,
        "base_os_ref": EXPECTED_REF,
        "base_os_digest": f"sha256:{digest}",
        "platform": "linux/amd64",
        "plan_sha256": sha256_file(plan_path),
        "package_script_sha256": sha256_file(package_script),
        "dockerfile_sha256": sha256_file(dockerfile),
        "wharfie_version": EXPECTED_WHARFIE_VERSION,
        "wharfie_sha256": EXPECTED_WHARFIE_SHA256,
        "verified": True,
    }


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = verify(args.plan, args.lock, args.repo_root.resolve())
    except (BindingError, OSError) as exc:
        print(f"ERROR: {exc}")
        return 1
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("OS PACKAGE BINDING: PASS")
    print(f"base_os_ref={report['base_os_ref']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
