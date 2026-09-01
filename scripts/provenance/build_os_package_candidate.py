#!/usr/bin/env python3
"""Build a reviewed OS/package input candidate from an exact OCI image."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
EXPECTED_REF = (
    "docker.io/rancher/harvester-os@sha256:"
    "d437600ddc5e809cd22d9a6ddfc3c10328ac88440cef2930aa73aaf36b4178b4"
)
EXPECTED_ALIAS = "docker.io/rancher/harvester-os:v1.8-20260806"


class CandidateError(ValueError):
    """Raised when OS/package discovery evidence is incomplete."""


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
        raise CandidateError(f"{label} does not exist: {path}") from exc
    except json.JSONDecodeError as exc:
        raise CandidateError(f"invalid JSON in {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise CandidateError(f"{label} must contain a JSON object")
    return value


def read_tsv(path: Path, expected_columns: list[str]) -> list[dict[str, str]]:
    try:
        handle = path.open("r", encoding="utf-8", newline="")
    except FileNotFoundError as exc:
        raise CandidateError(f"evidence file does not exist: {path}") from exc
    with handle:
        reader = csv.DictReader(handle, delimiter="\t")
        if reader.fieldnames != expected_columns:
            raise CandidateError(
                f"{path.name} columns are {reader.fieldnames}; expected {expected_columns}"
            )
        records = []
        for row_number, row in enumerate(reader, 2):
            if any(value is None for value in row.values()):
                raise CandidateError(f"{path.name}:{row_number}: malformed TSV row")
            records.append({key: str(value) for key, value in row.items()})
    return records


def require_sha(value: str, label: str) -> str:
    if not SHA256_RE.fullmatch(value):
        raise CandidateError(f"{label} must be exactly 64 lowercase hex characters")
    return value


def require_positive_int(value: str | int, label: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise CandidateError(f"{label} is not an integer") from exc
    if parsed <= 0:
        raise CandidateError(f"{label} must be positive")
    return parsed


def evidence_record(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size <= 0:
        raise CandidateError(f"required evidence file is empty or missing: {path}")
    return {
        "file": path.name,
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
    }


def build_candidate(
    plan_path: Path,
    evidence_dir: Path,
    source_commit: str,
    overlay_tree: str,
) -> dict[str, Any]:
    if not COMMIT_RE.fullmatch(source_commit):
        raise CandidateError("LayerSentry source commit must be exactly 40 lowercase hex characters")
    if not re.fullmatch(r"[0-9a-f]{40}", overlay_tree):
        raise CandidateError("overlay tree must be an exact 40-hex Git tree")
    plan = load_object(plan_path, "OS input plan")
    if plan.get("schema") != "layersentry.os-package-input-plan/v1":
        raise CandidateError("unsupported OS input plan schema")
    base = plan.get("base_os_image")
    if not isinstance(base, dict):
        raise CandidateError("OS input plan base_os_image must be an object")
    if base.get("ref") != EXPECTED_REF or base.get("alias") != EXPECTED_ALIAS:
        raise CandidateError("OS input plan does not contain the reviewed Harvester OS image")
    if plan.get("platform") != "linux/amd64" or plan.get("architecture") != "amd64":
        raise CandidateError("OS input plan must target linux/amd64")

    inspect_path = evidence_dir / "image-inspect.json"
    inspect = load_object(inspect_path, "canonical Docker image inspection")
    if inspect.get("schema") != "layersentry.oci-image-inspection/v1":
        raise CandidateError("unsupported image inspection schema")
    if inspect.get("ref") != EXPECTED_REF:
        raise CandidateError("image inspection ref does not match reviewed base OS ref")
    if inspect.get("architecture") != "amd64" or inspect.get("os") != "linux":
        raise CandidateError("base OS image is not linux/amd64")
    repo_digests = inspect.get("repo_digests")
    if not isinstance(repo_digests, list) or not any(
        str(value).endswith(EXPECTED_REF.split("@", 1)[1]) for value in repo_digests
    ):
        raise CandidateError("Docker inspection does not retain the reviewed base OS digest")
    layers = inspect.get("rootfs_layers")
    if not isinstance(layers, list) or not layers:
        raise CandidateError("base OS image has no rootfs layer list")
    for index, layer in enumerate(layers):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(layer)):
            raise CandidateError(f"rootfs layer {index} is not an immutable SHA-256 digest")

    rpm_path = evidence_dir / "rpm-packages.tsv"
    rpm_rows = read_tsv(
        rpm_path,
        ["name", "epoch", "version", "release", "arch", "vendor", "build_time"],
    )
    if len(rpm_rows) < 50:
        raise CandidateError(f"RPM inventory is unexpectedly small: {len(rpm_rows)} packages")
    if rpm_rows != sorted(
        rpm_rows,
        key=lambda item: (
            item["name"],
            item["epoch"],
            item["version"],
            item["release"],
            item["arch"],
        ),
    ):
        raise CandidateError("RPM inventory is not canonically sorted")
    package_ids = [
        (row["name"], row["epoch"], row["version"], row["release"], row["arch"])
        for row in rpm_rows
    ]
    if len(package_ids) != len(set(package_ids)):
        raise CandidateError("RPM inventory contains duplicate NEVRA records")

    boot_path = evidence_dir / "boot-files.tsv"
    boot_rows = read_tsv(
        boot_path, ["id", "logical_path", "resolved_path", "bytes", "sha256"]
    )
    boot_by_id = {row["id"]: row for row in boot_rows}
    if set(boot_by_id) != {"kernel", "initrd"} or len(boot_rows) != 2:
        raise CandidateError("boot evidence must contain exactly kernel and initrd")
    for item_id, row in boot_by_id.items():
        require_positive_int(row["bytes"], f"{item_id} byte count")
        require_sha(row["sha256"], f"{item_id} SHA-256")
        allowed_boot_prefixes = ("/boot/", "/usr/lib/modules/")
        if not row["resolved_path"].startswith(allowed_boot_prefixes):
            raise CandidateError(
                f"{item_id} resolved path is outside the approved kernel trees: "
                f"{row['resolved_path']!r}"
            )

    firmware_path = evidence_dir / "firmware-files.tsv"
    firmware_rows = read_tsv(
        firmware_path, ["type", "path", "bytes_or_target", "sha256"]
    )
    if not firmware_rows:
        raise CandidateError("firmware inventory is empty")
    firmware_regular = 0
    for row in firmware_rows:
        if row["type"] == "file":
            require_positive_int(row["bytes_or_target"], "firmware file byte count")
            require_sha(row["sha256"], "firmware file SHA-256")
            firmware_regular += 1
        elif row["type"] == "symlink":
            if not row["bytes_or_target"] or row["sha256"] != "-":
                raise CandidateError("firmware symlink record is invalid")
        else:
            raise CandidateError(f"unsupported firmware record type: {row['type']!r}")
    if firmware_regular == 0:
        raise CandidateError("firmware inventory has no regular files")

    repos_path = evidence_dir / "package-repositories.tsv"
    repo_rows = read_tsv(
        repos_path, ["type", "path", "bytes_or_target", "sha256"]
    )
    if not repo_rows:
        raise CandidateError("package repository configuration inventory is empty")
    for row in repo_rows:
        if row["type"] == "file":
            require_positive_int(row["bytes_or_target"], "repository file byte count")
            require_sha(row["sha256"], "repository file SHA-256")
        elif row["type"] == "symlink":
            if not row["bytes_or_target"] or row["sha256"] != "-":
                raise CandidateError("repository symlink record is invalid")
        elif row["type"] == "absent":
            if row["bytes_or_target"] != "-" or row["sha256"] != "-":
                raise CandidateError("absent repository record is invalid")
        else:
            raise CandidateError(f"unsupported repository record type: {row['type']!r}")

    tools_path = evidence_dir / "os-tools.tsv"
    tool_rows = read_tsv(
        tools_path, ["id", "path", "bytes", "sha256", "version_sha256"]
    )
    tools_by_id = {row["id"]: row for row in tool_rows}
    if set(tools_by_id) != {"elemental", "dracut"} or len(tool_rows) != 2:
        raise CandidateError("OS tool evidence must contain exactly elemental and dracut")
    for item_id, row in tools_by_id.items():
        require_positive_int(row["bytes"], f"{item_id} byte count")
        require_sha(row["sha256"], f"{item_id} SHA-256")
        require_sha(row["version_sha256"], f"{item_id} version-output SHA-256")

    os_release_path = evidence_dir / "os-release"
    os_release = os_release_path.read_text(encoding="utf-8")
    if "NAME=" not in os_release or "VERSION" not in os_release:
        raise CandidateError("os-release evidence is incomplete")

    overlay_path = evidence_dir / "layersentry-os-overlay.tar.gz"
    required_files = [
        inspect_path,
        rpm_path,
        boot_path,
        firmware_path,
        repos_path,
        tools_path,
        os_release_path,
        overlay_path,
    ]
    evidence = {path.name: evidence_record(path) for path in required_files}

    digest = EXPECTED_REF.rsplit("sha256:", 1)[1]
    packages = [
        {
            "id": "harvester-base-os-oci-manifest",
            "version": "v1.8-20260806-linux-amd64",
            "source": f"oci://{EXPECTED_REF}",
            "sha256": digest,
        },
        {
            "id": "harvester-base-os-rootfs-layer-set",
            "version": "v1.8-20260806-linux-amd64",
            "source": f"oci-metadata://{EXPECTED_REF}#rootfs-layers",
            "sha256": evidence["image-inspect.json"]["sha256"],
        },
        {
            "id": "harvester-base-os-rpm-inventory",
            "version": "v1.8-20260806-linux-amd64",
            "source": f"oci-inventory://{EXPECTED_REF}#rpm-nevra",
            "sha256": evidence["rpm-packages.tsv"]["sha256"],
        },
        {
            "id": "harvester-base-os-kernel",
            "version": "v1.8-20260806-linux-amd64",
            "source": f"oci-file://{EXPECTED_REF}#{boot_by_id['kernel']['resolved_path']}",
            "sha256": boot_by_id["kernel"]["sha256"],
        },
        {
            "id": "harvester-base-os-initrd",
            "version": "v1.8-20260806-linux-amd64",
            "source": f"oci-file://{EXPECTED_REF}#{boot_by_id['initrd']['resolved_path']}",
            "sha256": boot_by_id["initrd"]["sha256"],
        },
        {
            "id": "harvester-base-os-firmware-inventory",
            "version": "v1.8-20260806-linux-amd64",
            "source": f"oci-tree://{EXPECTED_REF}#/usr/lib/firmware",
            "sha256": evidence["firmware-files.tsv"]["sha256"],
        },
        {
            "id": "harvester-base-os-package-repositories",
            "version": "v1.8-20260806-linux-amd64",
            "source": f"oci-tree://{EXPECTED_REF}#/etc/zypp/repos.d",
            "sha256": evidence["package-repositories.tsv"]["sha256"],
        },
        {
            "id": "harvester-base-os-elemental",
            "version": "v1.8-20260806-linux-amd64",
            "source": f"oci-file://{EXPECTED_REF}#{tools_by_id['elemental']['path']}",
            "sha256": tools_by_id["elemental"]["sha256"],
        },
        {
            "id": "harvester-base-os-dracut",
            "version": "v1.8-20260806-linux-amd64",
            "source": f"oci-file://{EXPECTED_REF}#{tools_by_id['dracut']['path']}",
            "sha256": tools_by_id["dracut"]["sha256"],
        },
        {
            "id": "harvester-base-os-release-metadata",
            "version": "v1.8-20260806-linux-amd64",
            "source": f"oci-file://{EXPECTED_REF}#/etc/os-release",
            "sha256": evidence["os-release"]["sha256"],
        },
        {
            "id": "layersentry-harvester-os-overlay",
            "version": f"git-{source_commit[:12]}",
            "source": (
                "git+https://github.com/adaptgurus/harvester-installer.git@"
                f"{source_commit}#harvester-os-overlay-tree-{overlay_tree}"
            ),
            "sha256": evidence["layersentry-os-overlay.tar.gz"]["sha256"],
        },
    ]

    return {
        "schema": "layersentry.os-package-lock-candidate/v1",
        "source_commit": source_commit,
        "overlay_tree": overlay_tree,
        "plan_sha256": sha256_file(plan_path),
        "platform": "linux/amd64",
        "base_os_alias": EXPECTED_ALIAS,
        "base_os_ref": EXPECTED_REF,
        "base_os_image_id": inspect.get("image_id"),
        "rootfs_layer_count": len(layers),
        "rpm_package_count": len(rpm_rows),
        "firmware_record_count": len(firmware_rows),
        "firmware_regular_file_count": firmware_regular,
        "repository_record_count": len(repo_rows),
        "packages": packages,
        "evidence": evidence,
        "all_inputs_verified": True,
        "production_lock_complete": False,
        "release_approved": False,
    }


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--overlay-tree", required=True)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        candidate = build_candidate(
            args.plan,
            args.evidence_dir,
            args.source_commit,
            args.overlay_tree,
        )
    except (CandidateError, OSError, UnicodeError) as exc:
        print(f"ERROR: {exc}")
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(candidate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        "OS PACKAGE CANDIDATE: PASS "
        f"({candidate['rpm_package_count']} RPMs, "
        f"{candidate['firmware_record_count']} firmware records)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
