#!/usr/bin/env bash
set -Eeuo pipefail

OUTPUT_DIR=${1:?usage: collect_builder_toolchain_evidence.sh OUTPUT_DIR BUILDER_REF BUILDER_ALIAS SOURCE_COMMIT}
BUILDER_REF=${2:?usage: collect_builder_toolchain_evidence.sh OUTPUT_DIR BUILDER_REF BUILDER_ALIAS SOURCE_COMMIT}
BUILDER_ALIAS=${3:?usage: collect_builder_toolchain_evidence.sh OUTPUT_DIR BUILDER_REF BUILDER_ALIAS SOURCE_COMMIT}
SOURCE_COMMIT=${4:?usage: collect_builder_toolchain_evidence.sh OUTPUT_DIR BUILDER_REF BUILDER_ALIAS SOURCE_COMMIT}
TOP_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

[[ $SOURCE_COMMIT =~ ^[0-9a-f]{40}$ ]] || fail "source commit must be exactly 40 lowercase hex characters"
[[ $BUILDER_REF =~ ^ghcr\.io/adaptgurus/layersentry-full-offline-builder@sha256:[0-9a-f]{64}$ ]] \
  || fail "builder ref must be the approved GHCR repository at an exact SHA-256 digest"
[[ $BUILDER_ALIAS == "ghcr.io/adaptgurus/layersentry-full-offline-builder:source-${SOURCE_COMMIT}" ]] \
  || fail "builder alias is not bound to the exact source commit"
[[ $(git -C "$TOP_DIR" rev-parse HEAD) == "$SOURCE_COMMIT" ]] \
  || fail "checked-out source does not equal requested source commit"

for command in docker python3 git sha256sum stat mktemp; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done

OUTPUT_DIR=$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)
rm -rf "$OUTPUT_DIR"/*
docker pull --platform linux/amd64 "$BUILDER_REF" >/dev/null

inspect_raw=$(mktemp "${RUNNER_TEMP:-/tmp}/layersentry-builder-inspect.XXXXXX.json")
cleanup() {
  rm -f "$inspect_raw"
}
trap cleanup EXIT INT TERM

docker image inspect "$BUILDER_REF" > "$inspect_raw"
[[ -s "$inspect_raw" ]] || fail "docker image inspect returned empty output for $BUILDER_REF"

python3 - \
  "$BUILDER_REF" \
  "$SOURCE_COMMIT" \
  "$inspect_raw" \
  "$OUTPUT_DIR/image-inspect.json" <<'PY'
import json
import sys
from pathlib import Path

ref, source_commit, raw_path, output = sys.argv[1:]
try:
    values = json.loads(Path(raw_path).read_text(encoding="utf-8"))
except json.JSONDecodeError as exc:
    raise SystemExit(f"docker image inspect returned invalid JSON: {exc}") from exc
if not isinstance(values, list) or len(values) != 1:
    raise SystemExit("docker image inspect did not return exactly one builder image")
item = values[0]
if item.get("Os") != "linux" or item.get("Architecture") != "amd64":
    raise SystemExit("builder image is not linux/amd64")
digest = ref.split("@", 1)[1]
repo_digests = sorted(str(value) for value in item.get("RepoDigests") or [])
if not any(value.endswith(digest) for value in repo_digests):
    raise SystemExit("builder image does not retain the requested RepoDigest")
labels = dict(item.get("Config", {}).get("Labels") or {})
if labels.get("org.opencontainers.image.revision") != source_commit:
    raise SystemExit(
        "builder image revision label is not the exact workflow source commit"
    )
layers = item.get("RootFS", {}).get("Layers")
if not isinstance(layers, list) or not layers:
    raise SystemExit("builder image has no rootfs layers")
report = {
    "schema": "layersentry.builder-image-inspection/v1",
    "ref": ref,
    "os": item["Os"],
    "architecture": item["Architecture"],
    "repo_digests": repo_digests,
    "rootfs_type": item.get("RootFS", {}).get("Type"),
    "rootfs_layers": layers,
    "config": {
        "entrypoint": item.get("Config", {}).get("Entrypoint"),
        "cmd": item.get("Config", {}).get("Cmd"),
        "env": sorted(item.get("Config", {}).get("Env") or []),
        "labels": dict(sorted(labels.items())),
        "working_dir": item.get("Config", {}).get("WorkingDir"),
    },
}
Path(output).write_text(
    json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

docker run --rm --network none --platform linux/amd64 -i \
  --entrypoint /bin/bash "$BUILDER_REF" -s \
  > "$OUTPUT_DIR/rpm-packages.tsv" <<'EOS'
set -Eeuo pipefail
printf 'name\tepoch\tversion\trelease\tarch\tvendor\tbuild_time\n'
rpm -qa --qf '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{VENDOR}\t%{BUILDTIME}\n' \
  | LC_ALL=C sort -t $'\t' -k1,1 -k2,2 -k3,3 -k4,4 -k5,5
EOS
[[ -s "$OUTPUT_DIR/rpm-packages.tsv" ]] \
  || fail "builder RPM inventory is empty"
[[ $(wc -l < "$OUTPUT_DIR/rpm-packages.tsv") -gt 20 ]] \
  || fail "builder RPM inventory is unexpectedly small"

docker run --rm --network none --platform linux/amd64 -i \
  --entrypoint python3 "$BUILDER_REF" - "$BUILDER_REF" \
  > "$OUTPUT_DIR/toolchain.json" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

image_ref = sys.argv[1]
definitions = [
    ("go", "go", ["version"]),
    ("docker-client", "docker", ["--version"]),
    ("docker-daemon", "dockerd", ["--version"]),
    (
        "docker-buildx",
        "/usr/local/lib/docker/cli-plugins/docker-buildx",
        ["version"],
    ),
    ("python3", "python3", ["--version"]),
    ("git", "git", ["--version"]),
    ("curl", "curl", ["--version"]),
    ("wget", "wget", ["--version"]),
    ("yq", "yq", ["--version"]),
    ("jq", "jq", ["--version"]),
    ("helm", "helm", ["version", "--short"]),
    ("syft", "syft", ["version"]),
    ("xorriso", "xorriso", ["-version"]),
    ("mksquashfs", "mksquashfs", ["-version"]),
    ("zstd", "zstd", ["--version"]),
    ("tar", "tar", ["--version"]),
    ("gzip", "gzip", ["--version"]),
    ("sha256sum", "sha256sum", ["--version"]),
    ("sha512sum", "sha512sum", ["--version"]),
    ("mcopy", "mcopy", ["--version"]),
    ("mkfs-vfat", "mkfs.vfat", ["--version"]),
    ("rsync", "rsync", ["--version"]),
    ("patch", "patch", ["--version"]),
    ("awk", "awk", ["--version"]),
    ("sed", "sed", ["--version"]),
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


tools = []
for tool_id, command, version_args in definitions:
    if command.startswith("/"):
        path = Path(command)
    else:
        discovered = shutil.which(command)
        if not discovered:
            raise SystemExit(f"required builder tool is missing: {command}")
        path = Path(discovered)
    path = path.resolve()
    if not path.is_file():
        raise SystemExit(f"builder tool is not a regular file: {path}")
    proc = subprocess.run(
        [str(path), *version_args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        env={**os.environ, "LC_ALL": "C"},
    )
    version_output = " ".join(proc.stdout.split()) if proc.returncode == 0 else ""
    owner_proc = subprocess.run(
        [
            "rpm",
            "-qf",
            str(path),
            "--qf",
            "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    rpm_owner = " ".join(owner_proc.stdout.split()) if owner_proc.returncode == 0 else ""
    # RPM NEVRA is the canonical, deterministic version for packaged binaries.
    # CLI output remains the fallback for checksum-staged binaries that have no
    # RPM owner. Some daemon CLIs emit timestamped diagnostics even for
    # --version; those diagnostics must not become release identity.
    version = rpm_owner or version_output
    version_source = "rpm-nevra" if rpm_owner else "command-output"
    if not version:
        raise SystemExit(f"could not derive a version for builder tool {tool_id}")
    tools.append(
        {
            "id": f"layersentry-builder-{tool_id}",
            "path": str(path),
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
            "version": version[:500],
            "version_source": version_source,
            "rpm_owner": rpm_owner or None,
            "source": f"oci-file://{image_ref}#{path}",
        }
    )

document = {
    "schema": "layersentry.builder-toolchain-inventory/v1",
    "image_ref": image_ref,
    "tool_count": len(tools),
    "tools": sorted(tools, key=lambda item: item["id"]),
}
print(json.dumps(document, indent=2, sort_keys=True))
PY
[[ -s "$OUTPUT_DIR/toolchain.json" ]] \
  || fail "builder toolchain inventory is empty"
python3 - "$OUTPUT_DIR/toolchain.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    inventory = json.loads(path.read_text(encoding="utf-8"))
except json.JSONDecodeError as exc:
    raise SystemExit(f"builder toolchain inventory is invalid JSON: {exc}") from exc
if inventory.get("schema") != "layersentry.builder-toolchain-inventory/v1":
    raise SystemExit("builder toolchain inventory has an unexpected schema")
if inventory.get("tool_count") != 25:
    raise SystemExit(
        f"builder toolchain inventory contains {inventory.get('tool_count')} tools; expected 25"
    )
for tool in inventory.get("tools", []):
    if tool.get("version_source") not in {"rpm-nevra", "command-output"}:
        raise SystemExit(f"builder tool {tool.get('id')!r} has no canonical version source")
    if tool.get("rpm_owner") and tool.get("version") != tool.get("rpm_owner"):
        raise SystemExit(f"builder tool {tool.get('id')!r} does not use RPM NEVRA as version")
PY

(
  cd "$TOP_DIR"
  for path in \
    Dockerfile.dapper \
    provenance/layersentry-v1.0-syft-tool.json \
    scripts/test \
    scripts/provenance/collect_builder_toolchain_evidence.sh \
    scripts/provenance/locked_builder_entrypoint.sh \
    scripts/provenance/run_locked_builder.sh \
    scripts/provenance/review_builder_toolchain.py \
    scripts/provenance/verify_builder_binding.py \
    scripts/provenance/verify_lock.py \
    scripts/provenance/verify_staged_syft.py \
    tests/test_builder_toolchain_lock.py \
    .github/workflows/layersentry-v1.0-builder-toolchain-lock.yml \
    .github/workflows/layersentry-v1.0-full-offline-iso.yml; do
    [[ -f "$path" ]] || fail "required builder source input is missing: $path"
    printf '%s\t%s\t%s\n' "$path" "$(stat -c '%s' "$path")" "$(sha256sum "$path" | awk '{print $1}')"
  done
) > "$OUTPUT_DIR/source-inputs.tsv"
[[ -s "$OUTPUT_DIR/source-inputs.tsv" ]] \
  || fail "builder source-input inventory is empty"

python3 - \
  "$BUILDER_REF" \
  "$BUILDER_ALIAS" \
  "$SOURCE_COMMIT" \
  "$OUTPUT_DIR" <<'PY'
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

builder_ref, builder_alias, source_commit, output_raw = sys.argv[1:]
output = Path(output_raw)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


inspection = json.loads((output / "image-inspect.json").read_text(encoding="utf-8"))
inventory = json.loads((output / "toolchain.json").read_text(encoding="utf-8"))
digest = builder_ref.rsplit("sha256:", 1)[1]
version = f"source-{source_commit[:12]}-linux-amd64"
source_rows = {}
for line in (output / "source-inputs.tsv").read_text(encoding="utf-8").splitlines():
    path, size, checksum = line.split("\t")
    source_rows[path] = {
        "bytes": int(size),
        "sha256": checksum,
    }

artifacts = [
    {
        "id": "layersentry-builder-oci-manifest",
        "version": version,
        "source": f"oci://{builder_ref}",
        "sha256": digest,
    },
    {
        "id": "layersentry-builder-rpm-inventory",
        "version": version,
        "source": f"oci-inventory://{builder_ref}#rpm-nevra",
        "sha256": sha256(output / "rpm-packages.tsv"),
    },
    {
        "id": "layersentry-builder-source-contract",
        "version": f"git-{source_commit[:12]}",
        "source": (
            "git+https://github.com/adaptgurus/harvester-installer.git@"
            f"{source_commit}#locked-builder-inputs"
        ),
        "sha256": sha256(output / "source-inputs.tsv"),
    },
    {
        "id": "layersentry-builder-dockerfile",
        "version": f"git-{source_commit[:12]}",
        "source": (
            "git+https://github.com/adaptgurus/harvester-installer.git@"
            f"{source_commit}#Dockerfile.dapper"
        ),
        "sha256": source_rows["Dockerfile.dapper"]["sha256"],
    },
]
for item in inventory["tools"]:
    artifacts.append(
        {
            "id": item["id"],
            "version": item["version"],
            "source": item["source"],
            "sha256": item["sha256"],
        }
    )

candidate = {
    "schema": "layersentry.builder-toolchain-candidate/v1",
    "source_commit": source_commit,
    "release_identity": {
        "product": "LayerSentry v1.0",
        "embedded_platform": "Harvester v1.8.2",
    },
    "platform": "linux/amd64",
    "builder_image": {
        "id": "layersentry-full-offline-builder",
        "aliases": [builder_alias],
        "ref": builder_ref,
    },
    "rootfs_layer_count": len(inspection["rootfs_layers"]),
    "toolchain_artifacts": sorted(artifacts, key=lambda item: item["id"]),
    "tool_count": inventory["tool_count"],
    "source_input_count": len(source_rows),
    "release_approved": False,
}
(output / "builder-toolchain-candidate.json").write_text(
    json.dumps(candidate, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

status = f"""# LayerSentry v1.0 immutable builder/toolchain candidate

- Source commit: `{source_commit}`
- Builder image: `{builder_ref}`
- Builder source alias: `{builder_alias}`
- Platform: `linux/amd64`
- Rootfs layers: {candidate['rootfs_layer_count']}
- Inventoried tool binaries: {candidate['tool_count']}
- Reviewed toolchain lock records: {len(candidate['toolchain_artifacts'])}
- Production lock complete: **false**
- Release approval: **false**

The production build path consumes the builder by OCI digest, starts an internal
Docker daemon from that image, and does not mount the host Docker socket.
"""
(output / "STATUS.md").write_text(status, encoding="utf-8")
PY

(
  cd "$OUTPUT_DIR"
  find . -maxdepth 1 -type f ! -name evidence-files.sha256 -print0 \
    | sort -z \
    | xargs -0 sha256sum > evidence-files.sha256
  sha256sum -c evidence-files.sha256
)

echo "BUILDER TOOLCHAIN EVIDENCE: PASS"
echo "output=$OUTPUT_DIR"
echo "builder_ref=$BUILDER_REF"
echo "source_commit=$SOURCE_COMMIT"
