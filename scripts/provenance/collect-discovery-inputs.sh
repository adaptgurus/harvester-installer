#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <output-directory> <exact-source-commit>" >&2
  exit 2
fi

OUTPUT_DIR=$1
SOURCE_COMMIT=$2
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]
test "$(git rev-parse HEAD)" = "$SOURCE_COMMIT"

HARVESTER_COMMIT=5320dfa6770f63406750e7c64b24ed87c543e6ad
ADDONS_COMMIT=f60d73d894e00f18d5e11cd21a301ed1b016631c
RKE2_VERSION=$(sed -n 's/^RKE2_VERSION="\([^"]*\)"/\1/p' scripts/version-rke2)
RANCHER_VERSION=$(sed -n 's/^RANCHER_VERSION="\([^"]*\)"/\1/p' scripts/version-rancher)
RKE2_VERSION_NORMALIZED=${RKE2_VERSION/+/-}

test -n "$RKE2_VERSION"
test -n "$RANCHER_VERSION"

mkdir -p "$OUTPUT_DIR/downloads"
DOWNLOAD_SOURCES="$OUTPUT_DIR/download-sources.tsv"
: > "$DOWNLOAD_SOURCES"

TOOLS_DIR="${RUNNER_TEMP:-/tmp}/layersentry-provenance-tools"
WORK_DIR="${RUNNER_TEMP:-/tmp}/layersentry-provenance-source"
rm -rf "$TOOLS_DIR" "$WORK_DIR"
mkdir -p "$TOOLS_DIR" "$WORK_DIR"

download_file() {
  local url=$1
  local output=$2
  local expected=${3:-}
  curl --fail --location --silent --show-error \
    --retry 5 --retry-all-errors --connect-timeout 30 \
    "$url" -o "$output"
  if [[ -n "$expected" ]]; then
    echo "$expected  $output" | sha256sum -c -
  fi
  printf '%s\t%s\n' "$(basename "$output")" "$url" >> "$DOWNLOAD_SOURCES"
}

checkout_exact() {
  local url=$1
  local commit=$2
  local target=$3
  git init -q "$target"
  git -C "$target" remote add origin "$url"
  git -C "$target" fetch --quiet --depth 1 origin "$commit"
  git -C "$target" -c advice.detachedHead=false checkout --quiet --detach FETCH_HEAD
  test "$(git -C "$target" rev-parse HEAD)" = "$commit"
}

YQ_VERSION=v4.52.5
YQ_SHA256=75d893a0d5940d1019cb7cdc60001d9e876623852c31cfc6267047bc31149fa9
YQ_URL="https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_amd64"
download_file "$YQ_URL" "$TOOLS_DIR/yq" "$YQ_SHA256"
chmod +x "$TOOLS_DIR/yq"

HELM_VERSION=v3.20.0
HELM_SHA256=dbb4c8fc8e19d159d1a63dda8db655f9ffa4aac1b9a6b188b34a40957119b286
HELM_URL="https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz"
download_file \
  "$HELM_URL" \
  "$OUTPUT_DIR/downloads/helm-${HELM_VERSION}-linux-amd64.tar.gz" \
  "$HELM_SHA256"

WHARFIE_VERSION=v0.6.8
WHARFIE_SHA256=e6b5d27e5b5815ece828e3d2f4012ccec1e40dceb4e639815d6cdbc0f22e2fa8
WHARFIE_URL="https://github.com/rancher/wharfie/releases/download/${WHARFIE_VERSION}/wharfie-amd64"
download_file \
  "$WHARFIE_URL" \
  "$OUTPUT_DIR/downloads/wharfie-amd64" \
  "$WHARFIE_SHA256"

HARVESTER_DIR="$WORK_DIR/harvester"
ADDONS_DIR="$WORK_DIR/addons"
checkout_exact "https://github.com/harvester/harvester.git" "$HARVESTER_COMMIT" "$HARVESTER_DIR"
checkout_exact "https://github.com/harvester/addons.git" "$ADDONS_COMMIT" "$ADDONS_DIR"

ALIASES_RAW="$OUTPUT_DIR/image-aliases.raw.txt"
: > "$ALIASES_RAW"

cat scripts/images/rancher-images.txt >> "$ALIASES_RAW"
sed "s,\$RKE2_VERSION,${RKE2_VERSION_NORMALIZED},g" \
  scripts/images/rancherd-bootstrap-images.txt >> "$ALIASES_RAW"
cat scripts/images/harvester-additional-images.txt >> "$ALIASES_RAW"

# Build-time and evidence-tool images discovered from active build inputs and the lock.
awk '/^FROM[[:space:]]+/ && $2 !~ /^\$/ {print $2}' \
  Dockerfile.dapper package/harvester-repo/Dockerfile >> "$ALIASES_RAW"
sed -n 's/^BASE_OS_IMAGE="\([^"]*\)"/\1/p' scripts/package-harvester-os >> "$ALIASES_RAW"
python3 - "$ALIASES_RAW" <<'PY'
import json
import sys
from pathlib import Path

lock = json.loads(
    Path("provenance/layersentry-v1.0-harvester-v1.8.2.lock.json").read_text(
        encoding="utf-8"
    )
)
with Path(sys.argv[1]).open("a", encoding="utf-8") as handle:
    for item in lock.get("unresolved", []):
        observed = str(item.get("observed_mutable_reference", "")).strip()
        if observed:
            handle.write(observed + "\n")
PY

# Extract repository/tag pairs using the same expression as scripts/build-bundle.
mapfile -t repositories < <(
  "$TOOLS_DIR/yq" eval -r \
    'explode(.) | .. | select(has("repository")) | select(has("tag")) | .repository' \
    "$HARVESTER_DIR/deploy/charts/harvester/values.yaml"
)
mapfile -t tags < <(
  "$TOOLS_DIR/yq" eval -r \
    'explode(.) | .. | select(has("repository")) | select(has("tag")) | .tag' \
    "$HARVESTER_DIR/deploy/charts/harvester/values.yaml"
)
test "${#repositories[@]}" -eq "${#tags[@]}"
for index in "${!repositories[@]}"; do
  printf '%s:%s\n' "${repositories[$index]}" "${tags[$index]}" >> "$ALIASES_RAW"
done

# Source the exact add-ons commit and capture every image consumed by build-bundle.
# shellcheck disable=SC1090
source "$ADDONS_DIR/version_info"
printf '%s\n' \
  "$VM_IMPORT_CONTROLLER_IMAGE" \
  "$PCIDEVICES_CONTROLLER_IMAGE" \
  "$HARVESTER_SEEDER_IMAGE" \
  "$HARVESTER_EVENTROUTER_FULL_TAG" \
  "$KUBEOVN_OPERATOR_IMAGE" \
  "$DESCHEDULER_IMAGE" >> "$ALIASES_RAW"

RKE2_BASE_URL="https://github.com/rancher/rke2/releases/download/${RKE2_VERSION}"
for name in rke2-images.linux-amd64.txt rke2-images-multus.linux-amd64.txt; do
  download_file "$RKE2_BASE_URL/$name" "$OUTPUT_DIR/downloads/$name"
  cat "$OUTPUT_DIR/downloads/$name" >> "$ALIASES_RAW"
done

LONGHORN_ARCHIVE=$(find "$HARVESTER_DIR/deploy/charts/harvester/charts" \
  -maxdepth 1 -type f -name 'longhorn-*.tgz' -print -quit)
test -n "$LONGHORN_ARCHIVE"
LONGHORN_VERSION=$(basename "$LONGHORN_ARCHIVE")
LONGHORN_VERSION=${LONGHORN_VERSION#longhorn-}
LONGHORN_VERSION=${LONGHORN_VERSION%.tgz}
LONGHORN_TAG="v${LONGHORN_VERSION}"
LONGHORN_URL="https://raw.githubusercontent.com/longhorn/longhorn/${LONGHORN_TAG}/deploy/longhorn-images.txt"
download_file \
  "$LONGHORN_URL" \
  "$OUTPUT_DIR/downloads/longhorn-images-${LONGHORN_TAG}.txt"
cat "$OUTPUT_DIR/downloads/longhorn-images-${LONGHORN_TAG}.txt" >> "$ALIASES_RAW"

python3 scripts/provenance/normalize_image_list.py \
  "$ALIASES_RAW" "$OUTPUT_DIR/image-aliases.txt"

export \
  RKE2_VERSION RANCHER_VERSION LONGHORN_TAG \
  YQ_VERSION YQ_SHA256 YQ_URL \
  HELM_VERSION HELM_SHA256 HELM_URL \
  WHARFIE_VERSION WHARFIE_SHA256 WHARFIE_URL

python3 - "$OUTPUT_DIR" <<'PY'
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

out = Path(sys.argv[1])


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command(*args: str) -> str:
    proc = subprocess.run(
        list(args),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return proc.stdout.strip()


source_by_name = {}
for raw in (out / "download-sources.tsv").read_text(encoding="utf-8").splitlines():
    name, source = raw.split("\t", 1)
    source_by_name[name] = source

downloaded = []
for path in sorted((out / "downloads").iterdir()):
    downloaded.append(
        {
            "id": path.name,
            "source": source_by_name[path.name],
            "sha256": sha256(path),
            "size": path.stat().st_size,
        }
    )

metadata = {
    "schema": "layersentry.provenance-discovery/v1",
    "captured_at": dt.datetime.now(dt.timezone.utc)
    .replace(microsecond=0)
    .isoformat()
    .replace("+00:00", "Z"),
    "source_commit": os.environ["GITHUB_SHA"],
    "release_identity": {
        "product": "LayerSentry v1.0",
        "embedded_platform": "Harvester v1.8.2",
    },
    "source_commits": {
        "harvester": "5320dfa6770f63406750e7c64b24ed87c543e6ad",
        "harvester_addons": "f60d73d894e00f18d5e11cd21a301ed1b016631c",
    },
    "versions": {
        "rancher": os.environ["RANCHER_VERSION"],
        "rke2": os.environ["RKE2_VERSION"],
        "longhorn": os.environ["LONGHORN_TAG"],
    },
    "verified_tool_artifacts": [
        {
            "id": "yq-linux-amd64",
            "version": os.environ["YQ_VERSION"],
            "source": os.environ["YQ_URL"],
            "sha256": os.environ["YQ_SHA256"],
        },
        {
            "id": "helm-linux-amd64",
            "version": os.environ["HELM_VERSION"],
            "source": os.environ["HELM_URL"],
            "sha256": os.environ["HELM_SHA256"],
        },
        {
            "id": "wharfie-amd64",
            "version": os.environ["WHARFIE_VERSION"],
            "source": os.environ["WHARFIE_URL"],
            "sha256": os.environ["WHARFIE_SHA256"],
        },
    ],
    "downloaded_inputs": downloaded,
    "runner_observation": {
        "image_os": os.environ.get("ImageOS", ""),
        "image_version": os.environ.get("ImageVersion", ""),
        "kernel": platform.platform(),
        "python": sys.version.split()[0],
        "docker": command("docker", "--version"),
        "docker_buildx": command("docker", "buildx", "version"),
        "git": command("git", "--version"),
        "curl": command("curl", "--version").splitlines()[0],
    },
    "review_required": True,
    "release_approved": False,
}
(out / "input-discovery.json").write_text(
    json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

sha256sum "$OUTPUT_DIR/image-aliases.txt" > "$OUTPUT_DIR/image-aliases.txt.sha256"
find "$OUTPUT_DIR/downloads" -maxdepth 1 -type f -printf '%f\n' | sort > "$OUTPUT_DIR/downloads.manifest"
rm -rf "$OUTPUT_DIR/downloads"

echo "Collected $(grep -cvE '^[[:space:]]*(#|$)' "$OUTPUT_DIR/image-aliases.txt") unique image aliases"
