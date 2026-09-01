#!/usr/bin/env bash
set -Eeuo pipefail

export LC_ALL=C
umask 022

OUTPUT_DIR=${1:?usage: collect_os_package_evidence.sh OUTPUT_DIR SOURCE_COMMIT}
SOURCE_COMMIT=${2:?usage: collect_os_package_evidence.sh OUTPUT_DIR SOURCE_COMMIT}
TOP_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
PLAN_FILE="$TOP_DIR/provenance/layersentry-v1.0-harvester-os-input.json"
LOCK_FILE="$TOP_DIR/provenance/layersentry-v1.0-harvester-v1.8.2.lock.json"
BASE_OS_REF="docker.io/rancher/harvester-os@sha256:d437600ddc5e809cd22d9a6ddfc3c10328ac88440cef2930aa73aaf36b4178b4"
BASE_OS_ALIAS="docker.io/rancher/harvester-os:v1.8-20260806"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

for command in docker python3 git sha256sum stat tar gzip; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done
[[ $SOURCE_COMMIT =~ ^[0-9a-f]{40}$ ]] || fail "source commit must be exactly 40 lowercase hex characters"
[[ $(git -C "$TOP_DIR" rev-parse HEAD) == "$SOURCE_COMMIT" ]] \
  || fail "checked-out source does not equal requested source commit"

python3 "$TOP_DIR/scripts/provenance/verify_os_package_binding.py" \
  --plan "$PLAN_FILE" \
  --lock "$LOCK_FILE" \
  --repo-root "$TOP_DIR" \
  --report "${RUNNER_TEMP:-/tmp}/os-package-binding-report.json"

OUTPUT_DIR=$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)
rm -rf "$OUTPUT_DIR"/*

# Pull by digest and platform. The mutable alias is evidence only and is never
# consumed by the build path.
docker pull --platform linux/amd64 "$BASE_OS_REF" >/dev/null

python3 - "$BASE_OS_REF" "$OUTPUT_DIR/image-inspect.json" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

ref, output = sys.argv[1:]
raw = subprocess.check_output(["docker", "image", "inspect", ref], text=True)
values = json.loads(raw)
if not isinstance(values, list) or len(values) != 1:
    raise SystemExit("docker image inspect did not return exactly one image")
item = values[0]
repo_digests = sorted(str(value) for value in item.get("RepoDigests") or [])
expected_digest = ref.split("@", 1)[1]
if not any(value.endswith(expected_digest) for value in repo_digests):
    raise SystemExit(f"pulled image does not retain expected digest {expected_digest}: {repo_digests}")
if item.get("Architecture") != "amd64" or item.get("Os") != "linux":
    raise SystemExit(
        f"pulled image platform is {item.get('Os')}/{item.get('Architecture')}, expected linux/amd64"
    )
layers = item.get("RootFS", {}).get("Layers")
if not isinstance(layers, list) or not layers:
    raise SystemExit("pulled image has no rootfs layers")
report = {
    "schema": "layersentry.oci-image-inspection/v1",
    "ref": ref,
    "architecture": item["Architecture"],
    "os": item["Os"],
    "image_id": item.get("Id"),
    "repo_digests": repo_digests,
    "rootfs_type": item.get("RootFS", {}).get("Type"),
    "rootfs_layers": layers,
}
Path(output).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

run_in_image() {
  docker run --rm --network none --platform linux/amd64 -i \
    --entrypoint /bin/bash "$BASE_OS_REF" -s
}

# Canonical installed RPM inventory.
run_in_image > "$OUTPUT_DIR/rpm-packages.tsv" <<'EOS'
set -Eeuo pipefail
printf 'name\tepoch\tversion\trelease\tarch\tvendor\tbuild_time\n'
rpm -qa --qf '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{VENDOR}\t%{BUILDTIME}\n' \
  | LC_ALL=C sort -t $'\t' -k1,1 -k2,2 -k3,3 -k4,4 -k5,5
EOS

# Preserve exact OS release metadata bytes.
run_in_image > "$OUTPUT_DIR/os-release" <<'EOS'
set -Eeuo pipefail
cat /etc/os-release
EOS

# Kernel and initrd are direct build inputs copied from this base image.
run_in_image > "$OUTPUT_DIR/boot-files.tsv" <<'EOS'
set -Eeuo pipefail
printf 'id\tlogical_path\tresolved_path\tbytes\tsha256\n'
for record in 'kernel:/boot/vmlinuz' 'initrd:/boot/initrd'; do
  id=${record%%:*}
  logical=${record#*:}
  resolved=$(readlink -f "$logical")
  [[ -f "$resolved" ]]
  bytes=$(stat -c '%s' "$resolved")
  checksum=$(sha256sum "$resolved" | awk '{print $1}')
  printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$logical" "$resolved" "$bytes" "$checksum"
done
EOS

# Canonical regular-file and symlink manifest for a filesystem tree.
manifest_tree() {
  local requested=$1
  local output=$2
  docker run --rm --network none --platform linux/amd64 -i \
    --entrypoint /bin/bash "$BASE_OS_REF" -s -- "$requested" > "$output" <<'EOS'
set -Eeuo pipefail
requested=$1
root=$(readlink -f "$requested" 2>/dev/null || true)
printf 'type\tpath\tbytes_or_target\tsha256\n'
if [[ -z "$root" || ! -d "$root" ]]; then
  printf 'absent\t%s\t-\t-\n' "$requested"
  exit 0
fi
while IFS= read -r -d '' path; do
  [[ "$path" != *$'\t'* && "$path" != *$'\n'* && "$path" != *$'\r'* ]]
  if [[ -L "$path" ]]; then
    target=$(readlink "$path")
    [[ "$target" != *$'\t'* && "$target" != *$'\n'* && "$target" != *$'\r'* ]]
    printf 'symlink\t%s\t%s\t-\n' "$path" "$target"
  elif [[ -f "$path" ]]; then
    bytes=$(stat -c '%s' "$path")
    checksum=$(sha256sum "$path" | awk '{print $1}')
    printf 'file\t%s\t%s\t%s\n' "$path" "$bytes" "$checksum"
  fi
done < <(find "$root" -xdev \( -type f -o -type l \) -print0 | LC_ALL=C sort -z)
EOS
}

firmware_root=$(docker run --rm --network none --platform linux/amd64 \
  --entrypoint /bin/bash "$BASE_OS_REF" -lc '
    for candidate in /usr/lib/firmware /lib/firmware; do
      resolved=$(readlink -f "$candidate" 2>/dev/null || true)
      if [[ -n "$resolved" && -d "$resolved" ]]; then printf "%s\n" "$resolved"; exit 0; fi
    done
    exit 1
  ')
manifest_tree "$firmware_root" "$OUTPUT_DIR/firmware-files.tsv"
manifest_tree /etc/zypp/repos.d "$OUTPUT_DIR/package-repositories.tsv"

# Hash the exact OS binaries consumed by package-harvester-os.
run_in_image > "$OUTPUT_DIR/os-tools.tsv" <<'EOS'
set -Eeuo pipefail
printf 'id\tpath\tbytes\tsha256\tversion_sha256\n'
for id in elemental dracut; do
  path=$(command -v "$id")
  [[ -f "$path" ]]
  bytes=$(stat -c '%s' "$path")
  checksum=$(sha256sum "$path" | awk '{print $1}')
  version_file=$(mktemp)
  "$path" --version > "$version_file" 2>&1 || "$path" version > "$version_file" 2>&1 || true
  [[ -s "$version_file" ]]
  version_sha256=$(sha256sum "$version_file" | awk '{print $1}')
  rm -f "$version_file"
  printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$path" "$bytes" "$checksum" "$version_sha256"
done
EOS

# Canonical archive of all source-controlled files layered onto the exact base.
overlay_tree=$(git -C "$TOP_DIR" rev-parse "HEAD^{tree}")
(
  cd "$TOP_DIR"
  git archive --format=tar "$SOURCE_COMMIT" \
    package/harvester-os \
    scripts/package-harvester-os \
    | gzip -n -9 > "$OUTPUT_DIR/layersentry-os-overlay.tar.gz"
)

python3 "$TOP_DIR/scripts/provenance/build_os_package_candidate.py" \
  --plan "$PLAN_FILE" \
  --evidence-dir "$OUTPUT_DIR" \
  --source-commit "$SOURCE_COMMIT" \
  --overlay-tree "$overlay_tree" \
  --output "$OUTPUT_DIR/os-package-input-candidate.json"

python3 - "$OUTPUT_DIR" "$SOURCE_COMMIT" "$BASE_OS_ALIAS" "$BASE_OS_REF" <<'PY'
import json
import sys
from pathlib import Path

output = Path(sys.argv[1])
source_commit, alias, ref = sys.argv[2:]
candidate = json.loads((output / "os-package-input-candidate.json").read_text(encoding="utf-8"))
text = f"""# LayerSentry v1.0 Harvester OS/package input evidence

- Source commit: `{source_commit}`
- Product: LayerSentry v1.0
- Embedded platform: Harvester v1.8.2
- Base OS alias observed: `{alias}`
- Base OS consumed by digest: `{ref}`
- Platform: `{candidate['platform']}`
- Rootfs layers: {candidate['rootfs_layer_count']}
- Installed RPM packages: {candidate['rpm_package_count']}
- Firmware records: {candidate['firmware_record_count']}
- Reviewed package/input lock records: {len(candidate['packages'])}
- Production lock complete: **false**
- Release approval: **false**

The exact OCI digest covers the base root filesystem. Deterministic package,
kernel, initrd, firmware, repository, OS-tool and LayerSentry-overlay manifests
provide independently reviewable evidence of the inputs consumed by the ISO path.
"""
(output / "STATUS.md").write_text(text, encoding="utf-8")
PY

(
  cd "$OUTPUT_DIR"
  find . -maxdepth 1 -type f ! -name evidence-files.sha256 -print0 \
    | sort -z \
    | xargs -0 sha256sum > evidence-files.sha256
  sha256sum -c evidence-files.sha256
)

echo "OS PACKAGE EVIDENCE: PASS"
echo "output=$OUTPUT_DIR"
echo "source_commit=$SOURCE_COMMIT"
echo "base_os_ref=$BASE_OS_REF"
