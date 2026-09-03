#!/usr/bin/env bash
set -Eeuo pipefail

TOP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPTS_DIR="$TOP_DIR/scripts"
LOCK_FILE="$TOP_DIR/provenance/layersentry-v1.0-harvester-v1.8.2.lock.json"
ALIASES_FILE="$TOP_DIR/provenance/layersentry-v1.0-expanded-images.txt"
PACKAGE_OS_DIR="$TOP_DIR/package/harvester-os"
PACKAGE_REPO_DIR="$TOP_DIR/package/harvester-repo"
CHARTS_DIR="$PACKAGE_REPO_DIR/charts"
BUNDLE_DIR="$PACKAGE_OS_DIR/iso/bundle"
IMAGES_DIR="$BUNDLE_DIR/harvester/images"
IMAGES_LISTS_DIR="$BUNDLE_DIR/harvester/images-lists"
EXTRA_LIST="$IMAGES_LISTS_DIR/layersentry-expanded-images-v1.0.txt"
EXTRA_ARCHIVE="$IMAGES_DIR/layersentry-expanded-images-v1.0.tar.zst"
NFS_REPOSITORY=https://github.com/kubernetes-csi/csi-driver-nfs.git
NFS_COMMIT=57ba72f46ca0864b16e9523ee71e88878c0a5c48
NEUVECTOR_REPOSITORY=https://github.com/neuvector/neuvector-helm.git
NEUVECTOR_COMMIT=501b8f0e5213f2d1f4e1f904892fe86f7fb7e45b

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

for command in git python3 helm docker yq sha256sum stat zstd; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done
[[ ${ARCH:-amd64} == amd64 ]] || fail "LayerSentry expanded dependency bundle currently supports amd64 only"
[[ -f $LOCK_FILE ]] || fail "provenance lock is missing"
[[ -f $ALIASES_FILE ]] || fail "expanded image alias list is missing"

work_dir=$(mktemp -d "${RUNNER_TEMP:-/tmp}/layersentry-expanded-bundle.XXXXXX")
cleanup() {
  rm -rf "$work_dir"
}
trap cleanup EXIT INT TERM

checkout_exact() {
  local repository=$1
  local commit=$2
  local destination=$3
  git init -q "$destination"
  git -C "$destination" remote add origin "$repository"
  git -C "$destination" fetch --quiet --no-tags --depth 1 origin "$commit"
  git -C "$destination" -c advice.detachedHead=false checkout --quiet --detach FETCH_HEAD
  [[ $(git -C "$destination" rev-parse HEAD) == "$commit" ]] \
    || fail "source checkout mismatch for $repository"
}

nfs_dir="$work_dir/csi-driver-nfs"
neuvector_dir="$work_dir/neuvector-helm"
new_charts="$work_dir/charts"
mkdir -p "$nfs_dir" "$neuvector_dir" "$new_charts" "$CHARTS_DIR" "$IMAGES_DIR" "$IMAGES_LISTS_DIR"
checkout_exact "$NFS_REPOSITORY" "$NFS_COMMIT" "$nfs_dir"
checkout_exact "$NEUVECTOR_REPOSITORY" "$NEUVECTOR_COMMIT" "$neuvector_dir"

nfs_source="$nfs_dir/charts/v4.12.0/csi-driver-nfs-4.12.0.tgz"
[[ -s $nfs_source ]] || fail "pinned NFS CSI chart archive is missing"
cp "$nfs_source" "$new_charts/csi-driver-nfs-4.12.0.tgz"

security_core="$work_dir/core"
security_crd="$work_dir/crd"
cp -a "$neuvector_dir/charts/core" "$security_core"
cp -a "$neuvector_dir/charts/crd" "$security_crd"
python3 "$SCRIPTS_DIR/layersentry/prepare-runtime-security-chart.py" "$security_core"
helm package "$security_core" -d "$new_charts" >/dev/null
helm package "$security_crd" -d "$new_charts" >/dev/null

chart_epoch=$(python3 - "$LOCK_FILE" <<'PY'
import json
import sys
from pathlib import Path
lock = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
review = lock.get("reviewed_expanded_dependencies")
if not isinstance(review, dict):
    raise SystemExit("expanded dependency review is missing from the lock")
epoch = review.get("chart_source_date_epoch")
if not isinstance(epoch, int) or epoch <= 0:
    raise SystemExit("expanded chart source date epoch is invalid")
print(epoch)
PY
)

python3 "$SCRIPTS_DIR/provenance/normalize_chart_archives.py" \
  "$new_charts" \
  --source-date-epoch "$chart_epoch" \
  --report "$work_dir/chart-normalization-report.json" >/dev/null

python3 - "$LOCK_FILE" "$new_charts" <<'PY'
import hashlib
import json
import sys
from pathlib import Path
lock = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
charts_dir = Path(sys.argv[2])
expected = {
    "layersentry-csi-nfs": "csi-driver-nfs-4.12.0.tgz",
    "layersentry-runtime-security": "core-2.10.3.tgz",
    "layersentry-runtime-security-crd": "crd-2.10.3.tgz",
}
by_id = {item.get("id"): item for item in lock.get("charts", []) if isinstance(item, dict)}
for item_id, archive in expected.items():
    item = by_id.get(item_id)
    if not isinstance(item, dict):
        raise SystemExit(f"expanded chart is not locked: {item_id}")
    path = charts_dir / archive
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if item.get("archive") != archive or item.get("sha256") != digest or item.get("bytes") != path.stat().st_size:
        raise SystemExit(f"expanded chart differs from reviewed lock: {item_id}")
print("LAYERSENTRY EXPANDED CHART LOCK BINDING: PASS")
PY

cp "$new_charts"/*.tgz "$CHARTS_DIR/"
helm repo index "$CHARTS_DIR"

mapping="$work_dir/image-map.tsv"
python3 - "$LOCK_FILE" "$ALIASES_FILE" > "$mapping" <<'PY'
import json
import re
import sys
from pathlib import Path
lock = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
aliases = []
for raw in Path(sys.argv[2]).read_text(encoding="utf-8").splitlines():
    value = raw.strip()
    if value and not value.startswith("#"):
        aliases.append(value)
alias_to_ref = {}
for item in lock.get("container_images", []):
    if not isinstance(item, dict):
        continue
    ref = str(item.get("ref", ""))
    if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", ref):
        continue
    for alias in item.get("aliases") or []:
        alias_to_ref[str(alias)] = ref
missing = [alias for alias in aliases if alias not in alias_to_ref]
if missing:
    raise SystemExit(f"expanded runtime aliases are not digest-locked: {missing}")
for alias in sorted(aliases):
    print(f"{alias}\t{alias_to_ref[alias]}")
PY

while IFS=$'\t' read -r alias immutable_ref; do
  [[ -n $alias && -n $immutable_ref ]] || fail "invalid expanded image mapping"
  docker pull --platform linux/amd64 "$immutable_ref" >/dev/null
  ref_id=$(docker image inspect "$immutable_ref" --format '{{.Id}}')
  docker tag "$immutable_ref" "$alias"
  alias_id=$(docker image inspect "$alias" --format '{{.Id}}')
  [[ $ref_id == "$alias_id" ]] || fail "digest-to-alias identity mismatch for $alias"
done < "$mapping"

cp "$ALIASES_FILE" "$EXTRA_LIST"
# Remove comments before passing the list to docker image save.
grep -vE '^[[:space:]]*(#|$)' "$EXTRA_LIST" | sort -u > "$work_dir/images.txt"
mv "$work_dir/images.txt" "$EXTRA_LIST"

metadata="$BUNDLE_DIR/metadata.yaml"
rm -f "$EXTRA_ARCHIVE" "${EXTRA_ARCHIVE%.zst}"
if [[ -f $metadata ]]; then
  REL_LIST="/harvester/images-lists/$(basename "$EXTRA_LIST")" \
    yq -e 'del(.images.common[] | select(.list == strenv(REL_LIST)))' -i "$metadata"
fi

# All aliases are already staged from their immutable reviewed digest refs.
export USE_LOCAL_IMAGES=layersentry-provenance-lock
# shellcheck disable=SC1091
source "$SCRIPTS_DIR/lib/image"
save_image "common" "$BUNDLE_DIR" "$EXTRA_LIST" "$IMAGES_DIR"

[[ -s $EXTRA_ARCHIVE ]] || fail "expanded offline image archive was not created"

echo "LAYERSENTRY EXPANDED OFFLINE BUNDLE: PASS"
echo "nfs_csi=v4.12.0"
echo "runtime_security=NeuVector-5.5.3/chart-2.10.3"
echo "image_aliases=$(wc -l < "$EXTRA_LIST")"
