#!/usr/bin/env bash
set -Eeuo pipefail

export LC_ALL=C
umask 022

TOP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PLAN_FILE="$TOP_DIR/provenance/layersentry-v1.0-harvester-v1.8.2.chart-sources.json"
LOCK_FILE="$TOP_DIR/provenance/layersentry-v1.0-harvester-v1.8.2.lock.json"
OUTPUT_DIR=${1:?usage: collect_chart_evidence.sh OUTPUT_DIR LAYERSENTRY_SOURCE_COMMIT}
LAYERSENTRY_SOURCE_COMMIT=${2:?usage: collect_chart_evidence.sh OUTPUT_DIR LAYERSENTRY_SOURCE_COMMIT}

HARVESTER_REPOSITORY=https://github.com/harvester/harvester.git
HARVESTER_COMMIT=5320dfa6770f63406750e7c64b24ed87c543e6ad
HARVESTER_RELEASE_REF=v1.8.2
ADDONS_REPOSITORY=https://github.com/harvester/addons.git
ADDONS_COMMIT=f60d73d894e00f18d5e11cd21a301ed1b016631c
EXPECTED_HELM_VERSION=v3.20.0
EXPECTED_YQ_VERSION=v4.52.5

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

for command in git curl sha256sum stat python3 helm yq patch tar; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done

[[ $LAYERSENTRY_SOURCE_COMMIT =~ ^[0-9a-f]{40}$ ]] \
  || fail "LayerSentry source commit must be exactly 40 lowercase hex characters"
[[ -f $PLAN_FILE ]] || fail "chart source plan is missing: $PLAN_FILE"
[[ -f $LOCK_FILE ]] || fail "provenance lock is missing: $LOCK_FILE"
actual_source_commit=$(git -C "$TOP_DIR" rev-parse HEAD)
[[ $actual_source_commit == "$LAYERSENTRY_SOURCE_COMMIT" ]] \
  || fail "checked-out source $actual_source_commit does not equal requested source $LAYERSENTRY_SOURCE_COMMIT"
[[ $(helm version --short) == "$EXPECTED_HELM_VERSION"* ]] \
  || fail "helm version is not $EXPECTED_HELM_VERSION: $(helm version --short)"
yq --version | grep -Fq "$EXPECTED_YQ_VERSION" \
  || fail "yq version is not $EXPECTED_YQ_VERSION: $(yq --version)"

OUTPUT_DIR=$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)
rm -rf "$OUTPUT_DIR/final-charts"
mkdir -p "$OUTPUT_DIR/final-charts"
work_dir=$(mktemp -d "${RUNNER_TEMP:-/tmp}/layersentry-chart-evidence.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT
source_charts="$work_dir/source-charts"
harvester_dir="$work_dir/harvester"
addons_dir="$work_dir/addons"
mkdir -p "$source_charts" "$harvester_dir" "$addons_dir"

fetch_exact_commit() {
  local repository=$1
  local commit=$2
  local destination=$3
  git -C "$destination" init -q
  git -C "$destination" remote add origin "$repository"
  git -C "$destination" fetch --quiet --no-tags --depth 1 origin "$commit"
  git -C "$destination" -c advice.detachedHead=false checkout --quiet --detach FETCH_HEAD
  [[ $(git -C "$destination" rev-parse HEAD) == "$commit" ]] \
    || fail "source checkout mismatch for $repository"
}

fetch_exact_commit "$HARVESTER_REPOSITORY" "$HARVESTER_COMMIT" "$harvester_dir"
fetch_exact_commit "$ADDONS_REPOSITORY" "$ADDONS_COMMIT" "$addons_dir"

export ARCH=amd64
export HARVESTER_RELEASE_REF HARVESTER_RELEASE_COMMIT="$HARVESTER_COMMIT"
# shellcheck disable=SC1091
source "$TOP_DIR/scripts/version-harvester" "$harvester_dir"
[[ $HARVESTER_VERSION == "$HARVESTER_RELEASE_REF" ]] || fail "Harvester release binding failed"
[[ $HARVESTER_CHART_VERSION == "1.8.2" ]] || fail "unexpected Harvester chart version"
[[ $HARVESTER_APP_VERSION == "$HARVESTER_RELEASE_REF" ]] || fail "unexpected Harvester app version"

source_date_epoch=$(git -C "$harvester_dir" show -s --format=%ct "$HARVESTER_COMMIT")
[[ $source_date_epoch =~ ^[0-9]+$ ]] || fail "cannot resolve immutable source date epoch"
export SOURCE_DATE_EPOCH=$source_date_epoch

# Patch the locally generated Harvester charts exactly as the production bundle path does.
REPO=rancher "$TOP_DIR/scripts/patch-harvester" "$harvester_dir"
helm package "$harvester_dir/deploy/charts/harvester" -d "$OUTPUT_DIR/final-charts" >/dev/null
helm package "$harvester_dir/deploy/charts/harvester-crd" -d "$OUTPUT_DIR/final-charts" >/dev/null

printf 'id\turl\tarchive\tsha256\tbytes\n' > "$OUTPUT_DIR/source-downloads.tsv"
while IFS=$'\t' read -r chart_id chart_url chart_archive; do
  [[ -n $chart_id && -n $chart_url && -n $chart_archive ]] \
    || fail "invalid URL chart record from source plan"
  destination="$source_charts/$chart_archive"
  curl --fail --location --silent --show-error \
    --retry 5 --retry-all-errors --connect-timeout 30 \
    "$chart_url" -o "$destination"
  [[ -s $destination ]] || fail "downloaded chart is empty: $chart_id"
  checksum=$(sha256sum "$destination" | awk '{print $1}')
  bytes=$(stat -c '%s' "$destination")
  printf '%s\t%s\t%s\t%s\t%s\n' \
    "$chart_id" "$chart_url" "$chart_archive" "$checksum" "$bytes" \
    >> "$OUTPUT_DIR/source-downloads.tsv"
  cp "$destination" "$OUTPUT_DIR/final-charts/$chart_archive"
done < <(
  python3 - "$PLAN_FILE" <<'PY'
import json
import sys
from pathlib import Path
plan = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for item in plan["charts"]:
    source = item["source"]
    if source["kind"] == "url":
        values = (item["id"], source["url"], item["archive"])
        if any("\t" in value or "\n" in value for value in values):
            raise SystemExit("unsafe tab/newline in chart source plan")
        print("\t".join(values))
PY
)

# Verify the add-on release metadata before using its pinned patch set.
# shellcheck disable=SC1091
source "$addons_dir/version_info"
[[ $VM_IMPORT_CONTROLLER_CHART_VERSION == "1.8.2" ]]
[[ $PCIDEVICES_CONTROLLER_CHART_VERSION == "1.8.2" ]]
[[ $HARVESTER_SEEDER_CHART_VERSION == "1.8.2" ]]
[[ $NVIDIA_DRIVER_RUNTIME_CHART_VERSION == "1.8.2" ]]
[[ $RANCHER_LOGGING_CHART_VERSION == "108.0.2+up4.10.0-rancher.18" ]]
[[ $RANCHER_MONITORING_CHART_VERSION == "108.0.2+up77.9.1-rancher.11" ]]
[[ $KUBEOVN_OPERATOR_CHART_VERSION == "1.15.4-r2" ]]
[[ $DESCHEDULER_CHART_VERSION == "0.33.0" ]]

# shellcheck disable=SC1091
source "$addons_dir/scripts/hack/patch-rancher-monitoring"
# shellcheck disable=SC1091
source "$addons_dir/scripts/hack/patch-rancher-monitoring-crd"
# shellcheck disable=SC1091
source "$addons_dir/scripts/hack/patch-rancher-logging"

patch_rancher_monitoring_chart \
  "$OUTPUT_DIR/final-charts" \
  "$RANCHER_MONITORING_CHART_VERSION" \
  "$addons_dir/pkg/config/templates/patch/rancher-monitoring"
patch_rancher_monitoring_crd_chart \
  "$OUTPUT_DIR/final-charts" \
  "$RANCHER_MONITORING_CHART_VERSION" \
  "$addons_dir/pkg/config/templates/patch/rancher-monitoring-crd"
patch_rancher_logging_chart \
  "$OUTPUT_DIR/final-charts" \
  "$RANCHER_LOGGING_CHART_VERSION" \
  "$addons_dir/pkg/config/templates/patch/rancher-logging"

(
  cd "$OUTPUT_DIR"
  python3 "$TOP_DIR/scripts/provenance/normalize_chart_archives.py" \
    final-charts \
    --source-date-epoch "$source_date_epoch" \
    --report normalization-report.json \
    > normalization-checksums.txt
)

python3 "$TOP_DIR/scripts/provenance/build_chart_lock_candidate.py" \
  --plan "$PLAN_FILE" \
  --charts-dir "$OUTPUT_DIR/final-charts" \
  --source-checksums "$OUTPUT_DIR/source-downloads.tsv" \
  --normalization-report "$OUTPUT_DIR/normalization-report.json" \
  --source-commit "$LAYERSENTRY_SOURCE_COMMIT" \
  --source-date-epoch "$source_date_epoch" \
  --output "$OUTPUT_DIR/chart-lock-candidate.json"

python3 - "$OUTPUT_DIR" "$LAYERSENTRY_SOURCE_COMMIT" <<'PY'
import json
import sys
from pathlib import Path
output = Path(sys.argv[1])
source_commit = sys.argv[2]
candidate = json.loads((output / "chart-lock-candidate.json").read_text(encoding="utf-8"))
source_count = sum(1 for item in candidate["charts"] if "source_sha256" in item)
text = f"""# LayerSentry v1.0 deterministic chart evidence

- Source commit: `{source_commit}`
- Product: LayerSentry v1.0
- Embedded platform: Harvester v1.8.2
- Final normalized charts: {candidate['chart_count']}
- Downloaded source archives checksummed: {source_count}
- Git-source charts: {candidate['chart_count'] - source_count}
- Harvester source commit: `{candidate['harvester_commit']}`
- Add-ons patch source commit: `{candidate['addons_commit']}`
- Source date epoch: `{candidate['source_date_epoch']}`
- Full provenance lock complete: **false**
- Release approval: **false**

The final chart archives are uploaded as workflow evidence. Only checksummed text
metadata is committed. Remaining image, OS/package and toolchain inputs stay fail-closed.
"""
(output / "STATUS.md").write_text(text, encoding="utf-8")
PY

(
  cd "$OUTPUT_DIR"
  sha256sum \
    STATUS.md \
    chart-lock-candidate.json \
    normalization-checksums.txt \
    normalization-report.json \
    source-downloads.tsv \
    > evidence-files.sha256
)

echo "CHART EVIDENCE: PASS"
echo "output=$OUTPUT_DIR"
echo "chart_count=$(find "$OUTPUT_DIR/final-charts" -maxdepth 1 -type f -name '*.tgz' | wc -l)"
echo "source_date_epoch=$source_date_epoch"
