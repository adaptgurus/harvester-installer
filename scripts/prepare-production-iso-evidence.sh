#!/usr/bin/env bash
set -euo pipefail

artifacts_dir=${1:?usage: prepare-production-iso-evidence.sh ARTIFACTS_DIR OUTPUT_DIR}
output_dir=${2:?usage: prepare-production-iso-evidence.sh ARTIFACTS_DIR OUTPUT_DIR}

mkdir -p "$output_dir/iso-metadata"

mapfile -t full_isos < <(find "$artifacts_dir" -maxdepth 1 -type f -name '*-amd64.iso' ! -name '*-net-install.iso' -print)
if [[ ${#full_isos[@]} -ne 1 ]]; then
  echo "Expected exactly one full amd64 ISO, found ${#full_isos[@]}" >&2
  printf '%s\n' "${full_isos[@]}" >&2
  find "$artifacts_dir" -maxdepth 1 -type f -printf '%f\n' | sort >&2
  exit 1
fi

if find "$artifacts_dir" -maxdepth 1 -type f -name '*-net-install.iso' | grep -q .; then
  echo 'LayerSentry production policy forbids the network/net-install ISO artifact' >&2
  exit 1
fi

release_iso="$output_dir/layersentry-v1.0-harvester-v1.8.2-amd64.iso"
cp "${full_isos[0]}" "$release_iso"

sha512sum "$release_iso" > "${release_iso}.sha512"
stat -c '%s' "$release_iso" > "${release_iso}.bytes"
git rev-parse HEAD > "$output_dir/source-commit.txt"

xorriso -indev "$release_iso" -toc > "$output_dir/iso-metadata/iso-toc.txt" 2>&1
xorriso -indev "$release_iso" -report_el_torito plain > "$output_dir/iso-metadata/el-torito-layout.txt" 2>&1
grep -F "Volume id    : 'COS_LIVE'" "$output_dir/iso-metadata/iso-toc.txt"
grep -F 'El Torito' "$output_dir/iso-metadata/el-torito-layout.txt"

xorriso -osirrox on \
  -indev "$release_iso" \
  -extract /harvester-release.yaml "$output_dir/iso-metadata/harvester-release.yaml"

xorriso -osirrox on \
  -indev "$release_iso" \
  -extract /bundle/harvester/images-lists "$output_dir/iso-metadata/image-lists"

grep -F 'harvester: v1.8.2' "$output_dir/iso-metadata/harvester-release.yaml"
grep -F 'harvesterChart: 1.8.2' "$output_dir/iso-metadata/harvester-release.yaml"
grep -F 'os: Harvester v1.8.2' "$output_dir/iso-metadata/harvester-release.yaml"
grep -F 'kubernetes: v1.35.7+rke2r1' "$output_dir/iso-metadata/harvester-release.yaml"
grep -F 'rancher: v2.14.3' "$output_dir/iso-metadata/harvester-release.yaml"
grep -F 'kubevirt: 1.7.4-150700.3.24.2' "$output_dir/iso-metadata/harvester-release.yaml"

harvester_image_list="$output_dir/iso-metadata/image-lists/harvester-images-v1.0.txt"
[[ -f "$harvester_image_list" ]]
grep -F 'docker.io/rancher/harvester:v1.8.2' "$harvester_image_list"
grep -F 'docker.io/rancher/harvester-webhook:v1.8.2' "$harvester_image_list"
grep -F 'docker.io/rancher/harvester-upgrade:v1.8.2' "$harvester_image_list"
grep -R -F 'docker.io/longhornio/longhorn-manager:v1.11.2' "$output_dir/iso-metadata/image-lists"

if grep -RE 'rancher/(harvester|harvester-webhook|harvester-upgrade):v1\.8-head|0\.0\.0-v1\.8-[0-9a-f]{8}|Harvester [0-9a-f]{8}' \
  "$output_dir/iso-metadata/image-lists" "$output_dir/iso-metadata/harvester-release.yaml"; then
  echo 'Development Harvester provenance was found in the production ISO candidate' >&2
  exit 1
fi

source_commit=$(tr -d '[:space:]' < "$output_dir/source-commit.txt")
iso_bytes=$(tr -d '[:space:]' < "${release_iso}.bytes")
iso_sha512=$(awk '{print $1}' "${release_iso}.sha512")

cat > "$output_dir/build-manifest.yaml" <<EOF
apiVersion: release.layersentry.io/v1
kind: IsoBuildEvidence
metadata:
  product: LayerSentry
  productVersion: "1.0"
  generatedAtUtc: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
source:
  repository: adaptgurus/harvester-installer
  branch: feat/layersentry-v1.8.2-production
  commit: ${source_commit}
  workflowRunId: ${GITHUB_RUN_ID:-UNAVAILABLE}
  harvesterRef: v1.8.2
  harvesterCommit: 5320dfa6770f63406750e7c64b24ed87c543e6ad
  addonsRef: v1.8.2
  addonsCommit: f60d73d894e00f18d5e11cd21a301ed1b016631c
iso:
  filename: layersentry-v1.0-harvester-v1.8.2-amd64.iso
  bytes: ${iso_bytes}
  sha512: ${iso_sha512}
  classification: BUILD_GOOD
verified:
  checksumGenerated: true
  exactByteCountGenerated: true
  isoVolumeId: COS_LIVE
  elToritoBootMetadataPresent: true
  embeddedReleaseMetadata: true
  releaseImageTags: true
  harvesterDevelopmentRefsAbsent: true
  harvesterRelease: v1.8.2
  harvesterChartRelease: 1.8.2
  rke2Release: v1.35.7+rke2r1
  rancherRelease: v2.14.3
  kubeVirtRelease: 1.7.4-150700.3.24.2
  longhornRelease: v1.11.2
policy:
  fullOfflineIso: true
  netInstallIsoGenerated: false
  bootSmokeGood: false
  installGood: false
  airgapGood: false
  releaseGood: false
EOF

cat "$output_dir/build-manifest.yaml"
find "$output_dir" -maxdepth 4 -type f -printf '%p\t%s bytes\n' | sort

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo '# LayerSentry v1.8.2 production offline ISO'
    echo
    echo '- Classification: `BUILD_GOOD`'
    echo "- Source commit: `${source_commit}`"
    echo "- ISO bytes: `${iso_bytes}`"
    echo "- ISO SHA-512: `${iso_sha512}`"
    echo '- Harvester: `v1.8.2`'
    echo '- RKE2: `v1.35.7+rke2r1`'
    echo '- Rancher: `v2.14.3`'
    echo '- Longhorn: `v1.11.2`'
    echo '- Runtime boot, installation, air-gap and release gates remain pending'
  } >> "$GITHUB_STEP_SUMMARY"
fi
