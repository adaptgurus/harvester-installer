#!/usr/bin/env bash
set -euo pipefail

candidate_dir=${1:?usage: qualify-production-iso-evidence.sh CANDIDATE_DIR OUTPUT_DIR}
output_dir=${2:?usage: qualify-production-iso-evidence.sh CANDIDATE_DIR OUTPUT_DIR}

: "${SOURCE_RUN_ID:?SOURCE_RUN_ID is required}"
: "${SOURCE_ARTIFACT_NAME:?SOURCE_ARTIFACT_NAME is required}"
: "${EXPECTED_SOURCE_COMMIT:?EXPECTED_SOURCE_COMMIT is required}"
: "${EXPECTED_ARTIFACT_ID:?EXPECTED_ARTIFACT_ID is required}"
: "${EXPECTED_ARTIFACT_SHA256:?EXPECTED_ARTIFACT_SHA256 is required}"

mkdir -p "$output_dir"

iso=$(find "$candidate_dir" -type f -name 'layersentry-v1.0-harvester-v1.8.2-amd64.iso' -print -quit)
checksum_file=$(find "$candidate_dir" -type f -name 'layersentry-v1.0-harvester-v1.8.2-amd64.iso.sha512' -print -quit)
bytes_file=$(find "$candidate_dir" -type f -name 'layersentry-v1.0-harvester-v1.8.2-amd64.iso.bytes' -print -quit)
manifest=$(find "$candidate_dir" -type f -name 'build-manifest.yaml' -print -quit)
source_commit_file=$(find "$candidate_dir" -type f -name 'source-commit.txt' -print -quit)
packaged_release_metadata=$(find "$candidate_dir" -type f -path '*/iso-metadata/harvester-release.yaml' -print -quit)

for required in "$iso" "$checksum_file" "$bytes_file" "$manifest" "$source_commit_file" "$packaged_release_metadata"; do
  if [[ -z "$required" || ! -f "$required" ]]; then
    echo "Required production evidence file is missing: $required" >&2
    find "$candidate_dir" -maxdepth 4 -type f -printf '%p\n' | sort >&2
    exit 1
  fi
done

expected_sha512=$(awk '{print $1}' "$checksum_file")
actual_sha512=$(sha512sum "$iso" | awk '{print $1}')
[[ -n "$expected_sha512" ]]
[[ "$actual_sha512" == "$expected_sha512" ]]

expected_bytes=$(tr -d '[:space:]' < "$bytes_file")
actual_bytes=$(stat -c '%s' "$iso")
[[ -n "$expected_bytes" ]]
[[ "$actual_bytes" == "$expected_bytes" ]]

source_commit=$(tr -d '[:space:]' < "$source_commit_file")
[[ "$source_commit" == "$EXPECTED_SOURCE_COMMIT" ]]
grep -F "commit: $EXPECTED_SOURCE_COMMIT" "$manifest"
grep -F 'harvesterRef: v1.8.2' "$manifest"
grep -F 'harvesterCommit: 5320dfa6770f63406750e7c64b24ed87c543e6ad' "$manifest"
grep -F 'addonsRef: v1.8.2' "$manifest"
grep -F 'addonsCommit: f60d73d894e00f18d5e11cd21a301ed1b016631c' "$manifest"
grep -F 'fullOfflineIso: true' "$manifest"
grep -F 'netInstallIsoGenerated: false' "$manifest"
grep -F 'installGood: false' "$manifest"
grep -F 'airgapGood: false' "$manifest"
grep -F 'releaseGood: false' "$manifest"

xorriso -indev "$iso" -toc > "$output_dir/iso-toc.txt" 2>&1
xorriso -indev "$iso" -report_el_torito plain > "$output_dir/el-torito-layout.txt" 2>&1
grep -F "Volume id    : 'COS_LIVE'" "$output_dir/iso-toc.txt"
grep -F 'El Torito' "$output_dir/el-torito-layout.txt"

xorriso -osirrox on \
  -indev "$iso" \
  -extract /harvester-release.yaml "$output_dir/harvester-release.from-iso.yaml"

xorriso -osirrox on \
  -indev "$iso" \
  -extract /bundle/harvester/images-lists "$output_dir/image-lists"

cmp -s "$packaged_release_metadata" "$output_dir/harvester-release.from-iso.yaml"

grep -F 'harvester: v1.8.2' "$output_dir/harvester-release.from-iso.yaml"
grep -F 'harvesterChart: 1.8.2' "$output_dir/harvester-release.from-iso.yaml"
grep -F 'os: Harvester v1.8.2' "$output_dir/harvester-release.from-iso.yaml"
grep -F 'kubernetes: v1.35.7+rke2r1' "$output_dir/harvester-release.from-iso.yaml"
grep -F 'rancher: v2.14.3' "$output_dir/harvester-release.from-iso.yaml"
grep -F 'kubevirt: 1.7.4-150700.3.24.2' "$output_dir/harvester-release.from-iso.yaml"

harvester_image_list="$output_dir/image-lists/harvester-images-v1.0.txt"
[[ -f "$harvester_image_list" ]]
grep -F 'docker.io/rancher/harvester:v1.8.2' "$harvester_image_list"
grep -F 'docker.io/rancher/harvester-webhook:v1.8.2' "$harvester_image_list"
grep -F 'docker.io/rancher/harvester-upgrade:v1.8.2' "$harvester_image_list"
grep -R -F 'docker.io/longhornio/longhorn-manager:v1.11.2' "$output_dir/image-lists"

if grep -RE 'rancher/(harvester|harvester-webhook|harvester-upgrade):v1\.8-head|0\.0\.0-v1\.8-[0-9a-f]{8}|Harvester [0-9a-f]{8}' \
  "$output_dir/image-lists" "$output_dir/harvester-release.from-iso.yaml"; then
  echo 'Development Harvester provenance was found in the production ISO candidate' >&2
  exit 1
fi

cp "$checksum_file" "$output_dir/"
cp "$bytes_file" "$output_dir/"
cp "$manifest" "$output_dir/original-build-manifest.yaml"
cp "$source_commit_file" "$output_dir/"
cp "$packaged_release_metadata" "$output_dir/harvester-release.packaged.yaml"

cat > "$output_dir/build-qualification.yaml" <<EOF
apiVersion: release.layersentry.io/v1
kind: IsoBuildQualification
metadata:
  product: LayerSentry
  productVersion: "1.0"
  qualifiedAtUtc: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sourceBuild:
  workflowRunId: ${SOURCE_RUN_ID}
  artifactId: ${EXPECTED_ARTIFACT_ID}
  artifactName: ${SOURCE_ARTIFACT_NAME}
  artifactDigestSha256: ${EXPECTED_ARTIFACT_SHA256}
  sourceCommit: ${source_commit}
iso:
  filename: layersentry-v1.0-harvester-v1.8.2-amd64.iso
  bytes: ${actual_bytes}
  sha512: ${actual_sha512}
  classification: BUILD_GOOD
verified:
  checksumMatches: true
  byteCountMatches: true
  isoVolumeId: COS_LIVE
  elToritoBootMetadataPresent: true
  embeddedReleaseMetadataMatchesPackagedEvidence: true
  harvesterRelease: v1.8.2
  harvesterChartRelease: 1.8.2
  rke2Release: v1.35.7+rke2r1
  rancherRelease: v2.14.3
  kubeVirtRelease: 1.7.4-150700.3.24.2
  longhornRelease: v1.11.2
  harvesterDevelopmentRefsAbsent: true
  fullOfflineIso: true
  netInstallIsoGenerated: false
remainingGates:
  bootSmokeGood: false
  installGood: false
  airgapGood: false
  releaseGood: false
EOF

cat > "$output_dir/README.md" <<EOF
# LayerSentry v1.0 / Harvester v1.8.2 build evidence

This package independently validates the successful production ISO candidate from GitHub Actions run ${SOURCE_RUN_ID}.

Classification: **BUILD_GOOD** only.

This does not claim runtime boot-smoke, installation, true-air-gap, upgrade, recovery, or production release qualification.
EOF

cat "$output_dir/build-qualification.yaml"
find "$output_dir" -maxdepth 3 -type f -printf '%p\t%s bytes\n' | sort

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo '# LayerSentry production ISO build qualification'
    echo
    echo '- Classification: `BUILD_GOOD`'
    echo "- Source run: `${SOURCE_RUN_ID}`"
    echo "- Source commit: `${source_commit}`"
    echo "- ISO bytes: `${actual_bytes}`"
    echo "- ISO SHA-512: `${actual_sha512}`"
    echo '- Harvester: `v1.8.2`'
    echo '- RKE2: `v1.35.7+rke2r1`'
    echo '- Rancher: `v2.14.3`'
    echo '- Longhorn: `v1.11.2`'
    echo '- Development Harvester refs: absent'
    echo '- Runtime boot, installation, air-gap, recovery and release gates remain pending'
  } >> "$GITHUB_STEP_SUMMARY"
fi
