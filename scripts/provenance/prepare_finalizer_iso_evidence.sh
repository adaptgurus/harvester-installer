#!/usr/bin/env bash
set -Eeuo pipefail

OUTPUT_DIR=${1:?usage: prepare_finalizer_iso_evidence.sh OUTPUT_DIR CANDIDATE_DIR LOCK_FILE BUILD_SOURCE_COMMIT PROVENANCE_COMMIT}
CANDIDATE_DIR=${2:?usage: prepare_finalizer_iso_evidence.sh OUTPUT_DIR CANDIDATE_DIR LOCK_FILE BUILD_SOURCE_COMMIT PROVENANCE_COMMIT}
LOCK_FILE=${3:?usage: prepare_finalizer_iso_evidence.sh OUTPUT_DIR CANDIDATE_DIR LOCK_FILE BUILD_SOURCE_COMMIT PROVENANCE_COMMIT}
BUILD_SOURCE_COMMIT=${4:?usage: prepare_finalizer_iso_evidence.sh OUTPUT_DIR CANDIDATE_DIR LOCK_FILE BUILD_SOURCE_COMMIT PROVENANCE_COMMIT}
PROVENANCE_COMMIT=${5:?usage: prepare_finalizer_iso_evidence.sh OUTPUT_DIR CANDIDATE_DIR LOCK_FILE BUILD_SOURCE_COMMIT PROVENANCE_COMMIT}
TOP_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

[[ $BUILD_SOURCE_COMMIT =~ ^[0-9a-f]{40}$ ]] \
  || fail "build source commit must be exactly 40 lowercase hex characters"
[[ $PROVENANCE_COMMIT =~ ^[0-9a-f]{40}$ ]] \
  || fail "provenance commit must be exactly 40 lowercase hex characters"
[[ $(git -C "$TOP_DIR" rev-parse HEAD) == "$PROVENANCE_COMMIT" ]] \
  || fail "checked-out HEAD is not the completed-lock provenance commit"
git -C "$TOP_DIR" merge-base --is-ancestor "$BUILD_SOURCE_COMMIT" "$PROVENANCE_COMMIT" \
  || fail "build source commit is not an ancestor of provenance commit"
[[ -z $(git -C "$TOP_DIR" status --porcelain --untracked-files=no) ]] \
  || fail "tracked source is dirty after provenance commit"

OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd)
CANDIDATE_DIR=$(cd "$CANDIDATE_DIR" && pwd)
LOCK_FILE=$(cd "$(dirname "$LOCK_FILE")" && pwd)/$(basename "$LOCK_FILE")

release_iso="$OUTPUT_DIR/layersentry-v1.0-harvester-v1.8.2-amd64.iso"
[[ -f "$release_iso" ]] || fail "prepared LayerSentry ISO is missing: $release_iso"
[[ -f "$OUTPUT_DIR/source-commit.txt" ]] || fail "pre-lock ISO source evidence is missing"
[[ $(tr -d '[:space:]' < "$OUTPUT_DIR/source-commit.txt") == "$BUILD_SOURCE_COMMIT" ]] \
  || fail "pre-lock ISO evidence does not identify the exact build source commit"
[[ -f "$CANDIDATE_DIR/offline-image-set-candidate.json" ]] \
  || fail "offline image-set candidate evidence is missing"

python3 "$TOP_DIR/scripts/provenance/verify_lock.py" "$LOCK_FILE" \
  --require-complete \
  --repo-root "$TOP_DIR" \
  --scan-build-inputs \
  --report "$OUTPUT_DIR/completed-provenance-gate-report.json"
python3 "$TOP_DIR/scripts/provenance/verify_offline_image_set_binding.py" \
  --lock "$LOCK_FILE" \
  --repo-root "$TOP_DIR" \
  --report "$OUTPUT_DIR/offline-image-set-binding-report.json"
python3 "$TOP_DIR/scripts/provenance/verify_image_coverage.py" \
  "$LOCK_FILE" "$CANDIDATE_DIR/image-lists" \
  --report "$OUTPUT_DIR/generated-image-list-coverage-report.json"
python3 "$TOP_DIR/scripts/provenance/verify_image_coverage.py" \
  "$LOCK_FILE" "$OUTPUT_DIR/iso-metadata/image-lists" \
  --report "$OUTPUT_DIR/embedded-image-list-coverage-report.json"

actual_iso_sha256=$(sha256sum "$release_iso" | awk '{print $1}')
actual_iso_sha512=$(sha512sum "$release_iso" | awk '{print $1}')
actual_iso_bytes=$(stat -c '%s' "$release_iso")
lock_sha256=$(sha256sum "$LOCK_FILE" | awk '{print $1}')
source_tree=$(git -C "$TOP_DIR" rev-parse "${BUILD_SOURCE_COMMIT}^{tree}")
provenance_tree=$(git -C "$TOP_DIR" rev-parse "${PROVENANCE_COMMIT}^{tree}")

python3 - "$LOCK_FILE" "$BUILD_SOURCE_COMMIT" "$actual_iso_sha256" \
  "$actual_iso_sha512" "$actual_iso_bytes" <<'PY'
import json
import sys
from pathlib import Path

lock_path = Path(sys.argv[1])
build_source_commit, sha256, sha512, size = sys.argv[2:]
lock = json.loads(lock_path.read_text(encoding="utf-8"))
reviewed = lock.get("reviewed_offline_image_set")
if not isinstance(reviewed, dict):
    raise SystemExit("reviewed offline image-set metadata is missing")
if reviewed.get("build_source_commit") != build_source_commit:
    raise SystemExit("completed lock does not identify the ISO build source commit")
iso = reviewed.get("iso_candidate")
expected = {
    "sha256": sha256,
    "sha512": sha512,
    "bytes": int(size),
}
for field, value in expected.items():
    if iso.get(field) != value:
        raise SystemExit(
            f"prepared ISO {field} {value!r} differs from reviewed candidate {iso.get(field)!r}"
        )
if lock.get("lock_status") != "complete" or lock.get("unresolved") != []:
    raise SystemExit("dependency lock is not complete")
PY

cp "$LOCK_FILE" "$OUTPUT_DIR/provenance-lock.json"
mkdir -p "$OUTPUT_DIR/offline-image-set-evidence"
for relative in \
  offline-image-set-candidate.json \
  image-lists-manifest.json \
  iso-metadata.json \
  source-inputs.tsv \
  STATUS.md; do
  [[ -f "$CANDIDATE_DIR/$relative" ]] \
    || fail "candidate evidence file is missing: $relative"
  cp "$CANDIDATE_DIR/$relative" "$OUTPUT_DIR/offline-image-set-evidence/$relative"
done
cp -R "$CANDIDATE_DIR/images" "$OUTPUT_DIR/offline-image-set-evidence/images"
cp -R "$CANDIDATE_DIR/sboms" "$OUTPUT_DIR/offline-image-set-evidence/sboms"

source_snapshot=$(mktemp -d "${RUNNER_TEMP:-/tmp}/layersentry-finalizer-source.XXXXXX")
cleanup() {
  rm -rf "$source_snapshot"
}
trap cleanup EXIT INT TERM
git -C "$TOP_DIR" archive "$BUILD_SOURCE_COMMIT" | tar -xf - -C "$source_snapshot"
SYFT_CHECK_FOR_APP_UPDATE=false syft "$source_snapshot" \
  -o "spdx-json=$OUTPUT_DIR/build-source-sbom.spdx.json"
[[ -s "$OUTPUT_DIR/build-source-sbom.spdx.json" ]] \
  || fail "build-source SBOM is empty"
source_sbom_sha256=$(sha256sum "$OUTPUT_DIR/build-source-sbom.spdx.json" | awk '{print $1}')
source_sbom_bytes=$(stat -c '%s' "$OUTPUT_DIR/build-source-sbom.spdx.json")

python3 - \
  "$LOCK_FILE" \
  "$OUTPUT_DIR/resolved-provenance.json" \
  "$BUILD_SOURCE_COMMIT" \
  "$source_tree" \
  "$PROVENANCE_COMMIT" \
  "$provenance_tree" \
  "$lock_sha256" \
  "$actual_iso_sha256" \
  "$actual_iso_sha512" \
  "$actual_iso_bytes" \
  "$source_sbom_sha256" \
  "$source_sbom_bytes" <<'PY'
import datetime as dt
import json
import os
import sys
from pathlib import Path

(
    lock_raw,
    output_raw,
    build_commit,
    build_tree,
    provenance_commit,
    provenance_tree,
    lock_sha256,
    iso_sha256,
    iso_sha512,
    iso_bytes,
    source_sbom_sha256,
    source_sbom_bytes,
) = sys.argv[1:]
lock = json.loads(Path(lock_raw).read_text(encoding="utf-8"))
reviewed = lock["reviewed_offline_image_set"]
resolved = {
    "schema": "layersentry.finalizer-resolved-provenance/v1",
    "generated_at": dt.datetime.now(dt.timezone.utc)
    .replace(microsecond=0)
    .isoformat()
    .replace("+00:00", "Z"),
    "release_identity": lock["release_identity"],
    "build_source": {
        "repository": lock["product_source"]["repository"],
        "branch": lock["product_source"]["required_branch"],
        "commit": build_commit,
        "tree": build_tree,
    },
    "provenance_source": {
        "commit": provenance_commit,
        "tree": provenance_tree,
        "relationship": "child commit containing reviewed dependency lock and evidence",
    },
    "dependency_lock": {
        "status": lock["lock_status"],
        "unresolved_count": len(lock["unresolved"]),
        "sha256": lock_sha256,
        "file": "provenance-lock.json",
    },
    "generated_images": [
        {
            "id": image["id"],
            "aliases": image["aliases"],
            "ref": image["ref"],
            "config_digest": image["config_digest"],
            "rootfs_diff_ids": image["rootfs_diff_ids"],
            "sbom": image["sbom"],
        }
        for image in reviewed["images"]
    ],
    "iso": {
        "file": "layersentry-v1.0-harvester-v1.8.2-amd64.iso",
        "bytes": int(iso_bytes),
        "sha256": iso_sha256,
        "sha512": iso_sha512,
    },
    "source_sbom": {
        "file": "build-source-sbom.spdx.json",
        "format": "SPDX JSON",
        "bytes": int(source_sbom_bytes),
        "sha256": source_sbom_sha256,
        "input": "git archive of exact ISO build source commit",
    },
    "ci": {
        "repository": os.environ.get("GITHUB_REPOSITORY", "UNAVAILABLE"),
        "workflow": os.environ.get("GITHUB_WORKFLOW", "UNAVAILABLE"),
        "run_id": os.environ.get("GITHUB_RUN_ID", "UNAVAILABLE"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "UNAVAILABLE"),
    },
    "classification": "BUILD_CANDIDATE_ONLY",
    "dependency_lock_complete": True,
    "installation_qualified": False,
    "runtime_qualified": False,
    "airgap_qualified": False,
    "release_approved": False,
    "remaining_runtime_gates": [
        "Hyper-V boot smoke",
        "three-node installation",
        "cluster readiness",
        "storage and VM workload smoke",
        "true air-gap validation",
        "upgrade",
        "backup and restore",
        "HA and recovery",
    ],
}
Path(output_raw).write_text(
    json.dumps(resolved, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

cat > "$OUTPUT_DIR/artifact-digests.json" <<EOF_JSON
{
  "schema": "layersentry.finalizer-artifact-digests/v1",
  "artifact": "layersentry-v1.0-harvester-v1.8.2-amd64.iso",
  "bytes": ${actual_iso_bytes},
  "sha256": "${actual_iso_sha256}",
  "sha512": "${actual_iso_sha512}",
  "build_source_commit": "${BUILD_SOURCE_COMMIT}",
  "build_source_tree": "${source_tree}",
  "provenance_commit": "${PROVENANCE_COMMIT}",
  "provenance_tree": "${provenance_tree}",
  "provenance_lock_sha256": "${lock_sha256}",
  "build_source_sbom_sha256": "${source_sbom_sha256}",
  "dependency_lock_complete": true,
  "release_approved": false
}
EOF_JSON

printf '%s\n' "$BUILD_SOURCE_COMMIT" > "$OUTPUT_DIR/build-source-commit.txt"
printf '%s\n' "$PROVENANCE_COMMIT" > "$OUTPUT_DIR/provenance-commit.txt"
printf '%s\n' "$lock_sha256" > "$OUTPUT_DIR/provenance-lock.sha256"

(
  cd "$OUTPUT_DIR"
  find . -type f ! -name evidence-manifest.sha256 -print0 \
    | sort -z \
    | xargs -0 sha256sum > evidence-manifest.sha256
  sha256sum -c evidence-manifest.sha256
)

echo "FINALIZER ISO EVIDENCE: PASS"
echo "build_source_commit=$BUILD_SOURCE_COMMIT"
echo "provenance_commit=$PROVENANCE_COMMIT"
echo "iso_sha256=$actual_iso_sha256"
echo "dependency_lock_complete=true"
echo "release_approved=false"
