#!/usr/bin/env bash
set -Eeuo pipefail

artifacts_dir=${1:?usage: prepare-release-evidence.sh ARTIFACTS_DIR OUTPUT_DIR [LOCK_FILE]}
output_dir=${2:?usage: prepare-release-evidence.sh ARTIFACTS_DIR OUTPUT_DIR [LOCK_FILE]}

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
lock_file=${3:-"${root_dir}/provenance/layersentry-v1.0-harvester-v1.8.2.lock.json"}
verifier="${root_dir}/scripts/provenance/verify_lock.py"
coverage_verifier="${root_dir}/scripts/provenance/verify_image_coverage.py"

mkdir -p "$output_dir"

# The fast gate is deliberately repeated in the build job. This prevents a
# changed checkout, lock, or build script from bypassing the earlier CI job.
python3 "$verifier" "$lock_file" \
  --require-complete \
  --repo-root "$root_dir" \
  --scan-build-inputs \
  --report "$output_dir/provenance-gate-report.json"

if [[ -n "$(git -C "$root_dir" status --porcelain --untracked-files=no)" ]]; then
  echo "Tracked source is dirty; production evidence cannot be generated" >&2
  git -C "$root_dir" status --short >&2
  exit 1
fi

bash "$root_dir/scripts/prepare-production-iso-evidence.sh" "$artifacts_dir" "$output_dir"

image_lists_dir="$output_dir/iso-metadata/image-lists"
python3 "$coverage_verifier" "$lock_file" "$image_lists_dir" \
  --report "$output_dir/image-digest-coverage-report.json"

release_iso="$output_dir/layersentry-v1.0-harvester-v1.8.2-amd64.iso"
[[ -f "$release_iso" ]]

source_commit=$(git -C "$root_dir" rev-parse HEAD)
source_tree=$(git -C "$root_dir" write-tree)
lock_sha256=$(sha256sum "$lock_file" | awk '{print $1}')
iso_sha256=$(sha256sum "$release_iso" | awk '{print $1}')
iso_sha512=$(sha512sum "$release_iso" | awk '{print $1}')
iso_bytes=$(stat -c '%s' "$release_iso")
source_date_epoch=$(git -C "$root_dir" show -s --format=%ct HEAD)

cp "$lock_file" "$output_dir/provenance-lock.json"

python3 - "$root_dir" "$lock_file" "$output_dir/resolved-provenance.json" <<'PY'
import datetime as dt
import hashlib
import json
import os
import pathlib
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
lock_path = pathlib.Path(sys.argv[2])
out_path = pathlib.Path(sys.argv[3])
lock_bytes = lock_path.read_bytes()
lock = json.loads(lock_bytes)

def git(*args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()

source_commit = git("rev-parse", "HEAD")
source_tree = git("write-tree")
resolved = {
    "schema": "layersentry.resolved-provenance/v1",
    "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "release_identity": lock["release_identity"],
    "product_source": {
        "repository": lock["product_source"]["repository"],
        "branch": os.environ.get("GITHUB_REF_NAME", lock["product_source"]["required_branch"]),
        "commit": source_commit,
        "tree": source_tree,
        "audited_corrective_base_commit": lock["product_source"]["audited_corrective_base_commit"],
    },
    "dependency_lock": {
        "file": "provenance-lock.json",
        "sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "status": lock["lock_status"],
    },
    "source_locks": lock["source_locks"],
    "ci": {
        "repository": os.environ.get("GITHUB_REPOSITORY", "UNAVAILABLE"),
        "workflow": os.environ.get("GITHUB_WORKFLOW", "UNAVAILABLE"),
        "run_id": os.environ.get("GITHUB_RUN_ID", "UNAVAILABLE"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "UNAVAILABLE"),
        "actor": os.environ.get("GITHUB_ACTOR", "UNAVAILABLE"),
    },
    "classification": "BUILD_CANDIDATE_ONLY",
    "promotion_eligible": False,
    "remaining_runtime_gates": [
        "boot-smoke",
        "installation",
        "true-air-gap",
        "upgrade",
        "backup-restore",
        "recovery",
        "source-build-provenance-deployment-sha-equality",
    ],
}
out_path.write_text(json.dumps(resolved, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

cat > "$output_dir/artifact-digests.json" <<EOF
{
  "schema": "layersentry.artifact-digests/v1",
  "artifact": "layersentry-v1.0-harvester-v1.8.2-amd64.iso",
  "bytes": ${iso_bytes},
  "sha256": "${iso_sha256}",
  "sha512": "${iso_sha512}",
  "source_commit": "${source_commit}",
  "source_tree": "${source_tree}",
  "source_date_epoch": ${source_date_epoch},
  "provenance_lock_sha256": "${lock_sha256}"
}
EOF

printf '%s\n' "$source_commit" > "$output_dir/final-tested-source-commit.txt"
printf '%s\n' "$lock_sha256" > "$output_dir/provenance-lock.sha256"

# Evidence manifest. The manifest itself is intentionally excluded to avoid a
# self-referential checksum.
(
  cd "$output_dir"
  find . -type f ! -name evidence-manifest.sha256 -print0 \
    | sort -z \
    | xargs -0 sha256sum > evidence-manifest.sha256
  sha256sum -c evidence-manifest.sha256
)

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo '# LayerSentry v1.0 / embedded Harvester v1.8.2'
    echo
    echo '- Provenance lock: `PASS`'
    echo "- Source commit: \`${source_commit}\`"
    echo "- Source tree: \`${source_tree}\`"
    echo "- ISO SHA-256: \`${iso_sha256}\`"
    echo "- ISO SHA-512: \`${iso_sha512}\`"
    echo '- Classification: `BUILD_CANDIDATE_ONLY`'
    echo '- Promotion remains prohibited until runtime and SHA-equality gates pass.'
  } >> "$GITHUB_STEP_SUMMARY"
fi

printf 'Prepared fail-closed build evidence in %s\n' "$output_dir"
