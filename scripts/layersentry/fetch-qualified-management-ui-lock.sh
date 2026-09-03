#!/usr/bin/env bash
set -euo pipefail

SOURCE_URL="${LAYERSENTRY_UI_LOCK_URL:-https://raw.githubusercontent.com/adaptgurus/harvester-ui-extension/release-layersentry-v1.8.2/docs/build-evidence/layersentry-management-server-v1.8.2.lock}"
OUTPUT="${1:-build/locks/layersentry-management-server-v1.8.2.lock}"
MAX_ATTEMPTS="${LAYERSENTRY_UI_LOCK_MAX_ATTEMPTS:-30}"
SLEEP_SECONDS="${LAYERSENTRY_UI_LOCK_SLEEP_SECONDS:-120}"

mkdir -p "$(dirname "$OUTPUT")"
temporary="${OUTPUT}.tmp"
trap 'rm -f "$temporary"' EXIT

for ((attempt = 1; attempt <= MAX_ATTEMPTS; attempt++)); do
  if curl --fail --silent --show-error --location \
    --connect-timeout 20 \
    --max-time 60 \
    "$SOURCE_URL" \
    --output "$temporary"; then
    break
  fi

  if ((attempt == MAX_ATTEMPTS)); then
    echo "Qualified LayerSentry management UI lock was not available after ${MAX_ATTEMPTS} attempts." >&2
    exit 1
  fi

  echo "Qualified UI lock is not available yet; retrying in ${SLEEP_SECONDS}s (${attempt}/${MAX_ATTEMPTS})."
  sleep "$SLEEP_SECONDS"
done

required_keys=(
  product
  compatibility_base
  source_commit
  qualification_workflow_run
  immutable_image
  tracking_image
  digest_reference
)

for key in "${required_keys[@]}"; do
  if ! grep --quiet --extended-regexp "^${key}=.+$" "$temporary"; then
    echo "Required lock key is missing or empty: ${key}" >&2
    exit 1
  fi
done

product="$(sed -n 's/^product=//p' "$temporary")"
compatibility_base="$(sed -n 's/^compatibility_base=//p' "$temporary")"
source_commit="$(sed -n 's/^source_commit=//p' "$temporary")"
immutable_image="$(sed -n 's/^immutable_image=//p' "$temporary")"
digest_reference="$(sed -n 's/^digest_reference=//p' "$temporary")"

[[ "$product" == "LayerSentry" ]] || {
  echo "Unexpected product in UI image lock: ${product}" >&2
  exit 1
}
[[ "$compatibility_base" == "rancher/harvester:v1.8.2" ]] || {
  echo "Unexpected compatibility base: ${compatibility_base}" >&2
  exit 1
}
[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]] || {
  echo "Invalid UI source commit: ${source_commit}" >&2
  exit 1
}
[[ "$immutable_image" =~ ^ghcr\.io/adaptgurus/layersentry-harvester:v1\.8\.2-ui-[0-9a-f]{12}$ ]] || {
  echo "Invalid immutable image reference: ${immutable_image}" >&2
  exit 1
}
[[ "$digest_reference" =~ ^ghcr\.io/adaptgurus/layersentry-harvester@sha256:[0-9a-f]{64}$ ]] || {
  echo "Invalid digest reference: ${digest_reference}" >&2
  exit 1
}
[[ "$immutable_image" == *"${source_commit:0:12}" ]] || {
  echo "Immutable image tag does not match source commit." >&2
  exit 1
}

mv "$temporary" "$OUTPUT"
trap - EXIT
printf 'Qualified LayerSentry management UI lock: %s\n' "$OUTPUT"
