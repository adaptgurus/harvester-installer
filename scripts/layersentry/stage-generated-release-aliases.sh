#!/usr/bin/env bash
set -Eeuo pipefail

TOP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPTS_DIR="$TOP_DIR/scripts"

# Release aliases are only meaningful for the LayerSentry v1.0 release lane.
[[ ${DRONE_TAG:-} == v1.0 ]] || exit 0
[[ ${DRONE_BRANCH:-} == layersentry-v1.0-dev ]] || exit 0

# shellcheck disable=SC1091
source "$SCRIPTS_DIR/version"
[[ -n ${VERSION:-} ]]

for component in harvester-cluster-repo harvester-installer harvester-os; do
  source_ref="docker.io/rancher/${component}:${VERSION}"
  release_ref="docker.io/rancher/${component}:v1.0"
  docker image inspect "$source_ref" >/dev/null
  source_id=$(docker image inspect "$source_ref" --format '{{.Id}}')
  docker tag "$source_ref" "$release_ref"
  release_id=$(docker image inspect "$release_ref" --format '{{.Id}}')
  if [[ $source_id != "$release_id" ]]; then
    echo "ERROR: generated release alias identity mismatch for $component" >&2
    exit 1
  fi
  echo "LayerSentry generated image alias staged: $release_ref ($release_id)"
done

echo "LAYERSENTRY GENERATED RELEASE ALIASES: PASS"
