#!/usr/bin/env bash
set -Eeuo pipefail

TOP_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
LOCK_FILE=${LAYERSENTRY_LOCK_FILE:-"$TOP_DIR/provenance/layersentry-v1.0-harvester-v1.8.2.lock.json"}
start_daemon=true
if [[ ${1:-} == "--no-daemon" ]]; then
  start_daemon=false
  shift
fi
if [[ $# -eq 0 ]]; then
  set -- ./scripts/default
fi

for command in docker python3 git; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "ERROR: required host launcher command is missing: $command" >&2
    exit 1
  }
done

builder_ref=$(python3 - "$LOCK_FILE" <<'PY'
import json
import re
import sys
from pathlib import Path

lock = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
matches = [
    item
    for item in lock.get("container_images", [])
    if item.get("id") == "layersentry-full-offline-builder"
]
if len(matches) != 1:
    raise SystemExit("provenance lock must contain exactly one LayerSentry builder image")
ref = str(matches[0].get("ref", ""))
if not re.fullmatch(
    r"ghcr\.io/adaptgurus/layersentry-full-offline-builder@sha256:[0-9a-f]{64}",
    ref,
):
    raise SystemExit(f"builder image is not an approved immutable GHCR digest: {ref!r}")
print(ref)
PY
)

case ${LAYERSENTRY_BUILDER_PULL:-always} in
  always)
    docker pull --platform linux/amd64 "$builder_ref" >/dev/null
    ;;
  never)
    docker image inspect "$builder_ref" >/dev/null
    ;;
  *)
    echo "ERROR: LAYERSENTRY_BUILDER_PULL must be 'always' or 'never'" >&2
    exit 1
    ;;
esac

python3 - "$builder_ref" <<'PY'
import json
import subprocess
import sys

ref = sys.argv[1]
values = json.loads(
    subprocess.check_output(["docker", "image", "inspect", ref], text=True)
)
if len(values) != 1:
    raise SystemExit("docker image inspect did not return one builder image")
item = values[0]
if item.get("Os") != "linux" or item.get("Architecture") != "amd64":
    raise SystemExit(
        f"builder platform mismatch: {item.get('Os')}/{item.get('Architecture')}"
    )
digest = ref.split("@", 1)[1]
if not any(str(value).endswith(digest) for value in item.get("RepoDigests") or []):
    raise SystemExit("local builder image is not bound to the requested digest")
entrypoint = item.get("Config", {}).get("Entrypoint") or []
if entrypoint != ["/usr/local/bin/layersentry-builder-entrypoint"]:
    raise SystemExit(f"builder image has unexpected entrypoint: {entrypoint!r}")
PY

workspace=/go/src/github.com/harvester/harvester-installer
runner_temp=/tmp/layersentry-runner
docker_args=(
  run --rm
  --platform linux/amd64
  --shm-size 2g
  --ulimit nofile=1048576:1048576
  -e "LAYERSENTRY_WORKSPACE=$workspace"
  -e "LAYERSENTRY_START_DOCKER_DAEMON=$start_daemon"
  -e "LAYERSENTRY_HOST_UID=$(id -u)"
  -e "LAYERSENTRY_HOST_GID=$(id -g)"
  -e "LAYERSENTRY_DOCKER_STORAGE_DRIVER=${LAYERSENTRY_DOCKER_STORAGE_DRIVER:-overlay2}"
  -e "ARCH=amd64"
  -e "HOME=/root"
  -e "DOCKER_BUILDKIT=1"
  -e "GITHUB_WORKSPACE=$workspace"
  -e "RUNNER_TEMP=$runner_temp"
  -v "$TOP_DIR:$workspace"
  -v "layersentry-builder-go-cache:/root/go"
  -v "layersentry-builder-cache:/root/.cache"
  -w "$workspace"
)

if [[ "$start_daemon" == "true" ]]; then
  docker_args+=(
    --privileged
    -v "layersentry-builder-docker-${GITHUB_RUN_ID:-local}:/var/lib/docker"
  )
fi

for variable in \
  GITHUB_ACTIONS GITHUB_ACTOR GITHUB_EVENT_NAME GITHUB_REF_NAME \
  GITHUB_REPOSITORY GITHUB_RUN_ATTEMPT GITHUB_RUN_ID GITHUB_SHA \
  GITHUB_WORKFLOW SOURCE_DATE_EPOCH DRONE_TAG DRONE_BRANCH BUILD_QCOW \
  DISABLE_BUILD_NET_INSTALL_ISO SYFT_CHECK_FOR_APP_UPDATE REPO TAG CROSS \
  RKE2_IMAGE_REPO USE_LOCAL_IMAGES DRONE_BUILD_EVENT REMOTE_DEBUG; do
  if [[ -n ${!variable:-} ]]; then
    docker_args+=(-e "$variable=${!variable}")
  fi
done

exec docker "${docker_args[@]}" "$builder_ref" "$@"
