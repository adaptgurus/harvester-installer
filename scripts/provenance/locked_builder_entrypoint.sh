#!/usr/bin/env bash
set -Eeuo pipefail

workspace=${LAYERSENTRY_WORKSPACE:-/go/src/github.com/harvester/harvester-installer}
start_daemon=${LAYERSENTRY_START_DOCKER_DAEMON:-true}
host_uid=${LAYERSENTRY_HOST_UID:-${DAPPER_UID:-}}
host_gid=${LAYERSENTRY_HOST_GID:-${DAPPER_GID:-}}
dockerd_log=${LAYERSENTRY_DOCKERD_LOG:-/tmp/layersentry-dockerd.log}
dockerd_pid=

fail() {
  echo "ERROR: $*" >&2
  if [[ -s "$dockerd_log" ]]; then
    echo "--- dockerd log ---" >&2
    tail -200 "$dockerd_log" >&2 || true
  fi
  exit 1
}

cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ -n "$dockerd_pid" ]] && kill -0 "$dockerd_pid" 2>/dev/null; then
    kill "$dockerd_pid" 2>/dev/null || true
    wait "$dockerd_pid" 2>/dev/null || true
  fi
  if [[ -n "$host_uid" && -n "$host_gid" && -d "$workspace" ]]; then
    chown -R "$host_uid:$host_gid" "$workspace" 2>/dev/null || true
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

[[ -d "$workspace" ]] || fail "workspace does not exist: $workspace"
mkdir -p "${RUNNER_TEMP:-/tmp}"
cd "$workspace"
git config --global --add safe.directory "$workspace"

if [[ $# -eq 0 ]]; then
  set -- ./scripts/default
elif [[ -f "./scripts/$1" ]]; then
  script=$1
  shift
  set -- "./scripts/$script" "$@"
fi

if [[ "$start_daemon" == "true" ]]; then
  command -v dockerd >/dev/null 2>&1 || fail "dockerd is missing from locked builder image"
  command -v docker >/dev/null 2>&1 || fail "docker client is missing from locked builder image"
  mkdir -p /run/layersentry-docker /var/lib/docker
  rm -f /run/layersentry-docker/docker.pid "$dockerd_log" /var/run/docker.sock
  dockerd \
    --host=unix:///var/run/docker.sock \
    --data-root=/var/lib/docker \
    --exec-root=/run/layersentry-docker \
    --pidfile=/run/layersentry-docker/docker.pid \
    --storage-driver="${LAYERSENTRY_DOCKER_STORAGE_DRIVER:-overlay2}" \
    >"$dockerd_log" 2>&1 &
  dockerd_pid=$!

  ready=false
  for _ in $(seq 1 90); do
    if docker info >/dev/null 2>&1; then
      ready=true
      break
    fi
    if ! kill -0 "$dockerd_pid" 2>/dev/null; then
      break
    fi
    sleep 1
  done
  [[ "$ready" == "true" ]] || fail "locked internal Docker daemon did not become ready"

  docker version
  docker buildx version
  export DOCKER_BUILDKIT=1
fi

"$@"
