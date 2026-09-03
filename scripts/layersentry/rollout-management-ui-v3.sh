#!/usr/bin/env bash
set -Eeuo pipefail

NAMESPACE="${LAYERSENTRY_MANAGEMENT_NAMESPACE:-harvester-system}"
LOCK_FILE="${LAYERSENTRY_UI_LOCK_FILE:-build/locks/layersentry-management-server-v1.8.2-v3.lock}"
DASHBOARD_URL="${LAYERSENTRY_DASHBOARD_URL:-}"
ROLLOUT_TIMEOUT="${LAYERSENTRY_ROLLOUT_TIMEOUT:-15m}"
APPLY=false
EVIDENCE_DIR="${LAYERSENTRY_UI_EVIDENCE_DIR:-build/runtime-evidence}"

usage() {
  cat <<'EOF'
Usage:
  rollout-management-ui-v3.sh [--lock PATH] [--url HTTPS_URL] [--namespace NS] [--apply]

Without --apply, the script performs discovery and server-side dry-run validation
only. With --apply, it updates the discovered management container to the
qualified LayerSentry v3 digest, waits for rollout, verifies browser markers,
and restores the previous image automatically if any apply-time check fails.
EOF
}

while (($#)); do
  case "$1" in
    --lock)
      LOCK_FILE="$2"
      shift 2
      ;;
    --url)
      DASHBOARD_URL="$2"
      shift 2
      ;;
    --namespace)
      NAMESPACE="$2"
      shift 2
      ;;
    --apply)
      APPLY=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 64
      ;;
  esac
done

for command in kubectl python3; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "Required command is not available: ${command}" >&2
    exit 1
  }
done

[[ -s "$LOCK_FILE" ]] || {
  echo "Qualified LayerSentry v3 image lock is missing: ${LOCK_FILE}" >&2
  exit 1
}

declare -A lock
while IFS='=' read -r key value; do
  [[ -n "$key" ]] || continue
  lock["$key"]="$value"
done < "$LOCK_FILE"

[[ "${lock[product]:-}" == "LayerSentry" ]] || {
  echo "Unexpected product in lock." >&2
  exit 1
}
[[ "${lock[qualification_contract]:-}" == "v3" ]] || {
  echo "Only a qualification_contract=v3 image may be rolled out." >&2
  exit 1
}
[[ "${lock[source_commit]:-}" =~ ^[0-9a-f]{40}$ ]] || {
  echo "Invalid source commit in lock." >&2
  exit 1
}
[[ "${lock[digest_reference]:-}" =~ ^ghcr\.io/adaptgurus/layersentry-harvester@sha256:[0-9a-f]{64}$ ]] || {
  echo "Invalid digest reference in lock." >&2
  exit 1
}

SOURCE_SHA="${lock[source_commit]}"
QUALIFICATION_RUN="${lock[qualification_workflow_run]}"
TARGET_IMAGE="${lock[digest_reference]}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${EVIDENCE_DIR}/${TIMESTAMP}"
mkdir -p "$RUN_DIR"

kubectl version --client=true -o yaml > "$RUN_DIR/kubectl-client.yaml"
kubectl cluster-info > "$RUN_DIR/cluster-info.txt"
kubectl get namespace "$NAMESPACE" -o yaml > "$RUN_DIR/namespace.yaml"
kubectl -n "$NAMESPACE" get deployments -o json > "$RUN_DIR/deployments-before.json"

readarray -t target < <(
  python3 - "$RUN_DIR/deployments-before.json" <<'PY'
import json, pathlib, sys
payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
found = []
for deployment in payload.get("items", []):
    name = deployment.get("metadata", {}).get("name", "")
    for container in deployment.get("spec", {}).get("template", {}).get("spec", {}).get("containers", []):
        cname = container.get("name", "")
        image = container.get("image", "")
        score = 0
        if cname == "harvester":
            score += 100
        if name == "harvester":
            score += 80
        if "rancher/harvester" in image or "layersentry-harvester" in image:
            score += 60
        if "webhook" in name or "webhook" in cname:
            score -= 200
        if score > 0:
            found.append((score, name, cname, image))
found.sort(reverse=True)
if not found:
    raise SystemExit("No Harvester-compatible management deployment container was discovered.")
best_score = found[0][0]
best = [item for item in found if item[0] == best_score]
if len(best) != 1:
    raise SystemExit(f"Management deployment discovery is ambiguous: {best}")
_, deployment, container, image = best[0]
print(deployment)
print(container)
print(image)
PY
)

[[ ${#target[@]} -eq 3 ]] || {
  echo "Management deployment discovery returned an invalid result." >&2
  exit 1
}

DEPLOYMENT="${target[0]}"
CONTAINER="${target[1]}"
PREVIOUS_IMAGE="${target[2]}"

cat > "$RUN_DIR/selection.txt" <<EOF
namespace=${NAMESPACE}
deployment=${DEPLOYMENT}
container=${CONTAINER}
previous_image=${PREVIOUS_IMAGE}
target_image=${TARGET_IMAGE}
source_commit=${SOURCE_SHA}
qualification_workflow_run=${QUALIFICATION_RUN}
apply=${APPLY}
EOF

kubectl -n "$NAMESPACE" set image \
  "deployment/${DEPLOYMENT}" \
  "${CONTAINER}=${TARGET_IMAGE}" \
  --dry-run=server \
  -o yaml > "$RUN_DIR/server-dry-run.yaml"

if [[ "$APPLY" != true ]]; then
  echo "LayerSentry v3 management UI rollout dry-run: PASS"
  echo "Evidence: ${RUN_DIR}"
  echo "Re-run with --apply after the digest image is available to every cluster node."
  exit 0
fi

rollback_required=true
rollback() {
  rc=$?

  if [[ "$rollback_required" == true ]]; then
    echo "LayerSentry UI validation failed; restoring ${PREVIOUS_IMAGE}." >&2
    kubectl -n "$NAMESPACE" set image \
      "deployment/${DEPLOYMENT}" \
      "${CONTAINER}=${PREVIOUS_IMAGE}" || true
    kubectl -n "$NAMESPACE" rollout status \
      "deployment/${DEPLOYMENT}" \
      --timeout="$ROLLOUT_TIMEOUT" || true
    kubectl -n "$NAMESPACE" get deployment "$DEPLOYMENT" -o yaml > \
      "$RUN_DIR/deployment-after-rollback.yaml" || true
  fi

  exit "$rc"
}
trap rollback ERR

kubectl -n "$NAMESPACE" get deployment "$DEPLOYMENT" -o yaml > \
  "$RUN_DIR/deployment-before.yaml"

kubectl -n "$NAMESPACE" set image \
  "deployment/${DEPLOYMENT}" \
  "${CONTAINER}=${TARGET_IMAGE}"

kubectl -n "$NAMESPACE" annotate deployment "$DEPLOYMENT" \
  io.layersentry.ui.source-commit="$SOURCE_SHA" \
  io.layersentry.ui.qualification-run="$QUALIFICATION_RUN" \
  io.layersentry.ui.qualification-contract=v3 \
  --overwrite

kubectl -n "$NAMESPACE" rollout status \
  "deployment/${DEPLOYMENT}" \
  --timeout="$ROLLOUT_TIMEOUT"

kubectl -n "$NAMESPACE" wait \
  --for=condition=Available \
  "deployment/${DEPLOYMENT}" \
  --timeout="$ROLLOUT_TIMEOUT"

kubectl -n "$NAMESPACE" get deployment "$DEPLOYMENT" -o yaml > \
  "$RUN_DIR/deployment-after.yaml"
kubectl -n "$NAMESPACE" get pods -o wide > "$RUN_DIR/pods-after.txt"
kubectl -n "$NAMESPACE" get events --sort-by=.lastTimestamp > "$RUN_DIR/events-after.txt"

actual_image="$(kubectl -n "$NAMESPACE" get deployment "$DEPLOYMENT" \
  -o jsonpath="{.spec.template.spec.containers[?(@.name=='${CONTAINER}')].image}")"
[[ "$actual_image" == "$TARGET_IMAGE" ]] || {
  echo "Deployment image does not match the qualified digest." >&2
  exit 1
}

if [[ -n "$DASHBOARD_URL" ]]; then
  command -v curl >/dev/null 2>&1 || {
    echo "curl is required when --url is supplied." >&2
    exit 1
  }

  python3 - "$DASHBOARD_URL" "$RUN_DIR" <<'PY'
import html.parser
import pathlib
import ssl
import sys
import urllib.parse
import urllib.request

base, run_dir = sys.argv[1:]
run_dir = pathlib.Path(run_dir)
context = ssl._create_unverified_context()

class Scripts(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.sources = []
    def handle_starttag(self, tag, attrs):
        if tag.lower() != "script":
            return
        values = dict(attrs)
        if values.get("src"):
            self.sources.append(values["src"])

index_url = urllib.parse.urljoin(base.rstrip("/") + "/", "dashboard/")
with urllib.request.urlopen(index_url, context=context, timeout=60) as response:
    index = response.read()
(run_dir / "dashboard-index.html").write_bytes(index)

parser = Scripts()
parser.feed(index.decode("utf-8", errors="replace"))
combined = bytearray(index)
for number, src in enumerate(parser.sources):
    url = urllib.parse.urljoin(index_url, src)
    with urllib.request.urlopen(url, context=context, timeout=90) as response:
        body = response.read()
    (run_dir / f"dashboard-script-{number}.js").write_bytes(body)
    combined.extend(body)

required = [
    b"LayerSentry",
    b"Sign in to LayerSentry",
    b"layersentry-operations-dashboard",
    b"Operations Control Plane",
]
missing = [marker.decode() for marker in required if marker not in combined]
if missing:
    raise SystemExit(f"Browser validation markers are missing: {missing}")
PY
fi

rollback_required=false
trap - ERR
cat > "$RUN_DIR/RESULT.txt" <<EOF
LAYERSENTRY MANAGEMENT UI V3 ROLLOUT: PASS
namespace=${NAMESPACE}
deployment=${DEPLOYMENT}
container=${CONTAINER}
image=${TARGET_IMAGE}
source_commit=${SOURCE_SHA}
qualification_workflow_run=${QUALIFICATION_RUN}
dashboard_url=${DASHBOARD_URL}
EOF

printf 'LayerSentry v3 management UI rollout: PASS\nEvidence: %s\n' "$RUN_DIR"
