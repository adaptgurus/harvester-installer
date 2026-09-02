#!/usr/bin/env bash
set -Eeuo pipefail

log() { printf 'layersentry-branding: %s\n' "$*"; }

KUBECTL=""
for candidate in /var/lib/rancher/rke2/bin/kubectl /usr/local/bin/kubectl /usr/bin/kubectl; do
  if [[ -x "$candidate" ]]; then KUBECTL="$candidate"; break; fi
done
[[ -n "$KUBECTL" ]] || { log "kubectl is not available yet"; exit 75; }

KUBECONFIG="/etc/rancher/rke2/rke2.yaml"
[[ -s "$KUBECONFIG" ]] || { log "server kubeconfig is not available on this node"; exit 0; }
export KUBECONFIG

# This service runs only on an RKE2 server node with its local administrative
# kubeconfig. It is safe to retry and deliberately never touches first-login or
# eula-agreed: accepting legal terms remains an explicit user action.
for _ in $(seq 1 120); do
  if "$KUBECTL" get crd settings.management.cattle.io >/dev/null 2>&1; then
    break
  fi
  sleep 5
done
"$KUBECTL" get crd settings.management.cattle.io >/dev/null 2>&1 || { log "Rancher Setting CRD not ready"; exit 75; }

logo_svg='<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 720 180"><rect width="720" height="180" rx="24" fill="#101827"/><path d="M58 126V54h22v52h52v20H58zm105 0V54h99v20h-77v8h69v18h-69v8h80v18H163zm124 0 45-72h26l45 72h-25l-9-16h-49l-9 16h-24zm43-34h29l-14-25-15 25zm96 34V54h22v72h-22zm53 0V54h62c31 0 49 13 49 36 0 17-10 29-28 34l31 2v0h-31l-28-25h-33v25h-22zm22-43h40c17 0 26-3 26-11s-9-11-26-11h-40v22z" fill="#fff"/><text x="56" y="158" font-family="Arial,sans-serif" font-size="24" letter-spacing="5" fill="#72d7ff">LAYERSENTRY v1.0</text></svg>'
favicon_svg='<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="12" fill="#101827"/><path d="M16 14h10v26h25v10H16z" fill="#72d7ff"/></svg>'
background_svg='<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1600 900"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#07111f"/><stop offset="1" stop-color="#172a46"/></linearGradient></defs><rect width="1600" height="900" fill="url(#g)"/><g fill="none" stroke="#72d7ff" stroke-opacity=".13"><circle cx="1300" cy="180" r="420"/><circle cx="1300" cy="180" r="310"/><circle cx="1300" cy="180" r="200"/></g><text x="100" y="735" font-family="Arial,sans-serif" font-weight="700" font-size="92" fill="#fff">LayerSentry</text><text x="105" y="795" font-family="Arial,sans-serif" font-size="34" letter-spacing="9" fill="#72d7ff">SECURE PRIVATE CLOUD</text></svg>'

data_uri() {
  printf 'data:image/svg+xml;base64,%s' "$(printf '%s' "$1" | base64 -w0)"
}
logo_uri=$(data_uri "$logo_svg")
favicon_uri=$(data_uri "$favicon_svg")
background_uri=$(data_uri "$background_svg")

apply_setting() {
  local name=$1 value=$2
  "$KUBECTL" apply -f - >/dev/null <<EOF
apiVersion: management.cattle.io/v3
kind: Setting
metadata:
  name: ${name}
value: ${value}
EOF
}

apply_setting ui-pl 'LayerSentry'
apply_setting ui-brand 'layersentry'
apply_setting ui-logo-light "$logo_uri"
apply_setting ui-logo-dark "$logo_uri"
apply_setting ui-favicon "$favicon_uri"
apply_setting ui-login-background-light "$background_uri"
apply_setting ui-login-background-dark "$background_uri"
apply_setting ui-community-links 'false'

# Force the exact UI bundled inside the ISO/Harvester server image. This avoids
# the default external latest UI index and guarantees install/runtime operation
# without Internet access.
if "$KUBECTL" get settings.harvesterhci.io ui-source -n harvester-system >/dev/null 2>&1; then
  "$KUBECTL" patch settings.harvesterhci.io ui-source -n harvester-system --type merge -p '{"value":"bundled"}' >/dev/null
fi

# Record an auditable local state marker without exposing credentials.
install -d -m 0755 /var/lib/layersentry
printf 'LayerSentry v1.0 branding applied\n' > /var/lib/layersentry/branding-state
chmod 0644 /var/lib/layersentry/branding-state
log "LayerSentry private-label defaults applied; EULA state unchanged"
