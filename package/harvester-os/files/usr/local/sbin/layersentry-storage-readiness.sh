#!/usr/bin/env bash
set -Eeuo pipefail

STATE_DIR=/var/lib/layersentry
STATE_FILE="$STATE_DIR/storage-readiness.yaml"
mkdir -p "$STATE_DIR"
tmp=$(mktemp "$STATE_DIR/.storage-readiness.XXXXXX")
trap 'rm -f "$tmp"' EXIT

available() {
  command -v "$1" >/dev/null 2>&1 && printf true || printf false
}

unit_available() {
  systemctl list-unit-files "$1" --no-legend 2>/dev/null | grep -q "^$1" && printf true || printf false
}

cat > "$tmp" <<EOF
schema: layersentry.storage-readiness/v1
capturedAtUtc: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
capabilities:
  multipath:
    command: $(available multipath)
    daemon: $(available multipathd)
    serviceUnit: $(unit_available multipathd.service)
    activationPolicy: externalStorageConfig-only
  iscsi:
    initiator: $(available iscsiadm)
    daemon: $(available iscsid)
    serviceUnit: $(unit_available iscsid.service)
    automaticDiscovery: false
    automaticLogin: false
  nfs:
    mountHelper: $(available mount.nfs)
    mountHelperV4: $(available mount.nfs4)
    automaticMount: false
  csi:
    harvesterDriverConfigSetting: csi-driver-config
    bundledNfsCsiVersion: "4.12.0"
    genericIscsiCsiDefaultEnabled: false
policy:
  customerTargetsEmbedded: false
  customerCredentialsEmbedded: false
  multipathConfigurationSource: Harvester externalStorageConfig
  longhornVirtualDiskMultipathBlacklistPreserved: true
EOF
chmod 0644 "$tmp"
mv -f "$tmp" "$STATE_FILE"
trap - EXIT

echo "LayerSentry storage readiness report written to $STATE_FILE"
