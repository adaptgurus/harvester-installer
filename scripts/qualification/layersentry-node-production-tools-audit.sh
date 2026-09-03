#!/usr/bin/env bash
set -Eeuo pipefail

# Read-only LayerSentry installed-node audit.
# This script MUST NOT discover or log into iSCSI targets, mount NFS exports,
# alter multipath configuration, load HBA modules, or modify customer storage.

required_commands=(
  nc
  lsscsi
  multipath
  multipathd
  iscsiadm
  iscsid
  mount.nfs
  lspci
  lsmod
  modinfo
  dmesg
)

required_modules=(
  qla2xxx
  lpfc
  mpt3sas
  megaraid_sas
  fnic
)

failures=0

echo "LayerSentry installed-node production tools audit"
echo "capturedAtUtc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "hostname=$(hostname)"
echo "kernel=$(uname -r)"
echo "architecture=$(uname -m)"
echo

echo "[required commands]"
for command_name in "${required_commands[@]}"; do
  if command_path=$(command -v "$command_name" 2>/dev/null); then
    printf 'PASS command %-12s %s\n' "$command_name" "$command_path"
  else
    printf 'FAIL command %-12s missing\n' "$command_name"
    failures=$((failures + 1))
  fi
done

echo
echo "[safe command identity/smoke]"
{ nc -h || true; } 2>&1 | head -n 12
{ lsscsi --version || lsscsi -V || true; } 2>&1 | head -n 8
{ multipath -h || true; } 2>&1 | head -n 16
{ iscsiadm --version || true; } 2>&1 | head -n 8
{ lspci --version || true; } 2>&1 | head -n 8
{ modinfo --version || true; } 2>&1 | head -n 8

echo
echo "[required HBA/SAS module metadata]"
for module_name in "${required_modules[@]}"; do
  if modinfo "$module_name" >/dev/null 2>&1; then
    printf 'PASS module %-14s ' "$module_name"
    modinfo -F filename "$module_name" 2>/dev/null | head -n 1
  else
    printf 'FAIL module %-14s metadata unavailable\n' "$module_name"
    failures=$((failures + 1))
  fi
done

echo
echo "[PCI devices and bound kernel drivers]"
lspci -nnk || true

echo
echo "[currently loaded modules]"
# A physical-HBA module is NOT required to be loaded in Hyper-V. Hardware
# production qualification must prove the correct driver binds on real HBA/NICs.
lsmod || true

echo
echo "[current iSCSI sessions - read only]"
iscsiadm -m session 2>&1 || true

echo
echo "[current multipath topology - read only]"
multipath -ll 2>&1 || true

echo
echo "[LayerSentry storage-readiness service]"
if systemctl is-enabled layersentry-storage-readiness.service >/dev/null 2>&1; then
  echo "PASS service layersentry-storage-readiness.service enabled"
else
  echo "FAIL service layersentry-storage-readiness.service not enabled"
  failures=$((failures + 1))
fi
systemctl --no-pager --full status layersentry-storage-readiness.service 2>&1 || true

echo
echo "[LayerSentry storage-readiness state]"
if [[ -s /var/lib/layersentry/storage-readiness.yaml ]]; then
  echo "PASS state /var/lib/layersentry/storage-readiness.yaml present"
  cat /var/lib/layersentry/storage-readiness.yaml
else
  echo "FAIL state /var/lib/layersentry/storage-readiness.yaml missing or empty"
  failures=$((failures + 1))
fi

echo
echo "[policy assertions]"
if [[ -s /var/lib/layersentry/storage-readiness.yaml ]]; then
  grep -q 'activationPolicy: externalStorageConfig-only' /var/lib/layersentry/storage-readiness.yaml \
    && echo "PASS multipath activation is configuration-driven" \
    || { echo "FAIL multipath activation policy mismatch"; failures=$((failures + 1)); }
  grep -q 'automaticDiscovery: false' /var/lib/layersentry/storage-readiness.yaml \
    && echo "PASS iSCSI automatic discovery disabled" \
    || { echo "FAIL iSCSI automatic discovery policy mismatch"; failures=$((failures + 1)); }
  grep -q 'automaticLogin: false' /var/lib/layersentry/storage-readiness.yaml \
    && echo "PASS iSCSI automatic login disabled" \
    || { echo "FAIL iSCSI automatic login policy mismatch"; failures=$((failures + 1)); }
  grep -q 'automaticMount: false' /var/lib/layersentry/storage-readiness.yaml \
    && echo "PASS NFS automatic mount disabled" \
    || { echo "FAIL NFS automatic mount policy mismatch"; failures=$((failures + 1)); }
fi

echo
if (( failures > 0 )); then
  echo "LAYERSENTRY NODE PRODUCTION TOOLS AUDIT: FAIL ($failures requirement(s))"
  exit 1
fi

echo "LAYERSENTRY NODE PRODUCTION TOOLS AUDIT: PASS"
