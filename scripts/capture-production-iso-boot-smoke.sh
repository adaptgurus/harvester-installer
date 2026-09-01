#!/usr/bin/env bash
set -Eeuo pipefail

candidate_dir=${1:?usage: capture-production-iso-boot-smoke.sh CANDIDATE_DIR EVIDENCE_DIR}
evidence_dir=${2:?usage: capture-production-iso-boot-smoke.sh CANDIDATE_DIR EVIDENCE_DIR}

: "${EXPECTED_ISO_BYTES:=8180137984}"
: "${EXPECTED_ISO_SHA512:=7f1cd57c363f3b6b592fcbfb90d810c8f12f881e14e097fe17b2833250ee9e57a9831e4398147bd612bc7e3a36a4c45751019473e60eeaa263e5660c996feb81}"
: "${SOURCE_RUN_ID:=33479776571}"
: "${SOURCE_ARTIFACT_ID:=9790788698}"
: "${SOURCE_ARTIFACT_NAME:=layersentry-v1.0-harvester-v1.8.2-amd64-offline-iso}"
: "${SOURCE_COMMIT:=a104eab8cc5eca42b7ef002fc96561a21be3f163}"

mkdir -p "$evidence_dir/screenshots" "$evidence_dir/qmp"
evidence_dir=$(cd "$evidence_dir" && pwd)
candidate_dir=$(cd "$candidate_dir" && pwd)

iso=$(find "$candidate_dir" -type f -name 'layersentry-v1.0-harvester-v1.8.2-amd64.iso' -print -quit)
checksum_file=$(find "$candidate_dir" -type f -name 'layersentry-v1.0-harvester-v1.8.2-amd64.iso.sha512' -print -quit)
bytes_file=$(find "$candidate_dir" -type f -name 'layersentry-v1.0-harvester-v1.8.2-amd64.iso.bytes' -print -quit)

for required in "$iso" "$checksum_file" "$bytes_file"; do
  if [[ -z "$required" || ! -f "$required" ]]; then
    echo "Required ISO artifact member is missing: $required" >&2
    find "$candidate_dir" -maxdepth 4 -type f -printf '%p\n' | sort >&2
    exit 1
  fi
done

actual_bytes=$(stat -c '%s' "$iso")
actual_sha512=$(sha512sum "$iso" | awk '{print $1}')
sidecar_bytes=$(tr -d '[:space:]' < "$bytes_file")
sidecar_sha512=$(awk '{print $1}' "$checksum_file")

[[ "$actual_bytes" == "$EXPECTED_ISO_BYTES" ]]
[[ "$sidecar_bytes" == "$EXPECTED_ISO_BYTES" ]]
[[ "$actual_sha512" == "$EXPECTED_ISO_SHA512" ]]
[[ "$sidecar_sha512" == "$EXPECTED_ISO_SHA512" ]]

if [[ -f /usr/share/OVMF/OVMF_CODE_4M.fd && -f /usr/share/OVMF/OVMF_VARS_4M.fd ]]; then
  ovmf_code=/usr/share/OVMF/OVMF_CODE_4M.fd
  ovmf_vars_template=/usr/share/OVMF/OVMF_VARS_4M.fd
elif [[ -f /usr/share/OVMF/OVMF_CODE.fd && -f /usr/share/OVMF/OVMF_VARS.fd ]]; then
  ovmf_code=/usr/share/OVMF/OVMF_CODE.fd
  ovmf_vars_template=/usr/share/OVMF/OVMF_VARS.fd
else
  echo 'Unable to locate a matching non-Secure-Boot OVMF CODE/VARS pair' >&2
  find /usr/share -type f \( -name 'OVMF_CODE*.fd' -o -name 'OVMF_VARS*.fd' \) -print 2>/dev/null | sort >&2 || true
  exit 1
fi

cp "$ovmf_vars_template" "$evidence_dir/OVMF_VARS.fd"
qemu-img create -f qcow2 "$evidence_dir/boot-smoke-target.qcow2" 200G > "$evidence_dir/qemu-img-create.log"

cat > "$evidence_dir/qmp-command.py" <<'PY'
#!/usr/bin/env python3
import argparse
import json
import socket
import sys
import time
from pathlib import Path


def read_response(stream, command_id):
    while True:
        line = stream.readline()
        if not line:
            raise RuntimeError("QMP connection closed before a response arrived")
        payload = json.loads(line.decode("utf-8"))
        if payload.get("id") == command_id:
            return payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("socket_path")
    parser.add_argument("command")
    parser.add_argument("--arguments", default="{}")
    parser.add_argument("--output")
    args = parser.parse_args()

    deadline = time.time() + 30
    last_error = None
    while time.time() < deadline:
        try:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(args.socket_path)
            break
        except OSError as exc:
            last_error = exc
            time.sleep(0.5)
    else:
        raise RuntimeError(f"unable to connect to QMP socket: {last_error}")

    with client:
        stream = client.makefile("rwb", buffering=0)
        greeting = json.loads(stream.readline().decode("utf-8"))
        stream.write(json.dumps({"execute": "qmp_capabilities", "id": 1}).encode("utf-8") + b"\n")
        capabilities = read_response(stream, 1)
        command = {
            "execute": args.command,
            "arguments": json.loads(args.arguments),
            "id": 2,
        }
        stream.write(json.dumps(command).encode("utf-8") + b"\n")
        result = read_response(stream, 2)

    record = {"greeting": greeting, "capabilities": capabilities, "response": result}
    rendered = json.dumps(record, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    if "error" in result:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
PY
chmod +x "$evidence_dir/qmp-command.py"

qmp_socket="$evidence_dir/qmp.sock"
pid_file="$evidence_dir/qemu.pid"
qemu_stdout="$evidence_dir/qemu.stdout.log"
qemu_stderr="$evidence_dir/qemu.stderr.log"
serial_log="$evidence_dir/qemu.serial.log"

cleanup() {
  local rc=$?
  if [[ -S "$qmp_socket" ]]; then
    "$evidence_dir/qmp-command.py" "$qmp_socket" quit --output "$evidence_dir/qmp/quit.json" >/dev/null 2>&1 || true
  fi
  if [[ -f "$pid_file" ]]; then
    qemu_pid=$(cat "$pid_file" 2>/dev/null || true)
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
      kill "$qemu_pid" 2>/dev/null || true
      sleep 2
      kill -9 "$qemu_pid" 2>/dev/null || true
    fi
  fi
  rm -f "$qmp_socket"
  exit "$rc"
}
trap cleanup EXIT INT TERM

wait_for_qmp() {
  local pid=$1
  local deadline=$((SECONDS + 90))
  while (( SECONDS < deadline )); do
    if ! kill -0 "$pid" 2>/dev/null; then
      return 1
    fi
    if [[ -S "$qmp_socket" ]]; then
      if "$evidence_dir/qmp-command.py" "$qmp_socket" query-status --output "$evidence_dir/qmp/initial-status.json"; then
        return 0
      fi
    fi
    sleep 2
  done
  return 1
}

start_qemu() {
  local accelerator=$1
  local cpu_model=$2
  local mode=$3

  rm -f "$qmp_socket" "$pid_file"
  : > "$qemu_stdout"
  : > "$qemu_stderr"
  : > "$serial_log"

  qemu-system-x86_64 \
    -name layersentry-v1.8.2-boot-smoke \
    -machine q35 \
    -accel "$accelerator" \
    -cpu "$cpu_model" \
    -smp 2 \
    -m 7168 \
    -drive if=pflash,format=raw,readonly=on,file="$ovmf_code" \
    -drive if=pflash,format=raw,file="$evidence_dir/OVMF_VARS.fd" \
    -drive file="$evidence_dir/boot-smoke-target.qcow2",format=qcow2,if=virtio,cache=unsafe \
    -cdrom "$iso" \
    -boot order=d,menu=on,strict=on \
    -device virtio-rng-pci \
    -netdev user,id=net0 \
    -device e1000,netdev=net0 \
    -serial file:"$serial_log" \
    -qmp unix:"$qmp_socket",server=on,wait=off \
    -vnc 127.0.0.1:1 \
    -display none \
    -no-reboot \
    >"$qemu_stdout" 2>"$qemu_stderr" &

  qemu_pid=$!
  echo "$qemu_pid" > "$pid_file"

  if wait_for_qmp "$qemu_pid"; then
    printf '%s\n' "$mode" > "$evidence_dir/acceleration-mode.txt"
    return 0
  fi

  kill "$qemu_pid" 2>/dev/null || true
  wait "$qemu_pid" 2>/dev/null || true
  return 1
}

acceleration_mode=tcg
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
  if start_qemu kvm host kvm; then
    acceleration_mode=kvm
  else
    cp "$qemu_stderr" "$evidence_dir/qemu-kvm-attempt.stderr.log" || true
  fi
fi

if [[ "$acceleration_mode" != kvm ]]; then
  start_qemu 'tcg,thread=multi' max tcg
  acceleration_mode=tcg
fi

qemu_pid=$(cat "$pid_file")
start_epoch=$(date +%s)

capture_frame() {
  local sequence=$1
  local label=$2
  local elapsed=$3
  local ppm="$evidence_dir/screenshots/${sequence}-${label}.ppm"
  local png="$evidence_dir/screenshots/${sequence}-${label}.png"
  local status="$evidence_dir/qmp/${sequence}-${label}-status.json"

  if ! kill -0 "$qemu_pid" 2>/dev/null; then
    echo "QEMU exited before capture ${sequence}-${label}" >&2
    return 1
  fi

  "$evidence_dir/qmp-command.py" "$qmp_socket" query-status --output "$status"
  "$evidence_dir/qmp-command.py" "$qmp_socket" screendump \
    --arguments "{\"filename\": \"$ppm\"}" \
    --output "$evidence_dir/qmp/${sequence}-${label}-screendump.json"

  python3 - "$ppm" "$png" <<'PY'
from pathlib import Path
from PIL import Image
import sys

source = Path(sys.argv[1])
target = Path(sys.argv[2])
with Image.open(source) as image:
    image.save(target, format="PNG", optimize=True)
source.unlink()
PY

  printf '%s\t%s\t%s\t%s\n' "$sequence" "$label" "$elapsed" "$(sha256sum "$png" | awk '{print $1}')" \
    >> "$evidence_dir/screenshot-timeline.tsv"
}

printf 'sequence\tlabel\telapsedSeconds\tsha256\n' > "$evidence_dir/screenshot-timeline.tsv"

if [[ "$acceleration_mode" == kvm ]]; then
  schedule=(10 30 60 120 240 360)
else
  schedule=(15 60 180 360 600 900 1200)
fi

sequence=0
previous=0
for elapsed in "${schedule[@]}"; do
  sleep_for=$((elapsed - previous))
  sleep "$sleep_for"
  previous=$elapsed
  sequence=$((sequence + 1))
  printf -v sequence_label '%02d' "$sequence"
  capture_frame "$sequence_label" "elapsed-${elapsed}s" "$elapsed"

  if (( sequence == 1 )); then
    "$evidence_dir/qmp-command.py" "$qmp_socket" human-monitor-command \
      --arguments '{"command-line":"sendkey ret"}' \
      --output "$evidence_dir/qmp/send-enter.json" || true
  fi
done

"$evidence_dir/qmp-command.py" "$qmp_socket" query-block --output "$evidence_dir/qmp/final-block-devices.json" || true
"$evidence_dir/qmp-command.py" "$qmp_socket" query-pci --output "$evidence_dir/qmp/final-pci.json" || true
"$evidence_dir/qmp-command.py" "$qmp_socket" query-status --output "$evidence_dir/qmp/final-status.json" || true

python3 - "$evidence_dir/screenshots" "$evidence_dir/visual-metrics.json" <<'PY'
from __future__ import annotations

import hashlib
import json
import math
import sys
from pathlib import Path
from PIL import Image, ImageStat

screenshots = Path(sys.argv[1])
outfile = Path(sys.argv[2])
records = []

for path in sorted(screenshots.glob("*.png")):
    with Image.open(path).convert("RGB") as image:
        width, height = image.size
        reduced = image.resize((min(width, 256), min(height, 192)))
        colors = reduced.getcolors(maxcolors=reduced.width * reduced.height) or []
        total = reduced.width * reduced.height
        unique_colors = len(colors)
        black_pixels = sum(count for count, rgb in colors if max(rgb) <= 8)
        white_pixels = sum(count for count, rgb in colors if min(rgb) >= 247)
        grayscale = reduced.convert("L")
        histogram = grayscale.histogram()
        entropy = -sum((count / total) * math.log2(count / total) for count in histogram if count)
        extrema = ImageStat.Stat(grayscale).extrema[0]
        records.append({
            "file": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "width": width,
            "height": height,
            "uniqueColorsSampled": unique_colors,
            "blackRatioSampled": round(black_pixels / total, 6),
            "whiteRatioSampled": round(white_pixels / total, 6),
            "grayscaleEntropy": round(entropy, 6),
            "grayscaleExtrema": list(extrema),
            "visuallyNonBlankCandidate": unique_colors >= 8 and entropy >= 0.25 and extrema[1] - extrema[0] >= 16,
        })

summary = {
    "screenshots": records,
    "count": len(records),
    "distinctPngHashes": len({record["sha256"] for record in records}),
    "nonBlankCandidateCount": sum(record["visuallyNonBlankCandidate"] for record in records),
    "automatedMeaning": "Framebuffer activity only; visual review is required before BOOT_SMOKE_GOOD promotion.",
}
outfile.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if summary["count"] < 3:
    raise SystemExit("fewer than three screenshots were captured")
if summary["nonBlankCandidateCount"] < 1:
    raise SystemExit("all captured framebuffers appear blank")
PY

end_epoch=$(date +%s)
runtime_seconds=$((end_epoch - start_epoch))

{
  uname -a
  echo
  qemu-system-x86_64 --version
  echo
  lscpu
  echo
  free -h
  echo
  df -h
} > "$evidence_dir/runner-environment.txt"

cat > "$evidence_dir/boot-smoke-capture.yaml" <<EOF
apiVersion: release.layersentry.io/v1
kind: IsoRuntimeBootSmokeCapture
metadata:
  product: LayerSentry
  productVersion: "1.0"
  capturedAtUtc: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sourceArtifact:
  workflowRunId: ${SOURCE_RUN_ID}
  artifactId: ${SOURCE_ARTIFACT_ID}
  artifactName: ${SOURCE_ARTIFACT_NAME}
  sourceCommit: ${SOURCE_COMMIT}
iso:
  filename: layersentry-v1.0-harvester-v1.8.2-amd64.iso
  bytes: ${actual_bytes}
  sha512: ${actual_sha512}
virtualMachine:
  firmware: OVMF_UEFI
  ovmfCode: ${ovmf_code}
  machine: q35
  acceleration: ${acceleration_mode}
  vcpu: 2
  memoryMiB: 7168
  targetDiskGiB: 200
  network: qemu-user-e1000
capture:
  runtimeSeconds: ${runtime_seconds}
  screenshotCount: $(find "$evidence_dir/screenshots" -type f -name '*.png' | wc -l)
  visualMetricsFile: visual-metrics.json
  serialLogFile: qemu.serial.log
  qemuStderrFile: qemu.stderr.log
classification:
  state: RUNTIME_BOOT_EVIDENCE_CAPTURED_REVIEW_REQUIRED
  bootSmokeGood: false
  installGood: false
  airgapGood: false
  releaseGood: false
  note: Automated checks prove exact ISO identity, QEMU execution, QMP responsiveness and non-blank framebuffer activity. A visual review must identify a valid LayerSentry/Harvester boot or installer screen before promotion.
EOF

cat > "$evidence_dir/README.md" <<EOF
# LayerSentry v1.8.2 runtime boot-smoke capture

Exact source ISO artifact: \`${SOURCE_ARTIFACT_ID}\`  
Exact ISO SHA-512: \`${actual_sha512}\`

Capture state: **RUNTIME_BOOT_EVIDENCE_CAPTURED_REVIEW_REQUIRED**.

This evidence does not establish installation, cluster readiness, air-gap operation, or release approval. Review the staged screenshots and logs before changing the bootSmokeGood field.
EOF

rm -f "$evidence_dir/boot-smoke-target.qcow2" "$evidence_dir/OVMF_VARS.fd" "$evidence_dir/qmp-command.py" "$qmp_socket"

cat "$evidence_dir/boot-smoke-capture.yaml"
cat "$evidence_dir/visual-metrics.json"
find "$evidence_dir" -maxdepth 3 -type f -printf '%p\t%s bytes\n' | sort
