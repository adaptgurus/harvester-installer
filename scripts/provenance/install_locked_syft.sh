#!/usr/bin/env bash
set -Eeuo pipefail

export LC_ALL=C
umask 022

descriptor=${1:?usage: install_locked_syft.sh DESCRIPTOR BIN_DIR REPORT [EVIDENCE_DIR]}
bin_dir=${2:?usage: install_locked_syft.sh DESCRIPTOR BIN_DIR REPORT [EVIDENCE_DIR]}
report=${3:?usage: install_locked_syft.sh DESCRIPTOR BIN_DIR REPORT [EVIDENCE_DIR]}
evidence_dir=${4:-}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

for command in python3 curl sha256sum stat tar install; do
  command -v "$command" >/dev/null 2>&1 || fail "required command is missing: $command"
done
[[ -f "$descriptor" ]] || fail "locked Syft descriptor does not exist: $descriptor"

mapfile -t fields < <(
  python3 - "$descriptor" <<'PY'
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

path = Path(sys.argv[1])
try:
    value = json.loads(path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    raise SystemExit(f"invalid locked Syft descriptor: {exc}")
if not isinstance(value, dict) or value.get("schema") != "layersentry.locked-tool/v1":
    raise SystemExit("unsupported locked Syft descriptor schema")
checksums = value.get("checksums_manifest")
if not isinstance(checksums, dict):
    raise SystemExit("checksums_manifest must be an object")

fields = (
    value.get("id"),
    value.get("name"),
    value.get("version"),
    value.get("source"),
    value.get("sha256"),
    value.get("bytes"),
    checksums.get("source"),
    checksums.get("sha256"),
    checksums.get("bytes"),
)
for field in fields:
    text = str(field)
    if not text or "\n" in text or "\r" in text:
        raise SystemExit("descriptor field is empty or contains a newline")
    print(text)

source = str(value.get("source", ""))
manifest_source = str(checksums.get("source", ""))
for label, url in (("tool", source), ("checksums manifest", manifest_source)):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.netloc != "github.com":
        raise SystemExit(f"{label} source must use exact GitHub HTTPS release URL")
    if "/releases/download/" not in parsed.path or "/releases/latest" in parsed.path.lower():
        raise SystemExit(f"{label} source is not an exact release asset URL")

for label, checksum in (
    ("tool", str(value.get("sha256", ""))),
    ("checksums manifest", str(checksums.get("sha256", ""))),
):
    if not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise SystemExit(f"{label} SHA-256 is invalid")

for label, size in (("tool", value.get("bytes")), ("checksums manifest", checksums.get("bytes"))):
    if not isinstance(size, int) or size <= 0:
        raise SystemExit(f"{label} byte count is invalid")

print(Path(urlparse(source).path).name)
print(Path(urlparse(manifest_source).path).name)
PY
)

[[ ${#fields[@]} -eq 11 ]] || fail "locked Syft descriptor emitted an unexpected field count"
tool_id=${fields[0]}
tool_name=${fields[1]}
version=${fields[2]}
source=${fields[3]}
archive_sha256=${fields[4]}
archive_bytes=${fields[5]}
manifest_source=${fields[6]}
manifest_sha256=${fields[7]}
manifest_bytes=${fields[8]}
archive_name=${fields[9]}
manifest_name=${fields[10]}

[[ "$tool_id" == "syft-linux-amd64" ]] || fail "unexpected locked tool id: $tool_id"
[[ "$tool_name" == "syft" ]] || fail "unexpected locked tool name: $tool_name"
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "invalid Syft version: $version"

tmp_dir=$(mktemp -d "${RUNNER_TEMP:-/tmp}/layersentry-syft.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT
archive="$tmp_dir/$archive_name"
manifest="$tmp_dir/$manifest_name"
extract_dir="$tmp_dir/extracted"
mkdir -p "$extract_dir" "$bin_dir" "$(dirname "$report")"

curl --fail --location --silent --show-error \
  --retry 5 --retry-all-errors --connect-timeout 30 \
  "$source" -o "$archive"
printf '%s  %s\n' "$archive_sha256" "$archive" | sha256sum -c -
[[ $(stat -c '%s' "$archive") == "$archive_bytes" ]] \
  || fail "Syft archive byte count does not match the locked descriptor"

curl --fail --location --silent --show-error \
  --retry 5 --retry-all-errors --connect-timeout 30 \
  "$manifest_source" -o "$manifest"
printf '%s  %s\n' "$manifest_sha256" "$manifest" | sha256sum -c -
[[ $(stat -c '%s' "$manifest") == "$manifest_bytes" ]] \
  || fail "Syft checksum-manifest byte count does not match the locked descriptor"

python3 - "$manifest" "$archive_name" "$archive_sha256" <<'PY'
import sys
from pathlib import Path

manifest = Path(sys.argv[1])
asset_name = sys.argv[2]
expected = sys.argv[3]
matches = []
for raw in manifest.read_text(encoding="utf-8").splitlines():
    parts = raw.strip().split()
    if len(parts) >= 2 and parts[-1].lstrip("*") == asset_name:
        matches.append(parts[0])
if matches != [expected]:
    raise SystemExit(
        f"official checksum manifest does not uniquely bind {asset_name} to {expected}: {matches}"
    )
PY

python3 - "$archive" <<'PY'
import posixpath
import sys
import tarfile
from pathlib import PurePosixPath

archive_path = sys.argv[1]
syft_members = []
with tarfile.open(archive_path, mode="r:gz") as archive:
    members = archive.getmembers()
    if not members:
        raise SystemExit("Syft archive is empty")
    seen = set()
    for member in members:
        pure = PurePosixPath(member.name)
        normalized = posixpath.normpath(member.name)
        if (
            not member.name
            or "\x00" in member.name
            or pure.is_absolute()
            or normalized in {"", ".", ".."}
            or normalized.startswith("../")
            or member.name in seen
        ):
            raise SystemExit(f"unsafe or duplicate Syft archive member: {member.name!r}")
        seen.add(member.name)
        if member.ischr() or member.isblk() or member.isfifo():
            raise SystemExit(f"unsupported special file in Syft archive: {member.name!r}")
        if member.issym() or member.islnk():
            target = member.linkname
            resolved = posixpath.normpath(str(pure.parent / target))
            if not target or target.startswith("/") or resolved == ".." or resolved.startswith("../"):
                raise SystemExit(f"unsafe Syft archive link: {member.name!r} -> {target!r}")
        if normalized == "syft" and member.isfile():
            syft_members.append(member)
if len(syft_members) != 1:
    raise SystemExit(f"Syft archive must contain exactly one root syft binary; found {len(syft_members)}")
PY

tar -xzf "$archive" -C "$extract_dir" --no-same-owner --no-same-permissions syft
[[ -f "$extract_dir/syft" ]] || fail "Syft binary was not extracted"
install -m 0755 "$extract_dir/syft" "$bin_dir/syft"

version_output="$tmp_dir/syft-version.txt"
SYFT_CHECK_FOR_APP_UPDATE=false "$bin_dir/syft" version > "$version_output"
grep -Eq '(^|[^0-9])1\.51\.1([^0-9]|$)' "$version_output" \
  || fail "installed Syft binary does not report version 1.51.1"

binary_sha256=$(sha256sum "$bin_dir/syft" | awk '{print $1}')
binary_bytes=$(stat -c '%s' "$bin_dir/syft")
descriptor_sha256=$(sha256sum "$descriptor" | awk '{print $1}')

python3 - \
  "$report" \
  "$tool_id" \
  "$version" \
  "$source" \
  "$archive_sha256" \
  "$archive_bytes" \
  "$binary_sha256" \
  "$binary_bytes" \
  "$descriptor_sha256" <<'PY'
import datetime as dt
import json
import sys
from pathlib import Path

(
    output,
    tool_id,
    version,
    source,
    archive_sha256,
    archive_bytes,
    binary_sha256,
    binary_bytes,
    descriptor_sha256,
) = sys.argv[1:]
report = {
    "schema": "layersentry.locked-tool-validation/v1",
    "generated_at": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    "id": tool_id,
    "version": version,
    "source": source,
    "archive_sha256": archive_sha256,
    "archive_bytes": int(archive_bytes),
    "binary_sha256": binary_sha256,
    "binary_bytes": int(binary_bytes),
    "descriptor_sha256": descriptor_sha256,
    "version_verified": True,
    "official_checksum_manifest_verified": True,
    "archive_safety_verified": True,
}
Path(output).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

if [[ -n "$evidence_dir" ]]; then
  mkdir -p "$evidence_dir"
  cp "$archive" "$manifest" "$version_output" "$evidence_dir/"
  cp "$report" "$evidence_dir/locked-tool-validation.json"
  (
    cd "$evidence_dir"
    sha256sum \
      "$archive_name" \
      "$manifest_name" \
      syft-version.txt \
      locked-tool-validation.json \
      > evidence-files.sha256
  )
fi

echo "LOCKED SYFT VALIDATION: PASS"
echo "version=$version"
echo "archive_sha256=$archive_sha256"
echo "binary_sha256=$binary_sha256"
echo "binary=$bin_dir/syft"
