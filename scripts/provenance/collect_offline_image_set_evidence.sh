#!/usr/bin/env bash
set -Eeuo pipefail

OUTPUT_DIR=${1:?usage: collect_offline_image_set_evidence.sh OUTPUT_DIR SOURCE_COMMIT BUILD_RUN_ID}
SOURCE_COMMIT=${2:?usage: collect_offline_image_set_evidence.sh OUTPUT_DIR SOURCE_COMMIT BUILD_RUN_ID}
BUILD_RUN_ID=${3:?usage: collect_offline_image_set_evidence.sh OUTPUT_DIR SOURCE_COMMIT BUILD_RUN_ID}
TOP_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

[[ $SOURCE_COMMIT =~ ^[0-9a-f]{40}$ ]] \
  || fail "source commit must be exactly 40 lowercase hex characters"
[[ $BUILD_RUN_ID =~ ^[1-9][0-9]*$ ]] \
  || fail "build run ID must be a positive integer"
[[ $(git -C "$TOP_DIR" rev-parse HEAD) == "$SOURCE_COMMIT" ]] \
  || fail "checked-out source does not equal requested source commit"
[[ -z $(git -C "$TOP_DIR" status --porcelain --untracked-files=no) ]] \
  || fail "tracked source must be clean before local-image evidence is collected"

for command in docker python3 git sha256sum sha512sum stat syft find sort tee; do
  command -v "$command" >/dev/null 2>&1 \
    || fail "required command is missing: $command"
done

OUTPUT_DIR=$(mkdir -p "$OUTPUT_DIR" && cd "$OUTPUT_DIR" && pwd)
rm -rf "$OUTPUT_DIR"/*
mkdir -p "$OUTPUT_DIR/images" "$OUTPUT_DIR/sboms" "$OUTPUT_DIR/image-lists"
: > "$OUTPUT_DIR/images.tsv"

records=(
  "layersentry-generated-harvester-cluster-repo|docker.io/rancher/harvester-cluster-repo:v1.0|ghcr.io/adaptgurus/layersentry-harvester-cluster-repo"
  "layersentry-generated-harvester-installer|docker.io/rancher/harvester-installer:v1.0|ghcr.io/adaptgurus/layersentry-harvester-installer"
  "layersentry-generated-harvester-os|docker.io/rancher/harvester-os:v1.0|ghcr.io/adaptgurus/layersentry-harvester-os"
)

for record in "${records[@]}"; do
  IFS='|' read -r image_id runtime_alias target_repository <<< "$record"
  source_alias="${target_repository}:source-${SOURCE_COMMIT}-run-${BUILD_RUN_ID}"
  docker image inspect "$runtime_alias" >/dev/null \
    || fail "locally generated image is missing: $runtime_alias"
  docker tag "$runtime_alias" "$source_alias"

  push_log="$OUTPUT_DIR/images/${image_id}.push.log"
  docker push "$source_alias" 2>&1 | tee "$push_log"
  digest=$(grep -Eo 'digest: sha256:[0-9a-f]{64}' "$push_log" \
    | tail -n 1 | awk '{print $2}')
  [[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] \
    || fail "could not determine pushed manifest digest for $source_alias"
  exact_ref="${target_repository}@${digest}"

  docker pull --platform linux/amd64 "$exact_ref" >/dev/null
  raw_inspect="$OUTPUT_DIR/images/${image_id}.raw.json"
  inspect="$OUTPUT_DIR/images/${image_id}.json"
  docker image inspect "$exact_ref" > "$raw_inspect"
  python3 - "$raw_inspect" "$inspect" "$image_id" "$runtime_alias" \
    "$source_alias" "$exact_ref" <<'PY'
import json
import re
import sys
from pathlib import Path

raw_path, output_path, image_id, runtime_alias, source_alias, exact_ref = sys.argv[1:]
values = json.loads(Path(raw_path).read_text(encoding="utf-8"))
if not isinstance(values, list) or len(values) != 1:
    raise SystemExit("docker image inspect did not return exactly one image")
item = values[0]
if item.get("Os") != "linux" or item.get("Architecture") != "amd64":
    raise SystemExit(f"{image_id} is not linux/amd64")
manifest_digest = exact_ref.split("@", 1)[1]
repo_digests = sorted(str(value) for value in item.get("RepoDigests") or [])
if not any(value.endswith(manifest_digest) for value in repo_digests):
    raise SystemExit(f"{image_id} does not retain the requested RepoDigest")
config_id = str(item.get("Id", ""))
if not re.fullmatch(r"sha256:[0-9a-f]{64}", config_id):
    raise SystemExit(f"{image_id} has an invalid image config digest")
layers = item.get("RootFS", {}).get("Layers")
if not isinstance(layers, list) or not layers:
    raise SystemExit(f"{image_id} has no rootfs diff IDs")
for layer in layers:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(layer)):
        raise SystemExit(f"{image_id} has an invalid rootfs diff ID")
config = item.get("Config") or {}
projection = {
    "schema": "layersentry.generated-image-inspection/v1",
    "id": image_id,
    "runtime_alias": runtime_alias,
    "source_alias": source_alias,
    "ref": exact_ref,
    "config_digest": config_id.removeprefix("sha256:"),
    "repo_digests": repo_digests,
    "os": item["Os"],
    "architecture": item["Architecture"],
    "size_bytes": int(item.get("Size") or 0),
    "rootfs_type": item.get("RootFS", {}).get("Type"),
    "rootfs_diff_ids": layers,
    "runtime_config": {
        "user": config.get("User") or "",
        "entrypoint": config.get("Entrypoint"),
        "cmd": config.get("Cmd"),
        "working_dir": config.get("WorkingDir") or "",
        "labels": dict(sorted((config.get("Labels") or {}).items())),
        "environment": sorted(config.get("Env") or []),
        "exposed_ports": sorted((config.get("ExposedPorts") or {}).keys()),
    },
}
Path(output_path).write_text(
    json.dumps(projection, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
Path(raw_path).unlink()
PY

  sbom="$OUTPUT_DIR/sboms/${image_id}.spdx.json"
  SYFT_CHECK_FOR_APP_UPDATE=false syft "$exact_ref" -o spdx-json > "$sbom"
  python3 - "$sbom" "$image_id" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
image_id = sys.argv[2]
if not path.is_file() or path.stat().st_size <= 0:
    raise SystemExit(f"{image_id} SBOM is empty")
document = json.loads(path.read_text(encoding="utf-8"))
if not str(document.get("spdxVersion", "")).startswith("SPDX-"):
    raise SystemExit(f"{image_id} SBOM has no valid SPDX version")
if not isinstance(document.get("documentNamespace"), str):
    raise SystemExit(f"{image_id} SBOM has no document namespace")
if not isinstance(document.get("packages"), list):
    raise SystemExit(f"{image_id} SBOM has no packages array")
PY

  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$image_id" "$runtime_alias" "$source_alias" "$exact_ref" \
    "images/${image_id}.json" "sboms/${image_id}.spdx.json" \
    >> "$OUTPUT_DIR/images.tsv"
done

bundle_root="$TOP_DIR/package/harvester-os/iso/bundle"
[[ -d "$bundle_root" ]] || fail "generated bundle directory is missing: $bundle_root"
list_count=0
while IFS= read -r -d '' source; do
  relative=${source#"$bundle_root/"}
  destination="$OUTPUT_DIR/image-lists/$relative"
  mkdir -p "$(dirname "$destination")"
  cp "$source" "$destination"
  list_count=$((list_count + 1))
done < <(
  find \
    "$bundle_root/harvester/images-lists" \
    "$bundle_root/rancherd/images" \
    -type f -name '*.txt' -print0 2>/dev/null \
    | sort -z
)
[[ $list_count -gt 0 ]] || fail "no generated ISO image lists were found"

iso_path="$TOP_DIR/dist/artifacts/harvester-v1.0-amd64.iso"
[[ -f "$iso_path" ]] || fail "full-offline ISO candidate is missing: $iso_path"

source_inputs=(
  package/harvester-repo/Dockerfile
  package/harvester-installer/Dockerfile
  package/harvester-os/Dockerfile
  scripts/build
  scripts/build-bundle
  scripts/default
  scripts/package-harvester-repo
  scripts/package-harvester-installer
  scripts/package-harvester-os
  scripts/lib/image
  scripts/provenance/collect_offline_image_set_evidence.sh
  scripts/provenance/review_offline_image_set.py
  scripts/provenance/verify_offline_image_set_binding.py
  scripts/provenance/prepare_finalizer_iso_evidence.sh
  tests/test_offline_image_set_lock.py
  .github/workflows/layersentry-v1.0-offline-image-set-lock.yml
)
: > "$OUTPUT_DIR/source-inputs.tsv"
for relative in "${source_inputs[@]}"; do
  path="$TOP_DIR/$relative"
  [[ -f "$path" ]] || fail "required image-set source input is missing: $relative"
  printf '%s\t%s\t%s\n' "$relative" "$(stat -c '%s' "$path")" \
    "$(sha256sum "$path" | awk '{print $1}')" \
    >> "$OUTPUT_DIR/source-inputs.tsv"
done

python3 - "$OUTPUT_DIR" "$SOURCE_COMMIT" "$BUILD_RUN_ID" "$iso_path" "$TOP_DIR" <<'PY'
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

output = Path(sys.argv[1])
source_commit, build_run_id, iso_raw, top_raw = sys.argv[2:]
iso_path = Path(iso_raw)
top_dir = Path(top_raw)
sha256_re = re.compile(r"^[0-9a-f]{64}$")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha512(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


images = []
for line in (output / "images.tsv").read_text(encoding="utf-8").splitlines():
    image_id, runtime_alias, source_alias, ref, inspect_rel, sbom_rel = line.split("\t")
    inspection = json.loads((output / inspect_rel).read_text(encoding="utf-8"))
    sbom_path = output / sbom_rel
    sbom_document = json.loads(sbom_path.read_text(encoding="utf-8"))
    images.append(
        {
            "id": image_id,
            "aliases": [runtime_alias, source_alias],
            "ref": ref,
            "platform": "linux/amd64",
            "config_digest": inspection["config_digest"],
            "rootfs_diff_ids": inspection["rootfs_diff_ids"],
            "size_bytes": inspection["size_bytes"],
            "runtime_config": inspection["runtime_config"],
            "sbom": {
                "path": sbom_rel,
                "format": "SPDX JSON",
                "bytes": sbom_path.stat().st_size,
                "sha256": sha256(sbom_path),
                "package_count": len(sbom_document.get("packages", [])),
            },
        }
    )

source_inputs = []
for line in (output / "source-inputs.tsv").read_text(encoding="utf-8").splitlines():
    path, size, checksum = line.split("\t")
    if not sha256_re.fullmatch(checksum):
        raise SystemExit(f"invalid source-input checksum for {path}")
    source_inputs.append({"path": path, "bytes": int(size), "sha256": checksum})

list_files = []
observed_aliases = set()
for path in sorted((output / "image-lists").rglob("*.txt")):
    relative = path.relative_to(output).as_posix()
    entries = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        entries.append(value)
        observed_aliases.add(value)
    list_files.append(
        {
            "path": relative,
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
            "entry_count": len(entries),
        }
    )
if not list_files or not observed_aliases:
    raise SystemExit("image-list evidence is empty")

iso = {
    "path": "dist/artifacts/harvester-v1.0-amd64.iso",
    "bytes": iso_path.stat().st_size,
    "sha256": sha256(iso_path),
    "sha512": sha512(iso_path),
}
candidate = {
    "schema": "layersentry.offline-image-set-candidate/v1",
    "source_commit": source_commit,
    "source_tree": __import__("subprocess").check_output(
        ["git", "-C", str(top_dir), "write-tree"], text=True
    ).strip(),
    "build_run_id": int(build_run_id),
    "release_identity": {
        "product": "LayerSentry v1.0",
        "embedded_platform": "Harvester v1.8.2",
    },
    "images": sorted(images, key=lambda item: item["id"]),
    "source_inputs": sorted(source_inputs, key=lambda item: item["path"]),
    "image_lists": {
        "files": list_files,
        "file_count": len(list_files),
        "observed_alias_count": len(observed_aliases),
        "aggregate_sha256": hashlib.sha256(
            "".join(
                f"{item['path']}\t{item['sha256']}\n" for item in list_files
            ).encode("utf-8")
        ).hexdigest(),
    },
    "iso_candidate": iso,
    "dependency_lock_complete": False,
    "installed": False,
    "runtime_qualified": False,
    "release_approved": False,
}
(output / "offline-image-set-candidate.json").write_text(
    json.dumps(candidate, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
(output / "image-lists-manifest.json").write_text(
    json.dumps(candidate["image_lists"], indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
(output / "iso-metadata.json").write_text(
    json.dumps(iso, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
(output / "STATUS.md").write_text(
    f"""# LayerSentry v1.0 generated offline image-set candidate

- Build source commit: `{source_commit}`
- GitHub build run: `{build_run_id}`
- Generated images: {len(images)}
- ISO image-list files: {len(list_files)}
- Observed runtime aliases: {len(observed_aliases)}
- ISO candidate SHA-256: `{iso['sha256']}`
- Dependency lock complete: **false**
- Installation qualified: **false**
- Runtime qualified: **false**
- Release approved: **false**
""",
    encoding="utf-8",
)
PY

(
  cd "$OUTPUT_DIR"
  find . -type f ! -name evidence-files.sha256 -print0 \
    | sort -z \
    | xargs -0 sha256sum > evidence-files.sha256
  sha256sum -c evidence-files.sha256
)

echo "OFFLINE IMAGE-SET EVIDENCE: PASS"
echo "output=$OUTPUT_DIR"
echo "source_commit=$SOURCE_COMMIT"
echo "build_run_id=$BUILD_RUN_ID"
