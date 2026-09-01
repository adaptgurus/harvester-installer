#!/usr/bin/env python3
"""Verify that every ISO image alias is covered by one immutable OCI digest lock."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

DIGEST_RE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")


def canonical_alias(value: str) -> str:
    value = value.strip()
    if value.startswith("docker.io/"):
        value = value[len("docker.io/") :]
    if "/" not in value:
        value = f"library/{value}"
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("lock_file", type=Path)
    parser.add_argument("image_lists_dir", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    lock = json.loads(args.lock_file.read_text(encoding="utf-8"))
    alias_to_digest: dict[str, str] = {}
    errors: list[str] = []

    for index, image in enumerate(lock.get("container_images", [])):
        ref = str(image.get("ref", ""))
        if not DIGEST_RE.fullmatch(ref):
            errors.append(f"container_images[{index}] has no immutable OCI digest: {ref!r}")
            continue
        aliases = image.get("aliases", [])
        if not isinstance(aliases, list) or not aliases:
            errors.append(f"container_images[{index}] must list at least one runtime alias")
            continue
        for alias in aliases:
            key = canonical_alias(str(alias))
            previous = alias_to_digest.get(key)
            if previous and previous != ref:
                errors.append(f"runtime alias {alias!r} maps to multiple digests")
            alias_to_digest[key] = ref

    observed: dict[str, list[str]] = {}
    for path in sorted(args.image_lists_dir.rglob("*.txt")):
        for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            value = raw.strip()
            if not value or value.startswith("#"):
                continue
            lower = value.lower()
            if lower.endswith(":latest") or re.search(r"(?:^|[-:/.])head(?:$|[-:/.])", lower):
                errors.append(f"{path}:{number}: forbidden latest/head image alias {value!r}")
            key = canonical_alias(value)
            observed.setdefault(key, []).append(f"{path}:{number}")
            if key not in alias_to_digest and "@sha256:" not in key:
                errors.append(f"{path}:{number}: image alias is not covered by the digest lock: {value}")

    if not observed:
        errors.append(f"no image entries found under {args.image_lists_dir}")

    report = {
        "schema": "layersentry.image-coverage-report/v1",
        "eligible": not errors,
        "locked_alias_count": len(alias_to_digest),
        "observed_alias_count": len(observed),
        "errors": errors,
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    for error in errors:
        print(f"ERROR: {error}")
    if errors:
        print(f"IMAGE COVERAGE: FAIL ({len(errors)} error(s))")
        return 1
    print(f"IMAGE COVERAGE: PASS ({len(observed)} aliases mapped to immutable digests)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
