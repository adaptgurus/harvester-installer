#!/usr/bin/env python3
"""Validate an image list without inventing :latest aliases.

The script preserves operational tag aliases because Harvester's native bundle
format consumes them, but it rejects untagged, latest, and head-derived aliases.
Every accepted alias must later be mapped to an OCI digest in the provenance
lock and checked by verify_image_coverage.py.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")


def validate_alias(value: str) -> str | None:
    lower = value.lower()
    if any(ch.isspace() for ch in value):
        return "contains whitespace"
    if lower.endswith(":latest"):
        return "uses the forbidden latest tag"
    if re.search(r"(?:^|[-:/.])head(?:$|[-:/.])", lower):
        return "uses a forbidden head-derived tag"
    if DIGEST_RE.search(value):
        return None
    last = value.rsplit("/", 1)[-1]
    if ":" not in last:
        return "has no tag or digest; automatic :latest substitution is forbidden"
    tag = last.rsplit(":", 1)[1]
    if not tag:
        return "has an empty tag"
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    errors: list[str] = []
    accepted: list[str] = []
    for number, raw in enumerate(args.input.read_text(encoding="utf-8").splitlines(), 1):
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        error = validate_alias(value)
        if error:
            errors.append(f"{args.input}:{number}: {value!r} {error}")
        else:
            accepted.append(value)

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(accepted) + ("\n" if accepted else ""), encoding="utf-8")
    print(f"Validated {len(accepted)} image aliases without latest/head substitution")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
