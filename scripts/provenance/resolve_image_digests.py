#!/usr/bin/env python3
"""Resolve approved image aliases into a candidate immutable-digest lock.

This is a capture utility, not a release gate. It requires `skopeo`, rejects
latest/head/untagged aliases, and writes candidate JSON for review. It never
marks the main provenance lock complete.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def validate_alias(alias: str) -> None:
    lower = alias.lower()
    if lower.endswith(":latest"):
        raise ValueError("latest is forbidden")
    if re.search(r"(?:^|[-:/.])head(?:$|[-:/.])", lower):
        raise ValueError("head-derived tags are forbidden")
    if "@sha256:" in alias:
        return
    last = alias.rsplit("/", 1)[-1]
    if ":" not in last or not last.rsplit(":", 1)[1]:
        raise ValueError("an explicit non-latest tag or digest is required")


def repository_without_tag(alias: str) -> str:
    if "@" in alias:
        return alias.split("@", 1)[0]
    slash = alias.rfind("/")
    colon = alias.rfind(":")
    if colon > slash:
        return alias[:colon]
    return alias


def read_aliases(paths: list[Path]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            value = raw.strip()
            if not value or value.startswith("#"):
                continue
            try:
                validate_alias(value)
            except ValueError as exc:
                raise ValueError(f"{path}:{number}: {value!r}: {exc}") from exc
            values.add(value)
    return sorted(values)


def resolve(alias: str) -> str:
    proc = subprocess.run(
        ["skopeo", "inspect", "--format", "{{.Digest}}", f"docker://{alias}"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"unable to resolve {alias}: {proc.stderr.strip()}")
    digest = proc.stdout.strip()
    if not DIGEST_RE.fullmatch(digest):
        raise RuntimeError(f"registry returned an invalid digest for {alias}: {digest!r}")
    return f"{repository_without_tag(alias)}@{digest}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-list", action="append", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    if shutil.which("skopeo") is None:
        print("ERROR: skopeo is required", file=sys.stderr)
        return 2

    try:
        aliases = read_aliases(args.image_list)
        grouped: dict[str, list[str]] = defaultdict(list)
        for alias in aliases:
            immutable = resolve(alias)
            grouped[immutable].append(alias)
    except (ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    entries = []
    for index, immutable in enumerate(sorted(grouped), 1):
        repo = immutable.split("@", 1)[0]
        image_id = re.sub(r"[^a-z0-9]+", "-", repo.lower()).strip("-")
        entries.append(
            {
                "id": f"{image_id}-{index:04d}",
                "ref": immutable,
                "aliases": sorted(grouped[immutable]),
            }
        )

    output = {
        "schema": "layersentry.container-image-lock-candidate/v1",
        "captured_at": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "resolver": "skopeo inspect",
        "review_required": True,
        "container_images": entries,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Resolved {len(aliases)} aliases into {len(entries)} immutable image entries")
    print("Review registry ownership and signatures before copying entries into the release lock.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
