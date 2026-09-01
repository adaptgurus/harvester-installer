#!/usr/bin/env python3
"""Resolve a generated LayerSentry image alias inventory with Docker Buildx.

This is a discovery utility, not a release gate. It never edits the release
lock and never treats partial registry resolution as production approval.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import time
from collections import defaultdict
from pathlib import Path
from typing import Iterable

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
DIGEST_LINE_RE = re.compile(r"^\s*Digest:\s*(sha256:[0-9a-f]{64})\s*$", re.MULTILINE)


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


def canonical_alias(alias: str) -> str:
    alias = alias.strip()
    if not alias:
        return alias
    first = alias.split("/", 1)[0]
    if "/" not in alias or ("." not in first and ":" not in first and first != "localhost"):
        return f"docker.io/{alias}"
    return alias


def repository_without_tag(alias: str) -> str:
    alias = canonical_alias(alias)
    if "@" in alias:
        return alias.split("@", 1)[0]
    slash = alias.rfind("/")
    colon = alias.rfind(":")
    if colon > slash:
        return alias[:colon]
    return alias


def read_aliases(paths: Iterable[Path]) -> list[str]:
    values: set[str] = set()
    for path in paths:
        for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            value = raw.strip()
            if not value or value.startswith("#"):
                continue
            value = canonical_alias(value)
            try:
                validate_alias(value)
            except ValueError as exc:
                raise ValueError(f"{path}:{number}: {value!r}: {exc}") from exc
            values.add(value)
    return sorted(values)


def inspect(alias: str) -> tuple[str | None, str]:
    proc = subprocess.run(
        ["docker", "buildx", "imagetools", "inspect", alias],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    output = proc.stdout.strip()
    if proc.returncode != 0:
        return None, output
    match = DIGEST_LINE_RE.search(output)
    if not match:
        return None, f"registry response contained no valid Digest line: {output[:1000]}"
    digest = match.group(1)
    if not DIGEST_RE.fullmatch(digest):
        return None, f"registry returned an invalid digest: {digest!r}"
    return digest, ""


def resolve(alias: str, attempts: int, retry_delay: float) -> tuple[str | None, str, int]:
    last_error = ""
    for attempt in range(1, attempts + 1):
        digest, detail = inspect(alias)
        if digest is not None:
            return f"{repository_without_tag(alias)}@{digest}", "", attempt
        last_error = detail
        if attempt < attempts:
            time.sleep(retry_delay * attempt)
    return None, last_error, attempts


def stable_id(repository: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", repository.lower()).strip("-")
    return value or "image"


def utc_now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-list", action="append", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--failures", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--retry-delay", type=float, default=2.0)
    args = parser.parse_args()

    if args.attempts < 1:
        parser.error("--attempts must be at least 1")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
        parser.error("--source-commit must be an exact 40-hex commit")

    aliases = read_aliases(args.image_list)
    grouped: dict[str, list[str]] = defaultdict(list)
    failures: list[dict[str, object]] = []

    for index, alias in enumerate(aliases, 1):
        print(f"[{index}/{len(aliases)}] resolving {alias}", flush=True)
        immutable, error, attempts = resolve(alias, args.attempts, args.retry_delay)
        if immutable is None:
            failures.append(
                {"alias": alias, "attempts": attempts, "error": error[:4000]}
            )
            print(f"WARNING: unresolved {alias}: {error[:300]}", flush=True)
            continue
        grouped[immutable].append(alias)

    entries: list[dict[str, object]] = []
    used_ids: set[str] = set()
    for immutable in sorted(grouped):
        repository = immutable.split("@", 1)[0]
        base_id = stable_id(repository)
        image_id = base_id
        suffix = 2
        while image_id in used_ids:
            image_id = f"{base_id}-{suffix}"
            suffix += 1
        used_ids.add(image_id)
        entries.append(
            {
                "id": image_id,
                "ref": immutable,
                "aliases": sorted(grouped[immutable]),
            }
        )

    captured_at = utc_now()
    output = {
        "schema": "layersentry.container-image-lock-candidate/v1",
        "captured_at": captured_at,
        "source_commit": args.source_commit,
        "resolver": "docker buildx imagetools inspect",
        "review_required": True,
        "complete": not failures,
        "alias_count": len(aliases),
        "resolved_alias_count": len(aliases) - len(failures),
        "unresolved_alias_count": len(failures),
        "container_images": entries,
    }
    failure_output = {
        "schema": "layersentry.container-image-resolution-failures/v1",
        "captured_at": captured_at,
        "source_commit": args.source_commit,
        "failure_count": len(failures),
        "failures": failures,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.failures.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.failures.write_text(
        json.dumps(failure_output, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"Resolved {len(aliases) - len(failures)}/{len(aliases)} aliases; "
        f"{len(failures)} remain unresolved"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
