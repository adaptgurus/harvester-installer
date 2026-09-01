from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BUNDLE = Path(__file__).resolve().parents[1]
VERIFY_PATH = BUNDLE / "scripts/provenance/verify_lock.py"
NORMALIZE_PATH = BUNDLE / "scripts/provenance/normalize_image_list.py"
COVERAGE_PATH = BUNDLE / "scripts/provenance/verify_image_coverage.py"
LOCK_PATH = BUNDLE / "provenance/layersentry-v1.0-harvester-v1.8.2.lock.json"

spec = importlib.util.spec_from_file_location("verify_lock", VERIFY_PATH)
verify_lock = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(verify_lock)


def complete_lock() -> dict:
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    lock["lock_status"] = "complete"
    lock["unresolved"] = []
    lock["container_images"] = [
        {
            "id": "example-image",
            "ref": "docker.io/example/component@sha256:" + "a" * 64,
            "aliases": ["docker.io/example/component:v1.2.3"],
        }
    ]
    checksum = "b" * 64
    lock["charts"] = [
        {
            "id": "example-chart",
            "version": "1.2.3",
            "source": "https://example.invalid/example-chart-1.2.3.tgz",
            "sha256": checksum,
        }
    ]
    lock["packages"] = [
        {
            "id": "example-package",
            "version": "1.2.3-1",
            "source": "https://example.invalid/example-package-1.2.3-1.rpm",
            "sha256": checksum,
        }
    ]
    lock["toolchain_artifacts"] = [
        {
            "id": "example-tool",
            "version": "1.2.3",
            "source": "https://example.invalid/example-tool-1.2.3.tar.gz",
            "sha256": checksum,
        }
    ]
    return lock


class VerifyLockTests(unittest.TestCase):
    def validate(self, lock: dict, *, require_complete: bool = True):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lock.json"
            path.write_text(json.dumps(lock), encoding="utf-8")
            result, report = verify_lock.validate_lock(path, require_complete, None, False)
            return result, report

    def test_shipped_lock_is_valid_but_incomplete(self):
        lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        result, report = self.validate(lock, require_complete=False)
        self.assertEqual([], result.errors)
        self.assertFalse(report["eligible_for_full_offline_build"])

    def test_shipped_lock_blocks_full_build(self):
        lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        result, _ = self.validate(lock, require_complete=True)
        self.assertTrue(result.errors)
        self.assertTrue(any("remains blocked" in error for error in result.errors))

    def test_synthetic_complete_lock_passes(self):
        result, report = self.validate(complete_lock())
        self.assertEqual([], result.errors)
        self.assertTrue(report["eligible_for_full_offline_build"])

    def test_latest_image_is_rejected(self):
        lock = complete_lock()
        lock["container_images"][0]["ref"] = "docker.io/example/component:latest"
        result, _ = self.validate(lock)
        self.assertTrue(any("repository@sha256" in error for error in result.errors))

    def test_head_image_is_rejected(self):
        lock = complete_lock()
        lock["container_images"][0]["ref"] = "docker.io/example/component:v1.8-head"
        result, _ = self.validate(lock)
        self.assertTrue(result.errors)

    def test_wrong_addons_commit_is_rejected(self):
        lock = complete_lock()
        for entry in lock["source_locks"]:
            if entry["component"] == "harvester-addons":
                entry["commit"] = "c" * 40
        result, _ = self.validate(lock)
        self.assertTrue(any("harvester-addons" in error for error in result.errors))

    def test_product_platform_conflation_is_rejected(self):
        lock = complete_lock()
        lock["release_identity"]["product"]["version"] = "v1.8.2"
        result, _ = self.validate(lock)
        self.assertTrue(any("product.version" in error for error in result.errors))


class ImageListTests(unittest.TestCase):
    def test_normalizer_rejects_untagged_and_latest(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "images.txt"
            target = Path(tmp) / "normalized.txt"
            source.write_text("example/no-tag\nexample/bad:latest\n", encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(NORMALIZE_PATH), str(source), str(target)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            self.assertNotEqual(0, proc.returncode)
            self.assertIn("automatic :latest substitution is forbidden", proc.stdout)

    def test_digest_coverage_passes_for_locked_alias(self):
        lock = complete_lock()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lock_path = root / "lock.json"
            lists = root / "lists"
            lists.mkdir()
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            (lists / "images.txt").write_text(
                "docker.io/example/component:v1.2.3\n", encoding="utf-8"
            )
            proc = subprocess.run(
                [sys.executable, str(COVERAGE_PATH), str(lock_path), str(lists)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            self.assertEqual(0, proc.returncode, proc.stdout)

    def test_digest_coverage_rejects_unknown_alias(self):
        lock = complete_lock()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lock_path = root / "lock.json"
            lists = root / "lists"
            lists.mkdir()
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            (lists / "images.txt").write_text("docker.io/unknown/image:v1\n", encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(COVERAGE_PATH), str(lock_path), str(lists)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            self.assertNotEqual(0, proc.returncode)
            self.assertIn("not covered by the digest lock", proc.stdout)


class RepositoryScanTests(unittest.TestCase):
    def test_git_head_tokens_are_not_treated_as_floating_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "script.sh"
            path.write_text(
                "git rev-parse HEAD\n"
                "git -C repo checkout --detach FETCH_HEAD\n"
                "git show -s --format=%ct HEAD\n",
                encoding="utf-8",
            )
            result = verify_lock.Validation()
            verify_lock.scan_file(path, "script.sh", result, set())
            self.assertEqual([], result.errors, "\n".join(result.errors))

    def test_head_derived_image_remains_rejected_by_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "script.sh"
            path.write_text(
                'docker pull docker.io/rancher/harvester:v1.8-head\n',
                encoding="utf-8",
            )
            result = verify_lock.Validation()
            verify_lock.scan_file(path, "script.sh", result, set())
            self.assertTrue(any("head-derived" in error for error in result.errors))

    def test_post_patch_layout_passes_static_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for relative in (
                ".github/workflows/layersentry-v1.0-provenance-gate.yml",
                ".github/workflows/layersentry-v1.0-full-offline-iso.yml",
                "scripts/provenance/verify_lock.py",
                "scripts/provenance/normalize_image_list.py",
                "scripts/provenance/verify_image_coverage.py",
                "scripts/provenance/prepare-release-evidence.sh",
            ):
                source = BUNDLE / relative
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read_bytes())

            files = {
                "scripts/prepare-production-iso-evidence.sh": "#!/bin/bash\nset -e\n",
                "scripts/qualify-production-iso-evidence.sh": "#!/bin/bash\nset -e\n",
                "scripts/build": (
                    "#!/bin/bash\n"
                    "HARVESTER_COMMIT=5320dfa6770f63406750e7c64b24ed87c543e6ad\n"
                    "ADDONS_COMMIT=f60d73d894e00f18d5e11cd21a301ed1b016631c\n"
                    "git fetch --depth 1 origin \"${HARVESTER_COMMIT}\"\n"
                ),
                "scripts/build-bundle": (
                    "#!/bin/bash\n"
                    "HARVESTER_COMMIT=5320dfa6770f63406750e7c64b24ed87c543e6ad\n"
                    "ADDONS_COMMIT=f60d73d894e00f18d5e11cd21a301ed1b016631c\n"
                    "python3 scripts/provenance/normalize_image_list.py input output\n"
                ),
                "scripts/package-harvester-os": (
                    "#!/bin/bash\n"
                    "ADDONS_COMMIT=f60d73d894e00f18d5e11cd21a301ed1b016631c\n"
                ),
                "scripts/lib/addon": (
                    "#!/bin/bash\n"
                    "git fetch --depth 1 origin \"${commit}\"\n"
                ),
            }
            for relative, content in files.items():
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")

            result = verify_lock.Validation()
            verify_lock.scan_repository(root, result, complete_lock())
            self.assertEqual([], result.errors, "\n".join(result.errors))


if __name__ == "__main__":
    unittest.main()
