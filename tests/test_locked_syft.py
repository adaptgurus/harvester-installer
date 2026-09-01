from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DESCRIPTOR_PATH = ROOT / "provenance/layersentry-v1.0-syft-tool.json"
REVIEW_PATH = ROOT / "scripts/provenance/review_syft_tool.py"
VERIFY_PATH = ROOT / "scripts/provenance/verify_staged_syft.py"
INSTALLER_PATH = ROOT / "scripts/provenance/install_locked_syft.sh"
WORKFLOW_PATH = ROOT / ".github/workflows/layersentry-v1.0-full-offline-iso.yml"
EVIDENCE_PATH = ROOT / "scripts/provenance/prepare-release-evidence.sh"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


review_syft = load_module("review_syft", REVIEW_PATH)
verify_staged = load_module("verify_staged", VERIFY_PATH)


class LockedSyftReviewTests(unittest.TestCase):
    def fixture(self, root: Path):
        descriptor = json.loads(DESCRIPTOR_PATH.read_text(encoding="utf-8"))
        descriptor_path = root / "descriptor.json"
        descriptor_path.write_text(json.dumps(descriptor, indent=2) + "\n", encoding="utf-8")
        validation = {
            "schema": "layersentry.locked-tool-validation/v1",
            "id": descriptor["id"],
            "version": descriptor["version"],
            "source": descriptor["source"],
            "archive_sha256": descriptor["sha256"],
            "archive_bytes": descriptor["bytes"],
            "binary_sha256": "b" * 64,
            "binary_bytes": 123456,
            "descriptor_sha256": review_syft.sha256_file(descriptor_path),
            "version_verified": True,
            "official_checksum_manifest_verified": True,
            "archive_safety_verified": True,
        }
        validation_path = root / "validation.json"
        validation_path.write_text(json.dumps(validation, indent=2) + "\n", encoding="utf-8")
        lock = {
            "schema": "layersentry.provenance-lock/v1",
            "lock_status": "incomplete",
            "release_identity": {
                "product": {"version": "v1.0"},
                "embedded_platform": {"version": "v1.8.2"},
            },
            "toolchain_artifacts": [
                {
                    "id": "existing-tool",
                    "version": "v1.0.0",
                    "source": "https://example.invalid/tool-v1.0.0.tar.gz",
                    "sha256": "a" * 64,
                }
            ],
            "unresolved": [
                {
                    "id": review_syft.UNRESOLVED_ID,
                    "kind": "toolchain-artifact",
                    "required_resolution": "lock Syft",
                },
                {
                    "id": "other",
                    "kind": "toolchain-set",
                    "required_resolution": "lock remaining tools",
                },
            ],
        }
        lock_path = root / "lock.json"
        lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
        return descriptor_path, validation_path, lock_path

    def test_apply_merges_syft_but_keeps_lock_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            descriptor, validation, lock = self.fixture(Path(tmp))
            updated, report = review_syft.review(
                descriptor, validation, lock, "c" * 40, apply=True
            )
            self.assertEqual("incomplete", updated["lock_status"])
            self.assertEqual(
                ["other"], [item["id"] for item in updated["unresolved"]]
            )
            syft_entries = [
                item
                for item in updated["toolchain_artifacts"]
                if item["id"] == "syft-linux-amd64"
            ]
            self.assertEqual(1, len(syft_entries))
            self.assertEqual("b" * 64, syft_entries[0]["binary_sha256"])
            self.assertFalse(report["production_lock_complete"])
            self.assertFalse(report["release_approved"])
            self.assertEqual(updated, json.loads(lock.read_text(encoding="utf-8")))

    def test_descriptor_digest_drift_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            descriptor, validation, lock = self.fixture(Path(tmp))
            value = json.loads(descriptor.read_text(encoding="utf-8"))
            value["sha256"] = "d" * 64
            descriptor.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(review_syft.ReviewError):
                review_syft.review(
                    descriptor, validation, lock, "c" * 40, apply=False
                )


class StagedSyftVerifierTests(unittest.TestCase):
    def test_exact_executable_passes_and_mutation_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "syft"
            binary.write_text(
                "#!/bin/sh\nprintf 'Application: syft\\nVersion: 1.51.1\\n'\n",
                encoding="utf-8",
            )
            binary.chmod(0o755)
            descriptor = json.loads(DESCRIPTOR_PATH.read_text(encoding="utf-8"))
            entry = {
                "id": descriptor["id"],
                "name": descriptor["name"],
                "version": descriptor["version"],
                "source": descriptor["source"],
                "sha256": descriptor["sha256"],
                "bytes": descriptor["bytes"],
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "binary_bytes": binary.stat().st_size,
            }
            lock = {
                "schema": "layersentry.provenance-lock/v1",
                "toolchain_artifacts": [entry],
            }
            lock_path = root / "lock.json"
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            report = verify_staged.verify(lock_path, binary)
            self.assertTrue(report["verified"])
            with binary.open("a", encoding="utf-8") as handle:
                handle.write("# mutation\n")
            with self.assertRaises(verify_staged.VerificationError):
                verify_staged.verify(lock_path, binary)


class LockedSyftIntegrationTests(unittest.TestCase):
    def test_descriptor_and_installer_are_immutable(self):
        descriptor = json.loads(DESCRIPTOR_PATH.read_text(encoding="utf-8"))
        self.assertEqual(review_syft.EXPECTED["source"], descriptor["source"])
        self.assertEqual(review_syft.EXPECTED["sha256"], descriptor["sha256"])
        self.assertEqual(review_syft.EXPECTED["bytes"], descriptor["bytes"])
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertNotIn("releases/latest", json.dumps(descriptor).lower())
        self.assertIn('"/releases/latest" in parsed.path.lower()', installer)
        self.assertIn("official checksum manifest", installer)

    def test_full_offline_path_verifies_syft_before_build(self):
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        verification = workflow.index("verify_staged_syft.py")
        build = workflow.index("make default")
        self.assertLess(verification, build)
        self.assertIn('SYFT_CHECK_FOR_APP_UPDATE: "false"', workflow)

    def test_release_evidence_generates_source_sbom(self):
        evidence = EVIDENCE_PATH.read_text(encoding="utf-8")
        self.assertIn("verify_staged_syft.py", evidence)
        self.assertIn('git -C "$root_dir" archive --format=tar "$source_commit"', evidence)
        self.assertIn("spdx-json=$output_dir/source-sbom.spdx.json", evidence)


if __name__ == "__main__":
    unittest.main()
