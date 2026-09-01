from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "provenance" / "review_external_discovery.py"
SPEC = importlib.util.spec_from_file_location("review_external_discovery", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

SOURCE_COMMIT = "1" * 40


class ReviewExternalDiscoveryTests(unittest.TestCase):
    def base_documents(self):
        aliases = {
            "docker.io/rancher/example:v1",
            "registry.k8s.io/descheduler/descheduler:v1",
        }
        candidate = {
            "schema": "layersentry.container-image-lock-candidate/v1",
            "source_commit": SOURCE_COMMIT,
            "complete": True,
            "review_required": True,
            "resolver": "docker buildx imagetools inspect",
            "alias_count": 2,
            "resolved_alias_count": 2,
            "unresolved_alias_count": 0,
            "container_images": [
                {
                    "id": "docker-io-rancher-example",
                    "ref": "docker.io/rancher/example@sha256:" + "a" * 64,
                    "aliases": ["docker.io/rancher/example:v1"],
                },
                {
                    "id": "registry-k8s-io-descheduler-descheduler",
                    "ref": "registry.k8s.io/descheduler/descheduler@sha256:" + "b" * 64,
                    "aliases": ["registry.k8s.io/descheduler/descheduler:v1"],
                },
            ],
        }
        failures = {
            "schema": "layersentry.container-image-resolution-failures/v1",
            "source_commit": SOURCE_COMMIT,
            "failure_count": 0,
            "failures": [],
        }
        discovery = {
            "schema": "layersentry.provenance-discovery/v1",
            "source_commit": SOURCE_COMMIT,
            "release_approved": False,
            "review_required": True,
            "source_commits": MODULE.EXPECTED_SOURCE_COMMITS,
            "verified_tool_artifacts": [
                {
                    "id": "yq-linux-amd64",
                    "version": "v1.0.0",
                    "source": "https://example.invalid/yq-v1.0.0",
                    "sha256": "c" * 64,
                }
            ],
        }
        lock = {
            "schema": "layersentry.provenance-lock/v1",
            "lock_status": "incomplete",
            "container_images": [],
            "toolchain_artifacts": [],
            "unresolved": [
                {
                    "id": "trivy-scanner-image",
                    "kind": "container-image",
                    "required_resolution": "resolve",
                },
                {
                    "id": "bci-evidence-verifier-image",
                    "kind": "container-image",
                    "required_resolution": "resolve",
                },
                {
                    "id": "harvester-offline-image-set",
                    "kind": "container-image-set",
                    "required_resolution": "resolve",
                },
                {
                    "id": "remaining-input",
                    "kind": "package-set",
                    "required_resolution": "resolve",
                },
            ],
        }
        return aliases, candidate, failures, discovery, lock

    def test_canonical_alias_and_registry_port(self):
        self.assertEqual(
            MODULE.canonical_alias("rancher/example:v1"),
            "docker.io/rancher/example:v1",
        )
        self.assertEqual(
            MODULE.repository_without_tag("registry.example:5000/ns/image:v1"),
            "registry.example:5000/ns/image",
        )

    def test_forbidden_aliases_are_rejected(self):
        for alias in (
            "docker.io/example/image:latest",
            "docker.io/example/image:v1.8-head",
            "docker.io/example/image",
        ):
            with self.subTest(alias=alias):
                self.assertIsNotNone(MODULE.validate_alias(alias))

    def test_valid_documents_merge_but_lock_stays_incomplete(self):
        aliases, candidate, failures, discovery, lock = self.base_documents()
        result = MODULE.Review()
        images, tools = MODULE.validate_discovery(
            candidate, failures, discovery, aliases, SOURCE_COMMIT, result
        )
        self.assertEqual(result.errors, [])
        merged = MODULE.merge_lock(
            lock,
            images,
            tools,
            SOURCE_COMMIT,
            "d" * 64,
            "e" * 64,
            "provenance/reviews/report.json",
            result,
        )
        self.assertEqual(result.errors, [])
        self.assertEqual(merged["lock_status"], "incomplete")
        self.assertEqual(len(merged["container_images"]), 2)
        self.assertEqual(len(merged["toolchain_artifacts"]), 1)
        unresolved_ids = {item["id"] for item in merged["unresolved"]}
        self.assertNotIn("trivy-scanner-image", unresolved_ids)
        self.assertNotIn("bci-evidence-verifier-image", unresolved_ids)
        self.assertIn("harvester-offline-image-set", unresolved_ids)
        self.assertIn("remaining-input", unresolved_ids)

    def test_unapproved_repository_is_rejected(self):
        aliases, candidate, failures, discovery, _ = self.base_documents()
        aliases.remove("docker.io/rancher/example:v1")
        aliases.add("evil.invalid/example:v1")
        candidate["container_images"][0] = {
            "id": "evil-invalid-example",
            "ref": "evil.invalid/example@sha256:" + "a" * 64,
            "aliases": ["evil.invalid/example:v1"],
        }
        result = MODULE.Review()
        MODULE.validate_discovery(
            candidate, failures, discovery, aliases, SOURCE_COMMIT, result
        )
        self.assertTrue(any("outside the approved registry scope" in item for item in result.errors))

    def test_cli_apply_writes_report_and_lock(self):
        aliases, candidate, failures, discovery, lock = self.base_documents()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {
                "candidate": root / "candidate.json",
                "failures": root / "failures.json",
                "aliases": root / "aliases.txt",
                "input": root / "input.json",
                "lock": root / "lock.json",
                "report": root / "report.json",
            }
            paths["candidate"].write_text(json.dumps(candidate), encoding="utf-8")
            paths["failures"].write_text(json.dumps(failures), encoding="utf-8")
            paths["aliases"].write_text("\n".join(sorted(aliases)) + "\n", encoding="utf-8")
            paths["input"].write_text(json.dumps(discovery), encoding="utf-8")
            paths["lock"].write_text(json.dumps(lock), encoding="utf-8")
            rc = MODULE.main(
                [
                    "--candidate", str(paths["candidate"]),
                    "--failures", str(paths["failures"]),
                    "--aliases", str(paths["aliases"]),
                    "--input-discovery", str(paths["input"]),
                    "--lock", str(paths["lock"]),
                    "--source-commit", SOURCE_COMMIT,
                    "--report", str(paths["report"]),
                    "--apply",
                ]
            )
            self.assertEqual(rc, 0)
            report = json.loads(paths["report"].read_text(encoding="utf-8"))
            merged = json.loads(paths["lock"].read_text(encoding="utf-8"))
            self.assertTrue(report["eligible_for_incomplete_lock_merge"])
            self.assertTrue(report["applied"])
            self.assertFalse(report["release_approved"])
            self.assertEqual(merged["lock_status"], "incomplete")


if __name__ == "__main__":
    unittest.main()
