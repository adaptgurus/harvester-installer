from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts/provenance/review_controller_image.py"
)
spec = importlib.util.spec_from_file_location("review_controller_image", MODULE_PATH)
assert spec and spec.loader
review_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review_module)


class ControllerImageReviewTests(unittest.TestCase):
    source_commit = "1" * 40
    image_digest = "2" * 64

    def candidate(self) -> dict:
        source_inputs = [
            {"path": path, "bytes": 10, "sha256": "3" * 64}
            for path in sorted(review_module.EXPECTED_SOURCE_INPUTS)
        ]
        return {
            "schema": "layersentry.controller-image-candidate/v1",
            "source_commit": self.source_commit,
            "version": "v1.0.0",
            "build_epoch": 1788307200,
            "release_identity": {
                "product": "LayerSentry v1.0",
                "embedded_platform": "Harvester v1.8.2",
            },
            "controller_image": {
                "id": "layersentry-controller",
                "aliases": [
                    "ghcr.io/adaptgurus/layersentry-controller:v1.0.0",
                    "ghcr.io/adaptgurus/layersentry-controller:source-"
                    + self.source_commit,
                ],
                "ref": (
                    "ghcr.io/adaptgurus/layersentry-controller@sha256:"
                    + self.image_digest
                ),
            },
            "platform": "linux/amd64",
            "binary": {
                "path": "layersentry-controller-linux-amd64",
                "bytes": 1000,
                "sha256": "4" * 64,
            },
            "image_config_digest": "5" * 64,
            "rootfs_diff_ids": ["sha256:" + "6" * 64],
            "runtime_user": "65532:65532",
            "entrypoint": ["/usr/local/bin/layersentry-controller"],
            "cmd": ["--listen", "0.0.0.0:9443"],
            "image_labels": {
                "org.opencontainers.image.version": "v1.0.0",
                "org.opencontainers.image.revision": self.source_commit,
                "org.opencontainers.image.created": "1788307200",
                "io.layersentry.product": "LayerSentry",
                "io.layersentry.product-version": "v1.0",
                "io.layersentry.embedded-platform": "Harvester",
                "io.layersentry.embedded-platform-version": "v1.8.2",
                "io.layersentry.lifecycle": "BUNDLED_NOT_INSTALLED",
                "io.layersentry.runtime-qualified": "false",
                "io.layersentry.release-approved": "false",
            },
            "source_inputs": source_inputs,
            "sbom": {
                "path": "controller-sbom.spdx.json",
                "bytes": 500,
                "sha256": "7" * 64,
                "format": "SPDX JSON",
            },
            "bundled": True,
            "installed": False,
            "runtime_qualified": False,
            "release_approved": False,
        }

    def lock(self) -> dict:
        return {
            "schema": "layersentry.provenance-lock/v1",
            "lock_status": "incomplete",
            "release_identity": {
                "product": {"version": "v1.0"},
                "embedded_platform": {"version": "v1.8.2"},
            },
            "source_locks": [
                {
                    "component": "harvester-core",
                    "repository": "https://github.com/harvester/harvester.git",
                    "commit": "8" * 40,
                }
            ],
            "container_images": [
                {
                    "id": "existing-image",
                    "aliases": ["docker.io/example/image:v1"],
                    "ref": "docker.io/example/image@sha256:" + "9" * 64,
                }
            ],
            "unresolved": [
                {"id": "layersentry-controller-image"},
                {"id": "harvester-offline-image-set"},
            ],
        }

    @staticmethod
    def write_json(path: Path, value: dict) -> None:
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def test_apply_adds_source_and_image_but_keeps_lock_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            candidate_path = root / "candidate.json"
            lock_path = root / "lock.json"
            self.write_json(candidate_path, self.candidate())
            self.write_json(lock_path, self.lock())
            updated, report = review_module.review(
                candidate_path,
                lock_path,
                self.source_commit,
                True,
            )
            self.assertEqual(updated["lock_status"], "incomplete")
            self.assertEqual(
                report["remaining_unresolved_ids"],
                ["harvester-offline-image-set"],
            )
            controller_sources = [
                item
                for item in updated["source_locks"]
                if item["component"] == "layersentry-controller"
            ]
            controller_images = [
                item
                for item in updated["container_images"]
                if item["id"] == "layersentry-controller"
            ]
            self.assertEqual(len(controller_sources), 1)
            self.assertEqual(len(controller_images), 1)
            self.assertFalse(updated["reviewed_controller_image"]["runtime_qualified"])

    def test_rejects_tag_only_image(self) -> None:
        candidate = self.candidate()
        candidate["controller_image"]["ref"] = (
            "ghcr.io/adaptgurus/layersentry-controller:v1.0.0"
        )
        with self.assertRaises(review_module.ReviewError):
            review_module.validate_candidate(candidate, self.source_commit)

    def test_rejects_missing_source_input(self) -> None:
        candidate = self.candidate()
        candidate["source_inputs"].pop()
        with self.assertRaises(review_module.ReviewError):
            review_module.validate_candidate(candidate, self.source_commit)

    def test_rejects_replacement_after_marker_removed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            candidate_path = root / "candidate.json"
            lock_path = root / "lock.json"
            lock = self.lock()
            lock["unresolved"] = [
                item
                for item in lock["unresolved"]
                if item["id"] != "layersentry-controller-image"
            ]
            self.write_json(candidate_path, self.candidate())
            self.write_json(lock_path, lock)
            with self.assertRaises(review_module.ReviewError):
                review_module.review(
                    candidate_path,
                    lock_path,
                    self.source_commit,
                    False,
                )


if __name__ == "__main__":
    unittest.main()
