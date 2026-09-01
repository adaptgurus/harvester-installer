from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts/provenance/review_builder_toolchain.py"
spec = importlib.util.spec_from_file_location("review_builder_toolchain", MODULE_PATH)
assert spec and spec.loader
review_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review_module)


class BuilderToolchainReviewTests(unittest.TestCase):
    source_commit = "1" * 40
    digest = "2" * 64
    builder_ref = (
        "ghcr.io/adaptgurus/layersentry-full-offline-builder@sha256:" + digest
    )

    def candidate(self) -> dict:
        artifacts = []
        for item_id in sorted(review_module.EXPECTED_ARTIFACT_IDS):
            if item_id in {
                "layersentry-builder-source-contract",
                "layersentry-builder-dockerfile",
            }:
                source = (
                    "git+https://github.com/adaptgurus/harvester-installer.git@"
                    f"{self.source_commit}#{item_id}"
                )
            else:
                source = f"oci-file://{self.builder_ref}#/usr/bin/{item_id}"
            artifacts.append(
                {
                    "id": item_id,
                    "version": "v1-test",
                    "source": source,
                    "sha256": "3" * 64,
                }
            )
        return {
            "schema": "layersentry.builder-toolchain-candidate/v1",
            "source_commit": self.source_commit,
            "release_identity": {
                "product": "LayerSentry v1.0",
                "embedded_platform": "Harvester v1.8.2",
            },
            "platform": "linux/amd64",
            "builder_image": {
                "id": review_module.BUILDER_IMAGE_ID,
                "aliases": [
                    "ghcr.io/adaptgurus/layersentry-full-offline-builder:source-"
                    + self.source_commit
                ],
                "ref": self.builder_ref,
            },
            "rootfs_layer_count": 5,
            "toolchain_artifacts": artifacts,
            "tool_count": len(review_module.TOOL_IDS),
            "source_input_count": 12,
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
            "container_images": [],
            "toolchain_artifacts": [
                {
                    "id": "existing-tool",
                    "version": "v1",
                    "source": "https://example.invalid/tool-v1",
                    "sha256": "4" * 64,
                }
            ],
            "unresolved": [
                {"id": "layersentry-full-offline-builder-image"},
                {"id": "build-toolchain"},
                {"id": "layersentry-controller-image"},
                {"id": "harvester-offline-image-set"},
            ],
        }

    def write_json(self, path: Path, value: dict) -> None:
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def test_apply_adds_builder_and_removes_only_reviewed_markers(self) -> None:
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
            self.assertEqual(report["remaining_unresolved_ids"], [
                "harvester-offline-image-set",
                "layersentry-controller-image",
            ])
            self.assertEqual(updated["lock_status"], "incomplete")
            self.assertEqual(
                [item["id"] for item in updated["container_images"]],
                [review_module.BUILDER_IMAGE_ID],
            )
            builder_ids = {
                item["id"]
                for item in updated["toolchain_artifacts"]
                if item["id"].startswith("layersentry-builder-")
            }
            self.assertEqual(builder_ids, review_module.EXPECTED_ARTIFACT_IDS)

    def test_rejects_tag_only_builder(self) -> None:
        candidate = self.candidate()
        candidate["builder_image"]["ref"] = (
            "ghcr.io/adaptgurus/layersentry-full-offline-builder:source-"
            + self.source_commit
        )
        with self.assertRaises(review_module.ReviewError):
            review_module.validate_candidate(candidate, self.source_commit)

    def test_rejects_replacement_after_unresolved_marker_removed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            candidate_path = root / "candidate.json"
            lock_path = root / "lock.json"
            lock = self.lock()
            lock["unresolved"] = [
                item
                for item in lock["unresolved"]
                if item["id"] != "build-toolchain"
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
