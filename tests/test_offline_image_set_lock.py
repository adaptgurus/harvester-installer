from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts/provenance/review_offline_image_set.py"
)
spec = importlib.util.spec_from_file_location("review_offline_image_set", MODULE_PATH)
assert spec and spec.loader
review_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review_module)


class OfflineImageSetReviewTests(unittest.TestCase):
    source_commit = "1" * 40
    build_run_id = 12345

    def candidate(self) -> dict:
        images = []
        for index, (image_id, expected) in enumerate(
            sorted(review_module.EXPECTED_IMAGES.items()), start=2
        ):
            images.append(
                {
                    "id": image_id,
                    "aliases": [
                        expected["runtime_alias"],
                        f"{expected['repository']}:source-{self.source_commit}-run-{self.build_run_id}",
                    ],
                    "ref": expected["repository"] + "@sha256:" + str(index) * 64,
                    "platform": "linux/amd64",
                    "config_digest": str(index + 3) * 64,
                    "rootfs_diff_ids": ["sha256:" + str(index + 4) * 64],
                    "size_bytes": 1000 + index,
                    "runtime_config": {
                        "user": "",
                        "entrypoint": None,
                        "cmd": None,
                        "working_dir": "",
                        "labels": {},
                        "environment": [],
                        "exposed_ports": [],
                    },
                    "sbom": {
                        "path": f"sboms/{image_id}.spdx.json",
                        "format": "SPDX JSON",
                        "bytes": 500,
                        "sha256": str(index + 5) * 64,
                        "package_count": 0,
                    },
                }
            )
        source_inputs = [
            {"path": path, "bytes": 10, "sha256": "a" * 64}
            for path in sorted(review_module.EXPECTED_SOURCE_INPUTS)
        ]
        list_files = [
            {
                "path": "image-lists/harvester/images-lists/harvester-images-v1.0.txt",
                "bytes": 100,
                "sha256": "b" * 64,
                "entry_count": 120,
            }
        ]
        return {
            "schema": "layersentry.offline-image-set-candidate/v1",
            "source_commit": self.source_commit,
            "source_tree": "c" * 40,
            "build_run_id": self.build_run_id,
            "release_identity": {
                "product": "LayerSentry v1.0",
                "embedded_platform": "Harvester v1.8.2",
            },
            "images": images,
            "source_inputs": source_inputs,
            "image_lists": {
                "files": list_files,
                "file_count": 1,
                "observed_alias_count": 120,
                "aggregate_sha256": "d" * 64,
            },
            "iso_candidate": {
                "path": "dist/artifacts/harvester-v1.0-amd64.iso",
                "bytes": 2 * 1024 * 1024 * 1024,
                "sha256": "e" * 64,
                "sha512": "f" * 128,
            },
            "dependency_lock_complete": False,
            "installed": False,
            "runtime_qualified": False,
            "release_approved": False,
        }

    @staticmethod
    def lock() -> dict:
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
                    "commit": "9" * 40,
                }
            ],
            "container_images": [
                {
                    "id": "existing-image",
                    "aliases": ["docker.io/example/image:v1"],
                    "ref": "docker.io/example/image@sha256:" + "8" * 64,
                }
            ],
            "unresolved": [
                {
                    "id": "harvester-offline-image-set",
                    "kind": "container-image-set",
                    "required_resolution": "capture generated images",
                }
            ],
        }

    @staticmethod
    def write_json(path: Path, value: dict) -> None:
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def test_apply_completes_dependency_lock_without_runtime_approval(self) -> None:
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
                self.build_run_id,
                True,
            )
            self.assertEqual(updated["lock_status"], "complete")
            self.assertEqual(updated["unresolved"], [])
            self.assertEqual(report["remaining_unresolved_count"], 0)
            self.assertTrue(report["dependency_lock_complete"])
            self.assertFalse(report["runtime_qualified"])
            self.assertFalse(report["release_approved"])
            generated = {
                item["id"]
                for item in updated["container_images"]
                if item["id"].startswith("layersentry-generated-")
            }
            self.assertEqual(generated, set(review_module.EXPECTED_IMAGES))

    def test_rejects_tag_only_ref(self) -> None:
        candidate = self.candidate()
        candidate["images"][0]["ref"] = candidate["images"][0]["aliases"][1]
        with self.assertRaises(review_module.ReviewError):
            review_module.validate_candidate(
                candidate, self.source_commit, self.build_run_id
            )

    def test_rejects_missing_generated_image(self) -> None:
        candidate = self.candidate()
        candidate["images"].pop()
        with self.assertRaises(review_module.ReviewError):
            review_module.validate_candidate(
                candidate, self.source_commit, self.build_run_id
            )

    def test_rejects_completion_when_other_unresolved_entries_exist(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            candidate_path = root / "candidate.json"
            lock_path = root / "lock.json"
            lock = self.lock()
            lock["unresolved"].append(
                {
                    "id": "unexpected",
                    "kind": "test",
                    "required_resolution": "must remain blocked",
                }
            )
            self.write_json(candidate_path, self.candidate())
            self.write_json(lock_path, lock)
            with self.assertRaises(review_module.ReviewError):
                review_module.review(
                    candidate_path,
                    lock_path,
                    self.source_commit,
                    self.build_run_id,
                    False,
                )

    def test_rejects_release_approval_claim(self) -> None:
        candidate = self.candidate()
        candidate["release_approved"] = True
        with self.assertRaises(review_module.ReviewError):
            review_module.validate_candidate(
                candidate, self.source_commit, self.build_run_id
            )


if __name__ == "__main__":
    unittest.main()
