from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/provenance/review_chart_discovery.py"
spec = importlib.util.spec_from_file_location("chart_review", SCRIPT)
chart_review = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(chart_review)


class ChartReviewTests(unittest.TestCase):
    def fixture(self, root: Path):
        source_commit = "e" * 40
        plan = {
            "schema": "layersentry.chart-source-plan/v1",
            "source_locks": {
                "harvester": {"commit": chart_review.EXPECTED_HARVESTER_COMMIT},
                "addons": {"commit": chart_review.EXPECTED_ADDONS_COMMIT},
            },
            "charts": [
                {
                    "id": "chart-a",
                    "name": "chart-a",
                    "version": "1.2.3",
                    "archive": "chart-a-1.2.3.tgz",
                    "source": {"kind": "url", "url": "https://example.invalid/chart-a-1.2.3.tgz"},
                    "transformations": ["deterministic-archive-normalization"],
                }
            ],
        }
        plan_path = root / "plan.json"
        plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        candidate = {
            "schema": "layersentry.chart-lock-candidate/v1",
            "source_commit": source_commit,
            "source_date_epoch": 1234,
            "plan_sha256": chart_review.sha256_file(plan_path),
            "source_checksums_sha256": "f" * 64,
            "harvester_commit": chart_review.EXPECTED_HARVESTER_COMMIT,
            "addons_commit": chart_review.EXPECTED_ADDONS_COMMIT,
            "chart_count": 1,
            "all_sources_verified": True,
            "all_archives_normalized": True,
            "charts": [
                {
                    "id": "chart-a",
                    "name": "chart-a",
                    "version": "1.2.3",
                    "archive": "chart-a-1.2.3.tgz",
                    "source": "https://example.invalid/chart-a-1.2.3.tgz",
                    "sha256": "a" * 64,
                    "bytes": 456,
                    "source_sha256": "b" * 64,
                    "source_bytes": 500,
                    "transformations": ["deterministic-archive-normalization"],
                }
            ],
        }
        candidate_path = root / "candidate.json"
        candidate_path.write_text(json.dumps(candidate, indent=2) + "\n", encoding="utf-8")
        lock = {
            "schema": "layersentry.provenance-lock/v1",
            "lock_status": "incomplete",
            "release_identity": {
                "product": {"version": "v1.0"},
                "embedded_platform": {"version": "v1.8.2"},
            },
            "charts": [],
            "unresolved": [
                {"id": chart_review.UNRESOLVED_ID, "kind": "chart-set", "required_resolution": "lock charts"},
                {"id": "other", "kind": "toolchain", "required_resolution": "lock tool"},
            ],
        }
        lock_path = root / "lock.json"
        lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
        return source_commit, plan_path, candidate_path, lock_path

    def test_apply_merges_charts_but_keeps_lock_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_commit, plan, candidate, lock = self.fixture(Path(tmp))
            updated, report = chart_review.review(
                candidate, plan, lock, source_commit, apply=True
            )
            self.assertEqual("incomplete", updated["lock_status"])
            self.assertEqual(1, len(updated["charts"]))
            self.assertEqual(["other"], [item["id"] for item in updated["unresolved"]])
            self.assertFalse(report["release_approved"])
            persisted = json.loads(lock.read_text(encoding="utf-8"))
            self.assertEqual(updated, persisted)

    def test_wrong_source_commit_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            source_commit, plan, candidate, lock = self.fixture(Path(tmp))
            with self.assertRaises(chart_review.ReviewError):
                chart_review.review(candidate, plan, lock, "c" * 40, apply=False)


if __name__ == "__main__":
    unittest.main()
