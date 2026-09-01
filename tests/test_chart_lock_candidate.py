from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/provenance/build_chart_lock_candidate.py"
spec = importlib.util.spec_from_file_location("chart_candidate", SCRIPT)
chart_candidate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(chart_candidate)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_chart(path: Path, name: str, version: str) -> None:
    payload = f"apiVersion: v2\nname: {name}\nversion: {version}\n".encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                info = tarfile.TarInfo(f"{name}/Chart.yaml")
                info.size = len(payload)
                info.mtime = 0
                archive.addfile(info, io.BytesIO(payload))


class ChartCandidateTests(unittest.TestCase):
    def fixture(self, root: Path):
        charts = root / "charts"
        url_archive = "external-1.2.3.tgz"
        git_archive = "local-1.2.3.tgz"
        write_chart(charts / url_archive, "external", "1.2.3")
        write_chart(charts / git_archive, "local", "1.2.3")
        plan = {
            "schema": "layersentry.chart-source-plan/v1",
            "source_locks": {
                "harvester": {"commit": "a" * 40},
                "addons": {"commit": "b" * 40},
            },
            "charts": [
                {
                    "id": "external",
                    "name": "external",
                    "version": "1.2.3",
                    "archive": url_archive,
                    "source": {"kind": "url", "url": "https://example.invalid/external-1.2.3.tgz"},
                    "transformations": ["deterministic-archive-normalization"],
                },
                {
                    "id": "local",
                    "name": "local",
                    "version": "1.2.3",
                    "archive": git_archive,
                    "source": {
                        "kind": "git",
                        "repository": "https://github.com/example/local.git",
                        "commit": "c" * 40,
                        "path": "charts/local",
                    },
                    "transformations": ["deterministic-archive-normalization"],
                },
            ],
        }
        plan_path = root / "plan.json"
        plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        source_path = root / "sources.tsv"
        source_path.write_text(
            "id\turl\tarchive\tsha256\tbytes\n"
            f"external\thttps://example.invalid/external-1.2.3.tgz\t{url_archive}\t"
            f"{'d' * 64}\t123\n",
            encoding="utf-8",
        )
        report = {
            "schema": "layersentry.deterministic-chart-normalization/v1",
            "source_date_epoch": 1234,
            "chart_count": 2,
            "charts": [
                {
                    "path": f"final-charts/{url_archive}",
                    "sha256": sha256(charts / url_archive),
                    "bytes": (charts / url_archive).stat().st_size,
                },
                {
                    "path": f"final-charts/{git_archive}",
                    "sha256": sha256(charts / git_archive),
                    "bytes": (charts / git_archive).stat().st_size,
                },
            ],
        }
        report_path = root / "normalization.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        return plan_path, charts, source_path, report_path

    def test_builds_path_independent_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, charts, sources, report = self.fixture(root)
            candidate = chart_candidate.build_candidate(
                plan, charts, sources, report, "e" * 40, 1234
            )
            self.assertEqual(2, candidate["chart_count"])
            self.assertEqual("e" * 40, candidate["source_commit"])
            self.assertTrue(candidate["all_sources_verified"])
            by_id = {item["id"]: item for item in candidate["charts"]}
            self.assertEqual("d" * 64, by_id["external"]["source_sha256"])
            self.assertNotIn("source_sha256", by_id["local"])
            self.assertEqual(
                "git+https://github.com/example/local.git@" + "c" * 40 + "#charts/local",
                by_id["local"]["source"],
            )

    def test_rejects_chart_metadata_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, charts, sources, report = self.fixture(root)
            write_chart(charts / "external-1.2.3.tgz", "wrong", "1.2.3")
            normalization = json.loads(report.read_text(encoding="utf-8"))
            normalization["charts"][0]["sha256"] = sha256(charts / "external-1.2.3.tgz")
            normalization["charts"][0]["bytes"] = (charts / "external-1.2.3.tgz").stat().st_size
            report.write_text(json.dumps(normalization), encoding="utf-8")
            with self.assertRaises(chart_candidate.CandidateError):
                chart_candidate.build_candidate(
                    plan, charts, sources, report, "e" * 40, 1234
                )


if __name__ == "__main__":
    unittest.main()
