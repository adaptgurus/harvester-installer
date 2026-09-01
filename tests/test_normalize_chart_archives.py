from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "provenance" / "normalize_chart_archives.py"
SPEC = importlib.util.spec_from_file_location("normalize_chart_archives", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class NormalizeChartArchivesTests(unittest.TestCase):
    def write_chart(self, path: Path, *, epoch: int, reverse: bool = False) -> None:
        members = [
            ("example/Chart.yaml", b"apiVersion: v2\nname: example\nversion: 1.0.0\n", 0o644),
            ("example/templates/config.yaml", b"kind: ConfigMap\n", 0o640),
        ]
        if reverse:
            members.reverse()
        with path.open("wb") as raw:
            with gzip.GzipFile(filename="source-name.tgz", mode="wb", fileobj=raw, mtime=epoch) as gz:
                with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    for index, (name, data, mode) in enumerate(members):
                        info = tarfile.TarInfo(name)
                        info.size = len(data)
                        info.mode = mode
                        info.uid = 1000 + index
                        info.gid = 2000 + index
                        info.uname = "builder"
                        info.gname = "builder"
                        info.mtime = epoch + index
                        archive.addfile(info, io.BytesIO(data))

    def digest(self, path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def test_equivalent_archives_normalize_to_identical_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.tgz"
            second = root / "second.tgz"
            self.write_chart(first, epoch=10, reverse=False)
            self.write_chart(second, epoch=999, reverse=True)
            self.assertNotEqual(self.digest(first), self.digest(second))
            MODULE.normalize(first, 0)
            MODULE.normalize(second, 0)
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_normalization_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "chart.tgz"
            self.write_chart(path, epoch=123)
            MODULE.normalize(path, 0)
            first = path.read_bytes()
            MODULE.normalize(path, 0)
            self.assertEqual(first, path.read_bytes())

    def test_normalized_metadata_is_fixed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "chart.tgz"
            self.write_chart(path, epoch=123)
            MODULE.normalize(path, 7)
            with tarfile.open(path, "r:gz") as archive:
                names = [member.name for member in archive.getmembers()]
                self.assertEqual(names, sorted(names))
                for member in archive.getmembers():
                    self.assertEqual(member.uid, 0)
                    self.assertEqual(member.gid, 0)
                    self.assertEqual(member.uname, "")
                    self.assertEqual(member.gname, "")
                    self.assertEqual(member.mtime, 7)

    def test_path_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.tgz"
            with tarfile.open(path, "w:gz") as archive:
                data = b"apiVersion: v2\n"
                info = tarfile.TarInfo("../Chart.yaml")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            with self.assertRaises(ValueError):
                MODULE.normalized_bytes(path, 0)

    def test_archive_without_chart_metadata_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.tgz"
            with tarfile.open(path, "w:gz") as archive:
                data = b"not a chart\n"
                info = tarfile.TarInfo("example/README.md")
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            with self.assertRaises(ValueError):
                MODULE.normalized_bytes(path, 0)


if __name__ == "__main__":
    unittest.main()
