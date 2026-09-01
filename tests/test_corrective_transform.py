from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HARVESTER_COMMIT = "5320dfa6770f63406750e7c64b24ed87c543e6ad"
ADDONS_COMMIT = "f60d73d894e00f18d5e11cd21a301ed1b016631c"


class CorrectiveTreeTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_addon_loader_is_commit_only(self):
        text = self.read("scripts/lib/addon")
        self.assertIn('git -C "${apath}" fetch --depth 1 origin "${commit}"', text)
        self.assertIn('[[ ! ${commit} =~ ^[0-9a-f]{40}$ ]]', text)
        self.assertNotIn("git clone --branch", text)
        self.assertNotIn("branch=main", text)

    def test_build_uses_exact_embedded_source_commits(self):
        text = self.read("scripts/build")
        self.assertIn(f'HARVESTER_COMMIT="{HARVESTER_COMMIT}"', text)
        self.assertIn(f'ADDONS_COMMIT="{ADDONS_COMMIT}"', text)
        self.assertIn('fetch --depth 1 origin "${HARVESTER_COMMIT}"', text)
        self.assertIn("${ADDONS_COMMIT}", text)
        self.assertNotIn("git clone --branch", text)
        self.assertNotIn("tag --points-at HEAD", text)

    def test_build_bundle_rejects_implicit_latest_and_head_images(self):
        text = self.read("scripts/build-bundle")
        self.assertIn(f'HARVESTER_COMMIT="{HARVESTER_COMMIT}"', text)
        self.assertIn(f'ADDONS_COMMIT="{ADDONS_COMMIT}"', text)
        self.assertIn("normalize_image_list.py", text)
        self.assertNotIn('print $1\":latest\"', text)
        self.assertNotIn("${HARVESTER_APP_VERSION}-head", text)
        self.assertNotIn("git clone --branch v1.8.2", text)

    def test_packaging_uses_exact_addons_commit(self):
        text = self.read("scripts/package-harvester-os")
        self.assertIn(f'ADDONS_COMMIT="{ADDONS_COMMIT}"', text)
        self.assertIn(
            "load_and_source_addon ${addons_path} https://github.com/harvester/addons.git ${ADDONS_COMMIT}",
            text,
        )
        self.assertNotIn(
            "load_and_source_addon ${addons_path} https://github.com/harvester/addons.git v1.8.2",
            text,
        )

    def test_evidence_binds_to_layersentry_development_branch(self):
        text = self.read("scripts/prepare-production-iso-evidence.sh")
        self.assertIn("branch: layersentry-v1.0-dev", text)
        self.assertNotIn("branch: feat/layersentry-v1.8.2-production", text)

    def test_unsafe_legacy_workflows_are_archived(self):
        names = (
            "layersentry-production-bootstrap.yml",
            "layersentry-production-iso.yml",
            "layersentry-build-evidence.yml",
        )
        for name in names:
            self.assertFalse((ROOT / ".github/workflows" / name).exists(), name)
            self.assertTrue(
                (
                    ROOT
                    / ".github/workflows-disabled/pre-provenance-v1.8.2"
                    / name
                ).is_file(),
                name,
            )


if __name__ == "__main__":
    unittest.main()
