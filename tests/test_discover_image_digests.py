from __future__ import annotations

import importlib.util
import pathlib
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "provenance" / "discover_image_digests.py"
SPEC = importlib.util.spec_from_file_location("discover_image_digests", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DiscoverImageDigestsTests(unittest.TestCase):
    def test_canonical_alias_adds_docker_hub_registry(self) -> None:
        self.assertEqual(
            MODULE.canonical_alias("rancher/harvester:v1.8.2"),
            "docker.io/rancher/harvester:v1.8.2",
        )
        self.assertEqual(
            MODULE.canonical_alias("registry.k8s.io/pause:3.10"),
            "registry.k8s.io/pause:3.10",
        )

    def test_repository_without_tag_preserves_registry_port(self) -> None:
        self.assertEqual(
            MODULE.repository_without_tag("registry.example.test:5000/ns/image:v1"),
            "registry.example.test:5000/ns/image",
        )

    def test_validate_alias_rejects_latest_head_and_untagged(self) -> None:
        for alias in (
            "docker.io/example/image:latest",
            "docker.io/example/image:v1.8-head",
            "docker.io/example/image",
        ):
            with self.subTest(alias=alias):
                with self.assertRaises(ValueError):
                    MODULE.validate_alias(alias)

    @mock.patch.object(MODULE.subprocess, "run")
    def test_inspect_extracts_buildx_digest(self, run: mock.Mock) -> None:
        run.return_value = mock.Mock(
            returncode=0,
            stdout=(
                "Name:      docker.io/example/image:v1\n"
                "MediaType: application/vnd.oci.image.index.v1+json\n"
                "Digest:    sha256:"
                + "a" * 64
                + "\n"
            ),
        )
        digest, error = MODULE.inspect("docker.io/example/image:v1")
        self.assertEqual(digest, "sha256:" + "a" * 64)
        self.assertEqual(error, "")

    @mock.patch.object(MODULE.subprocess, "run")
    def test_inspect_returns_error_when_digest_is_missing(self, run: mock.Mock) -> None:
        run.return_value = mock.Mock(returncode=0, stdout="Name: image\n")
        digest, error = MODULE.inspect("docker.io/example/image:v1")
        self.assertIsNone(digest)
        self.assertIn("no valid Digest line", error)


if __name__ == "__main__":
    unittest.main()
