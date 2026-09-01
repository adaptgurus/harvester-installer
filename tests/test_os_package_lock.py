from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = ROOT / "provenance/layersentry-v1.0-harvester-os-input.json"
BINDING_PATH = ROOT / "scripts/provenance/verify_os_package_binding.py"
CANDIDATE_PATH = ROOT / "scripts/provenance/build_os_package_candidate.py"
REVIEW_PATH = ROOT / "scripts/provenance/review_os_package_discovery.py"


def module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(value)
    return value


binding = module("os_binding", BINDING_PATH)
candidate_builder = module("os_candidate", CANDIDATE_PATH)
reviewer = module("os_reviewer", REVIEW_PATH)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class BindingTests(unittest.TestCase):
    def test_synthetic_locked_build_path_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            lock = {
                "schema": "layersentry.provenance-lock/v1",
                "container_images": [
                    {
                        "id": binding.EXPECTED_IMAGE_ID,
                        "aliases": [binding.EXPECTED_ALIAS],
                        "ref": binding.EXPECTED_REF,
                    }
                ],
                "toolchain_artifacts": [
                    {
                        "id": "wharfie-amd64",
                        "version": binding.EXPECTED_WHARFIE_VERSION,
                        "sha256": binding.EXPECTED_WHARFIE_SHA256,
                    }
                ],
            }
            lock_path = root / "lock.json"
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            for relative in plan["source_controlled_overlay"]["paths"]:
                target = root / relative
                if Path(relative).suffix or Path(relative).name in {"Dockerfile", "package-harvester-os"}:
                    write(target, "placeholder\n")
                else:
                    target.mkdir(parents=True, exist_ok=True)
            write(
                root / "scripts/package-harvester-os",
                f'BASE_OS_IMAGE="{binding.EXPECTED_REF}"\n'
                'docker image inspect "${BASE_OS_IMAGE}" >/dev/null\n'
                'docker build --pull=false --build-arg BASE_OS_IMAGE="${BASE_OS_IMAGE}" .\n',
            )
            write(
                root / "package/harvester-os/Dockerfile",
                "ARG BASE_OS_IMAGE\nFROM ${BASE_OS_IMAGE}\n"
                f"ARG WHARFIE_VERSION={binding.EXPECTED_WHARFIE_VERSION}\n"
                f"ARG WHARFIE_SUM_amd64={binding.EXPECTED_WHARFIE_SHA256}\n",
            )
            report = binding.verify(plan_path, lock_path, root)
            self.assertTrue(report["verified"])

    def test_mutable_base_tag_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            lock = {
                "schema": "layersentry.provenance-lock/v1",
                "container_images": [
                    {
                        "id": binding.EXPECTED_IMAGE_ID,
                        "aliases": [binding.EXPECTED_ALIAS],
                        "ref": binding.EXPECTED_REF,
                    }
                ],
                "toolchain_artifacts": [
                    {
                        "id": "wharfie-amd64",
                        "version": binding.EXPECTED_WHARFIE_VERSION,
                        "sha256": binding.EXPECTED_WHARFIE_SHA256,
                    }
                ],
            }
            lock_path = root / "lock.json"
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            for relative in plan["source_controlled_overlay"]["paths"]:
                target = root / relative
                if Path(relative).suffix or Path(relative).name in {"Dockerfile", "package-harvester-os"}:
                    write(target, "placeholder\n")
                else:
                    target.mkdir(parents=True, exist_ok=True)
            write(
                root / "scripts/package-harvester-os",
                f'BASE_OS_IMAGE="{binding.EXPECTED_ALIAS}"\n'
                'docker image inspect "${BASE_OS_IMAGE}" >/dev/null\n'
                'docker build --pull=false .\n',
            )
            write(
                root / "package/harvester-os/Dockerfile",
                "ARG BASE_OS_IMAGE\nFROM ${BASE_OS_IMAGE}\n"
                f"ARG WHARFIE_VERSION={binding.EXPECTED_WHARFIE_VERSION}\n"
                f"ARG WHARFIE_SUM_amd64={binding.EXPECTED_WHARFIE_SHA256}\n",
            )
            with self.assertRaises(binding.BindingError):
                binding.verify(plan_path, lock_path, root)


class CandidateTests(unittest.TestCase):
    def fixture(self, root: Path):
        evidence = root / "evidence"
        evidence.mkdir()
        inspect = {
            "schema": "layersentry.oci-image-inspection/v1",
            "ref": candidate_builder.EXPECTED_REF,
            "architecture": "amd64",
            "os": "linux",
            "image_id": "sha256:" + "a" * 64,
            "repo_digests": [candidate_builder.EXPECTED_REF],
            "rootfs_type": "layers",
            "rootfs_layers": ["sha256:" + "b" * 64],
        }
        write(evidence / "image-inspect.json", json.dumps(inspect, indent=2) + "\n")
        rows = ["name\tepoch\tversion\trelease\tarch\tvendor\tbuild_time"]
        for index in range(50):
            rows.append(f"package-{index:03d}\t0\t1.0\t1\tx86_64\tExample\t1")
        write(evidence / "rpm-packages.tsv", "\n".join(rows) + "\n")
        write(
            evidence / "boot-files.tsv",
            "id\tlogical_path\tresolved_path\tbytes\tsha256\n"
            f"kernel\t/boot/vmlinuz\t/boot/vmlinuz-1\t100\t{'c' * 64}\n"
            f"initrd\t/boot/initrd\t/boot/initrd-1\t200\t{'d' * 64}\n",
        )
        write(
            evidence / "firmware-files.tsv",
            "type\tpath\tbytes_or_target\tsha256\n"
            f"file\t/usr/lib/firmware/a.bin\t10\t{'e' * 64}\n"
            "symlink\t/usr/lib/firmware/a.link\ta.bin\t-\n",
        )
        write(
            evidence / "package-repositories.tsv",
            "type\tpath\tbytes_or_target\tsha256\n"
            f"file\t/etc/zypp/repos.d/base.repo\t20\t{'f' * 64}\n",
        )
        write(
            evidence / "os-tools.tsv",
            "id\tpath\tbytes\tsha256\tversion_sha256\n"
            f"elemental\t/usr/bin/elemental\t300\t{'1' * 64}\t{'2' * 64}\n"
            f"dracut\t/usr/bin/dracut\t400\t{'3' * 64}\t{'4' * 64}\n",
        )
        write(evidence / "os-release", 'NAME="Example"\nVERSION="1"\n')
        (evidence / "layersentry-os-overlay.tar.gz").write_bytes(b"overlay")
        return evidence

    def test_builds_complete_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = self.fixture(root)
            candidate = candidate_builder.build_candidate(
                PLAN_PATH, evidence, "5" * 40, "6" * 40
            )
            self.assertEqual(50, candidate["rpm_package_count"])
            self.assertEqual(11, len(candidate["packages"]))
            self.assertTrue(candidate["all_inputs_verified"])
            self.assertFalse(candidate["release_approved"])

    def test_accepts_boot_symlinks_resolved_into_usr_lib_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = self.fixture(root)
            boot = evidence / "boot-files.tsv"
            text = boot.read_text(encoding="utf-8")
            text = text.replace(
                "/boot/vmlinuz-1", "/usr/lib/modules/6.12.0-default/vmlinuz"
            ).replace(
                "/boot/initrd-1", "/usr/lib/modules/6.12.0-default/initrd"
            )
            boot.write_text(text, encoding="utf-8")
            candidate = candidate_builder.build_candidate(
                PLAN_PATH, evidence, "5" * 40, "6" * 40
            )
            by_id = {item["id"]: item for item in candidate["packages"]}
            self.assertIn(
                "/usr/lib/modules/6.12.0-default/vmlinuz",
                by_id["harvester-base-os-kernel"]["source"],
            )

    def test_rejects_kernel_digest_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = self.fixture(root)
            text = (evidence / "boot-files.tsv").read_text(encoding="utf-8")
            (evidence / "boot-files.tsv").write_text(
                text.replace("c" * 64, "not-a-sha"), encoding="utf-8"
            )
            with self.assertRaises(candidate_builder.CandidateError):
                candidate_builder.build_candidate(
                    PLAN_PATH, evidence, "5" * 40, "6" * 40
                )


class ReviewTests(unittest.TestCase):
    def test_review_merges_inputs_and_keeps_lock_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = CandidateTests().fixture(root)
            candidate = candidate_builder.build_candidate(
                PLAN_PATH, evidence, "5" * 40, "6" * 40
            )
            candidate_path = root / "candidate.json"
            candidate_path.write_text(json.dumps(candidate, indent=2) + "\n", encoding="utf-8")
            lock = {
                "schema": "layersentry.provenance-lock/v1",
                "lock_status": "incomplete",
                "release_identity": {
                    "product": {"version": "v1.0"},
                    "embedded_platform": {"version": "v1.8.2"},
                },
                "container_images": [
                    {
                        "id": reviewer.EXPECTED_IMAGE_ID,
                        "aliases": [reviewer.EXPECTED_ALIAS],
                        "ref": reviewer.EXPECTED_REF,
                    }
                ],
                "packages": [],
                "unresolved": [
                    {
                        "id": reviewer.UNRESOLVED_ID,
                        "kind": "package-set",
                        "required_resolution": "lock OS inputs",
                    },
                    {
                        "id": "other",
                        "kind": "toolchain-set",
                        "required_resolution": "lock tools",
                    },
                ],
            }
            lock_path = root / "lock.json"
            lock_path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
            updated, report = reviewer.review(
                candidate_path, PLAN_PATH, lock_path, "5" * 40, apply=True
            )
            self.assertEqual("incomplete", updated["lock_status"])
            self.assertEqual(11, len(updated["packages"]))
            self.assertEqual(["other"], [item["id"] for item in updated["unresolved"]])
            self.assertFalse(report["production_lock_complete"])
            self.assertFalse(report["release_approved"])
            self.assertEqual(updated, json.loads(lock_path.read_text(encoding="utf-8")))


class PlanTests(unittest.TestCase):
    def test_plan_uses_exact_digest_and_no_latest(self):
        plan = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
        self.assertEqual(binding.EXPECTED_REF, plan["base_os_image"]["ref"])
        self.assertNotIn(":latest", json.dumps(plan).lower())
        self.assertEqual("linux/amd64", plan["platform"])


class RepositoryIntegrationTests(unittest.TestCase):
    def test_real_build_path_consumes_digest_without_pull(self):
        package_script = (ROOT / "scripts/package-harvester-os").read_text(encoding="utf-8")
        self.assertIn(f'BASE_OS_IMAGE="{binding.EXPECTED_REF}"', package_script)
        self.assertNotIn(binding.EXPECTED_ALIAS, package_script)
        self.assertIn('docker image inspect "${BASE_OS_IMAGE}" >/dev/null', package_script)
        self.assertIn("docker build --pull=false", package_script)

    def test_default_checks_binding_before_other_build_steps(self):
        default = (ROOT / "scripts/default").read_text(encoding="utf-8")
        self.assertLess(
            default.index("verify_os_package_binding.py"),
            default.index("./check-images"),
        )

    def test_workflow_runs_two_passes_and_keeps_iso_blocked(self):
        workflow = (
            ROOT / ".github/workflows/layersentry-v1.0-os-package-lock.yml"
        ).read_text(encoding="utf-8")
        self.assertEqual(2, workflow.count('scripts/provenance/collect_os_package_evidence.sh "$pass'))
        self.assertIn('assert len(unresolved) == 4', workflow)
        self.assertIn('assert "harvester-offline-image-set" in unresolved', workflow)
        self.assertNotIn("make default", workflow)

    def test_collector_pulls_only_exact_base_digest(self):
        collector = (
            ROOT / "scripts/provenance/collect_os_package_evidence.sh"
        ).read_text(encoding="utf-8")
        self.assertIn(f'BASE_OS_REF="{binding.EXPECTED_REF}"', collector)
        self.assertIn('docker pull --platform linux/amd64 "$BASE_OS_REF"', collector)
        self.assertNotIn(f'BASE_OS_REF="{binding.EXPECTED_ALIAS}"', collector)


if __name__ == "__main__":
    unittest.main()
