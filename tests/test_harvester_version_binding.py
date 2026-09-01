from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
VERSION_SCRIPT = ROOT / "scripts" / "version-harvester"
DEFAULT_SCRIPT = ROOT / "scripts" / "default"


def run(*args: str, cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class HarvesterVersionBindingTests(unittest.TestCase):
    def create_origin(self, root: Path) -> tuple[Path, str]:
        origin = root / "origin"
        origin.mkdir()
        self.assertEqual(run("git", "init", "-q", cwd=origin).returncode, 0)
        self.assertEqual(run("git", "config", "user.name", "test", cwd=origin).returncode, 0)
        self.assertEqual(run("git", "config", "user.email", "test@example.invalid", cwd=origin).returncode, 0)
        (origin / "scripts").mkdir()
        (origin / "package").mkdir()
        values = origin / "deploy" / "charts" / "harvester"
        values.mkdir(parents=True)
        # Match the relevant upstream behavior: SPRINT_RELEASE is optional and
        # read without initialization. The wrapper must remain correct even when
        # its caller has `set -u` enabled.
        (origin / "scripts" / "version").write_text(
            """#!/bin/bash
GIT_TAG=$(git tag -l --contains HEAD | head -n 1)
if [[ \"$GIT_TAG\" == *\"-dev-\"* ]]; then
  SPRINT_RELEASE=\"-dev-\"
fi
if [[ -n \"$GIT_TAG\" && -z \"$SPRINT_RELEASE\" ]]; then
  VERSION=$GIT_TAG
  APP_VERSION=$GIT_TAG
  CHART_VERSION=${GIT_TAG#v}
  MIN_UPGRADABLE_VERSION=$(yq -e e ignored package/upgrade-matrix.yaml)
else
  VERSION=$(git rev-parse --short=8 HEAD)
  APP_VERSION=HEAD-head
  CHART_VERSION=v0.0.0-HEAD-head
  MIN_UPGRADABLE_VERSION=
fi
""",
            encoding="utf-8",
        )
        (origin / "package" / "upgrade-matrix.yaml").write_text("versions: []\n", encoding="utf-8")
        (values / "values.yaml").write_text("kubevirt-operator: {}\n", encoding="utf-8")
        self.assertEqual(run("git", "add", ".", cwd=origin).returncode, 0)
        self.assertEqual(run("git", "commit", "-q", "-m", "source", cwd=origin).returncode, 0)
        commit = run("git", "rev-parse", "HEAD", cwd=origin).stdout.strip()
        self.assertEqual(run("git", "tag", "v1.8.2", commit, cwd=origin).returncode, 0)
        return origin, commit

    def create_commit_only_checkout(self, root: Path, origin: Path, commit: str) -> Path:
        checkout = root / "checkout"
        checkout.mkdir()
        self.assertEqual(run("git", "init", "-q", cwd=checkout).returncode, 0)
        self.assertEqual(run("git", "remote", "add", "origin", str(origin), cwd=checkout).returncode, 0)
        self.assertEqual(
            run("git", "fetch", "-q", "--no-tags", "--depth", "1", "origin", commit, cwd=checkout).returncode,
            0,
        )
        self.assertEqual(run("git", "checkout", "-q", "--detach", "FETCH_HEAD", cwd=checkout).returncode, 0)
        self.assertNotEqual(run("git", "rev-parse", "refs/tags/v1.8.2", cwd=checkout).returncode, 0)
        return checkout

    def fake_yq(self, root: Path) -> Path:
        tools = root / "tools"
        tools.mkdir()
        yq = tools / "yq"
        yq.write_text(
            """#!/bin/bash
case \"$*\" in
  *upgrade-matrix.yaml*) echo v1.7.0 ;;
  *) echo v1.7.4 ;;
esac
""",
            encoding="utf-8",
        )
        yq.chmod(0o755)
        return tools

    def test_missing_release_tag_is_fetched_under_nounset_and_bound_to_exact_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            origin, commit = self.create_origin(root)
            checkout = self.create_commit_only_checkout(root, origin, commit)
            tools = self.fake_yq(root)
            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{tools}:{env['PATH']}",
                    "ARCH": "amd64",
                    "HARVESTER_RELEASE_REF": "v1.8.2",
                    "HARVESTER_RELEASE_COMMIT": commit,
                }
            )
            proc = run(
                "bash",
                "-c",
                'set -Eeuo pipefail; source "$1" "$2"; printf "%s|%s|%s|%s|%s" "$HARVESTER_VERSION" "$HARVESTER_APP_VERSION" "$HARVESTER_CHART_VERSION" "$HARVESTER_KUBEVIRT_VERSION" "$HARVESTER_MIN_UPGRADABLE_VERSION"',
                "bash",
                str(VERSION_SCRIPT),
                str(checkout),
                env=env,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stdout, "v1.8.2|v1.8.2|1.8.2|v1.7.4|v1.7.0")
            self.assertEqual(
                run("git", "rev-parse", "refs/tags/v1.8.2^{commit}", cwd=checkout).stdout.strip(),
                commit,
            )

    def test_wrong_head_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            origin, commit = self.create_origin(root)
            checkout = self.create_commit_only_checkout(root, origin, commit)
            tools = self.fake_yq(root)
            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{tools}:{env['PATH']}",
                    "ARCH": "amd64",
                    "HARVESTER_RELEASE_REF": "v1.8.2",
                    "HARVESTER_RELEASE_COMMIT": "0" * 40,
                }
            )
            proc = run(
                "bash",
                "-c",
                'set -Eeuo pipefail; source "$1" "$2"',
                "bash",
                str(VERSION_SCRIPT),
                str(checkout),
                env=env,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("does not equal", proc.stderr)

    def test_default_build_normalizes_charts_before_packaging_repo(self) -> None:
        text = DEFAULT_SCRIPT.read_text(encoding="utf-8")
        bundle = text.index("./build-bundle")
        normalize = text.index("normalize_chart_archives.py")
        reindex = text.index("helm repo index")
        package = text.index("./package-harvester-repo")
        self.assertLess(bundle, normalize)
        self.assertLess(normalize, reindex)
        self.assertLess(reindex, package)


if __name__ == "__main__":
    unittest.main()
