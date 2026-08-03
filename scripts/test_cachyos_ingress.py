from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


INVENTORY = load("inventory_cachyos")
VERIFY = load("verify_cachyos_ingress")


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def policy_text(revision: str, target: int) -> str:
    return f'''format = 1
upstream_repository = "https://github.com/CachyOS/CachyOS-PKGBUILDS.git"
mirror_revision = "{revision}"
target_package_outputs = {target}
max_pkgbuild_bytes = 524288
classes = ["static", "sealed-script", "meta", "template", "rejected"]
reason_codes = [
  "DYNAMIC_PKGVER",
  "EVAL",
  "FLOATING_VCS",
  "INSTALL_HOOK",
  "KERNEL_TEMPLATE",
  "MISSING_CHECKSUM",
  "PACMAN_HOOK",
  "SHELL_SUBSTITUTION",
  "SPLIT_PACKAGE",
  "UNPARSED_FUNCTION",
  "UNRESOLVED_PACKAGE_NAMES",
  "UNSUPPORTED_ARCHITECTURE",
  "UNSUPPORTED_SOURCE",
  "UNSUPPORTED_SYNTAX",
]
kernel_package_prefixes = ["linux-cachyos"]
'''


class CachyosIngressTests(unittest.TestCase):
    def mirror(self, root: Path) -> str:
        git(root, "init", "--quiet")
        git(root, "config", "user.name", "Tester")
        git(root, "config", "user.email", "tester@example.invalid")
        static = root / "simple"
        static.mkdir()
        (static / "PKGBUILD").write_text(
            """pkgname=simple\npkgver=1.0\npkgrel=1\nsource=('https://example.invalid/simple.tar.xz')\nsha256sums=('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')\n""",
            encoding="utf-8",
        )
        split = root / "split"
        split.mkdir()
        (split / "PKGBUILD").write_text(
            """pkgname=('split-runtime' 'split-devel')\npkgver=1.0\npkgrel=1\nsource=('https://example.invalid/split.tar.xz')\nsha256sums=('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')\nbuild() { :; }\npackage_split-runtime() { :; }\npackage_split-devel() { :; }\n""",
            encoding="utf-8",
        )
        git(root, "add", ".")
        git(root, "commit", "--quiet", "-m", "fixture")
        return git(root, "rev-parse", "HEAD")

    def test_counts_split_outputs_and_classifies_conservatively(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            revision = self.mirror(root)
            policy_path = root / "policy.toml"
            policy_path.write_text(policy_text(revision, 3), encoding="utf-8")
            policy = INVENTORY.load_policy(policy_path)
            manifest = INVENTORY.inventory(root, policy)
            self.assertEqual(manifest["pkgbuild_count"], 2)
            self.assertEqual(manifest["resolved_package_outputs"], 3)
            self.assertTrue(manifest["complete"])
            classes = {record["path"]: record["admission_class"] for record in manifest["records"]}
            self.assertEqual(classes["simple/PKGBUILD"], "static")
            self.assertEqual(classes["split/PKGBUILD"], "sealed-script")
            VERIFY.validate_policy(policy)
            VERIFY.validate_manifest(policy, manifest, require_complete=True)

    def test_unresolved_pkgname_is_rejected_and_blocks_completeness(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            git(root, "init", "--quiet")
            git(root, "config", "user.name", "Tester")
            git(root, "config", "user.email", "tester@example.invalid")
            package = root / "dynamic"
            package.mkdir()
            (package / "PKGBUILD").write_text(
                "pkgname=${project}\npkgver=1\npkgrel=1\n", encoding="utf-8"
            )
            git(root, "add", ".")
            git(root, "commit", "--quiet", "-m", "fixture")
            revision = git(root, "rev-parse", "HEAD")
            policy_path = root / "policy.toml"
            policy_path.write_text(policy_text(revision, 1), encoding="utf-8")
            policy = INVENTORY.load_policy(policy_path)
            manifest = INVENTORY.inventory(root, policy)
            self.assertFalse(manifest["complete"])
            self.assertEqual(manifest["unresolved_pkgbuilds"], 1)
            self.assertEqual(manifest["records"][0]["admission_class"], "rejected")
            with self.assertRaisesRegex(VERIFY.ValidationError, "snapshot is incomplete"):
                VERIFY.validate_manifest(policy, manifest, require_complete=True)

    def test_manifest_output_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            revision = self.mirror(root)
            policy_path = root / "policy.toml"
            policy_path.write_text(policy_text(revision, 3), encoding="utf-8")
            policy = INVENTORY.load_policy(policy_path)
            first = INVENTORY.inventory(root, policy)
            second = INVENTORY.inventory(root, policy)
            self.assertEqual(
                json.dumps(first, sort_keys=True, separators=(",", ":")),
                json.dumps(second, sort_keys=True, separators=(",", ":")),
            )

    def test_duplicate_package_outputs_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.mirror(root)
            duplicate = root / "duplicate"
            duplicate.mkdir()
            (duplicate / "PKGBUILD").write_text(
                "pkgname=simple\npkgver=2\npkgrel=1\n", encoding="utf-8"
            )
            git(root, "add", ".")
            git(root, "commit", "--quiet", "-m", "duplicate")
            revision = git(root, "rev-parse", "HEAD")
            policy_path = root / "policy.toml"
            policy_path.write_text(policy_text(revision, 4), encoding="utf-8")
            policy = INVENTORY.load_policy(policy_path)
            manifest = INVENTORY.inventory(root, policy)
            self.assertEqual(len(manifest["duplicate_packages"]), 1)
            self.assertFalse(manifest["complete"])


if __name__ == "__main__":
    unittest.main()
