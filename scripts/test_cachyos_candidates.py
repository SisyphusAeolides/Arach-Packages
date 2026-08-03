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
EMIT = load("emit_cachyos_candidates")
VERIFY = load("verify_cachyos_candidates")


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def policy(revision: str) -> dict:
    return {
        "format": 1,
        "upstream_repository": "https://github.com/CachyOS/CachyOS-PKGBUILDS.git",
        "mirror_revision": revision,
        "target_package_outputs": 2,
        "max_pkgbuild_bytes": 524288,
        "classes": ["static", "sealed-script", "meta", "template", "rejected"],
        "reason_codes": [
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
        ],
        "kernel_package_prefixes": ["linux-cachyos"],
    }


class CandidateRecipeTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[dict, dict]:
        git(root, "init", "--quiet")
        git(root, "config", "user.name", "Tester")
        git(root, "config", "user.email", "tester@example.invalid")
        package = root / "bundle"
        package.mkdir()
        (package / "PKGBUILD").write_text(
            """pkgname=('bundle' 'bundle-devel')
pkgver=1.2.3
pkgrel=4
build() { :; }
package_bundle() { :; }
package_bundle-devel() { :; }
""",
            encoding="utf-8",
        )
        (package / ".SRCINFO").write_text(
            """pkgbase = bundle
	pkgdesc = Test bundle
	pkgver = 1.2.3
	pkgrel = 4
	url = https://example.invalid/bundle
	arch = x86_64
	license = MIT
	makedepends = cmake
	source = https://example.invalid/bundle.tar.xz
	sha256sums = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

pkgname = bundle
	depends = libc>=1
	provides = bundle-api=1

pkgname = bundle-devel
	depends = bundle=1.2.3
""",
            encoding="utf-8",
        )
        git(root, "add", ".")
        git(root, "commit", "--quiet", "-m", "fixture")
        revision = git(root, "rev-parse", "HEAD")
        value = policy(revision)
        manifest = INVENTORY.inventory(root, value)
        return value, manifest

    def test_emits_one_candidate_per_split_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "mirror"
            root.mkdir()
            value, manifest = self.fixture(root)
            output = Path(directory) / "candidates"
            index = EMIT.emit(root, manifest, value, output)
            self.assertEqual(index["candidate_count"], 2)
            VERIFY.verify(manifest, index, output, require_complete=True)
            bundle = next(
                output / entry["path"]
                for entry in index["candidates"]
                if entry["package"] == "bundle"
            ).read_text(encoding="utf-8")
            self.assertIn('version = "1.2.3"', bundle)
            self.assertIn('runtime = ["libc>=1"]', bundle)
            self.assertIn('admission_class = "sealed-script"', bundle)
            self.assertIn("requires_worker_evidence = true", bundle)

    def test_candidate_output_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "mirror"
            root.mkdir()
            value, manifest = self.fixture(root)
            first = EMIT.emit(root, manifest, value, Path(directory) / "first")
            second = EMIT.emit(root, manifest, value, Path(directory) / "second")
            self.assertEqual(
                json.dumps(first, sort_keys=True, separators=(",", ":")),
                json.dumps(second, sort_keys=True, separators=(",", ":")),
            )

    def test_changed_candidate_fails_digest_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "mirror"
            root.mkdir()
            value, manifest = self.fixture(root)
            output = Path(directory) / "candidates"
            index = EMIT.emit(root, manifest, value, output)
            target = output / index["candidates"][0]["path"]
            target.write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(VERIFY.CandidateValidationError, "digest mismatch"):
                VERIFY.verify(manifest, index, output, require_complete=True)


if __name__ == "__main__":
    unittest.main()
