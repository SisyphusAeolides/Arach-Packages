from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "inventory_gentoo_ebuild_shard.py"
SPEC = importlib.util.spec_from_file_location("inventory_gentoo_ebuild_shard", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def repository(root: Path, ebuild: str, manifest: str) -> str:
    git(root, "init", "--quiet")
    git(root, "config", "user.name", "Tester")
    git(root, "config", "user.email", "tester@example.invalid")
    package = root / "app-misc" / "demo"
    package.mkdir(parents=True)
    (package / "demo-1.2.3.ebuild").write_text(ebuild, encoding="utf-8")
    (package / "Manifest").write_text(manifest, encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "--quiet", "-m", "fixture")
    return git(root, "rev-parse", "HEAD")


STATIC_EBUILD = '''EAPI=8
DESCRIPTION="Demo package"
LICENSE="MIT"
KEYWORDS="~amd64"
SRC_URI="https://example.invalid/demo-1.2.3.tar.xz -> demo.tar.xz"

src_compile() {
  emake
}
'''

MANIFEST = (
    "DIST demo.tar.xz 42 "
    "BLAKE2B " + "A" * 128 + " "
    "SHA512 " + "B" * 128 + "\n"
)


class GentooEbuildShardTests(unittest.TestCase):
    def test_manifest_accepts_hash_pairs_after_size(self) -> None:
        parsed = MODULE.parse_manifest(MANIFEST.encode())
        self.assertEqual(parsed["demo.tar.xz"]["size"], "42")
        self.assertEqual(parsed["demo.tar.xz"]["BLAKE2B"], "a" * 128)
        self.assertEqual(parsed["demo.tar.xz"]["SHA512"], "b" * 128)

    def test_redirect_uses_manifest_target_filename(self) -> None:
        sources = MODULE.static_sources(
            "https://example.invalid/demo-1.2.3.tar.xz -> demo.tar.xz"
        )
        self.assertEqual(
            sources,
            [
                {
                    "url": "https://example.invalid/demo-1.2.3.tar.xz",
                    "filename": "demo.tar.xz",
                }
            ],
        )

    def test_phase_function_does_not_force_worker_route(self) -> None:
        assignments, dynamic = MODULE.parse_static_assignments(STATIC_EBUILD.encode())
        self.assertEqual(dynamic, [])
        self.assertEqual(assignments["DESCRIPTION"], "Demo package")

    def test_inventory_retains_manifest_evidence_and_sha256_gap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            revision = repository(root, STATIC_EBUILD, MANIFEST)
            document = MODULE.inventory(root, revision, 0, 1)
            MODULE.validate_manifest(document, revision, 0, 1)
            self.assertEqual(document["record_count"], 1)
            self.assertEqual(
                document["counts"],
                {
                    "quarantined": 0,
                    "static-source-lock-candidate": 1,
                    "worker-required": 0,
                },
            )
            record = document["records"][0]
            self.assertEqual(record["status"], "static-source-lock-candidate")
            self.assertEqual(record["sha256_fetches_required"], 1)
            self.assertEqual(record["sources"][0]["filename"], "demo.tar.xz")
            self.assertIs(record["sources"][0]["sha256_required"], True)
            self.assertIn("SHA512", record["sources"][0]["manifest_hashes"])

    def test_dynamic_source_is_worker_required(self) -> None:
        dynamic = STATIC_EBUILD.replace(
            "https://example.invalid/demo-1.2.3.tar.xz -> demo.tar.xz",
            "https://example.invalid/${P}.tar.xz",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            revision = repository(root, dynamic, MANIFEST)
            document = MODULE.inventory(root, revision, 0, 1)
            record = document["records"][0]
            self.assertEqual(record["status"], "worker-required")
            self.assertIn("SRC_URI", record["dynamic_fields"])

    def test_manifest_cannot_claim_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            revision = repository(root, STATIC_EBUILD, MANIFEST)
            document = MODULE.inventory(root, revision, 0, 1)
            changed = copy.deepcopy(document)
            changed["production_authority"] = True
            with self.assertRaisesRegex(MODULE.GentooError, "identity"):
                MODULE.validate_manifest(changed, revision, 0, 1)

    def test_invalid_manifest_is_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            revision = repository(root, STATIC_EBUILD, "DIST demo.tar.xz bad\n")
            document = MODULE.inventory(root, revision, 0, 1)
            record = document["records"][0]
            self.assertEqual(record["status"], "quarantined")
            self.assertEqual(record["reason"], "invalid-static-ebuild")


if __name__ == "__main__":
    unittest.main()
