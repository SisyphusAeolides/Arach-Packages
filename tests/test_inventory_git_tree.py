from __future__ import annotations

import copy
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "inventory_git_tree.py"
SPEC = importlib.util.spec_from_file_location("inventory_git_tree", MODULE_PATH)
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


def repository(root: Path, files: dict[str, str]) -> str:
    git(root, "init", "--quiet")
    git(root, "config", "user.name", "Tester")
    git(root, "config", "user.email", "tester@example.invalid")
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "--quiet", "-m", "fixture")
    return git(root, "rev-parse", "HEAD")


class GitTreeInventoryTests(unittest.TestCase):
    def test_gentoo_inventory_uses_category_package_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            revision = repository(
                root,
                {
                    "app-editors/demo/demo-1.2.3.ebuild": "EAPI=8\n",
                    "app-editors/demo/demo-2.0-r1.ebuild": "EAPI=8\n",
                    "app-editors/demo/metadata.xml": "<pkgmetadata/>\n",
                    "profiles/repo_name": "gentoo\n",
                },
            )
            document = MODULE.inventory(root, revision, "gentoo")
            MODULE.validate_manifest(document, "gentoo", revision)
            self.assertEqual(document["summary"]["candidate_count"], 2)
            self.assertEqual(document["summary"]["category_package_count"], 1)
            self.assertEqual(
                [record["version"] for record in document["records"]],
                ["1.2.3", "2.0-r1"],
            )
            self.assertTrue(
                all(record["source_lock_required"] for record in document["records"])
            )

    def test_cargo_inventory_accepts_every_registry_path_class(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            revision = repository(
                root,
                {
                    "1/a": "{}\n",
                    "2/ab": "{}\n",
                    "3/a/abc": "{}\n",
                    "ab/cd/abcd": "{}\n",
                    "config.json": "{}\n",
                    "wrong/layout/crate": "{}\n",
                },
            )
            document = MODULE.inventory(root, revision, "cargo")
            MODULE.validate_manifest(document, "cargo", revision)
            self.assertEqual(document["summary"]["candidate_count"], 4)
            self.assertEqual(document["summary"]["crate_name_count"], 4)
            self.assertEqual(
                [record["package"] for record in document["records"]],
                ["a", "ab", "abc", "abcd"],
            )
            self.assertTrue(
                all(record["version_inventory_required"] for record in document["records"])
            )

    def test_nix_inventory_is_evaluation_candidate_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            revision = repository(
                root,
                {
                    "pkgs/by-name/de/demo/package.nix": "{ }: null\n",
                    "pkgs/tools/demo/default.nix": "{ }: null\n",
                    "lib/default.nix": "{}\n",
                    "pkgs/README.md": "packages\n",
                },
            )
            document = MODULE.inventory(root, revision, "nix")
            MODULE.validate_manifest(document, "nix", revision)
            self.assertEqual(document["summary"]["candidate_count"], 2)
            self.assertTrue(
                all(record["evaluation_required"] for record in document["records"])
            )

    def test_manifest_cannot_claim_production_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            revision = repository(
                root,
                {"app-misc/demo/demo-1.ebuild": "EAPI=8\n"},
            )
            document = MODULE.inventory(root, revision, "gentoo")
            changed = copy.deepcopy(document)
            changed["production_authority"] = True
            with self.assertRaisesRegex(MODULE.InventoryError, "authority"):
                MODULE.validate_manifest(changed, "gentoo", revision)

    def test_manifest_requires_sha256_follow_up(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            revision = repository(root, {"1/a": "{}\n"})
            document = MODULE.inventory(root, revision, "cargo")
            changed = copy.deepcopy(document)
            changed["records"][0]["metadata_sha256_required"] = False
            with self.assertRaisesRegex(MODULE.InventoryError, "identity"):
                MODULE.validate_manifest(changed, "cargo", revision)

    def test_wrong_revision_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository(root, {"1/a": "{}\n"})
            with self.assertRaisesRegex(MODULE.InventoryError, "exact requested commit"):
                MODULE.inventory(root, "0" * 40, "cargo")

    def test_cargo_path_parser_rejects_noncanonical_layout(self) -> None:
        self.assertIsNone(MODULE.cargo_name_from_path("a/b/crate"))
        self.assertIsNone(MODULE.cargo_name_from_path("ab/xx/abcd"))
        self.assertEqual(MODULE.cargo_name_from_path("cr/at/crate"), "crate")


if __name__ == "__main__":
    unittest.main()
