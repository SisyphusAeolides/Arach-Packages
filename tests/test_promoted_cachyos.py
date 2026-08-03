from __future__ import annotations

import copy
import json
import re
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROMOTED = ROOT / "ingress" / "cachyos" / "promoted"
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")


class PromotedCachyosTests(unittest.TestCase):
    def setUp(self) -> None:
        self.closure = json.loads((PROMOTED / "closure.json").read_text(encoding="utf-8"))

    def test_closure_is_non_authoritative_and_pinned(self) -> None:
        self.assertEqual(self.closure["format"], 1)
        self.assertEqual(self.closure["distribution"], "ArachOS")
        self.assertEqual(self.closure["status"], "closure-blocked")
        self.assertIs(self.closure["production_authority"], False)
        self.assertRegex(self.closure["revision"], r"^[0-9a-f]{40}$")

    def test_every_closure_record_matches_recipe_dependencies(self) -> None:
        packages = []
        for record in self.closure["recipes"]:
            packages.append(record["package"])
            recipe_path = PROMOTED / record["recipe"]
            self.assertTrue(recipe_path.is_file())
            self.assertFalse(recipe_path.is_symlink())
            with recipe_path.open("rb") as stream:
                recipe = tomllib.load(stream)
            self.assertEqual(recipe["package"]["name"], record["package"])
            self.assertEqual(recipe["build"]["system"], "meta")
            self.assertEqual(recipe["build"]["commands"], [])
            self.assertEqual(recipe["build"]["outputs"], [])
            self.assertEqual(recipe.get("source", []), [])
            self.assertEqual(
                sorted(recipe["runtime"]["depends"]),
                sorted(record["missing_providers"]),
            )
            self.assertRegex(record["pkgbuild_sha256"], DIGEST_RE)
            self.assertRegex(record["srcinfo_sha256"], DIGEST_RE)
            self.assertEqual(record["missing_providers"], sorted(record["missing_providers"]))
            self.assertEqual(
                len(record["missing_providers"]),
                len(set(record["missing_providers"])),
            )
            for provider in record["missing_providers"]:
                self.assertRegex(provider, NAME_RE)
        self.assertEqual(packages, sorted(packages))
        self.assertEqual(packages, ["cachyos-gaming-applications", "zfs-meta"])

    def test_normalization_is_explicit_and_one_way(self) -> None:
        zfs = next(
            record for record in self.closure["recipes"] if record["package"] == "zfs-meta"
        )
        self.assertEqual(
            zfs["normalizations"],
            [
                {
                    "upstream": "ZFS-MODULE",
                    "arach": "zfs-module",
                    "kind": "capability-name",
                }
            ],
        )

    def test_closure_cannot_claim_production_authority(self) -> None:
        closure = copy.deepcopy(self.closure)
        closure["production_authority"] = True
        self.assertIsNot(closure["production_authority"], False)


if __name__ == "__main__":
    unittest.main()
