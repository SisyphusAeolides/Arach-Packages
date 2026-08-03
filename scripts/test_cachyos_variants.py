from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "validate_cachyos_variants.py"
SPEC = importlib.util.spec_from_file_location("validate_cachyos_variants", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

VARIANTS_PATH = ROOT / "ingress" / "cachyos" / "variants.toml"
RECORDS_PATH = (
    ROOT
    / "ingress"
    / "cachyos"
    / "snapshots"
    / "8753877a6ed4af2bf510b8b3f5bda88b793f28ec.records.json"
)
POLICY_PATH = ROOT / "ingress" / "cachyos" / "policy.toml"


class CachyosVariantTests(unittest.TestCase):
    def setUp(self) -> None:
        self.variants = tomllib.loads(VARIANTS_PATH.read_text(encoding="utf-8"))
        self.records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        self.policy = tomllib.loads(POLICY_PATH.read_text(encoding="utf-8"))

    def validate(self, variants: dict | None = None, records: dict | None = None):
        return MODULE.validate(
            variants or self.variants,
            records or self.records,
            self.policy["upstream_repository"],
            self.policy["mirror_revision"],
        )

    def test_current_policy_covers_every_duplicate_alternative(self) -> None:
        mapping = self.validate()
        self.assertEqual(len(mapping), 10)
        self.assertEqual(
            mapping[("openblas/openblas-v3/PKGBUILD", "openblas")],
            "x86-64-v3",
        )
        self.assertEqual(mapping[("zstd/zstd-pgo/PKGBUILD", "zstd")], "pgo")

    def test_missing_duplicate_package_is_rejected(self) -> None:
        variants = copy.deepcopy(self.variants)
        variants["group"][0]["packages"].remove("openblas64")
        with self.assertRaisesRegex(MODULE.VariantError, "differs from duplicate package set"):
            self.validate(variants=variants)

    def test_wrong_variant_path_is_rejected(self) -> None:
        variants = copy.deepcopy(self.variants)
        variants["group"][0]["candidate"][0]["pkgbuild_path"] = "zstd/zstd/PKGBUILD"
        with self.assertRaisesRegex(MODULE.VariantError, "does not emit configured package"):
            self.validate(variants=variants)

    def test_coinstallable_variants_are_rejected(self) -> None:
        variants = copy.deepcopy(self.variants)
        variants["group"][1]["coinstallable"] = True
        with self.assertRaisesRegex(MODULE.VariantError, "selection contract is invalid"):
            self.validate(variants=variants)

    def test_optional_selection_is_rejected(self) -> None:
        variants = copy.deepcopy(self.variants)
        variants["group"][0]["selection_required"] = False
        with self.assertRaisesRegex(MODULE.VariantError, "selection contract is invalid"):
            self.validate(variants=variants)

    def test_revision_drift_is_rejected(self) -> None:
        variants = copy.deepcopy(self.variants)
        variants["revision"] = "0" * 40
        with self.assertRaisesRegex(MODULE.VariantError, "differs from ingress policy"):
            self.validate(variants=variants)


if __name__ == "__main__":
    unittest.main()
