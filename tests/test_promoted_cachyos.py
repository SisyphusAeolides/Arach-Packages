from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROMOTED = ROOT / "ingress" / "cachyos" / "promoted"
MODULE_PATH = ROOT / "scripts" / "validate_promoted_cachyos.py"
SPEC = importlib.util.spec_from_file_location("validate_promoted_cachyos", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class PromotedCachyosTests(unittest.TestCase):
    def setUp(self) -> None:
        self.closure = json.loads((PROMOTED / "closure.json").read_text(encoding="utf-8"))

    def validate(self, document: dict | None = None) -> dict[str, int]:
        return MODULE.validate(document or self.closure, PROMOTED)

    def test_current_promoted_closure_is_valid(self) -> None:
        summary = self.validate()
        self.assertEqual(summary, {"recipes": 2, "blockers": 12, "normalizations": 1})

    def test_closure_cannot_claim_production_authority(self) -> None:
        closure = copy.deepcopy(self.closure)
        closure["production_authority"] = True
        with self.assertRaisesRegex(MODULE.PromotionError, "authority"):
            self.validate(closure)

    def test_missing_provider_cannot_disappear_from_closure(self) -> None:
        closure = copy.deepcopy(self.closure)
        closure["recipes"][0]["missing_providers"].pop()
        with self.assertRaisesRegex(MODULE.PromotionError, "differs from its closure"):
            self.validate(closure)

    def test_normalization_target_must_be_a_missing_provider(self) -> None:
        closure = copy.deepcopy(self.closure)
        closure["recipes"][1]["normalizations"][0]["arach"] = "other-capability"
        with self.assertRaisesRegex(MODULE.PromotionError, "normalizations"):
            self.validate(closure)

    def test_recipe_dependency_mutation_is_rejected(self) -> None:
        closure = copy.deepcopy(self.closure)
        closure["recipes"][1]["missing_providers"] = ["zfs-utils"]
        closure["recipes"][1]["normalizations"] = []
        with self.assertRaisesRegex(MODULE.PromotionError, "differs from its closure"):
            self.validate(closure)

    def test_recipe_order_is_canonical(self) -> None:
        closure = copy.deepcopy(self.closure)
        closure["recipes"].reverse()
        with self.assertRaisesRegex(MODULE.PromotionError, "unsorted"):
            self.validate(closure)


if __name__ == "__main__":
    unittest.main()
