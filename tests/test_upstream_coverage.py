from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "validate_upstream_coverage.py"
SPEC = importlib.util.spec_from_file_location("validate_upstream_coverage", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class UpstreamCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = json.loads(
            (ROOT / "production" / "upstream-coverage.json").read_text(encoding="utf-8")
        )

    def test_current_contract_is_valid(self) -> None:
        summary = MODULE.validate(self.document)
        self.assertEqual(summary["known"], 326)
        self.assertEqual(summary["remaining"], 38865)
        self.assertEqual(summary["pinned_upstreams"], 1)
        self.assertEqual(summary["planned_upstreams"], 10)
        self.assertEqual(summary["static_importers"], 10)
        self.assertEqual(summary["worker_fallbacks"], 11)

    def test_missing_upstream_is_rejected(self) -> None:
        document = copy.deepcopy(self.document)
        document["upstreams"].pop()
        with self.assertRaisesRegex(MODULE.CoverageError, "every canonical upstream"):
            MODULE.validate(document)

    def test_reordered_upstream_is_rejected(self) -> None:
        document = copy.deepcopy(self.document)
        document["upstreams"][0], document["upstreams"][1] = (
            document["upstreams"][1],
            document["upstreams"][0],
        )
        with self.assertRaisesRegex(MODULE.CoverageError, "order or set differs"):
            MODULE.validate(document)

    def test_planned_inventory_cannot_claim_a_count(self) -> None:
        document = copy.deepcopy(self.document)
        document["upstreams"][0]["known_package_identities"] = 100
        with self.assertRaisesRegex(MODULE.CoverageError, "cannot claim pinned evidence"):
            MODULE.validate(document)

    def test_pinned_inventory_requires_revision(self) -> None:
        document = copy.deepcopy(self.document)
        document["upstreams"][0]["inventory_state"] = "pinned"
        document["upstreams"][0]["known_package_identities"] = 100
        with self.assertRaisesRegex(MODULE.CoverageError, "pinned inventory is incomplete"):
            MODULE.validate(document)

    def test_complete_status_requires_exact_target(self) -> None:
        document = copy.deepcopy(self.document)
        document["status"] = "complete"
        with self.assertRaisesRegex(MODULE.CoverageError, "exact target count"):
            MODULE.validate(document)

    def test_native_shell_execution_cannot_be_enabled(self) -> None:
        document = copy.deepcopy(self.document)
        document["policy"]["native_shell_execution"] = True
        with self.assertRaisesRegex(MODULE.CoverageError, "fail-closed"):
            MODULE.validate(document)


if __name__ == "__main__":
    unittest.main()
