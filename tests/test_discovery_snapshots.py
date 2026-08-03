from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "validate_discovery_snapshots.py"
SPEC = importlib.util.spec_from_file_location("validate_discovery_snapshots", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class DiscoverySnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = json.loads(
            (ROOT / "production" / "discovery-snapshots.json").read_text(
                encoding="utf-8"
            )
        )

    def test_current_snapshots_are_valid(self) -> None:
        summary = MODULE.validate(self.document)
        self.assertEqual(summary["retained"], 1)
        self.assertEqual(summary["snapshot_pinned"], 3)
        self.assertEqual(summary["known_package_identities"], 326)

    def test_symbolic_object_is_rejected(self) -> None:
        document = copy.deepcopy(self.document)
        document["snapshots"][1]["object_id"] = "master"
        with self.assertRaisesRegex(MODULE.SnapshotError, "object"):
            MODULE.validate(document)

    def test_snapshot_pin_cannot_claim_count(self) -> None:
        document = copy.deepcopy(self.document)
        document["snapshots"][1]["known_package_identities"] = 100
        with self.assertRaisesRegex(MODULE.SnapshotError, "cannot claim"):
            MODULE.validate(document)

    def test_retained_inventory_requires_count(self) -> None:
        document = copy.deepcopy(self.document)
        document["snapshots"][0]["known_package_identities"] = None
        with self.assertRaisesRegex(MODULE.SnapshotError, "positive count"):
            MODULE.validate(document)

    def test_repository_authority_cannot_drift(self) -> None:
        document = copy.deepcopy(self.document)
        document["snapshots"][2]["repository"] = "https://example.invalid/nixpkgs.git"
        with self.assertRaisesRegex(MODULE.SnapshotError, "repository"):
            MODULE.validate(document)

    def test_production_authority_is_rejected(self) -> None:
        document = copy.deepcopy(self.document)
        document["production_authority"] = True
        with self.assertRaisesRegex(MODULE.SnapshotError, "authority"):
            MODULE.validate(document)

    def test_signed_snapshot_requirement_cannot_be_removed(self) -> None:
        document = copy.deepcopy(self.document)
        document["snapshots"][3]["promotion_requirements"].remove("signed-snapshot")
        with self.assertRaisesRegex(MODULE.SnapshotError, "promotion_requirements"):
            MODULE.validate(document)


if __name__ == "__main__":
    unittest.main()
