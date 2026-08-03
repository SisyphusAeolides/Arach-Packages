from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "merge_recipe_inventories.py"
SPEC = importlib.util.spec_from_file_location("merge_recipe_inventories", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def digest(character: str) -> str:
    return character * 64


def entry(package: str, strategy: str = "static-importer") -> dict:
    worker = strategy == "deterministic-worker"
    return {
        "package": package,
        "version": "1.0.0",
        "architecture": "x86-64",
        "strategy": strategy,
        "ingress_lock": f"locks/{package}.toml",
        "ingress_lock_sha256": digest("a"),
        "ingress_signature": f"signatures/{package}.lock.sig",
        "ingress_signature_sha256": digest("b"),
        "target_policy": f"targets/{package}.toml",
        "target_policy_sha256": digest("c"),
        "target_signature": f"signatures/{package}.target.sig",
        "target_signature_sha256": digest("d"),
        "recipe": f"recipes/{package}/package.toml",
        "receipt": f"receipts/{package}.toml",
        "worker_request": f"workers/{package}.json" if worker else None,
        "worker_request_sha256": digest("e") if worker else None,
        "fallback_reason": "dynamic packaging logic" if worker else None,
    }


def inventory(upstream: str, entries: list[dict]) -> dict:
    return {
        "format": 1,
        "distribution": "ArachOS",
        "upstream": upstream,
        "snapshot_revision": "1" * 40,
        "snapshot_sha256": digest("f"),
        "entries": entries,
    }


class RecipeInventoryMergeTests(unittest.TestCase):
    def test_merges_static_and_worker_inventories_canonically(self) -> None:
        manifest, report = MODULE.merge(
            [
                ("arch.json", inventory("arch", [entry("alpha")])),
                (
                    "github.json",
                    inventory("github", [entry("omega", "deterministic-worker")]),
                ),
            ],
            require_complete=False,
        )
        self.assertEqual(manifest["distribution"], "ArachOS")
        self.assertEqual(manifest["target_count"], 2)
        self.assertEqual([item["ordinal"] for item in manifest["entries"]], [0, 1])
        self.assertEqual([item["upstream"] for item in manifest["entries"]], ["arch", "github"])
        self.assertEqual(
            manifest["entries"][0]["shard"],
            MODULE.corpus_shard("arch", "alpha", "1.0.0", "x86-64"),
        )
        self.assertEqual(report["status"], "building")
        self.assertEqual(report["merged_entries"], 2)
        self.assertEqual(report["remaining_entries"], 39189)
        self.assertEqual(report["authorization"], "unsigned-package-index-manifest")
        self.assertEqual(
            report["strategy_counts"],
            {"deterministic-worker": 1, "static-importer": 1},
        )

    def test_same_upstream_cannot_be_supplied_twice(self) -> None:
        with self.assertRaisesRegex(MODULE.MergeError, "multiple inventories"):
            MODULE.merge(
                [
                    ("first.json", inventory("arch", [entry("alpha")])),
                    ("second.json", inventory("arch", [entry("beta")])),
                ],
                require_complete=False,
            )

    def test_cross_inventory_path_collision_is_rejected(self) -> None:
        arch = inventory("arch", [entry("alpha")])
        aur_entry = entry("beta")
        aur_entry["ingress_lock"] = "locks/alpha.toml"
        aur = inventory("aur", [aur_entry])
        with self.assertRaisesRegex(MODULE.MergeError, "path collision"):
            MODULE.merge(
                [("arch.json", arch), ("aur.json", aur)],
                require_complete=False,
            )

    def test_github_cannot_claim_static_import(self) -> None:
        with self.assertRaisesRegex(MODULE.MergeError, "unsupported static importer"):
            MODULE.validate_inventory(
                inventory("github", [entry("alpha")]),
                "github.json",
            )

    def test_non_x86_entry_is_rejected_by_x86_corpus(self) -> None:
        value = inventory("arch", [entry("alpha")])
        value["entries"][0]["architecture"] = "aarch64"
        with self.assertRaisesRegex(MODULE.MergeError, "architecture"):
            MODULE.validate_inventory(value, "arch.json")

    def test_incomplete_union_cannot_claim_completion(self) -> None:
        with self.assertRaisesRegex(MODULE.MergeError, "corpus is incomplete"):
            MODULE.merge(
                [("arch.json", inventory("arch", [entry("alpha")]))],
                require_complete=True,
            )

    def test_static_entry_cannot_carry_worker_metadata(self) -> None:
        value = inventory("arch", [entry("alpha")])
        value["entries"][0]["worker_request"] = "workers/alpha.json"
        with self.assertRaisesRegex(MODULE.MergeError, "carries worker metadata"):
            MODULE.validate_inventory(value, "arch.json")

    def test_worker_entry_requires_reason(self) -> None:
        value = inventory("arch", [entry("alpha", "deterministic-worker")])
        value["entries"][0]["fallback_reason"] = ""
        with self.assertRaisesRegex(MODULE.MergeError, "fallback_reason"):
            MODULE.validate_inventory(value, "arch.json")

    def test_inventory_entries_must_be_sorted(self) -> None:
        value = inventory("arch", [entry("zeta"), entry("alpha")])
        with self.assertRaisesRegex(MODULE.MergeError, "canonical order"):
            MODULE.validate_inventory(value, "arch.json")

    def test_snapshot_revision_cannot_be_symbolic(self) -> None:
        value = inventory("arch", [entry("alpha")])
        value["snapshot_revision"] = "main"
        with self.assertRaisesRegex(MODULE.MergeError, "snapshot identity"):
            MODULE.validate_inventory(value, "arch.json")


if __name__ == "__main__":
    unittest.main()
