from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "inventory_cargo_index_shard.py"
SPEC = importlib.util.spec_from_file_location("inventory_cargo_index_shard", MODULE_PATH)
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


def registry_line(name: str, version: str, checksum: str, yanked: bool = False) -> str:
    return json.dumps(
        {
            "name": name,
            "vers": version,
            "deps": [],
            "cksum": checksum,
            "features": {},
            "yanked": yanked,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def crate_path(name: str) -> str:
    lowered = name.lower()
    if len(lowered) == 1:
        return f"1/{lowered}"
    if len(lowered) == 2:
        return f"2/{lowered}"
    if len(lowered) == 3:
        return f"3/{lowered[0]}/{lowered}"
    return f"{lowered[:2]}/{lowered[2:4]}/{lowered}"


def repository(root: Path, crates: dict[str, str]) -> str:
    git(root, "init", "--quiet")
    git(root, "config", "user.name", "Tester")
    git(root, "config", "user.email", "tester@example.invalid")
    (root / "config.json").write_text("{}\n", encoding="utf-8")
    for name, content in crates.items():
        path = root / crate_path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "--quiet", "-m", "fixture")
    return git(root, "rev-parse", "HEAD")


class CargoIndexShardTests(unittest.TestCase):
    def test_large_valid_index_above_legacy_bound_is_accepted(self) -> None:
        release = {
            "name": "demo",
            "vers": "1.0.0",
            "deps": [],
            "cksum": "a" * 64,
            "features": {"large": ["x" * (8 * 1024 * 1024)]},
            "yanked": False,
        }
        data = (json.dumps(release, separators=(",", ":")) + "\n").encode()
        self.assertGreater(len(data), 8 * 1024 * 1024)
        self.assertLess(len(data), MODULE.MAX_INDEX_BLOB_BYTES)
        result = MODULE.parse_release_lines("demo", data)
        self.assertEqual(result["status"], "candidate")
        self.assertEqual(result["version"], "1.0.0")

    def test_index_blob_bound_is_enforced(self) -> None:
        with mock.patch.object(MODULE, "MAX_INDEX_BLOB_BYTES", 64):
            with self.assertRaisesRegex(MODULE.CargoIndexError, "byte bound"):
                MODULE.parse_release_lines("demo", b"x" * 65)

    def test_selects_latest_non_yanked_release(self) -> None:
        data = (
            registry_line("demo", "1.0.0", "a" * 64)
            + "\n"
            + registry_line("demo", "2.0.0", "b" * 64, yanked=True)
            + "\n"
            + registry_line("demo", "1.5.0", "c" * 64)
            + "\n"
        ).encode()
        result = MODULE.parse_release_lines("demo", data)
        self.assertEqual(result["status"], "candidate")
        self.assertEqual(result["version"], "1.5.0")
        self.assertEqual(result["checksum"], "c" * 64)
        self.assertEqual(result["release_count"], 3)
        self.assertEqual(result["yanked_count"], 1)

    def test_all_yanked_crate_is_quarantined(self) -> None:
        data = (
            registry_line("demo", "1.0.0", "a" * 64, yanked=True) + "\n"
        ).encode()
        result = MODULE.parse_release_lines("demo", data)
        self.assertEqual(result["status"], "quarantined")
        self.assertEqual(result["reason"], "all-releases-yanked")

    def test_inventory_emits_candidate_and_quarantine(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            revision = repository(
                root,
                {
                    "alpha": registry_line("alpha", "1.0.0", "a" * 64) + "\n",
                    "beta": registry_line("beta", "2.0.0", "b" * 64, True) + "\n",
                },
            )
            shard_count = 1
            document = MODULE.inventory(root, revision, 0, shard_count)
            MODULE.validate_manifest(document, revision, 0, shard_count)
            self.assertEqual(document["record_count"], 2)
            self.assertEqual(document["candidate_count"], 1)
            self.assertEqual(document["quarantined_count"], 1)
            alpha = next(record for record in document["records"] if record["package"] == "alpha")
            self.assertEqual(alpha["version"], "1.0.0")
            self.assertEqual(
                alpha["archive_url"],
                "https://static.crates.io/crates/alpha/alpha-1.0.0.crate",
            )
            self.assertIs(alpha["production_authority"], False)

    def test_malformed_index_is_retained_as_quarantine(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            revision = repository(root, {"alpha": "not-json\n"})
            document = MODULE.inventory(root, revision, 0, 1)
            self.assertEqual(document["candidate_count"], 0)
            self.assertEqual(document["quarantined_count"], 1)
            self.assertEqual(document["records"][0]["reason"], "invalid-index-metadata")

    def test_shard_assignment_is_stable_and_bounded(self) -> None:
        first = MODULE.shard_for("serde", 256)
        second = MODULE.shard_for("serde", 256)
        self.assertEqual(first, second)
        self.assertGreaterEqual(first, 0)
        self.assertLess(first, 256)
        with self.assertRaisesRegex(MODULE.CargoIndexError, "power of two"):
            MODULE.shard_for("serde", 255)

    def test_manifest_cannot_claim_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            revision = repository(
                root,
                {"alpha": registry_line("alpha", "1.0.0", "a" * 64) + "\n"},
            )
            document = MODULE.inventory(root, revision, 0, 1)
            changed = copy.deepcopy(document)
            changed["production_authority"] = True
            with self.assertRaisesRegex(MODULE.CargoIndexError, "identity"):
                MODULE.validate_manifest(changed, revision, 0, 1)

    def test_archive_checksum_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            revision = repository(
                root,
                {"alpha": registry_line("alpha", "1.0.0", "a" * 64) + "\n"},
            )
            document = MODULE.inventory(root, revision, 0, 1)
            changed = copy.deepcopy(document)
            changed["records"][0]["checksum"] = "0" * 63
            with self.assertRaisesRegex(MODULE.CargoIndexError, "candidate"):
                MODULE.validate_manifest(changed, revision, 0, 1)


if __name__ == "__main__":
    unittest.main()
