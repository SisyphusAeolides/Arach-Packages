from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "audit_package_coverage.py"
SPEC = importlib.util.spec_from_file_location("audit_package_coverage", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def manifest(status: str, packages: list[str], route: str = "native-recipe", evidence: list[str] | None = None) -> dict:
    return {
        "format": 1,
        "distribution": "Arach OS",
        "routes": MODULE.ROUTES,
        "categories": [
            {
                "id": "test",
                "title": "Test",
                "workloads": [
                    {
                        "name": "workload",
                        "route": route,
                        "status": status,
                        "packages": packages,
                        "evidence": evidence or [],
                    }
                ],
            }
        ],
    }


class PackageCoverageTests(unittest.TestCase):
    def test_present_native_workload_requires_recipes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(MODULE.CoverageError, "missing packages"):
                MODULE.audit(root, manifest("present", ["missing"]), {})

    def test_missing_workload_can_name_future_packages(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            counts = MODULE.audit(Path(directory), manifest("missing", ["future"]), {})
            self.assertEqual(counts["missing"], 1)

    def test_qualified_workload_requires_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(MODULE.CoverageError, "qualified without evidence"):
                MODULE.audit(
                    Path(directory),
                    manifest("qualified", ["base"]),
                    {"base": Path("recipes/base/base/package.toml")},
                )

    def test_unqualified_workload_cannot_carry_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "production" / "evidence" / "report.json"
            evidence.parent.mkdir(parents=True)
            evidence.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.CoverageError, "before qualification"):
                MODULE.audit(
                    root,
                    manifest("present", ["base"], evidence=["production/evidence/report.json"]),
                    {"base": Path("recipes/base/base/package.toml")},
                )

    def test_recipe_loader_rejects_duplicate_package_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("one", "two"):
                path = root / "recipes" / name / "package.toml"
                path.parent.mkdir(parents=True)
                path.write_text('[package]\nname = "duplicate"\n', encoding="utf-8")
            with self.assertRaisesRegex(MODULE.CoverageError, "duplicate recipe package name"):
                MODULE.load_recipes(root)

    def test_manifest_round_trip_shape(self) -> None:
        payload = manifest("planned", ["binary"], route="signed-binary")
        self.assertEqual(json.loads(json.dumps(payload)), payload)


if __name__ == "__main__":
    unittest.main()
