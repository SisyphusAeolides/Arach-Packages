from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "prepare_cachyos_overlay.py"
SPEC = importlib.util.spec_from_file_location("prepare_cachyos_overlay", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

REPOSITORY = "https://github.com/CachyOS/CachyOS-PKGBUILDS.git"
REVISION = "a" * 40


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_pkgbuild(root: Path, directory: str, text: str, srcinfo: str) -> tuple[str, str]:
    package_root = root / directory
    package_root.mkdir(parents=True)
    pkgbuild = text.encode()
    srcinfo_bytes = srcinfo.encode()
    (package_root / "PKGBUILD").write_bytes(pkgbuild)
    (package_root / ".SRCINFO").write_bytes(srcinfo_bytes)
    return sha(pkgbuild), sha(srcinfo_bytes)


class PrepareCachyosOverlayTests(unittest.TestCase):
    def fixture(self, root: Path):
        first_sha, first_srcinfo = write_pkgbuild(
            root,
            "foo-v3",
            "pkgname=foo\npkgver=1\npkgrel=1\nbuild() { :; }\n",
            "pkgbase = foo\n\tpkgver = 1\n\tpkgrel = 1\n\tarch = x86_64\n\tlicense = MIT\n\npkgname = foo\n",
        )
        second_sha, second_srcinfo = write_pkgbuild(
            root,
            "foo-v4",
            "pkgname=foo\npkgver=1\npkgrel=1\nbuild() { :; }\n",
            "pkgbase = foo\n\tpkgver = 1\n\tpkgrel = 1\n\tarch = x86_64\n\tlicense = MIT\n\npkgname = foo\n",
        )
        meta_sha, meta_srcinfo = write_pkgbuild(
            root,
            "meta",
            "pkgname=meta\npkgver=2\npkgrel=3\ndepends=('foo')\n",
            "pkgbase = meta\n\tpkgver = 2\n\tpkgrel = 3\n\tarch = any\n\tlicense = MIT\n\tdepends = foo\n\npkgname = meta\n",
        )
        bad_sha, bad_srcinfo = write_pkgbuild(
            root,
            "bad",
            "pkgname=bad\npkgver=1\npkgrel=1\ninstall=bad.install\n",
            "pkgbase = bad\n\tpkgver = 1\n\tpkgrel = 1\n\tarch = x86_64\n\tlicense = MIT\n\npkgname = bad\n",
        )
        records = {
            "format": 1,
            "repository": REPOSITORY,
            "revision": REVISION,
            "pkgbuild_count": 4,
            "resolved_package_outputs": 4,
            "unresolved_pkgbuilds": 0,
            "duplicate_packages": [
                {
                    "package": "foo",
                    "first": "foo-v3/PKGBUILD",
                    "second": "foo-v4/PKGBUILD",
                }
            ],
            "records": [
                {
                    "admission_class": "sealed-script",
                    "line_count": 4,
                    "packages": ["foo"],
                    "path": "foo-v3/PKGBUILD",
                    "pkgbuild_sha256": first_sha,
                    "reason_codes": [],
                    "signals": {},
                    "srcinfo_sha256": first_srcinfo,
                },
                {
                    "admission_class": "sealed-script",
                    "line_count": 4,
                    "packages": ["foo"],
                    "path": "foo-v4/PKGBUILD",
                    "pkgbuild_sha256": second_sha,
                    "reason_codes": [],
                    "signals": {},
                    "srcinfo_sha256": second_srcinfo,
                },
                {
                    "admission_class": "meta",
                    "line_count": 4,
                    "packages": ["meta"],
                    "path": "meta/PKGBUILD",
                    "pkgbuild_sha256": meta_sha,
                    "reason_codes": [],
                    "signals": {},
                    "srcinfo_sha256": meta_srcinfo,
                },
                {
                    "admission_class": "rejected",
                    "line_count": 4,
                    "packages": ["bad"],
                    "path": "bad/PKGBUILD",
                    "pkgbuild_sha256": bad_sha,
                    "reason_codes": ["INSTALL_HOOK"],
                    "signals": {},
                    "srcinfo_sha256": bad_srcinfo,
                },
            ],
        }
        policy = {
            "upstream_repository": REPOSITORY,
            "mirror_revision": REVISION,
            "target_package_outputs": 4,
            "max_pkgbuild_bytes": 524288,
        }
        variants = {
            "format": 1,
            "repository": REPOSITORY,
            "revision": REVISION,
            "group": [
                {
                    "id": "foo-microarchitecture",
                    "selection_dimension": "microarchitecture",
                    "selection_required": True,
                    "coinstallable": False,
                    "packages": ["foo"],
                    "candidate": [
                        {
                            "id": "x86-64-v3",
                            "pkgbuild_path": "foo-v3/PKGBUILD",
                            "policy_value": "x86-64-v3",
                            "build_identity": "target-v3",
                        },
                        {
                            "id": "x86-64-v4",
                            "pkgbuild_path": "foo-v4/PKGBUILD",
                            "policy_value": "x86-64-v4",
                            "build_identity": "target-v4",
                        },
                    ],
                }
            ],
        }
        return policy, records, variants

    def test_prepares_every_output_with_distinct_variant_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mirror = root / "mirror"
            mirror.mkdir()
            policy, records, variants = self.fixture(mirror)
            output = root / "stage"
            manifest = MODULE.prepare(mirror, policy, records, variants, output)
            MODULE.verify(manifest, output)
            self.assertEqual(manifest["package_output_count"], 4)
            self.assertEqual(manifest["canonical_package_name_count"], 3)
            self.assertEqual(manifest["variant_entry_count"], 2)
            self.assertEqual(manifest["variant_collision_count"], 1)
            self.assertEqual(
                manifest["counts"],
                {
                    "meta-target-ready": 1,
                    "quarantined": 1,
                    "worker-required": 2,
                },
            )
            identities = {entry["candidate_id"] for entry in manifest["entries"]}
            self.assertEqual(
                identities,
                {"bad", "foo--x86-64-v3", "foo--x86-64-v4", "meta"},
            )

    def test_meta_target_is_valid_command_free_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mirror = root / "mirror"
            mirror.mkdir()
            policy, records, variants = self.fixture(mirror)
            output = root / "stage"
            manifest = MODULE.prepare(mirror, policy, records, variants, output)
            meta = next(entry for entry in manifest["entries"] if entry["package"] == "meta")
            target = output / meta["artifacts"]["target_policy"]["path"]
            text = target.read_text(encoding="utf-8")
            self.assertIn('build_system = "meta"', text)
            self.assertIn("build_commands = []", text)
            self.assertIn("outputs = []", text)

    def test_worker_plan_requires_exact_tool_binding_and_two_runs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mirror = root / "mirror"
            mirror.mkdir()
            policy, records, variants = self.fixture(mirror)
            output = root / "stage"
            manifest = MODULE.prepare(mirror, policy, records, variants, output)
            worker = next(
                entry for entry in manifest["entries"] if entry["candidate_id"] == "foo--x86-64-v3"
            )
            plan = json.loads(
                (output / worker["artifacts"]["worker_plan"]["path"]).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(plan["state"], "toolchain-binding-required")
            self.assertEqual(plan["reproducibility_runs"], 2)
            self.assertTrue(
                all(tool["binding"] == "exact-artifact-required" for tool in plan["required_tools"])
            )

    def test_changed_artifact_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mirror = root / "mirror"
            mirror.mkdir()
            policy, records, variants = self.fixture(mirror)
            output = root / "stage"
            manifest = MODULE.prepare(mirror, policy, records, variants, output)
            artifact = output / manifest["entries"][0]["artifacts"]["candidate"]["path"]
            artifact.write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.OverlayError, "differs from retained bytes"):
                MODULE.verify(manifest, output)

    def test_missing_variant_mapping_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mirror = root / "mirror"
            mirror.mkdir()
            policy, records, variants = self.fixture(mirror)
            variants = copy.deepcopy(variants)
            variants["group"][0]["candidate"].pop()
            with self.assertRaises(MODULE.VARIANTS.VariantError):
                MODULE.prepare(mirror, policy, records, variants, root / "stage")


if __name__ == "__main__":
    unittest.main()
