from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "generate_source_sbom.py"
SPEC = importlib.util.spec_from_file_location("generate_source_sbom", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def write_recipe(root: Path, revision: str = "a" * 40) -> None:
    path = root / "recipes" / "base" / "sample" / "package.toml"
    path.parent.mkdir(parents=True)
    path.write_text(
        f'''format = 1

[package]
name = "sample"
version = "1.2.3"
release = 1
summary = "Sample package"
license = "MIT"
scope = "system"
publish_authority = "arach-native"
architectures = ["x86-64"]

[[source]]
kind = "git"
url = "https://example.invalid/sample.git"
revision = "{revision}"
submodules = false

[build]
system = "cargo"
commands = ["cargo build --release --locked"]
outputs = ["target/release/sample"]

[runtime]
depends = []
provides = []

[policy]
network = false
sandbox = true
reproducible = true
''',
        encoding="utf-8",
    )


class SourceSbomTests(unittest.TestCase):
    def test_generates_spdx_document_with_pinned_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_recipe(root)
            records = MODULE.collect(root)
            document = MODULE.build_document(records, 0)
            self.assertEqual(document["spdxVersion"], "SPDX-2.3")
            self.assertEqual(document["creationInfo"]["created"], "1970-01-01T00:00:00Z")
            self.assertEqual(document["packages"][0]["name"], "sample")
            self.assertIn("@" + "a" * 40, document["packages"][0]["downloadLocation"])

    def test_namespace_is_independent_of_creation_time(self) -> None:
        records = [
            {
                "name": "sample",
                "version": "1",
                "summary": "Sample",
                "license": "MIT",
                "recipe": "recipes/sample/package.toml",
                "sources": ["git+https://example.invalid/sample.git@" + "a" * 40],
            }
        ]
        first = MODULE.build_document(records, 0)
        second = MODULE.build_document(records, 100)
        self.assertEqual(first["documentNamespace"], second["documentNamespace"])
        self.assertNotEqual(first["creationInfo"]["created"], second["creationInfo"]["created"])

    def test_rejects_short_git_revision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_recipe(root, revision="deadbeef")
            with self.assertRaisesRegex(MODULE.SbomError, "full object ID"):
                MODULE.collect(root)

    def test_rejects_unpinned_archive(self) -> None:
        with self.assertRaisesRegex(MODULE.SbomError, "lacks a lowercase SHA-256"):
            MODULE.source_locator(
                {"kind": "archive", "url": "https://example.invalid/source.tar.xz"},
                Path("package.toml"),
            )

    def test_output_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            link = root / "sbom.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(MODULE.SbomError, "cannot be a symlink"):
                MODULE.write_document(link, {})


if __name__ == "__main__":
    unittest.main()
