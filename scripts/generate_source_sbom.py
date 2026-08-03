#!/usr/bin/env python3
"""Generate a deterministic SPDX 2.3 source SBOM from Arach package recipes."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote


DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40,64}$")


class SbomError(ValueError):
    pass


def load_recipe(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise SbomError(f"recipe is not a regular file: {path}")
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise SbomError(f"cannot parse recipe {path}: {error}") from error
    package = document.get("package")
    sources = document.get("source", [])
    if not isinstance(package, dict) or not isinstance(sources, list):
        raise SbomError(f"recipe has invalid package or source tables: {path}")
    for field in ("name", "version", "summary", "license"):
        if not isinstance(package.get(field), str) or not package[field].strip():
            raise SbomError(f"recipe package.{field} is invalid: {path}")
    return document


def require_digest(source: dict[str, Any], path: Path) -> str:
    digest = source.get("checksum")
    if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
        raise SbomError(f"non-git source lacks a lowercase SHA-256 checksum: {path}")
    return digest


def source_locator(source: dict[str, Any], path: Path) -> str:
    kind = source.get("kind")
    if not isinstance(kind, str):
        raise SbomError(f"invalid source identity: {path}")
    if kind == "git":
        url = source.get("url")
        revision = source.get("revision")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise SbomError(f"git source lacks an HTTPS URL: {path}")
        if not isinstance(revision, str) or not REVISION_RE.fullmatch(revision):
            raise SbomError(f"git source is not pinned to a full object ID: {path}")
        return f"git+{url}@{revision}"
    if kind == "archive":
        url = source.get("url")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise SbomError(f"archive source lacks an HTTPS URL: {path}")
        return f"archive+{url}#sha256={require_digest(source, path)}"
    if kind == "crates-io":
        package = source.get("package")
        version = source.get("version")
        if not isinstance(package, str) or not package:
            raise SbomError(f"crates.io source lacks a package name: {path}")
        if not isinstance(version, str) or not version:
            raise SbomError(f"crates.io source lacks an exact version: {path}")
        return (
            f"pkg:cargo/{quote(package, safe='')}@{quote(version, safe='')}"
            f"#sha256={require_digest(source, path)}"
        )
    if kind == "local":
        local_path = source.get("url")
        if (
            not isinstance(local_path, str)
            or not local_path
            or Path(local_path).is_absolute()
            or ".." in Path(local_path).parts
        ):
            raise SbomError(f"local source lacks a safe repository-relative path: {path}")
        return f"file:{quote(local_path, safe='/')}#sha256={require_digest(source, path)}"
    raise SbomError(f"unsupported source kind {kind!r}: {path}")


def spdx_id(name: str) -> str:
    token = re.sub(r"[^A-Za-z0-9.-]", "-", name)
    return f"SPDXRef-Package-{token}"


def collect(root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    names: set[str] = set()
    for path in sorted((root / "recipes").glob("**/package.toml")):
        document = load_recipe(path)
        package = document["package"]
        name = package["name"]
        if name in names:
            raise SbomError(f"duplicate package name: {name}")
        names.add(name)
        locators = [source_locator(source, path) for source in document.get("source", [])]
        records.append(
            {
                "name": name,
                "version": package["version"],
                "summary": package["summary"],
                "license": package["license"],
                "recipe": path.relative_to(root).as_posix(),
                "sources": sorted(locators),
            }
        )
    if not records:
        raise SbomError("recipe tree is empty")
    return sorted(records, key=lambda record: record["name"])


def build_document(records: list[dict[str, Any]], created_unix: int) -> dict[str, Any]:
    if created_unix < 0:
        raise SbomError("created-unix cannot be negative")
    inventory_bytes = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    inventory_digest = hashlib.sha256(inventory_bytes).hexdigest()
    created = datetime.fromtimestamp(created_unix, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    packages = []
    relationships = []
    for record in records:
        identifier = spdx_id(record["name"])
        packages.append(
            {
                "SPDXID": identifier,
                "name": record["name"],
                "versionInfo": record["version"],
                "downloadLocation": record["sources"][0]
                if len(record["sources"]) == 1
                else "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": record["license"],
                "supplier": "Organization: Arach OS",
                "summary": record["summary"],
                "externalRefs": [
                    {
                        "referenceCategory": "OTHER",
                        "referenceType": "arach-source",
                        "referenceLocator": locator,
                    }
                    for locator in record["sources"]
                ]
                + [
                    {
                        "referenceCategory": "OTHER",
                        "referenceType": "arach-recipe",
                        "referenceLocator": record["recipe"],
                    }
                ],
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": identifier,
            }
        )

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Arach-Packages source inventory",
        "documentNamespace": f"urn:arach:spdx:recipes:{inventory_digest}",
        "creationInfo": {
            "created": created,
            "creators": ["Organization: Arach OS", "Tool: generate_source_sbom.py"],
        },
        "packages": packages,
        "relationships": relationships,
    }


def write_document(path: Path, document: dict[str, Any]) -> None:
    if path.is_symlink():
        raise SbomError(f"SBOM output cannot be a symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--created-unix", type=int, required=True)
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    output = arguments.output if arguments.output.is_absolute() else root / arguments.output
    try:
        records = collect(root)
        document = build_document(records, arguments.created_unix)
        write_document(output, document)
    except (OSError, SbomError) as error:
        print(error, file=sys.stderr)
        return 1
    print(f"wrote SPDX source SBOM for {len(records)} packages to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
