#!/usr/bin/env python3
"""Validate closure-blocked canonical recipes promoted from CachyOS metadata."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
UPSTREAM_ATOM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.@-]{0,127}$")


class PromotionError(ValueError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise PromotionError(f"closure is not a regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PromotionError(f"cannot parse closure: {error}") from error
    if not isinstance(value, dict):
        raise PromotionError("closure root must be an object")
    return value


def safe_relative(value: str) -> bool:
    path = Path(value)
    return (
        bool(value)
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def load_recipe(root: Path, relative: str) -> dict[str, Any]:
    if not safe_relative(relative) or not relative.endswith("/package.toml"):
        raise PromotionError(f"unsafe promoted recipe path: {relative}")
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise PromotionError(f"promoted recipe is not a regular file: {relative}")
    canonical_root = root.resolve()
    canonical = path.resolve()
    if not canonical.is_relative_to(canonical_root):
        raise PromotionError(f"promoted recipe escapes its root: {relative}")
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise PromotionError(f"cannot parse promoted recipe {relative}: {error}") from error
    if not isinstance(value, dict):
        raise PromotionError(f"promoted recipe root is not a table: {relative}")
    return value


def validate(document: dict[str, Any], root: Path) -> dict[str, int]:
    if set(document) != {
        "format",
        "distribution",
        "repository",
        "revision",
        "status",
        "production_authority",
        "recipes",
    }:
        raise PromotionError("closure has missing or unknown top-level fields")
    if (
        document["format"] != 1
        or document["distribution"] != "ArachOS"
        or document["repository"]
        != "https://github.com/CachyOS/CachyOS-PKGBUILDS.git"
        or not isinstance(document["revision"], str)
        or not REVISION_RE.fullmatch(document["revision"])
        or document["status"] != "closure-blocked"
        or document["production_authority"] is not False
    ):
        raise PromotionError("closure identity, status, or authority is invalid")
    records = document["recipes"]
    if not isinstance(records, list) or not records:
        raise PromotionError("closure recipes must be a non-empty array")
    expected_fields = {
        "package",
        "recipe",
        "pkgbuild_path",
        "pkgbuild_sha256",
        "srcinfo_sha256",
        "normalizations",
        "missing_providers",
    }
    previous: str | None = None
    packages: set[str] = set()
    blockers = 0
    normalizations = 0
    for index, record in enumerate(records):
        base = f"recipes[{index}]"
        if not isinstance(record, dict) or set(record) != expected_fields:
            raise PromotionError(f"{base} has missing or unknown fields")
        package = record["package"]
        if (
            not isinstance(package, str)
            or not NAME_RE.fullmatch(package)
            or package in packages
            or previous is not None
            and previous >= package
        ):
            raise PromotionError(f"{base}.package is invalid, duplicated, or unsorted")
        previous = package
        packages.add(package)
        pkgbuild_path = record["pkgbuild_path"]
        if (
            not isinstance(pkgbuild_path, str)
            or not safe_relative(pkgbuild_path)
            or not pkgbuild_path.endswith("/PKGBUILD")
        ):
            raise PromotionError(f"{base}.pkgbuild_path is invalid")
        for field in ("pkgbuild_sha256", "srcinfo_sha256"):
            digest = record[field]
            if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
                raise PromotionError(f"{base}.{field} is invalid")
        missing = record["missing_providers"]
        if (
            not isinstance(missing, list)
            or not missing
            or missing != sorted(missing)
            or len(missing) != len(set(missing))
            or any(
                not isinstance(provider, str) or not NAME_RE.fullmatch(provider)
                for provider in missing
            )
        ):
            raise PromotionError(f"{base}.missing_providers is invalid")
        blockers += len(missing)

        mappings = record["normalizations"]
        if not isinstance(mappings, list):
            raise PromotionError(f"{base}.normalizations must be an array")
        seen_upstream: set[str] = set()
        seen_arach: set[str] = set()
        for mapping_index, mapping in enumerate(mappings):
            mapping_base = f"{base}.normalizations[{mapping_index}]"
            if not isinstance(mapping, dict) or set(mapping) != {
                "upstream",
                "arach",
                "kind",
            }:
                raise PromotionError(f"{mapping_base} has invalid fields")
            upstream = mapping["upstream"]
            arach = mapping["arach"]
            if (
                not isinstance(upstream, str)
                or not UPSTREAM_ATOM_RE.fullmatch(upstream)
                or upstream in seen_upstream
                or not isinstance(arach, str)
                or not NAME_RE.fullmatch(arach)
                or arach in seen_arach
                or mapping["kind"] != "capability-name"
                or arach not in missing
            ):
                raise PromotionError(f"{mapping_base} is invalid")
            seen_upstream.add(upstream)
            seen_arach.add(arach)
            normalizations += 1

        recipe = load_recipe(root, record["recipe"])
        if set(recipe) != {"format", "package", "build", "runtime", "policy"}:
            raise PromotionError(f"{base} promoted recipe has invalid sections")
        if recipe["format"] != 1:
            raise PromotionError(f"{base} promoted recipe format is invalid")
        package_table = recipe["package"]
        build = recipe["build"]
        runtime = recipe["runtime"]
        policy = recipe["policy"]
        if (
            not isinstance(package_table, dict)
            or package_table.get("name") != package
            or package_table.get("architectures") != ["x86-64"]
            or package_table.get("publish_authority") != "arach-native"
            or not isinstance(build, dict)
            or build != {
                "system": "meta",
                "depends": [],
                "commands": [],
                "outputs": [],
            }
            or not isinstance(runtime, dict)
            or runtime.get("depends") != missing
            or not isinstance(runtime.get("provides"), list)
            or not isinstance(runtime.get("conflicts"), list)
            or policy
            != {"network": False, "sandbox": True, "reproducible": True}
        ):
            raise PromotionError(f"{base} promoted recipe differs from its closure contract")
    return {
        "recipes": len(records),
        "blockers": blockers,
        "normalizations": normalizations,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--closure", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        summary = validate(load_json(arguments.closure), arguments.root.resolve())
    except PromotionError as error:
        print(error, file=sys.stderr)
        return 1
    print(
        f"validated {summary['recipes']} closure-blocked recipes with "
        f"{summary['blockers']} missing providers and "
        f"{summary['normalizations']} explicit normalizations"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
