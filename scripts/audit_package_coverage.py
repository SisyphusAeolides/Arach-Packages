#!/usr/bin/env python3
"""Audit production package coverage against the recipe tree."""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from collections import Counter
from pathlib import Path
from typing import Any


MANIFEST = Path("production/package-coverage.json")
ROUTES = [
    "native-recipe",
    "signed-binary",
    "compatibility-runtime",
    "container",
    "managed-vm",
]
STATUSES = {"missing", "planned", "present", "qualified"}


class CoverageError(ValueError):
    pass


def safe_relative(value: str) -> bool:
    path = Path(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts


def load_recipes(root: Path) -> dict[str, Path]:
    recipes: dict[str, Path] = {}
    for path in sorted((root / "recipes").glob("**/package.toml")):
        if path.is_symlink() or not path.is_file():
            raise CoverageError(f"recipe is not a regular file: {path}")
        try:
            document = tomllib.loads(path.read_text(encoding="utf-8"))
            name = document["package"]["name"]
        except (OSError, tomllib.TOMLDecodeError, KeyError, TypeError) as error:
            raise CoverageError(f"invalid recipe {path}: {error}") from error
        if not isinstance(name, str) or not name:
            raise CoverageError(f"recipe package name is invalid: {path}")
        if name in recipes:
            raise CoverageError(f"duplicate recipe package name: {name}")
        recipes[name] = path.relative_to(root)
    if not recipes:
        raise CoverageError("recipe tree is empty")
    return recipes


def load_manifest(root: Path) -> dict[str, Any]:
    path = root / MANIFEST
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CoverageError(f"invalid coverage manifest {path}: {error}") from error
    if not isinstance(value, dict):
        raise CoverageError("coverage manifest root must be an object")
    return value


def audit(root: Path, manifest: dict[str, Any], recipes: dict[str, Path]) -> Counter[str]:
    if set(manifest) != {"format", "distribution", "routes", "categories"}:
        raise CoverageError("coverage manifest has unexpected or missing fields")
    if manifest["format"] != 1 or manifest["distribution"] != "Arach OS":
        raise CoverageError("coverage manifest identity is invalid")
    if manifest["routes"] != ROUTES:
        raise CoverageError("coverage routes differ from the canonical order")
    categories = manifest["categories"]
    if not isinstance(categories, list) or not categories:
        raise CoverageError("coverage categories must be a non-empty array")

    category_ids: set[str] = set()
    workload_names: set[str] = set()
    counts: Counter[str] = Counter()
    for category_index, category in enumerate(categories):
        base = f"categories[{category_index}]"
        if not isinstance(category, dict) or set(category) != {"id", "title", "workloads"}:
            raise CoverageError(f"{base} has invalid fields")
        category_id = category["id"]
        if not isinstance(category_id, str) or not category_id or category_id in category_ids:
            raise CoverageError(f"{base}.id must be unique and non-empty")
        category_ids.add(category_id)
        if not isinstance(category["title"], str) or not category["title"].strip():
            raise CoverageError(f"{base}.title must be non-empty")
        workloads = category["workloads"]
        if not isinstance(workloads, list) or not workloads:
            raise CoverageError(f"{base}.workloads must be non-empty")

        for workload_index, workload in enumerate(workloads):
            item = f"{base}.workloads[{workload_index}]"
            expected = {"name", "route", "status", "packages", "evidence"}
            if not isinstance(workload, dict) or set(workload) != expected:
                raise CoverageError(f"{item} has invalid fields")
            name = workload["name"]
            route = workload["route"]
            status = workload["status"]
            packages = workload["packages"]
            evidence = workload["evidence"]
            if not isinstance(name, str) or not name or name in workload_names:
                raise CoverageError(f"{item}.name must be unique and non-empty")
            workload_names.add(name)
            if route not in ROUTES:
                raise CoverageError(f"{item}.route is invalid")
            if status not in STATUSES:
                raise CoverageError(f"{item}.status is invalid")
            if (
                not isinstance(packages, list)
                or not packages
                or len(packages) != len(set(packages))
                or not all(isinstance(package, str) and package for package in packages)
            ):
                raise CoverageError(f"{item}.packages must be a non-empty unique string array")
            if not isinstance(evidence, list) or len(evidence) != len(set(evidence)):
                raise CoverageError(f"{item}.evidence must be a unique array")
            for evidence_path in evidence:
                if not isinstance(evidence_path, str) or not safe_relative(evidence_path):
                    raise CoverageError(f"{item}.evidence contains an unsafe path")
                resolved = root / evidence_path
                evidence_root = root / "production" / "evidence"
                try:
                    resolved.relative_to(evidence_root)
                except ValueError as error:
                    raise CoverageError(f"{item}.evidence must be beneath production/evidence") from error
                if resolved.is_symlink() or not resolved.is_file():
                    raise CoverageError(f"{item}.evidence file is missing: {evidence_path}")

            if status in {"present", "qualified"} and route == "native-recipe":
                missing = sorted(set(packages) - set(recipes))
                if missing:
                    raise CoverageError(f"{item} claims recipe coverage for missing packages: {missing}")
            if status == "qualified" and not evidence:
                raise CoverageError(f"{item} is qualified without evidence")
            if status != "qualified" and evidence:
                raise CoverageError(f"{item} carries evidence before qualification")
            counts[status] += 1

    return counts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    try:
        recipes = load_recipes(root)
        counts = audit(root, load_manifest(root), recipes)
    except CoverageError as error:
        print(error, file=sys.stderr)
        return 1

    total = sum(counts.values())
    print(
        f"package coverage: {counts['qualified']}/{total} qualified, "
        f"{counts['present']} present, {counts['planned']} planned, {counts['missing']} missing; "
        f"{len(recipes)} recipes indexed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
