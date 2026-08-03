#!/usr/bin/env python3
"""Validate mutually exclusive CachyOS package variant policy."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+_.@-]{0,127}$")


class VariantError(ValueError):
    pass


def load_toml(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise VariantError(f"variant policy is not a regular file: {path}")
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise VariantError(f"cannot parse variant policy: {error}") from error
    if not isinstance(value, dict):
        raise VariantError("variant policy root must be a table")
    return value


def load_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise VariantError(f"snapshot record is not a regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise VariantError(f"cannot parse snapshot records: {error}") from error
    if not isinstance(value, dict):
        raise VariantError("snapshot record root must be an object")
    return value


def safe_pkgbuild_path(value: str) -> bool:
    path = Path(value)
    return (
        bool(value)
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
        and path.name == "PKGBUILD"
    )


def record_packages(records: dict[str, Any]) -> dict[str, set[str]]:
    entries = records.get("records")
    if not isinstance(entries, list) or not entries:
        raise VariantError("snapshot records must contain a non-empty records array")
    output: dict[str, set[str]] = {}
    for index, record in enumerate(entries):
        if not isinstance(record, dict):
            raise VariantError(f"records[{index}] must be an object")
        path = record.get("path")
        packages = record.get("packages")
        if not isinstance(path, str) or not safe_pkgbuild_path(path):
            raise VariantError(f"records[{index}].path is invalid")
        if path in output:
            raise VariantError(f"duplicate snapshot record path: {path}")
        if (
            not isinstance(packages, list)
            or not packages
            or any(not isinstance(package, str) or not PACKAGE_RE.fullmatch(package) for package in packages)
            or len(packages) != len(set(packages))
        ):
            raise VariantError(f"records[{index}].packages is invalid")
        output[path] = set(packages)
    return output


def duplicate_paths(records: dict[str, Any]) -> dict[str, set[str]]:
    duplicates = records.get("duplicate_packages")
    if not isinstance(duplicates, list):
        raise VariantError("snapshot duplicate_packages must be an array")
    output: dict[str, set[str]] = {}
    for index, duplicate in enumerate(duplicates):
        if not isinstance(duplicate, dict) or set(duplicate) != {"package", "first", "second"}:
            raise VariantError(f"duplicate_packages[{index}] has invalid fields")
        package = duplicate["package"]
        first = duplicate["first"]
        second = duplicate["second"]
        if (
            not isinstance(package, str)
            or not PACKAGE_RE.fullmatch(package)
            or not isinstance(first, str)
            or not safe_pkgbuild_path(first)
            or not isinstance(second, str)
            or not safe_pkgbuild_path(second)
            or first == second
        ):
            raise VariantError(f"duplicate_packages[{index}] is invalid")
        paths = output.setdefault(package, set())
        paths.update((first, second))
    return output


def validate(
    variants: dict[str, Any],
    records: dict[str, Any],
    expected_repository: str | None = None,
    expected_revision: str | None = None,
) -> dict[tuple[str, str], str]:
    if set(variants) != {"format", "repository", "revision", "group"}:
        raise VariantError("variant policy has missing or unknown top-level fields")
    repository = variants["repository"]
    revision = variants["revision"]
    if (
        variants["format"] != 1
        or repository != "https://github.com/CachyOS/CachyOS-PKGBUILDS.git"
        or not isinstance(revision, str)
        or not REVISION_RE.fullmatch(revision)
    ):
        raise VariantError("variant policy authority is invalid")
    if expected_repository is not None and repository != expected_repository:
        raise VariantError("variant repository differs from ingress policy")
    if expected_revision is not None and revision != expected_revision:
        raise VariantError("variant revision differs from ingress policy")
    if records.get("repository") != repository or records.get("revision") != revision:
        raise VariantError("variant authority differs from retained snapshot records")

    snapshot_paths = record_packages(records)
    duplicates = duplicate_paths(records)
    groups = variants["group"]
    if not isinstance(groups, list) or not groups:
        raise VariantError("variant policy must contain groups")

    group_ids: set[str] = set()
    dimensions: set[str] = set()
    claimed_packages: set[str] = set()
    mapping: dict[tuple[str, str], str] = {}

    for group_index, group in enumerate(groups):
        if not isinstance(group, dict) or set(group) != {
            "id",
            "selection_dimension",
            "selection_required",
            "coinstallable",
            "packages",
            "candidate",
        }:
            raise VariantError(f"group[{group_index}] has missing or unknown fields")
        group_id = group["id"]
        dimension = group["selection_dimension"]
        packages = group["packages"]
        candidates = group["candidate"]
        if (
            not isinstance(group_id, str)
            or not ID_RE.fullmatch(group_id)
            or group_id in group_ids
            or not isinstance(dimension, str)
            or not ID_RE.fullmatch(dimension)
            or dimension in dimensions
            or group["selection_required"] is not True
            or group["coinstallable"] is not False
        ):
            raise VariantError(f"group[{group_index}] identity or selection contract is invalid")
        group_ids.add(group_id)
        dimensions.add(dimension)
        if (
            not isinstance(packages, list)
            or not packages
            or packages != sorted(packages)
            or len(packages) != len(set(packages))
            or any(not isinstance(package, str) or not PACKAGE_RE.fullmatch(package) for package in packages)
            or claimed_packages.intersection(packages)
        ):
            raise VariantError(f"group[{group_index}].packages is invalid")
        claimed_packages.update(packages)
        if not isinstance(candidates, list) or len(candidates) < 2:
            raise VariantError(f"group[{group_index}] requires at least two candidates")

        candidate_ids: set[str] = set()
        policy_values: set[str] = set()
        build_identities: set[str] = set()
        candidate_paths: set[str] = set()
        for candidate_index, candidate in enumerate(candidates):
            if not isinstance(candidate, dict) or set(candidate) != {
                "id",
                "pkgbuild_path",
                "policy_value",
                "build_identity",
            }:
                raise VariantError(
                    f"group[{group_index}].candidate[{candidate_index}] has invalid fields"
                )
            candidate_id = candidate["id"]
            path = candidate["pkgbuild_path"]
            policy_value = candidate["policy_value"]
            build_identity = candidate["build_identity"]
            if (
                not isinstance(candidate_id, str)
                or not ID_RE.fullmatch(candidate_id)
                or candidate_id in candidate_ids
                or not isinstance(path, str)
                or not safe_pkgbuild_path(path)
                or path in candidate_paths
                or path not in snapshot_paths
                or not isinstance(policy_value, str)
                or not ID_RE.fullmatch(policy_value)
                or policy_value in policy_values
                or not isinstance(build_identity, str)
                or not ID_RE.fullmatch(build_identity)
                or build_identity in build_identities
            ):
                raise VariantError(
                    f"group[{group_index}].candidate[{candidate_index}] is invalid"
                )
            candidate_ids.add(candidate_id)
            candidate_paths.add(path)
            policy_values.add(policy_value)
            build_identities.add(build_identity)
            for package in packages:
                if package not in snapshot_paths[path]:
                    raise VariantError(
                        f"variant path {path} does not emit configured package {package}"
                    )
                key = (path, package)
                if key in mapping:
                    raise VariantError(f"variant mapping is duplicated: {path}:{package}")
                mapping[key] = candidate_id

        for package in packages:
            expected_paths = duplicates.get(package)
            if expected_paths is None or expected_paths != candidate_paths:
                raise VariantError(
                    f"variant group {group_id} does not exactly cover duplicate package {package}"
                )

    if claimed_packages != set(duplicates):
        missing = sorted(set(duplicates) - claimed_packages)
        extra = sorted(claimed_packages - set(duplicates))
        raise VariantError(
            f"variant policy differs from duplicate package set: missing={missing}, extra={extra}"
        )
    expected_mappings = sum(len(paths) for paths in duplicates.values())
    if len(mapping) != expected_mappings:
        raise VariantError("variant mapping count differs from duplicate package alternatives")
    return mapping


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--variants", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--policy", type=Path)
    arguments = parser.parse_args()
    try:
        variants = load_toml(arguments.variants)
        records = load_json(arguments.records)
        repository = None
        revision = None
        if arguments.policy is not None:
            policy = load_toml(arguments.policy)
            repository = policy.get("upstream_repository")
            revision = policy.get("mirror_revision")
        mapping = validate(variants, records, repository, revision)
    except (OSError, VariantError) as error:
        print(error, file=sys.stderr)
        return 1
    print(f"validated {len(mapping)} CachyOS package variant alternatives")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
