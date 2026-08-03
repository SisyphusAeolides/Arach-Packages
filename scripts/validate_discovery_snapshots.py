#!/usr/bin/env python3
"""Validate non-authoritative, immutable upstream discovery snapshots."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

OBJECT_RE = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
EXPECTED = {
    "cachyos": (
        "https://github.com/CachyOS/CachyOS-PKGBUILDS.git",
        "pkgbuild-monorepo",
    ),
    "gentoo": ("https://github.com/gentoo/gentoo.git", "ebuild-tree"),
    "nix": ("https://github.com/NixOS/nixpkgs.git", "nixpkgs-tree"),
    "cargo": (
        "https://github.com/rust-lang/crates.io-index.git",
        "cargo-registry-index",
    ),
}
REQUIREMENT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")


class SnapshotError(ValueError):
    pass


def load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise SnapshotError(f"snapshot contract is not a regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SnapshotError(f"cannot parse snapshot contract: {error}") from error
    if not isinstance(value, dict):
        raise SnapshotError("snapshot contract root must be an object")
    return value


def validate(document: dict[str, Any]) -> dict[str, int]:
    if set(document) != {
        "format",
        "distribution",
        "kind",
        "production_authority",
        "snapshots",
    }:
        raise SnapshotError("snapshot contract has missing or unknown top-level fields")
    if (
        document["format"] != 1
        or document["distribution"] != "ArachOS"
        or document["kind"] != "unsigned-discovery-snapshots"
        or document["production_authority"] is not False
    ):
        raise SnapshotError("snapshot contract identity or authority is invalid")
    snapshots = document["snapshots"]
    if not isinstance(snapshots, list) or len(snapshots) != len(EXPECTED):
        raise SnapshotError("snapshot contract does not contain the canonical set")
    expected_fields = {
        "upstream",
        "repository",
        "object_id",
        "default_branch",
        "metadata_family",
        "inventory_state",
        "known_package_identities",
        "promotion_requirements",
    }
    seen: set[str] = set()
    repositories: set[str] = set()
    retained = 0
    pinned = 0
    known = 0
    for index, snapshot in enumerate(snapshots):
        base = f"snapshots[{index}]"
        if not isinstance(snapshot, dict) or set(snapshot) != expected_fields:
            raise SnapshotError(f"{base} has missing or unknown fields")
        upstream = snapshot["upstream"]
        if upstream not in EXPECTED or upstream in seen:
            raise SnapshotError(f"{base}.upstream is unknown or duplicated")
        seen.add(upstream)
        repository, metadata_family = EXPECTED[upstream]
        if (
            snapshot["repository"] != repository
            or snapshot["repository"] in repositories
            or snapshot["metadata_family"] != metadata_family
            or not isinstance(snapshot["object_id"], str)
            or not OBJECT_RE.fullmatch(snapshot["object_id"])
            or not isinstance(snapshot["default_branch"], str)
            or not IDENTIFIER_RE.fullmatch(snapshot["default_branch"])
        ):
            raise SnapshotError(f"{base} repository, object, or metadata family is invalid")
        repositories.add(snapshot["repository"])
        state = snapshot["inventory_state"]
        count = snapshot["known_package_identities"]
        if state == "retained":
            retained += 1
            if not isinstance(count, int) or count <= 0:
                raise SnapshotError(f"{base} retained inventory lacks a positive count")
            known += count
        elif state == "snapshot-pinned":
            pinned += 1
            if count is not None:
                raise SnapshotError(f"{base} snapshot-pinned inventory cannot claim a count")
        else:
            raise SnapshotError(f"{base}.inventory_state is invalid")
        requirements = snapshot["promotion_requirements"]
        if (
            not isinstance(requirements, list)
            or len(requirements) < 4
            or len(requirements) != len(set(requirements))
            or any(
                not isinstance(requirement, str)
                or not REQUIREMENT_RE.fullmatch(requirement)
                for requirement in requirements
            )
            or "signed-snapshot" not in requirements
        ):
            raise SnapshotError(f"{base}.promotion_requirements are invalid")
    if seen != set(EXPECTED):
        raise SnapshotError("snapshot upstream set differs from the canonical set")
    return {
        "retained": retained,
        "snapshot_pinned": pinned,
        "known_package_identities": known,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshots", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        summary = validate(load(arguments.snapshots))
    except SnapshotError as error:
        print(error, file=sys.stderr)
        return 1
    print(
        "validated discovery snapshots: "
        f"retained={summary['retained']} "
        f"snapshot_pinned={summary['snapshot_pinned']} "
        f"known={summary['known_package_identities']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
