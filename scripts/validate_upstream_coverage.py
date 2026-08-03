#!/usr/bin/env python3
"""Validate the ArachOS multi-upstream package coverage contract."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

UPSTREAMS = [
    "arch",
    "aur",
    "cachyos",
    "fedora",
    "debian",
    "alpine",
    "gentoo",
    "crux",
    "nix",
    "cargo",
    "github",
]
TARGET = 39_191
REVISION_RE = re.compile(r"^[0-9a-f]{40,64}$")
IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")


class CoverageError(ValueError):
    pass


def load(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise CoverageError(f"coverage contract is not a regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CoverageError(f"cannot parse coverage contract: {error}") from error
    if not isinstance(value, dict):
        raise CoverageError("coverage contract root must be an object")
    return value


def validate(document: dict[str, Any]) -> dict[str, int]:
    if set(document) != {
        "format",
        "distribution",
        "target_package_identities",
        "status",
        "policy",
        "upstreams",
    }:
        raise CoverageError("coverage contract has missing or unknown top-level fields")
    if (
        document["format"] != 1
        or document["distribution"] != "ArachOS"
        or document["target_package_identities"] != TARGET
        or document["status"] not in {"building", "complete"}
    ):
        raise CoverageError("coverage identity or status is invalid")
    expected_policy = {
        "signed_snapshot_required": True,
        "immutable_source_required": True,
        "static_import_first": True,
        "deterministic_worker_fallback": True,
        "native_shell_execution": False,
        "quarantine_is_non_publishable": True,
    }
    if document["policy"] != expected_policy:
        raise CoverageError("coverage policy must remain fail-closed")

    upstreams = document["upstreams"]
    if not isinstance(upstreams, list) or len(upstreams) != len(UPSTREAMS):
        raise CoverageError("coverage contract must contain every canonical upstream")
    names = [entry.get("name") if isinstance(entry, dict) else None for entry in upstreams]
    if names != UPSTREAMS:
        raise CoverageError("upstream order or set differs from the canonical list")

    expected_fields = {
        "name",
        "metadata_format",
        "static_importer",
        "worker_fallback",
        "inventory_state",
        "known_package_identities",
        "snapshot_revision",
    }
    known_total = 0
    pinned_count = 0
    planned_count = 0
    static_count = 0
    worker_count = 0
    for index, entry in enumerate(upstreams):
        base = f"upstreams[{index}]"
        if not isinstance(entry, dict) or set(entry) != expected_fields:
            raise CoverageError(f"{base} has missing or unknown fields")
        metadata_format = entry["metadata_format"]
        static_importer = entry["static_importer"]
        worker_fallback = entry["worker_fallback"]
        state = entry["inventory_state"]
        known = entry["known_package_identities"]
        revision = entry["snapshot_revision"]
        if not isinstance(metadata_format, str) or not IDENTIFIER_RE.fullmatch(metadata_format):
            raise CoverageError(f"{base}.metadata_format is invalid")
        if static_importer is not None and (
            not isinstance(static_importer, str) or not IDENTIFIER_RE.fullmatch(static_importer)
        ):
            raise CoverageError(f"{base}.static_importer is invalid")
        if worker_fallback is not True:
            raise CoverageError(f"{base} lacks deterministic worker fallback")
        if static_importer is None and not worker_fallback:
            raise CoverageError(f"{base} has no workload route")
        if state not in {"planned", "pinned"}:
            raise CoverageError(f"{base}.inventory_state is invalid")
        if state == "pinned":
            pinned_count += 1
            if (
                not isinstance(known, int)
                or known <= 0
                or not isinstance(revision, str)
                or not REVISION_RE.fullmatch(revision)
            ):
                raise CoverageError(f"{base} pinned inventory is incomplete")
            known_total += known
        else:
            planned_count += 1
            if known is not None or revision is not None:
                raise CoverageError(f"{base} planned inventory cannot claim pinned evidence")
        if static_importer is not None:
            static_count += 1
        if worker_fallback:
            worker_count += 1

    if known_total > TARGET:
        raise CoverageError("known package identity count exceeds the production target")
    if document["status"] == "complete" and (
        known_total != TARGET or planned_count != 0
    ):
        raise CoverageError("complete status requires every upstream pinned and exact target count")
    return {
        "known": known_total,
        "remaining": TARGET - known_total,
        "pinned_upstreams": pinned_count,
        "planned_upstreams": planned_count,
        "static_importers": static_count,
        "worker_fallbacks": worker_count,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--coverage", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        summary = validate(load(arguments.coverage))
    except CoverageError as error:
        print(error, file=sys.stderr)
        return 1
    print(
        "validated multi-upstream coverage: "
        f"known={summary['known']} remaining={summary['remaining']} "
        f"pinned={summary['pinned_upstreams']} planned={summary['planned_upstreams']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
