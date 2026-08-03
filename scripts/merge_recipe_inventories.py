#!/usr/bin/env python3
"""Merge independently prepared upstream inventories into one unsigned corpus manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
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
UPSTREAM_ORDER = {name: index for index, name in enumerate(UPSTREAMS)}
STATIC_UPSTREAMS = set(UPSTREAMS) - {"github"}
STRATEGIES = {"static-importer", "deterministic-worker"}
TARGET = 39_191
SHARDS = 256
MAX_ENTRIES = 50_000
REVISION_RE = re.compile(r"^[0-9a-f]{40,64}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+_.@-]{0,127}$")


class MergeError(ValueError):
    pass


def load_json(path: Path, maximum_bytes: int = 64 * 1024 * 1024) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise MergeError(f"inventory is not a regular file: {path}")
    if path.stat().st_size > maximum_bytes:
        raise MergeError(f"inventory exceeds its byte bound: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise MergeError(f"cannot parse {path}: {error}") from error
    if not isinstance(value, dict):
        raise MergeError(f"inventory root must be an object: {path}")
    return value


def safe_relative(value: str) -> bool:
    path = Path(value)
    return (
        bool(value)
        and len(value) <= 4096
        and not path.is_absolute()
        and "\\" not in value
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def require_path(value: Any, label: str, prefix: str, suffix: str) -> str:
    if (
        not isinstance(value, str)
        or not safe_relative(value)
        or not value.startswith(prefix)
        or not value.endswith(suffix)
    ):
        raise MergeError(f"{label} is outside the canonical layout")
    return value


def require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
        raise MergeError(f"{label} must be a lowercase SHA-256 digest")
    return value


def valid_version(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value) <= 256
        and not any(character.isspace() or character == "\0" for character in value)
    )


def corpus_shard(
    upstream: str,
    package: str,
    version: str,
    architecture: str,
    shard_count: int = SHARDS,
) -> int:
    if shard_count <= 0 or shard_count & (shard_count - 1):
        raise MergeError("shard count must be a power of two")
    identity = b"\0".join(
        value.encode("utf-8") for value in (upstream, package, version, architecture)
    )
    digest = hashlib.sha256(identity).digest()
    return int.from_bytes(digest[:2], "big") & (shard_count - 1)


def validate_inventory(document: dict[str, Any], source: str) -> tuple[str, list[dict[str, Any]]]:
    if set(document) != {
        "format",
        "distribution",
        "upstream",
        "snapshot_revision",
        "snapshot_sha256",
        "entries",
    }:
        raise MergeError(f"{source}: inventory has missing or unknown fields")
    upstream = document["upstream"]
    if (
        document["format"] != 1
        or document["distribution"] != "ArachOS"
        or upstream not in UPSTREAMS
        or not isinstance(document["snapshot_revision"], str)
        or not REVISION_RE.fullmatch(document["snapshot_revision"])
        or not isinstance(document["snapshot_sha256"], str)
        or not DIGEST_RE.fullmatch(document["snapshot_sha256"])
    ):
        raise MergeError(f"{source}: inventory authority or snapshot identity is invalid")
    entries = document["entries"]
    if not isinstance(entries, list) or not entries or len(entries) > MAX_ENTRIES:
        raise MergeError(f"{source}: inventory entries are empty or exceed capacity")

    expected_fields = {
        "package",
        "version",
        "architecture",
        "strategy",
        "ingress_lock",
        "ingress_lock_sha256",
        "ingress_signature",
        "ingress_signature_sha256",
        "target_policy",
        "target_policy_sha256",
        "target_signature",
        "target_signature_sha256",
        "recipe",
        "receipt",
        "worker_request",
        "worker_request_sha256",
        "fallback_reason",
    }
    previous: tuple[str, str, str] | None = None
    identities: set[tuple[str, str, str]] = set()
    local_paths: set[str] = set()
    for index, entry in enumerate(entries):
        base = f"{source}: entries[{index}]"
        if not isinstance(entry, dict) or set(entry) != expected_fields:
            raise MergeError(f"{base} has missing or unknown fields")
        package = entry["package"]
        version = entry["version"]
        architecture = entry["architecture"]
        strategy = entry["strategy"]
        if (
            not isinstance(package, str)
            or not PACKAGE_RE.fullmatch(package)
            or not valid_version(version)
            or architecture not in {"x86-64", "aarch64", "riscv64"}
            or strategy not in STRATEGIES
        ):
            raise MergeError(f"{base} package identity or strategy is invalid")
        identity = (package, version, architecture)
        if previous is not None and previous >= identity:
            raise MergeError(f"{base} is not in canonical order")
        previous = identity
        if identity in identities:
            raise MergeError(f"{base} duplicates an inventory identity")
        identities.add(identity)
        if strategy == "static-importer" and upstream not in STATIC_UPSTREAMS:
            raise MergeError(f"{base} selects an unsupported static importer")

        paths = {
            "ingress_lock": require_path(
                entry["ingress_lock"], f"{base}.ingress_lock", "locks/", ".toml"
            ),
            "ingress_signature": require_path(
                entry["ingress_signature"],
                f"{base}.ingress_signature",
                "signatures/",
                ".sig",
            ),
            "target_policy": require_path(
                entry["target_policy"], f"{base}.target_policy", "targets/", ".toml"
            ),
            "target_signature": require_path(
                entry["target_signature"],
                f"{base}.target_signature",
                "signatures/",
                ".sig",
            ),
            "recipe": require_path(
                entry["recipe"], f"{base}.recipe", "recipes/", "/package.toml"
            ),
            "receipt": require_path(
                entry["receipt"], f"{base}.receipt", "receipts/", ".toml"
            ),
        }
        for field in (
            "ingress_lock_sha256",
            "ingress_signature_sha256",
            "target_policy_sha256",
            "target_signature_sha256",
        ):
            require_digest(entry[field], f"{base}.{field}")
        for label, path in paths.items():
            if path in local_paths:
                raise MergeError(f"{base}.{label} reuses an inventory path")
            local_paths.add(path)

        if strategy == "static-importer":
            if (
                entry["worker_request"] is not None
                or entry["worker_request_sha256"] is not None
                or entry["fallback_reason"] is not None
            ):
                raise MergeError(f"{base} static entry carries worker metadata")
        else:
            request = require_path(
                entry["worker_request"],
                f"{base}.worker_request",
                "workers/",
                ".json",
            )
            if request in local_paths:
                raise MergeError(f"{base}.worker_request reuses an inventory path")
            local_paths.add(request)
            require_digest(entry["worker_request_sha256"], f"{base}.worker_request_sha256")
            reason = entry["fallback_reason"]
            if not isinstance(reason, str) or not reason.strip() or len(reason) > 512:
                raise MergeError(f"{base}.fallback_reason is invalid")
    return upstream, entries


def merge(inventories: list[tuple[str, dict[str, Any]]], require_complete: bool) -> tuple[dict[str, Any], dict[str, Any]]:
    if not inventories:
        raise MergeError("at least one inventory is required")
    seen_upstreams: set[str] = set()
    seen_identities: set[tuple[str, str, str, str]] = set()
    seen_paths: set[str] = set()
    merged: list[dict[str, Any]] = []
    snapshots: list[dict[str, Any]] = []
    strategies: Counter[str] = Counter()

    for source, document in inventories:
        upstream, entries = validate_inventory(document, source)
        if upstream in seen_upstreams:
            raise MergeError(f"multiple inventories supplied for upstream {upstream}")
        seen_upstreams.add(upstream)
        snapshots.append(
            {
                "upstream": upstream,
                "snapshot_revision": document["snapshot_revision"],
                "snapshot_sha256": document["snapshot_sha256"],
                "entry_count": len(entries),
                "source": source,
            }
        )
        for entry in entries:
            identity = (
                upstream,
                entry["package"],
                entry["version"],
                entry["architecture"],
            )
            if identity in seen_identities:
                raise MergeError(f"duplicate cross-inventory identity: {identity}")
            seen_identities.add(identity)
            for field in (
                "ingress_lock",
                "ingress_signature",
                "target_policy",
                "target_signature",
                "recipe",
                "receipt",
            ):
                path = entry[field]
                if path in seen_paths:
                    raise MergeError(f"cross-inventory path collision: {path}")
                seen_paths.add(path)
            if entry["strategy"] == "deterministic-worker":
                path = entry["worker_request"]
                if path in seen_paths:
                    raise MergeError(f"cross-inventory path collision: {path}")
                seen_paths.add(path)
            merged_entry = {
                "ordinal": 0,
                "upstream": upstream,
                "package": entry["package"],
                "version": entry["version"],
                "architecture": entry["architecture"],
                "shard": corpus_shard(*identity),
                "strategy": entry["strategy"],
                "ingress_lock": entry["ingress_lock"],
                "ingress_lock_sha256": entry["ingress_lock_sha256"],
                "ingress_signature": entry["ingress_signature"],
                "ingress_signature_sha256": entry["ingress_signature_sha256"],
                "target_policy": entry["target_policy"],
                "target_policy_sha256": entry["target_policy_sha256"],
                "target_signature": entry["target_signature"],
                "target_signature_sha256": entry["target_signature_sha256"],
                "recipe": entry["recipe"],
                "receipt": entry["receipt"],
                "worker_request": entry["worker_request"],
                "worker_request_sha256": entry["worker_request_sha256"],
                "fallback_reason": entry["fallback_reason"],
            }
            strategies[entry["strategy"]] += 1
            merged.append(merged_entry)

    if len(merged) > MAX_ENTRIES:
        raise MergeError("merged corpus exceeds bounded capacity")
    merged.sort(
        key=lambda entry: (
            UPSTREAM_ORDER[entry["upstream"]],
            entry["package"],
            entry["version"],
            entry["architecture"],
        )
    )
    for ordinal, entry in enumerate(merged):
        entry["ordinal"] = ordinal

    complete = len(merged) == TARGET and seen_upstreams == set(UPSTREAMS)
    if require_complete and not complete:
        missing = sorted(set(UPSTREAMS) - seen_upstreams, key=UPSTREAM_ORDER.get)
        raise MergeError(
            f"corpus is incomplete: entries={len(merged)}/{TARGET} missing_upstreams={missing}"
        )
    manifest = {
        "format": 1,
        "distribution": "ArachOS",
        "target_count": len(merged),
        "shard_count": SHARDS,
        "architecture": "x86-64",
        "entries": merged,
    }
    snapshots.sort(key=lambda item: UPSTREAM_ORDER[item["upstream"]])
    report = {
        "format": 1,
        "distribution": "ArachOS",
        "status": "complete" if complete else "building",
        "production_target": TARGET,
        "merged_entries": len(merged),
        "remaining_entries": TARGET - len(merged),
        "upstream_count": len(seen_upstreams),
        "missing_upstreams": sorted(set(UPSTREAMS) - seen_upstreams, key=UPSTREAM_ORDER.get),
        "strategy_counts": dict(sorted(strategies.items())),
        "snapshots": snapshots,
        "manifest_sha256": hashlib.sha256(
            (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        ).hexdigest(),
        "authorization": "unsigned-package-index-manifest",
    }
    return manifest, report


def write_new(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise MergeError(f"output path must be new: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", action="append", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--require-complete", action="store_true")
    arguments = parser.parse_args()
    try:
        inventories = [(str(path), load_json(path)) for path in arguments.inventory]
        manifest, report = merge(inventories, arguments.require_complete)
        write_new(arguments.manifest, manifest)
        write_new(arguments.report, report)
    except (OSError, MergeError) as error:
        print(error, file=sys.stderr)
        return 1
    print(
        f"merged {report['merged_entries']}/{report['production_target']} package identities "
        f"from {report['upstream_count']} upstreams; status={report['status']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
