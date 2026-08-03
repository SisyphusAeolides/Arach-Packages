#!/usr/bin/env python3
"""Validate the 39,191-package Arach recipe corpus and completion receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any


PLAN_PATH = Path("production/recipe-corpus-plan.json")
TARGET_COUNT = 39_191
SHARD_COUNT = 256
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
STRATEGIES = {"static-importer", "deterministic-worker"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+_.-]{0,127}$")


class CorpusError(ValueError):
    pass


def load_json(path: Path, maximum_bytes: int = 64 * 1024 * 1024) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise CorpusError(f"file is not a regular file: {path}")
    if path.stat().st_size > maximum_bytes:
        raise CorpusError(f"file exceeds bounded size: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CorpusError(f"cannot load {path}: {error}") from error
    if not isinstance(value, dict):
        raise CorpusError(f"root must be an object: {path}")
    return value


def safe_relative(value: str) -> bool:
    path = Path(value)
    return (
        bool(value)
        and not path.is_absolute()
        and ".." not in path.parts
        and all(part not in {"", "."} for part in path.parts)
    )


def require_path(value: Any, path: str) -> str:
    if not isinstance(value, str) or not safe_relative(value):
        raise CorpusError(f"{path} must be a safe relative path")
    return value


def validate_plan(plan: dict[str, Any]) -> None:
    expected = {
        "format",
        "distribution",
        "target_count",
        "shard_count",
        "architecture",
        "corpus_schema",
        "signature_scope",
        "upstreams",
        "paths",
        "policy",
        "status",
    }
    if set(plan) != expected:
        raise CorpusError("recipe corpus plan has unexpected or missing fields")
    if (
        plan["format"] != 1
        or plan["distribution"] != "ArachOS"
        or plan["target_count"] != TARGET_COUNT
        or plan["shard_count"] != SHARD_COUNT
        or plan["architecture"] != "x86-64"
        or plan["corpus_schema"] != "corinth-recipe-corpus-v1"
        or plan["signature_scope"] != "package-index"
        or plan["upstreams"] != UPSTREAMS
        or plan["status"] not in {"building", "complete"}
    ):
        raise CorpusError("recipe corpus plan identity or target differs")
    paths = plan["paths"]
    if not isinstance(paths, dict) or set(paths) != {
        "manifest",
        "manifest_signature",
        "corpus_root",
        "recipe_root",
        "receipt_root",
        "worker_root",
        "shard_report_root",
        "build_receipt",
    }:
        raise CorpusError("recipe corpus plan paths are invalid")
    for key, value in paths.items():
        require_path(value, f"paths.{key}")
    if paths != {
        "manifest": "generated/recipe-corpus.json",
        "manifest_signature": "generated/recipe-corpus.json.sig",
        "corpus_root": "generated/corpus",
        "recipe_root": "generated/corpus/recipes",
        "receipt_root": "generated/corpus/receipts",
        "worker_root": "generated/corpus/workers",
        "shard_report_root": "generated/corpus/shard-reports",
        "build_receipt": "generated/recipe-corpus-receipt.json",
    }:
        raise CorpusError("recipe corpus paths differ from the canonical layout")
    if plan["policy"] != {
        "require_signed_manifest": True,
        "require_signed_entry_inputs": True,
        "require_immutable_sources": True,
        "static_import_first": True,
        "deterministic_worker_fallback": True,
        "native_shell_execution": False,
        "minimum_worker_reproducibility_runs": 2,
        "require_all_recipes_for_completion": True,
        "require_zero_blocked_for_completion": True,
        "require_merkle_root_for_completion": True,
    }:
        raise CorpusError("recipe corpus policy must remain fail-closed")


def corpus_shard(
    upstream: str,
    package: str,
    version: str,
    architecture: str,
    shard_count: int,
) -> int:
    if shard_count <= 0 or shard_count & (shard_count - 1):
        raise CorpusError("shard count must be a power of two")
    identity = b"\0".join(
        value.encode("utf-8")
        for value in (upstream, package, version, architecture)
    )
    digest = hashlib.sha256(identity).digest()
    return int.from_bytes(digest[:2], "big") & (shard_count - 1)


def validate_digest(value: Any, path: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise CorpusError(f"{path} must be a lowercase SHA-256 digest")
    return value


def validate_manifest(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    if set(manifest) != {
        "format",
        "distribution",
        "target_count",
        "shard_count",
        "architecture",
        "entries",
    }:
        raise CorpusError("recipe corpus manifest has unexpected or missing fields")
    if (
        manifest["format"] != 1
        or manifest["distribution"] != "ArachOS"
        or manifest["target_count"] != TARGET_COUNT
        or manifest["shard_count"] != SHARD_COUNT
        or manifest["architecture"] != "x86-64"
    ):
        raise CorpusError("recipe corpus manifest identity differs from the production target")
    entries = manifest["entries"]
    if not isinstance(entries, list) or len(entries) != TARGET_COUNT:
        raise CorpusError(f"recipe corpus manifest must contain exactly {TARGET_COUNT} entries")

    expected_fields = {
        "ordinal",
        "upstream",
        "package",
        "version",
        "architecture",
        "shard",
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
    previous: tuple[str, str, str, str] | None = None
    identities: set[tuple[str, str, str, str]] = set()
    path_sets = {
        "ingress_lock": set(),
        "ingress_signature": set(),
        "target_policy": set(),
        "target_signature": set(),
        "recipe": set(),
        "receipt": set(),
        "worker_request": set(),
    }
    for index, entry in enumerate(entries):
        base = f"entries[{index}]"
        if not isinstance(entry, dict) or set(entry) != expected_fields:
            raise CorpusError(f"{base} has unexpected or missing fields")
        if entry["ordinal"] != index:
            raise CorpusError(f"{base}.ordinal differs from canonical order")
        upstream = entry["upstream"]
        package = entry["package"]
        version = entry["version"]
        architecture = entry["architecture"]
        if upstream not in UPSTREAMS:
            raise CorpusError(f"{base}.upstream is invalid")
        if not isinstance(package, str) or not PACKAGE_RE.fullmatch(package):
            raise CorpusError(f"{base}.package is invalid")
        if (
            not isinstance(version, str)
            or not version
            or len(version) > 256
            or any(character.isspace() or character == "\0" for character in version)
        ):
            raise CorpusError(f"{base}.version is invalid")
        if architecture != "x86-64":
            raise CorpusError(f"{base}.architecture differs from the corpus")
        identity = (upstream, package, version, architecture)
        if previous is not None and previous >= identity:
            raise CorpusError(f"{base} is not in canonical order")
        previous = identity
        if identity in identities:
            raise CorpusError(f"{base} duplicates a package identity")
        identities.add(identity)
        expected_shard = corpus_shard(*identity, SHARD_COUNT)
        if entry["shard"] != expected_shard:
            raise CorpusError(f"{base}.shard differs from deterministic assignment")
        strategy = entry["strategy"]
        if strategy not in STRATEGIES:
            raise CorpusError(f"{base}.strategy is invalid")

        path_contracts = {
            "ingress_lock": ("locks/", ".toml"),
            "ingress_signature": ("signatures/", ".sig"),
            "target_policy": ("targets/", ".toml"),
            "target_signature": ("signatures/", ".sig"),
            "recipe": ("recipes/", "/package.toml"),
            "receipt": ("receipts/", ".toml"),
        }
        for field, (prefix, suffix) in path_contracts.items():
            value = require_path(entry[field], f"{base}.{field}")
            if not value.startswith(prefix) or not value.endswith(suffix):
                raise CorpusError(f"{base}.{field} is outside the canonical layout")
            if value in path_sets[field]:
                raise CorpusError(f"{base}.{field} is duplicated")
            path_sets[field].add(value)
        for field in (
            "ingress_lock_sha256",
            "ingress_signature_sha256",
            "target_policy_sha256",
            "target_signature_sha256",
        ):
            validate_digest(entry[field], f"{base}.{field}")

        if strategy == "static-importer":
            if (
                entry["worker_request"] is not None
                or entry["worker_request_sha256"] is not None
                or entry["fallback_reason"] is not None
            ):
                raise CorpusError(f"{base} static importer carries worker metadata")
        else:
            request = require_path(entry["worker_request"], f"{base}.worker_request")
            if not request.startswith("workers/") or not request.endswith(".json"):
                raise CorpusError(f"{base}.worker_request is outside the worker layout")
            if request in path_sets["worker_request"]:
                raise CorpusError(f"{base}.worker_request is duplicated")
            path_sets["worker_request"].add(request)
            validate_digest(entry["worker_request_sha256"], f"{base}.worker_request_sha256")
            reason = entry["fallback_reason"]
            if not isinstance(reason, str) or not reason.strip() or len(reason) > 512:
                raise CorpusError(f"{base}.fallback_reason is invalid")
    return entries


def verify_file(root: Path, relative: str, expected: str, maximum_bytes: int) -> bytes:
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise CorpusError(f"corpus input is not a regular file: {relative}")
    if path.stat().st_size > maximum_bytes:
        raise CorpusError(f"corpus input exceeds bounded size: {relative}")
    canonical = path.resolve()
    if canonical != path or not canonical.is_relative_to(root):
        raise CorpusError(f"corpus input traverses a symlink or escapes: {relative}")
    data = canonical.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise CorpusError(f"corpus input digest differs: {relative}")
    return data


def verify_inputs(root: Path, entries: list[dict[str, Any]]) -> None:
    for entry in entries:
        for path_field, digest_field, maximum in (
            ("ingress_lock", "ingress_lock_sha256", 4 * 1024 * 1024),
            ("ingress_signature", "ingress_signature_sha256", 512 * 1024),
            ("target_policy", "target_policy_sha256", 4 * 1024 * 1024),
            ("target_signature", "target_signature_sha256", 512 * 1024),
        ):
            verify_file(root, entry[path_field], entry[digest_field], maximum)
        if entry["strategy"] == "deterministic-worker":
            verify_file(
                root,
                entry["worker_request"],
                entry["worker_request_sha256"],
                4 * 1024 * 1024,
            )


def validate_recipe(path: Path, entry: dict[str, Any]) -> str:
    if path.is_symlink() or not path.is_file():
        raise CorpusError(f"recipe is missing or not regular: {entry['recipe']}")
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise CorpusError(f"recipe is invalid TOML: {entry['recipe']}: {error}") from error
    package = document.get("package")
    build = document.get("build")
    policy = document.get("policy")
    sources = document.get("source", [])
    if document.get("format") != 1 or not isinstance(package, dict) or not isinstance(build, dict):
        raise CorpusError(f"recipe identity is invalid: {entry['recipe']}")
    if package.get("name") != entry["package"] or package.get("version") != entry["version"]:
        raise CorpusError(f"recipe package identity differs: {entry['recipe']}")
    if package.get("architectures") != [entry["architecture"]]:
        raise CorpusError(f"recipe architecture differs: {entry['recipe']}")
    if policy != {"network": False, "sandbox": True, "reproducible": True}:
        raise CorpusError(f"recipe policy is not fail-closed: {entry['recipe']}")
    if build.get("system") == "meta":
        if sources or build.get("commands") or build.get("outputs"):
            raise CorpusError(f"meta recipe executes or carries sources: {entry['recipe']}")
    elif not isinstance(sources, list) or not sources:
        raise CorpusError(f"non-meta recipe lacks immutable sources: {entry['recipe']}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def merkle_root(leaves: list[bytes]) -> str:
    if not leaves:
        raise CorpusError("cannot build a Merkle root from an empty recipe set")
    level = [hashlib.sha256(leaf).digest() for leaf in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(level[index] + level[index + 1]).digest()
            for index in range(0, len(level), 2)
        ]
    return level[0].hex()


def verify_outputs(root: Path, entries: list[dict[str, Any]]) -> str:
    leaves: list[bytes] = []
    for entry in entries:
        recipe_path = root / entry["recipe"]
        receipt_path = root / entry["receipt"]
        recipe_sha256 = validate_recipe(recipe_path, entry)
        if receipt_path.is_symlink() or not receipt_path.is_file():
            raise CorpusError(f"recipe receipt is missing or not regular: {entry['receipt']}")
        identity = b"\0".join(
            value.encode("utf-8")
            for value in (
                entry["upstream"],
                entry["package"],
                entry["version"],
                entry["architecture"],
                recipe_sha256,
            )
        )
        leaves.append(identity)
    return merkle_root(leaves)


def seed_recipe_count(root: Path) -> int:
    names: set[str] = set()
    count = 0
    for path in sorted((root / "recipes").glob("**/package.toml")):
        if path.is_symlink() or not path.is_file():
            raise CorpusError(f"seed recipe is not regular: {path}")
        try:
            document = tomllib.loads(path.read_text(encoding="utf-8"))
            name = document["package"]["name"]
        except (OSError, tomllib.TOMLDecodeError, KeyError, TypeError) as error:
            raise CorpusError(f"seed recipe is invalid: {path}: {error}") from error
        if not isinstance(name, str) or not name or name in names:
            raise CorpusError(f"seed recipe name is invalid or duplicated: {path}")
        names.add(name)
        count += 1
    return count


def validate_receipt(
    receipt: dict[str, Any],
    manifest_sha256: str,
    expected_merkle_root: str,
) -> None:
    if set(receipt) != {
        "format",
        "corpus_sha256",
        "target_count",
        "generated",
        "worker_required",
        "blocked",
        "recipe_merkle_root",
    }:
        raise CorpusError("corpus build receipt has invalid fields")
    if (
        receipt["format"] != 1
        or receipt["corpus_sha256"] != manifest_sha256
        or receipt["target_count"] != TARGET_COUNT
        or receipt["generated"] != TARGET_COUNT
        or receipt["worker_required"] != 0
        or receipt["blocked"] != 0
        or receipt["recipe_merkle_root"] != expected_merkle_root
    ):
        raise CorpusError("corpus build receipt does not prove complete generation")


def write_report(path: Path, report: dict[str, Any]) -> None:
    if path.is_symlink():
        raise CorpusError(f"report path cannot be a symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def audit(
    root: Path,
    require_complete: bool,
    check_inputs: bool,
    check_outputs: bool,
) -> dict[str, Any]:
    plan = load_json(root / PLAN_PATH, 1024 * 1024)
    validate_plan(plan)
    seed_count = seed_recipe_count(root)
    manifest_path = root / plan["paths"]["manifest"]
    signature_path = root / plan["paths"]["manifest_signature"]
    receipt_path = root / plan["paths"]["build_receipt"]
    corpus_root = (root / plan["paths"]["corpus_root"]).resolve()

    report: dict[str, Any] = {
        "format": 1,
        "target_count": TARGET_COUNT,
        "seed_recipes": seed_count,
        "manifest_present": manifest_path.is_file() and not manifest_path.is_symlink(),
        "generated_entries": 0,
        "complete": False,
    }
    if not report["manifest_present"]:
        if require_complete or plan["status"] == "complete":
            raise CorpusError("complete corpus requires the signed production manifest")
        return report
    if signature_path.is_symlink() or not signature_path.is_file():
        raise CorpusError("corpus manifest signature is missing or not regular")

    manifest_bytes = manifest_path.read_bytes()
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    manifest = load_json(manifest_path)
    entries = validate_manifest(manifest)
    report["generated_entries"] = len(entries)
    report["manifest_sha256"] = manifest_sha256
    if check_inputs or require_complete:
        verify_inputs(corpus_root, entries)
    expected_merkle_root: str | None = None
    if check_outputs or require_complete:
        expected_merkle_root = verify_outputs(corpus_root, entries)
        report["recipe_merkle_root"] = expected_merkle_root
    if require_complete or plan["status"] == "complete":
        if expected_merkle_root is None:
            raise CorpusError("complete corpus requires output verification")
        receipt = load_json(receipt_path, 1024 * 1024)
        validate_receipt(receipt, manifest_sha256, expected_merkle_root)
        report["complete"] = True
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument("--check-inputs", action="store_true")
    parser.add_argument("--check-outputs", action="store_true")
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    try:
        report = audit(
            root,
            require_complete=arguments.require_complete,
            check_inputs=arguments.check_inputs,
            check_outputs=arguments.check_outputs,
        )
        if arguments.report is not None:
            path = arguments.report if arguments.report.is_absolute() else root / arguments.report
            write_report(path, report)
    except CorpusError as error:
        print(error, file=sys.stderr)
        return 1
    print(
        f"recipe corpus: {report['generated_entries']}/{TARGET_COUNT} generated, "
        f"{report['seed_recipes']} seed recipes, complete={str(report['complete']).lower()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
