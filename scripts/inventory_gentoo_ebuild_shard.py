#!/usr/bin/env python3
"""Classify one immutable Gentoo ebuild shard without sourcing Bash."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


SCRIPTS = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "inventory_git_tree", SCRIPTS / "inventory_git_tree.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Git tree inventory module")
TREE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = TREE
SPEC.loader.exec_module(TREE)

MAX_EBUILD_BYTES = 512 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_SHARD_RECORDS = 10_000
ASSIGNMENT_RE = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$")
FUNCTION_RE = re.compile(r"(?m)^\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*\)\s*\{")
STATIC_KEYS = {"DESCRIPTION", "LICENSE", "KEYWORDS", "SRC_URI"}
HASH_RE = re.compile(r"^[A-F0-9]{32,256}$")


class GentooError(ValueError):
    pass


def shard_for(category: str, package: str, shard_count: int) -> int:
    if shard_count <= 0 or shard_count & (shard_count - 1):
        raise GentooError("shard count must be a power of two")
    key = f"{category}/{package}".encode("utf-8")
    digest = hashlib.sha256(key).digest()
    return int.from_bytes(digest[:2], "big") & (shard_count - 1)


def strip_comment(line: str) -> str:
    quote: str | None = None
    for index, character in enumerate(line):
        if quote is not None:
            if character == quote:
                quote = None
        elif character in {"'", '"'}:
            quote = character
        elif character == "#":
            return line[:index]
    return line


def parse_static_assignments(data: bytes) -> tuple[dict[str, str], list[str]]:
    if not data or len(data) > MAX_EBUILD_BYTES:
        raise GentooError("ebuild is empty or exceeds its byte bound")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GentooError("ebuild is not UTF-8") from error
    assignments: dict[str, str] = {}
    dynamic: list[str] = []
    for line in text.splitlines():
        code = strip_comment(line).strip()
        if not code:
            continue
        match = ASSIGNMENT_RE.fullmatch(code)
        if match is None:
            continue
        key, raw = match.groups()
        if key not in STATIC_KEYS:
            continue
        if key in assignments:
            raise GentooError(f"duplicate static assignment: {key}")
        raw = raw.strip()
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {"'", '"'}:
            value = raw[1:-1]
        else:
            value = raw
        if any(token in value for token in ("$", "`", "${", "$(", "\\")):
            dynamic.append(key)
        else:
            assignments[key] = value.strip()
    if FUNCTION_RE.search(text):
        dynamic.append("phase-functions")
    return assignments, sorted(set(dynamic))


def split_shell_words(value: str) -> list[str]:
    output: list[str] = []
    cursor = 0
    while cursor < len(value):
        while cursor < len(value) and value[cursor].isspace():
            cursor += 1
        if cursor == len(value):
            break
        if value[cursor] in {"'", '"'}:
            quote = value[cursor]
            end = value.find(quote, cursor + 1)
            if end < 0:
                raise GentooError("unterminated quoted static value")
            token = value[cursor + 1 : end]
            cursor = end + 1
        else:
            end = cursor
            while end < len(value) and not value[end].isspace():
                end += 1
            token = value[cursor:end]
            cursor = end
        if not token:
            raise GentooError("empty static token")
        output.append(token)
    return output


def parse_manifest(data: bytes) -> dict[str, dict[str, str]]:
    if not data or len(data) > MAX_MANIFEST_BYTES:
        raise GentooError("Gentoo Manifest is empty or exceeds its byte bound")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GentooError("Gentoo Manifest is not UTF-8") from error
    output: dict[str, dict[str, str]] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        fields = line.split()
        if not fields or fields[0] != "DIST":
            continue
        if len(fields) < 6 or len(fields) % 2 != 0:
            raise GentooError(f"invalid DIST entry at line {line_number}")
        filename = fields[1]
        try:
            size = int(fields[2])
        except ValueError as error:
            raise GentooError(f"invalid DIST size at line {line_number}") from error
        if (
            not filename
            or "/" in filename
            or "\\" in filename
            or filename in {".", ".."}
            or size < 0
            or filename in output
        ):
            raise GentooError(f"invalid or duplicate DIST file at line {line_number}")
        hashes = {"size": str(size)}
        for index in range(3, len(fields), 2):
            algorithm = fields[index]
            value = fields[index + 1]
            if (
                not algorithm.isupper()
                or not HASH_RE.fullmatch(value)
                or algorithm in hashes
            ):
                raise GentooError(f"invalid DIST hash at line {line_number}")
            hashes[algorithm] = value.lower()
        output[filename] = hashes
    return output


def static_sources(value: str) -> list[dict[str, Any]]:
    words = split_shell_words(value)
    sources: list[dict[str, Any]] = []
    redirect = False
    for word in words:
        if redirect:
            redirect = False
            continue
        if word == "->":
            if not sources:
                raise GentooError("SRC_URI redirect has no source")
            redirect = True
            continue
        if not word.startswith("https://") or any(character.isspace() for character in word):
            raise GentooError("SRC_URI contains a non-HTTPS or dynamic source")
        filename = word.rsplit("/", 1)[-1]
        if not filename:
            raise GentooError("SRC_URI source has no filename")
        sources.append({"url": word, "filename": filename})
    if redirect:
        raise GentooError("SRC_URI redirect has no target")
    return sources


def read_blob(repository: Path, object_id: str, limit: int) -> bytes:
    if not TREE.OBJECT_RE.fullmatch(object_id):
        raise GentooError("Git blob identity is invalid")
    result = subprocess.run(
        ["git", "-C", str(repository), "cat-file", "blob", object_id],
        check=False,
        capture_output=True,
        env={
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        },
    )
    if result.returncode != 0:
        raise GentooError(
            "cannot read Git blob: "
            + result.stderr[:4096].decode("utf-8", errors="replace")
        )
    if len(result.stdout) > limit:
        raise GentooError("Git blob exceeds its byte bound")
    return result.stdout


def collect_tree(
    repository: Path,
    revision: str,
    shard: int,
    shard_count: int,
) -> tuple[list[tuple[dict[str, Any], str]], dict[str, str]]:
    TREE.verify_revision(repository, revision)
    process = subprocess.Popen(
        [
            "git",
            "-C",
            str(repository),
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            revision,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        },
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        raise GentooError("cannot capture Gentoo tree")
    ebuilds: list[tuple[dict[str, Any], str]] = []
    manifests: dict[str, str] = {}
    try:
        for raw in TREE.iter_nul_records(process.stdout):
            parsed = TREE.parse_ls_tree_record(raw)
            if parsed is None:
                continue
            object_id, path = parsed
            parts = path.split("/")
            if len(parts) != 3:
                continue
            category, package, filename = parts
            package_root = f"{category}/{package}"
            if filename == "Manifest":
                manifests[package_root] = object_id
                continue
            record = TREE.gentoo_record(object_id, path)
            if record is None or shard_for(category, package, shard_count) != shard:
                continue
            ebuilds.append((record, object_id))
            if len(ebuilds) > MAX_SHARD_RECORDS:
                process.kill()
                raise GentooError("Gentoo shard exceeds bounded capacity")
    finally:
        process.stdout.close()
    stderr = process.stderr.read(256 * 1024)
    process.stderr.close()
    status = process.wait()
    if status != 0:
        raise GentooError(
            "git ls-tree failed: " + stderr.decode("utf-8", errors="replace").strip()
        )
    ebuilds.sort(key=lambda item: (item[0]["namespace"], item[0]["package"], item[0]["version"]))
    return ebuilds, manifests


def classify(
    repository: Path,
    record: dict[str, Any],
    object_id: str,
    manifest_object_id: str | None,
) -> dict[str, Any]:
    ebuild = read_blob(repository, object_id, MAX_EBUILD_BYTES)
    base = {
        "candidate_id": record["candidate_id"],
        "category": record["namespace"],
        "package": record["package"],
        "version": record["version"],
        "ebuild_path": record["path"],
        "ebuild_blob_object_id": object_id,
        "ebuild_sha256": hashlib.sha256(ebuild).hexdigest(),
        "manifest_blob_object_id": manifest_object_id,
        "production_authority": False,
    }
    try:
        assignments, dynamic = parse_static_assignments(ebuild)
        missing = sorted(STATIC_KEYS - assignments.keys() - set(dynamic))
        if dynamic or missing:
            return {
                **base,
                "status": "worker-required",
                "reason": "dynamic-or-incomplete-ebuild-metadata",
                "dynamic_fields": dynamic,
                "missing_fields": missing,
            }
        sources = static_sources(assignments["SRC_URI"])
        manifest = {}
        manifest_sha256 = None
        if manifest_object_id is not None:
            manifest_bytes = read_blob(repository, manifest_object_id, MAX_MANIFEST_BYTES)
            manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
            manifest = parse_manifest(manifest_bytes)
        for source in sources:
            evidence = manifest.get(source["filename"], {})
            source["manifest_hashes"] = evidence
            source["sha256_required"] = "SHA256" not in evidence
        keywords = split_shell_words(assignments["KEYWORDS"])
        return {
            **base,
            "status": "static-source-lock-candidate",
            "description": assignments["DESCRIPTION"],
            "license": assignments["LICENSE"],
            "keywords": keywords,
            "sources": sources,
            "manifest_sha256": manifest_sha256,
            "sha256_fetches_required": sum(
                source["sha256_required"] for source in sources
            ),
            "route": "gentoo-source-lock-resolution-required",
        }
    except GentooError as error:
        return {
            **base,
            "status": "quarantined",
            "reason": "invalid-static-ebuild",
            "detail": str(error)[:512],
        }


def inventory(
    repository: Path,
    revision: str,
    shard: int,
    shard_count: int,
) -> dict[str, Any]:
    repository = TREE.canonical_repository(repository)
    if shard < 0 or shard >= shard_count:
        raise GentooError("shard is outside the shard set")
    ebuilds, manifests = collect_tree(repository, revision, shard, shard_count)
    records = []
    for record, object_id in ebuilds:
        package_root = f"{record['namespace']}/{record['package']}"
        records.append(
            classify(repository, record, object_id, manifests.get(package_root))
        )
    counts = {
        status: sum(record["status"] == status for record in records)
        for status in (
            "static-source-lock-candidate",
            "worker-required",
            "quarantined",
        )
    }
    return {
        "format": 1,
        "distribution": "ArachOS",
        "kind": "unsigned-gentoo-ebuild-shard",
        "production_authority": False,
        "repository": "https://github.com/gentoo/gentoo.git",
        "revision": revision,
        "shard": shard,
        "shard_count": shard_count,
        "record_count": len(records),
        "counts": counts,
        "records": records,
    }


def validate_manifest(document: dict[str, Any], revision: str, shard: int, shard_count: int) -> None:
    if set(document) != {
        "format",
        "distribution",
        "kind",
        "production_authority",
        "repository",
        "revision",
        "shard",
        "shard_count",
        "record_count",
        "counts",
        "records",
    }:
        raise GentooError("Gentoo shard has missing or unknown top-level fields")
    records = document["records"]
    if (
        document["format"] != 1
        or document["distribution"] != "ArachOS"
        or document["kind"] != "unsigned-gentoo-ebuild-shard"
        or document["production_authority"] is not False
        or document["repository"] != "https://github.com/gentoo/gentoo.git"
        or document["revision"] != revision
        or document["shard"] != shard
        or document["shard_count"] != shard_count
        or not isinstance(records, list)
        or document["record_count"] != len(records)
    ):
        raise GentooError("Gentoo shard identity or counts are invalid")
    expected_counts = {
        status: sum(record.get("status") == status for record in records)
        for status in (
            "static-source-lock-candidate",
            "worker-required",
            "quarantined",
        )
    }
    if document["counts"] != expected_counts:
        raise GentooError("Gentoo shard disposition counts differ")
    previous: tuple[str, str, str] | None = None
    seen: set[str] = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise GentooError(f"records[{index}] is not an object")
        category = record.get("category")
        package = record.get("package")
        version = record.get("version")
        candidate = record.get("candidate_id")
        if (
            not isinstance(category, str)
            or not isinstance(package, str)
            or not isinstance(version, str)
            or not isinstance(candidate, str)
            or candidate in seen
            or shard_for(category, package, shard_count) != shard
            or record.get("production_authority") is not False
            or not isinstance(record.get("ebuild_blob_object_id"), str)
            or not TREE.OBJECT_RE.fullmatch(record["ebuild_blob_object_id"])
            or not isinstance(record.get("ebuild_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", record["ebuild_sha256"])
        ):
            raise GentooError(f"records[{index}] identity is invalid")
        seen.add(candidate)
        key = (category, package, version)
        if previous is not None and previous >= key:
            raise GentooError(f"records[{index}] is not in canonical order")
        previous = key
        status = record.get("status")
        if status == "static-source-lock-candidate":
            if (
                record.get("route") != "gentoo-source-lock-resolution-required"
                or not isinstance(record.get("sources"), list)
                or any(
                    not isinstance(source, dict)
                    or source.get("sha256_required") is not True
                    and "SHA256" not in source.get("manifest_hashes", {})
                    for source in record["sources"]
                )
            ):
                raise GentooError(f"records[{index}] static candidate is invalid")
        elif status == "worker-required":
            if record.get("reason") != "dynamic-or-incomplete-ebuild-metadata":
                raise GentooError(f"records[{index}] worker route is invalid")
        elif status == "quarantined":
            if record.get("reason") != "invalid-static-ebuild":
                raise GentooError(f"records[{index}] quarantine is invalid")
        else:
            raise GentooError(f"records[{index}] status is invalid")


def json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_new(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise GentooError("output must be a new non-symlink path")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json_bytes(value))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--shard", type=int, required=True)
    parser.add_argument("--shard-count", type=int, default=32)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify-only", action="store_true")
    arguments = parser.parse_args()
    try:
        if arguments.verify_only:
            document = json.loads(arguments.output.read_text(encoding="utf-8"))
            validate_manifest(
                document,
                arguments.revision,
                arguments.shard,
                arguments.shard_count,
            )
        else:
            if arguments.repository is None:
                raise GentooError("repository is required unless --verify-only is used")
            document = inventory(
                arguments.repository,
                arguments.revision,
                arguments.shard,
                arguments.shard_count,
            )
            validate_manifest(
                document,
                arguments.revision,
                arguments.shard,
                arguments.shard_count,
            )
            write_new(arguments.output, document)
    except (OSError, json.JSONDecodeError, TREE.InventoryError, GentooError) as error:
        print(error, file=sys.stderr)
        return 1
    print(
        f"inventoried Gentoo shard {arguments.shard}/{arguments.shard_count}: "
        f"{document['counts']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
