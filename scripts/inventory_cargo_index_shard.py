#!/usr/bin/env python3
"""Resolve latest non-yanked crate releases from one immutable index shard."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterator


SCRIPTS = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "inventory_git_tree", SCRIPTS / "inventory_git_tree.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Git tree inventory module")
TREE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = TREE
SPEC.loader.exec_module(TREE)

DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^[^\x00-\x20/\\@]{1,256}$")
MAX_INDEX_BLOB_BYTES = 8 * 1024 * 1024
MAX_SHARD_RECORDS = 25_000


class CargoIndexError(ValueError):
    pass


def shard_for(package: str, shard_count: int) -> int:
    if shard_count <= 0 or shard_count & (shard_count - 1):
        raise CargoIndexError("shard count must be a power of two")
    digest = hashlib.sha256(package.encode("utf-8")).digest()
    return int.from_bytes(digest[:2], "big") & (shard_count - 1)


def parse_release_lines(package: str, data: bytes) -> dict[str, Any]:
    if not data or len(data) > MAX_INDEX_BLOB_BYTES:
        raise CargoIndexError("crate index blob is empty or exceeds its byte bound")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CargoIndexError("crate index blob is not UTF-8") from error
    releases: list[dict[str, Any]] = []
    versions: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line:
            raise CargoIndexError(f"crate index contains an empty line at {line_number}")
        try:
            release = json.loads(line)
        except json.JSONDecodeError as error:
            raise CargoIndexError(
                f"crate index contains invalid JSON at line {line_number}"
            ) from error
        if not isinstance(release, dict):
            raise CargoIndexError(f"crate release at line {line_number} is not an object")
        name = release.get("name")
        version = release.get("vers")
        checksum = release.get("cksum")
        yanked = release.get("yanked", False)
        dependencies = release.get("deps")
        if (
            not isinstance(name, str)
            or name.lower() != package
            or not isinstance(version, str)
            or not VERSION_RE.fullmatch(version)
            or version in versions
            or not isinstance(checksum, str)
            or not DIGEST_RE.fullmatch(checksum)
            or not isinstance(yanked, bool)
            or not isinstance(dependencies, list)
            or any(not isinstance(dependency, dict) for dependency in dependencies)
        ):
            raise CargoIndexError(f"crate release fields are invalid at line {line_number}")
        versions.add(version)
        releases.append(
            {
                "name": name,
                "version": version,
                "checksum": checksum,
                "yanked": yanked,
                "dependency_count": len(dependencies),
                "line_number": line_number,
            }
        )
    if not releases:
        raise CargoIndexError("crate index contains no releases")
    active = next((release for release in reversed(releases) if not release["yanked"]), None)
    if active is None:
        return {
            "status": "quarantined",
            "reason": "all-releases-yanked",
            "release_count": len(releases),
            "yanked_count": len(releases),
        }
    return {
        "status": "candidate",
        "upstream_name": active["name"],
        "version": active["version"],
        "checksum": active["checksum"],
        "dependency_count": active["dependency_count"],
        "selected_line": active["line_number"],
        "release_count": len(releases),
        "yanked_count": sum(release["yanked"] for release in releases),
    }


def read_blob(repository: Path, object_id: str) -> bytes:
    if not TREE.OBJECT_RE.fullmatch(object_id):
        raise CargoIndexError("crate index blob object ID is invalid")
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
        raise CargoIndexError(
            "cannot read crate index blob: "
            + result.stderr[:4096].decode("utf-8", errors="replace")
        )
    if len(result.stdout) > MAX_INDEX_BLOB_BYTES:
        raise CargoIndexError("crate index blob exceeds its byte bound")
    return result.stdout


def selected_tree_records(
    repository: Path,
    revision: str,
    shard: int,
    shard_count: int,
) -> Iterator[tuple[str, str, str]]:
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
        raise CargoIndexError("cannot capture crate index tree")
    count = 0
    try:
        for raw in TREE.iter_nul_records(process.stdout):
            parsed = TREE.parse_ls_tree_record(raw)
            if parsed is None:
                continue
            object_id, path = parsed
            package = TREE.cargo_name_from_path(path)
            if package is None or shard_for(package, shard_count) != shard:
                continue
            count += 1
            if count > MAX_SHARD_RECORDS:
                process.kill()
                raise CargoIndexError("crate shard exceeds bounded capacity")
            yield package, path, object_id
    finally:
        process.stdout.close()
    stderr = process.stderr.read(256 * 1024)
    process.stderr.close()
    status = process.wait()
    if status != 0:
        raise CargoIndexError(
            "git ls-tree failed: " + stderr.decode("utf-8", errors="replace").strip()
        )


def inventory(
    repository: Path,
    revision: str,
    shard: int,
    shard_count: int,
) -> dict[str, Any]:
    repository = TREE.canonical_repository(repository)
    if shard < 0 or shard >= shard_count:
        raise CargoIndexError("shard is outside the shard set")
    records: list[dict[str, Any]] = []
    for package, path, object_id in selected_tree_records(
        repository, revision, shard, shard_count
    ):
        data = read_blob(repository, object_id)
        base = {
            "package": package,
            "index_path": path,
            "index_blob_object_id": object_id,
            "index_blob_sha256": hashlib.sha256(data).hexdigest(),
            "shard": shard,
        }
        try:
            resolution = parse_release_lines(package, data)
        except CargoIndexError as error:
            resolution = {
                "status": "quarantined",
                "reason": "invalid-index-metadata",
                "detail": str(error)[:512],
            }
        if resolution["status"] == "candidate":
            version = resolution["version"]
            base.update(
                {
                    **resolution,
                    "archive_url": (
                        f"https://static.crates.io/crates/{package}/"
                        f"{package}-{version}.crate"
                    ),
                    "route": "cargo-closure-resolution-required",
                    "production_authority": False,
                }
            )
        else:
            base.update({**resolution, "production_authority": False})
        records.append(base)
    records.sort(key=lambda record: record["package"])
    packages = [record["package"] for record in records]
    if len(packages) != len(set(packages)):
        raise CargoIndexError("crate package is duplicated within a shard")
    candidates = sum(record["status"] == "candidate" for record in records)
    quarantined = len(records) - candidates
    return {
        "format": 1,
        "distribution": "ArachOS",
        "kind": "unsigned-cargo-index-shard",
        "production_authority": False,
        "repository": "https://github.com/rust-lang/crates.io-index.git",
        "revision": revision,
        "shard": shard,
        "shard_count": shard_count,
        "record_count": len(records),
        "candidate_count": candidates,
        "quarantined_count": quarantined,
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
        "candidate_count",
        "quarantined_count",
        "records",
    }:
        raise CargoIndexError("Cargo shard manifest has missing or unknown fields")
    records = document["records"]
    if (
        document["format"] != 1
        or document["distribution"] != "ArachOS"
        or document["kind"] != "unsigned-cargo-index-shard"
        or document["production_authority"] is not False
        or document["repository"]
        != "https://github.com/rust-lang/crates.io-index.git"
        or document["revision"] != revision
        or document["shard"] != shard
        or document["shard_count"] != shard_count
        or not isinstance(records, list)
        or document["record_count"] != len(records)
        or document["candidate_count"]
        + document["quarantined_count"]
        != len(records)
    ):
        raise CargoIndexError("Cargo shard manifest identity or counts are invalid")
    previous: str | None = None
    candidates = 0
    quarantined = 0
    for index, record in enumerate(records):
        package = record.get("package") if isinstance(record, dict) else None
        if (
            not isinstance(package, str)
            or TREE.cargo_name_from_path(record.get("index_path", "")) != package
            or record.get("shard") != shard
            or shard_for(package, shard_count) != shard
            or not isinstance(record.get("index_blob_object_id"), str)
            or not TREE.OBJECT_RE.fullmatch(record["index_blob_object_id"])
            or not isinstance(record.get("index_blob_sha256"), str)
            or not DIGEST_RE.fullmatch(record["index_blob_sha256"])
            or record.get("production_authority") is not False
            or previous is not None
            and previous >= package
        ):
            raise CargoIndexError(f"records[{index}] identity is invalid")
        previous = package
        if record.get("status") == "candidate":
            candidates += 1
            version = record.get("version")
            checksum = record.get("checksum")
            if (
                not isinstance(version, str)
                or not VERSION_RE.fullmatch(version)
                or not isinstance(checksum, str)
                or not DIGEST_RE.fullmatch(checksum)
                or record.get("archive_url")
                != f"https://static.crates.io/crates/{package}/{package}-{version}.crate"
                or record.get("route") != "cargo-closure-resolution-required"
            ):
                raise CargoIndexError(f"records[{index}] candidate is invalid")
        elif record.get("status") == "quarantined":
            quarantined += 1
            if not isinstance(record.get("reason"), str) or not record["reason"]:
                raise CargoIndexError(f"records[{index}] quarantine is invalid")
        else:
            raise CargoIndexError(f"records[{index}] status is invalid")
    if candidates != document["candidate_count"] or quarantined != document["quarantined_count"]:
        raise CargoIndexError("Cargo shard disposition counts differ from records")


def json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_new(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise CargoIndexError("output must be a new non-symlink path")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json_bytes(value))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--shard", type=int, required=True)
    parser.add_argument("--shard-count", type=int, default=256)
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
                raise CargoIndexError("repository is required unless --verify-only is used")
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
    except (OSError, json.JSONDecodeError, TREE.InventoryError, CargoIndexError) as error:
        print(error, file=sys.stderr)
        return 1
    print(
        f"inventoried Cargo shard {arguments.shard}/{arguments.shard_count}: "
        f"candidates={document['candidate_count']} "
        f"quarantined={document['quarantined_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
