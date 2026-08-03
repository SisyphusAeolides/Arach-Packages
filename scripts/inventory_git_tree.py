#!/usr/bin/env python3
"""Inventory immutable Git trees without checking out or downloading every blob."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, BinaryIO, Iterator

REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
OBJECT_RE = re.compile(r"^[0-9a-f]{40}$")
GENTOO_NAME_RE = re.compile(r"^[A-Za-z0-9+_.-]+$")
CRATE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
MAX_PATH_BYTES = 4096
MAX_RECORDS = 500_000
SUPPORTED = {"gentoo", "cargo", "nix"}


class InventoryError(ValueError):
    pass


def candidate_id(upstream: str, path: str) -> str:
    return f"{upstream}-{hashlib.sha256(path.encode('utf-8')).hexdigest()[:24]}"


def iter_nul_records(stream: BinaryIO, chunk_size: int = 1024 * 1024) -> Iterator[bytes]:
    pending = bytearray()
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        pending.extend(chunk)
        cursor = 0
        while True:
            try:
                boundary = pending.index(0, cursor)
            except ValueError:
                if cursor:
                    del pending[:cursor]
                break
            yield bytes(pending[cursor:boundary])
            cursor = boundary + 1
    if pending:
        raise InventoryError("git ls-tree output ended without a NUL terminator")


def parse_ls_tree_record(record: bytes) -> tuple[str, str] | None:
    if not record:
        raise InventoryError("git ls-tree emitted an empty record")
    if len(record) > MAX_PATH_BYTES + 128:
        raise InventoryError("git ls-tree record exceeds its byte bound")
    try:
        metadata, path_bytes = record.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split(" ")
        path = path_bytes.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as error:
        raise InventoryError("git ls-tree emitted malformed metadata") from error
    if kind != "blob":
        return None
    if mode not in {"100644", "100755", "120000"} or not OBJECT_RE.fullmatch(object_id):
        raise InventoryError("git ls-tree blob identity is invalid")
    if mode == "120000":
        return None
    if (
        not path
        or len(path.encode("utf-8")) > MAX_PATH_BYTES
        or path.startswith("/")
        or "\\" in path
        or any(component in {"", ".", ".."} for component in path.split("/"))
    ):
        raise InventoryError("git ls-tree path is unsafe")
    return object_id, path


def gentoo_record(object_id: str, path: str) -> dict[str, Any] | None:
    parts = path.split("/")
    if len(parts) != 3 or not path.endswith(".ebuild"):
        return None
    category, package, filename = parts
    prefix = f"{package}-"
    if (
        not GENTOO_NAME_RE.fullmatch(category)
        or not GENTOO_NAME_RE.fullmatch(package)
        or not filename.startswith(prefix)
    ):
        return None
    version = filename[len(prefix) : -len(".ebuild")]
    if not version or not GENTOO_NAME_RE.fullmatch(version):
        return None
    return {
        "candidate_id": candidate_id("gentoo", path),
        "namespace": category,
        "package": package.lower(),
        "version": version,
        "path": path,
        "git_blob_object_id": object_id,
        "metadata_sha256_required": True,
        "source_lock_required": True,
        "route": "gentoo-static-importer-candidate",
    }


def cargo_name_from_path(path: str) -> str | None:
    if path == "config.json" or path.startswith("."):
        return None
    parts = path.split("/")
    name = parts[-1]
    if not CRATE_NAME_RE.fullmatch(name):
        return None
    lowered = name.lower()
    length = len(lowered)
    valid_layout = (
        length == 1
        and parts == ["1", lowered]
        or length == 2
        and parts == ["2", lowered]
        or length == 3
        and parts == ["3", lowered[0], lowered]
        or length >= 4
        and parts == [lowered[:2], lowered[2:4], lowered]
    )
    return lowered if valid_layout else None


def cargo_record(object_id: str, path: str) -> dict[str, Any] | None:
    package = cargo_name_from_path(path)
    if package is None:
        return None
    return {
        "candidate_id": candidate_id("cargo", path),
        "package": package,
        "path": path,
        "git_blob_object_id": object_id,
        "metadata_sha256_required": True,
        "version_inventory_required": True,
        "route": "cargo-index-candidate",
    }


def nix_record(object_id: str, path: str) -> dict[str, Any] | None:
    if not path.startswith("pkgs/"):
        return None
    filename = path.rsplit("/", 1)[-1]
    if filename not in {"package.nix", "default.nix"}:
        return None
    return {
        "candidate_id": candidate_id("nix", path),
        "path": path,
        "git_blob_object_id": object_id,
        "metadata_sha256_required": True,
        "evaluation_required": True,
        "route": "nix-evaluation-candidate",
    }


def adapter(upstream: str, object_id: str, path: str) -> dict[str, Any] | None:
    if upstream == "gentoo":
        return gentoo_record(object_id, path)
    if upstream == "cargo":
        return cargo_record(object_id, path)
    if upstream == "nix":
        return nix_record(object_id, path)
    raise InventoryError(f"unsupported tree inventory upstream: {upstream}")


def canonical_repository(path: Path) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise InventoryError("repository must be a regular directory")
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise InventoryError("repository is not a directory")
    return path.resolve()


def verify_revision(repository: Path, revision: str) -> None:
    if not REVISION_RE.fullmatch(revision):
        raise InventoryError("revision must be a full lowercase Git object ID")
    result = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", f"{revision}^{{commit}}"],
        check=False,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        },
    )
    if result.returncode != 0 or result.stdout.strip() != revision:
        raise InventoryError("repository does not contain the exact requested commit")


def inventory(repository: Path, revision: str, upstream: str) -> dict[str, Any]:
    repository = canonical_repository(repository)
    if upstream not in SUPPORTED:
        raise InventoryError("unsupported upstream")
    verify_revision(repository, revision)
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
        raise InventoryError("cannot capture git ls-tree output")
    records: list[dict[str, Any]] = []
    tree_blobs = 0
    try:
        for raw in iter_nul_records(process.stdout):
            parsed = parse_ls_tree_record(raw)
            if parsed is None:
                continue
            tree_blobs += 1
            object_id, path = parsed
            record = adapter(upstream, object_id, path)
            if record is None:
                continue
            records.append(record)
            if len(records) > MAX_RECORDS:
                process.kill()
                raise InventoryError("inventory exceeds bounded candidate capacity")
    finally:
        process.stdout.close()
    stderr = process.stderr.read(256 * 1024)
    process.stderr.close()
    status = process.wait()
    if status != 0:
        raise InventoryError(
            "git ls-tree failed: " + stderr.decode("utf-8", errors="replace").strip()
        )

    records.sort(key=lambda item: (item.get("package", ""), item.get("version", ""), item["path"]))
    candidate_ids = [record["candidate_id"] for record in records]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise InventoryError("candidate identity collision")
    paths = [record["path"] for record in records]
    if len(paths) != len(set(paths)):
        raise InventoryError("candidate path collision")

    summary: dict[str, Any] = {
        "candidate_count": len(records),
        "tree_blob_count": tree_blobs,
    }
    if upstream == "gentoo":
        package_keys = {(record["namespace"], record["package"]) for record in records}
        bare_names = Counter(record["package"] for record in records)
        summary.update(
            {
                "category_count": len({record["namespace"] for record in records}),
                "category_package_count": len(package_keys),
                "bare_package_name_count": len(bare_names),
                "bare_name_collisions": sum(count > 1 for count in bare_names.values()),
            }
        )
    elif upstream == "cargo":
        summary["crate_name_count"] = len({record["package"] for record in records})
    else:
        summary["evaluation_candidate_count"] = len(records)

    return {
        "format": 1,
        "distribution": "ArachOS",
        "kind": "unsigned-git-tree-inventory",
        "production_authority": False,
        "upstream": upstream,
        "revision": revision,
        "complete_tree_walk": True,
        "blob_contents_fetched": False,
        "summary": summary,
        "records": records,
    }


def json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_new(path: Path, value: dict[str, Any]) -> None:
    if path.exists() or path.is_symlink():
        raise InventoryError("output must be a new non-symlink path")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json_bytes(value))


def validate_manifest(document: dict[str, Any], expected_upstream: str, expected_revision: str) -> None:
    if set(document) != {
        "format",
        "distribution",
        "kind",
        "production_authority",
        "upstream",
        "revision",
        "complete_tree_walk",
        "blob_contents_fetched",
        "summary",
        "records",
    }:
        raise InventoryError("manifest has missing or unknown top-level fields")
    if (
        document["format"] != 1
        or document["distribution"] != "ArachOS"
        or document["kind"] != "unsigned-git-tree-inventory"
        or document["production_authority"] is not False
        or document["upstream"] != expected_upstream
        or document["revision"] != expected_revision
        or document["complete_tree_walk"] is not True
        or document["blob_contents_fetched"] is not False
        or not isinstance(document["summary"], dict)
        or not isinstance(document["records"], list)
        or document["summary"].get("candidate_count") != len(document["records"])
    ):
        raise InventoryError("manifest identity, authority, or counts are invalid")
    previous: tuple[str, str, str] | None = None
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    for index, record in enumerate(document["records"]):
        if not isinstance(record, dict):
            raise InventoryError(f"records[{index}] is not an object")
        candidate = record.get("candidate_id")
        path = record.get("path")
        object_id = record.get("git_blob_object_id")
        if (
            not isinstance(candidate, str)
            or not candidate.startswith(f"{expected_upstream}-")
            or candidate in seen_ids
            or not isinstance(path, str)
            or path in seen_paths
            or not isinstance(object_id, str)
            or not OBJECT_RE.fullmatch(object_id)
            or record.get("metadata_sha256_required") is not True
        ):
            raise InventoryError(f"records[{index}] identity is invalid")
        seen_ids.add(candidate)
        seen_paths.add(path)
        key = (str(record.get("package", "")), str(record.get("version", "")), path)
        if previous is not None and previous >= key:
            raise InventoryError(f"records[{index}] is not in canonical order")
        previous = key


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--upstream", choices=sorted(SUPPORTED), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify-only", action="store_true")
    arguments = parser.parse_args()
    try:
        if arguments.verify_only:
            document = json.loads(arguments.output.read_text(encoding="utf-8"))
            validate_manifest(document, arguments.upstream, arguments.revision)
        else:
            if arguments.repository is None:
                raise InventoryError("repository is required unless --verify-only is used")
            document = inventory(arguments.repository, arguments.revision, arguments.upstream)
            validate_manifest(document, arguments.upstream, arguments.revision)
            write_new(arguments.output, document)
    except (OSError, json.JSONDecodeError, InventoryError) as error:
        print(error, file=sys.stderr)
        return 1
    print(
        f"inventoried {document['summary']['candidate_count']} {arguments.upstream} "
        f"tree candidates at {arguments.revision}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
