#!/usr/bin/env python3
"""Verify candidate recipe coverage and retained file digests."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from pathlib import Path

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+_.@-]*$")
CLASSES = {"static", "sealed-script", "meta", "template", "rejected"}


class CandidateValidationError(ValueError):
    pass


def regular_beneath(root: Path, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise CandidateValidationError(f"unsafe candidate path: {relative}")
    cursor = root
    for part in path.parts:
        cursor = cursor / part
        metadata = cursor.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise CandidateValidationError(f"candidate path traverses a symlink: {relative}")
    if not stat.S_ISREG(cursor.lstat().st_mode):
        raise CandidateValidationError(f"candidate is not a regular file: {relative}")
    return cursor


def verify(manifest: dict, index: dict, root: Path, require_complete: bool) -> None:
    if set(index) != {"format", "upstream", "target_package_outputs", "candidate_count", "candidates"}:
        raise CandidateValidationError("candidate index has missing or unknown fields")
    if index["format"] != 1 or index["upstream"] != manifest["upstream"]:
        raise CandidateValidationError("candidate index authority differs from ingress manifest")
    expected_packages = sorted(
        package for record in manifest["records"] for package in record["packages"]
    )
    candidates = index["candidates"]
    if not isinstance(candidates, list) or index["candidate_count"] != len(candidates):
        raise CandidateValidationError("candidate count differs from index entries")
    if [entry.get("package") for entry in candidates] != expected_packages:
        raise CandidateValidationError("candidate package set differs from ingress manifest")
    seen_paths: set[str] = set()
    for entry in candidates:
        if set(entry) != {"package", "path", "sha256", "admission_class"}:
            raise CandidateValidationError("candidate index entry has missing or unknown fields")
        if not PACKAGE_RE.fullmatch(entry["package"]):
            raise CandidateValidationError("candidate package name is invalid")
        if entry["admission_class"] not in CLASSES:
            raise CandidateValidationError("candidate admission class is invalid")
        if entry["path"] in seen_paths:
            raise CandidateValidationError("candidate path is duplicated")
        seen_paths.add(entry["path"])
        if not SHA256_RE.fullmatch(entry["sha256"]):
            raise CandidateValidationError("candidate digest is invalid")
        path = regular_beneath(root, entry["path"])
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != entry["sha256"]:
            raise CandidateValidationError(f"candidate digest mismatch: {entry['path']}")
    if index["target_package_outputs"] != manifest["target_package_outputs"]:
        raise CandidateValidationError("candidate target differs from ingress manifest")
    if require_complete and len(candidates) != manifest["target_package_outputs"]:
        raise CandidateValidationError(
            f"candidate set is incomplete: {len(candidates)}/{manifest['target_package_outputs']}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--require-complete", action="store_true")
    arguments = parser.parse_args()
    try:
        manifest = json.loads(arguments.manifest.read_text(encoding="utf-8"))
        index = json.loads(arguments.index.read_text(encoding="utf-8"))
        verify(manifest, index, arguments.root.resolve(), arguments.require_complete)
    except (OSError, json.JSONDecodeError, CandidateValidationError) as error:
        print(error, file=sys.stderr)
        return 1
    print(f"validated {index['candidate_count']} CachyOS candidate recipes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
