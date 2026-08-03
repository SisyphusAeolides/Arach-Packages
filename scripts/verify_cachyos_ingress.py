#!/usr/bin/env python3
"""Validate CachyOS ingress policy and generated snapshot manifests."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+_.@-]*$")
CLASSES = {"static", "sealed-script", "meta", "template", "rejected"}


class ValidationError(ValueError):
    pass


def load_toml(path: Path) -> dict[str, Any]:
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ValidationError(f"cannot read policy: {error}") from error
    if not isinstance(value, dict):
        raise ValidationError("policy root must be a table")
    return value


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValidationError(f"cannot read manifest: {error}") from error
    if not isinstance(value, dict):
        raise ValidationError("manifest root must be an object")
    return value


def validate_policy(policy: dict[str, Any]) -> None:
    expected = {
        "format",
        "upstream_repository",
        "mirror_revision",
        "target_package_outputs",
        "max_pkgbuild_bytes",
        "classes",
        "reason_codes",
        "kernel_package_prefixes",
    }
    if set(policy) != expected:
        raise ValidationError("policy has missing or unknown fields")
    if policy["format"] != 1:
        raise ValidationError("unsupported policy format")
    if policy["upstream_repository"] != "https://github.com/CachyOS/CachyOS-PKGBUILDS.git":
        raise ValidationError("unexpected upstream repository authority")
    if not isinstance(policy["mirror_revision"], str) or not REVISION_RE.fullmatch(
        policy["mirror_revision"]
    ):
        raise ValidationError("mirror revision is not a full lowercase Git object ID")
    if not isinstance(policy["target_package_outputs"], int) or policy["target_package_outputs"] <= 0:
        raise ValidationError("target package output count is invalid")
    if not isinstance(policy["max_pkgbuild_bytes"], int) or policy["max_pkgbuild_bytes"] <= 0:
        raise ValidationError("PKGBUILD size bound is invalid")
    if set(policy["classes"]) != CLASSES or len(policy["classes"]) != len(CLASSES):
        raise ValidationError("policy classes differ from the canonical set")
    reasons = policy["reason_codes"]
    if not isinstance(reasons, list) or not reasons or len(reasons) != len(set(reasons)):
        raise ValidationError("reason code vocabulary must be non-empty and unique")
    if not all(
        isinstance(reason, str) and re.fullmatch(r"[A-Z][A-Z0-9_]*", reason)
        for reason in reasons
    ):
        raise ValidationError("reason code vocabulary contains an invalid code")
    prefixes = policy["kernel_package_prefixes"]
    if not isinstance(prefixes, list) or not prefixes or len(prefixes) != len(set(prefixes)):
        raise ValidationError("kernel package prefixes must be non-empty and unique")


def safe_path(value: str) -> bool:
    path = Path(value)
    return (
        bool(value)
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
        and (value.endswith("/PKGBUILD") or value == "PKGBUILD")
    )


def validate_manifest(
    policy: dict[str, Any], manifest: dict[str, Any], require_complete: bool
) -> None:
    expected = {
        "format",
        "upstream",
        "target_package_outputs",
        "pkgbuild_count",
        "resolved_package_outputs",
        "unresolved_pkgbuilds",
        "complete",
        "summary",
        "duplicate_packages",
        "records",
    }
    if set(manifest) != expected:
        raise ValidationError("manifest has missing or unknown fields")
    if manifest["format"] != 1:
        raise ValidationError("unsupported manifest format")
    if manifest["upstream"] != {
        "repository": policy["upstream_repository"],
        "revision": policy["mirror_revision"],
    }:
        raise ValidationError("manifest upstream identity differs from policy")
    if manifest["target_package_outputs"] != policy["target_package_outputs"]:
        raise ValidationError("manifest target package count differs from policy")
    records = manifest["records"]
    if not isinstance(records, list) or not records:
        raise ValidationError("manifest records must be a non-empty array")
    if manifest["pkgbuild_count"] != len(records):
        raise ValidationError("PKGBUILD count differs from record count")

    allowed_reasons = set(policy["reason_codes"])
    seen_paths: set[str] = set()
    seen_packages: dict[str, str] = {}
    class_counts: dict[str, int] = {}
    reason_counts: dict[str, int] = {}
    resolved = 0
    unresolved = 0
    duplicates: list[dict[str, str]] = []

    expected_record_fields = {
        "path",
        "pkgbuild_sha256",
        "srcinfo_sha256",
        "packages",
        "admission_class",
        "reason_codes",
        "line_count",
        "signals",
    }
    for index, record in enumerate(records):
        if not isinstance(record, dict) or set(record) != expected_record_fields:
            raise ValidationError(f"record {index} has missing or unknown fields")
        path = record["path"]
        if not isinstance(path, str) or not safe_path(path) or path in seen_paths:
            raise ValidationError(f"record {index} has an unsafe or duplicate path")
        seen_paths.add(path)
        if not isinstance(record["pkgbuild_sha256"], str) or not SHA256_RE.fullmatch(
            record["pkgbuild_sha256"]
        ):
            raise ValidationError(f"record {index} has an invalid PKGBUILD digest")
        srcinfo = record["srcinfo_sha256"]
        if srcinfo is not None and (
            not isinstance(srcinfo, str) or not SHA256_RE.fullmatch(srcinfo)
        ):
            raise ValidationError(f"record {index} has an invalid .SRCINFO digest")
        admission = record["admission_class"]
        if admission not in CLASSES:
            raise ValidationError(f"record {index} has an invalid admission class")
        reasons = record["reason_codes"]
        if (
            not isinstance(reasons, list)
            or len(reasons) != len(set(reasons))
            or reasons != sorted(reasons)
            or not set(reasons) <= allowed_reasons
        ):
            raise ValidationError(f"record {index} has invalid reason codes")
        packages = record["packages"]
        if not isinstance(packages, list) or len(packages) != len(set(packages)):
            raise ValidationError(f"record {index} has an invalid package list")
        if packages != sorted(packages):
            raise ValidationError(f"record {index} package list is not canonical")
        if not packages:
            unresolved += 1
            if admission != "rejected" or "UNRESOLVED_PACKAGE_NAMES" not in reasons:
                raise ValidationError(
                    f"record {index} lacks the unresolved-package rejection contract"
                )
        for package in packages:
            if not isinstance(package, str) or not PACKAGE_RE.fullmatch(package):
                raise ValidationError(f"record {index} has an invalid package name")
            resolved += 1
            if package in seen_packages:
                duplicates.append(
                    {"package": package, "first": seen_packages[package], "second": path}
                )
            else:
                seen_packages[package] = path
        weight = len(packages) if packages else 1
        class_counts[admission] = class_counts.get(admission, 0) + weight
        for reason in reasons:
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
        if not isinstance(record["line_count"], int) or record["line_count"] < 0:
            raise ValidationError(f"record {index} has an invalid line count")
        if not isinstance(record["signals"], dict):
            raise ValidationError(f"record {index} signals must be an object")

    if manifest["resolved_package_outputs"] != resolved:
        raise ValidationError("resolved package count differs from records")
    if manifest["unresolved_pkgbuilds"] != unresolved:
        raise ValidationError("unresolved PKGBUILD count differs from records")
    if manifest["duplicate_packages"] != duplicates:
        raise ValidationError("duplicate package report differs from records")
    if manifest["summary"] != {
        "classes": dict(sorted(class_counts.items())),
        "reasons": dict(sorted(reason_counts.items())),
    }:
        raise ValidationError("summary differs from records")
    complete = (
        resolved == policy["target_package_outputs"] and unresolved == 0 and not duplicates
    )
    if manifest["complete"] is not complete:
        raise ValidationError("manifest completeness flag is incorrect")
    if require_complete and not complete:
        raise ValidationError(
            f"snapshot is incomplete: {resolved}/{policy['target_package_outputs']} package outputs, "
            f"{unresolved} unresolved PKGBUILDs, {len(duplicates)} duplicate packages"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--require-complete", action="store_true")
    arguments = parser.parse_args()
    try:
        policy = load_toml(arguments.policy)
        validate_policy(policy)
        if arguments.manifest is not None:
            manifest = load_json(arguments.manifest)
            validate_manifest(policy, manifest, arguments.require_complete)
    except ValidationError as error:
        print(error, file=sys.stderr)
        return 1
    if arguments.manifest is None:
        print(
            f"validated CachyOS ingress policy for {policy['target_package_outputs']} package outputs"
        )
    else:
        print("validated CachyOS ingress snapshot")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
