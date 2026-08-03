#!/usr/bin/env python3
"""Emit deterministic per-package CachyOS candidate recipe records."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import inventory_cachyos as inventory


class CandidateError(ValueError):
    pass


def quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def array(values: list[str]) -> str:
    return "[" + ", ".join(quote(value) for value in values) + "]"


def parse_srcinfo(
    path: Path,
    mirror: Path,
    maximum: int,
) -> tuple[dict[str, list[str]], dict[str, dict[str, list[str]]]]:
    data = inventory.ensure_contained_regular(mirror, path, maximum)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CandidateError(f".SRCINFO is not UTF-8: {path}") from error
    base: dict[str, list[str]] = {}
    packages: dict[str, dict[str, list[str]]] = {}
    current = base
    for line_number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise CandidateError(f"invalid .SRCINFO line {line_number}: {path}")
        key, value = (part.strip() for part in line.split("=", 1))
        if not key:
            raise CandidateError(f"empty .SRCINFO key on line {line_number}: {path}")
        if not value:
            if key in {"pkgbase", "pkgname", "pkgver", "pkgrel"}:
                raise CandidateError(
                    f"empty required .SRCINFO field on line {line_number}: {path}"
                )
            continue
        if key == "pkgbase":
            base.setdefault(key, []).append(value)
            current = base
        elif key == "pkgname":
            if value in packages:
                raise CandidateError(f"duplicate .SRCINFO package section {value}: {path}")
            current = packages.setdefault(value, {})
            current.setdefault(key, []).append(value)
        else:
            current.setdefault(key, []).append(value)
    return base, packages


def merged_values(
    base: dict[str, list[str]],
    package: dict[str, list[str]],
    key: str,
) -> list[str]:
    return sorted(set(base.get(key, []) + package.get(key, [])))


def scalar(
    base: dict[str, list[str]],
    package: dict[str, list[str]],
    key: str,
) -> str | None:
    values = package.get(key) or base.get(key) or []
    return values[-1] if values else None


def assignment_scalar(text: str, key: str) -> str | None:
    value = inventory.assignment_value(text, key)
    if value is None:
        return None
    tokens = inventory.parse_tokens(value)
    return tokens[0] if tokens and len(tokens) == 1 else None


def record_metadata(
    mirror: Path,
    pkgbuild: Path,
    package_name: str,
    maximum: int,
) -> dict[str, Any]:
    srcinfo = pkgbuild.with_name(".SRCINFO")
    if srcinfo.exists():
        base, packages = parse_srcinfo(srcinfo, mirror, maximum)
        section = packages.get(package_name, {})
        return {
            "version": scalar(base, section, "pkgver"),
            "release": scalar(base, section, "pkgrel"),
            "epoch": scalar(base, section, "epoch") or "0",
            "summary": scalar(base, section, "pkgdesc"),
            "homepage": scalar(base, section, "url"),
            "architectures": merged_values(base, section, "arch"),
            "licenses": merged_values(base, section, "license"),
            "runtime": merged_values(base, section, "depends"),
            "build": merged_values(base, section, "makedepends"),
            "check": merged_values(base, section, "checkdepends"),
            "optional": merged_values(base, section, "optdepends"),
            "provides": merged_values(base, section, "provides"),
            "conflicts": merged_values(base, section, "conflicts"),
            "replaces": merged_values(base, section, "replaces"),
            "sources": sorted(
                value
                for key, values in base.items()
                if key == "source" or key.startswith("source_")
                for value in values
            ),
            "checksums": sorted(
                value
                for key, values in base.items()
                if key.endswith("sums") or "sums_" in key
                for value in values
            ),
        }
    data = inventory.ensure_contained_regular(mirror, pkgbuild, maximum)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return {}
    return {
        "version": assignment_scalar(text, "pkgver"),
        "release": assignment_scalar(text, "pkgrel"),
        "epoch": assignment_scalar(text, "epoch") or "0",
        "summary": assignment_scalar(text, "pkgdesc"),
        "homepage": assignment_scalar(text, "url"),
        "architectures": inventory.parse_tokens(
            inventory.assignment_value(text, "arch") or ""
        )
        or [],
        "licenses": inventory.parse_tokens(
            inventory.assignment_value(text, "license") or ""
        )
        or [],
        "runtime": inventory.parse_tokens(
            inventory.assignment_value(text, "depends") or ""
        )
        or [],
        "build": inventory.parse_tokens(
            inventory.assignment_value(text, "makedepends") or ""
        )
        or [],
        "check": inventory.parse_tokens(
            inventory.assignment_value(text, "checkdepends") or ""
        )
        or [],
        "optional": inventory.parse_tokens(
            inventory.assignment_value(text, "optdepends") or ""
        )
        or [],
        "provides": inventory.parse_tokens(
            inventory.assignment_value(text, "provides") or ""
        )
        or [],
        "conflicts": inventory.parse_tokens(
            inventory.assignment_value(text, "conflicts") or ""
        )
        or [],
        "replaces": inventory.parse_tokens(
            inventory.assignment_value(text, "replaces") or ""
        )
        or [],
        "sources": inventory.source_tokens(text),
        "checksums": [],
    }


def render_candidate(
    package_name: str,
    record: dict[str, Any],
    metadata: dict[str, Any],
    upstream: dict[str, str],
) -> str:
    lines = [
        "format = 1",
        'state = "candidate"',
        f"admission_class = {quote(record['admission_class'])}",
        f"reason_codes = {array(record['reason_codes'])}",
        f"requires_target_policy = {'false' if record['admission_class'] in {'rejected', 'template'} else 'true'}",
        f"requires_worker_evidence = {'true' if record['admission_class'] == 'sealed-script' else 'false'}",
        "",
        "[package]",
        f"name = {quote(package_name)}",
    ]
    for key in ("version", "release", "epoch", "summary", "homepage"):
        value = metadata.get(key)
        if isinstance(value, str) and value:
            lines.append(f"{key} = {quote(value)}")
    for key in ("architectures", "licenses"):
        values = metadata.get(key, [])
        if values:
            lines.append(f"{key} = {array(values)}")
    lines.extend(
        [
            "",
            "[upstream]",
            f"repository = {quote(upstream['repository'])}",
            f"revision = {quote(upstream['revision'])}",
            f"pkgbuild_path = {quote(record['path'])}",
            f"pkgbuild_sha256 = {quote(record['pkgbuild_sha256'])}",
        ]
    )
    if record.get("srcinfo_sha256"):
        lines.append(f"srcinfo_sha256 = {quote(record['srcinfo_sha256'])}")
    lines.extend(["", "[dependencies]"])
    for key in (
        "runtime",
        "build",
        "check",
        "optional",
        "provides",
        "conflicts",
        "replaces",
    ):
        lines.append(f"{key} = {array(metadata.get(key, []))}")
    lines.extend(
        [
            "",
            "[sources]",
            f"raw = {array(metadata.get('sources', []))}",
            f"checksums = {array(metadata.get('checksums', []))}",
            "",
        ]
    )
    return "\n".join(lines)


def emit(
    mirror: Path,
    manifest: dict[str, Any],
    policy: dict[str, Any],
    output: Path,
) -> dict[str, Any]:
    mirror = mirror.resolve()
    output = output.resolve()
    if output == mirror or mirror in output.parents:
        raise CandidateError("candidate output cannot be inside the upstream mirror")
    if output.is_symlink():
        raise CandidateError("candidate output cannot be a symlink")
    output.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, str]] = []
    seen: set[str] = set()
    for record in manifest["records"]:
        pkgbuild = mirror / record["path"]
        for package_name in record["packages"]:
            if package_name in seen:
                raise CandidateError(f"duplicate package output: {package_name}")
            seen.add(package_name)
            metadata = record_metadata(
                mirror,
                pkgbuild,
                package_name,
                policy["max_pkgbuild_bytes"],
            )
            text = render_candidate(package_name, record, metadata, manifest["upstream"])
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            shard = hashlib.sha256(package_name.encode("utf-8")).hexdigest()[:2]
            relative = Path(shard) / f"{package_name}.toml"
            destination = output / relative
            if destination.is_symlink():
                raise CandidateError(f"candidate destination is a symlink: {relative}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text, encoding="utf-8")
            entries.append(
                {
                    "package": package_name,
                    "path": relative.as_posix(),
                    "sha256": digest,
                    "admission_class": record["admission_class"],
                }
            )
    entries.sort(key=lambda item: item["package"])
    return {
        "format": 1,
        "upstream": manifest["upstream"],
        "target_package_outputs": manifest["target_package_outputs"],
        "candidate_count": len(entries),
        "candidates": entries,
    }


def write_index(path: Path, index: dict[str, Any]) -> None:
    if path.is_symlink():
        raise CandidateError("candidate index cannot be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(index, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mirror", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--index", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        policy = inventory.load_policy(arguments.policy)
        manifest = json.loads(arguments.manifest.read_text(encoding="utf-8"))
        index = emit(arguments.mirror, manifest, policy, arguments.output)
        write_index(arguments.index, index)
    except (
        OSError,
        json.JSONDecodeError,
        CandidateError,
        inventory.InventoryError,
    ) as error:
        print(error, file=sys.stderr)
        return 1
    print(f"emitted {index['candidate_count']} CachyOS candidate recipes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
