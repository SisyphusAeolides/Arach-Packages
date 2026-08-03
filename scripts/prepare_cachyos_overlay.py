#!/usr/bin/env python3
"""Prepare deterministic ArachOS staging records for a pinned CachyOS overlay."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
from collections import Counter
from pathlib import Path
from typing import Any


SCRIPTS = Path(__file__).resolve().parent


def load_module(name: str):
    path = SCRIPTS / f"{name}.py"
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


INVENTORY = load_module("inventory_cachyos")
CANDIDATES = load_module("emit_cachyos_candidates")
VARIANTS = load_module("validate_cachyos_variants")

FORMAT = 1
DISTRIBUTION = "ArachOS"
ARCHITECTURE = "x86-64"
ID_RE = re.compile(r"^[a-z0-9][a-z0-9+_.@-]{0,255}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class OverlayError(ValueError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def array(values: list[str]) -> str:
    return "[" + ", ".join(quote(value) for value in values) + "]"


def safe_relative(value: str) -> bool:
    path = Path(value)
    return (
        bool(value)
        and not path.is_absolute()
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def regular_beneath(root: Path, relative: str, maximum: int = 4 * 1024 * 1024) -> bytes:
    if not safe_relative(relative):
        raise OverlayError(f"unsafe staging path: {relative}")
    path = root
    for component in Path(relative).parts:
        path = path / component
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise OverlayError(f"staging path traverses a symlink: {relative}")
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
        raise OverlayError(f"staging artifact is not a bounded regular file: {relative}")
    canonical_root = root.resolve()
    canonical = path.resolve()
    if not canonical.is_relative_to(canonical_root):
        raise OverlayError(f"staging artifact escapes its root: {relative}")
    data = canonical.read_bytes()
    if len(data) > maximum:
        raise OverlayError(f"staging artifact exceeds its bound: {relative}")
    return data


def write_new(path: Path, data: bytes) -> str:
    if path.exists() or path.is_symlink():
        raise OverlayError(f"staging artifact already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise OverlayError(f"temporary staging artifact already exists: {temporary}")
    temporary.write_bytes(data)
    temporary.replace(path)
    return digest(data)


def normalize_architectures(values: list[str]) -> list[str]:
    normalized = []
    for value in values:
        mapped = {
            "x86_64": "x86-64",
            "any": "any",
        }.get(value, value)
        if mapped not in normalized:
            normalized.append(mapped)
    return sorted(normalized)


def candidate_version(metadata: dict[str, Any]) -> tuple[str, int, int]:
    version = metadata.get("version")
    release_text = metadata.get("release")
    epoch_text = metadata.get("epoch", "0")
    if not isinstance(version, str) or not version or any(character.isspace() for character in version):
        raise OverlayError("candidate version is missing or invalid")
    try:
        release = int(release_text)
        epoch = int(epoch_text)
    except (TypeError, ValueError) as error:
        raise OverlayError("candidate release or epoch is invalid") from error
    if release <= 0 or epoch < 0:
        raise OverlayError("candidate release or epoch is outside its bounds")
    return version, release, epoch


def variant_details(variants: dict[str, Any]) -> dict[tuple[str, str], dict[str, str]]:
    details: dict[tuple[str, str], dict[str, str]] = {}
    for group in variants["group"]:
        for candidate in group["candidate"]:
            for package in group["packages"]:
                key = (candidate["pkgbuild_path"], package)
                details[key] = {
                    "group": group["id"],
                    "dimension": group["selection_dimension"],
                    "variant": candidate["id"],
                    "policy_value": candidate["policy_value"],
                    "build_identity": candidate["build_identity"],
                }
    return details


def render_lock(
    package: str,
    repository: str,
    revision: str,
    metadata_path: str,
    metadata_sha256: str,
) -> bytes:
    text = f'''format = 1
ecosystem = "arch"
package = {quote(package)}

[origin]
kind = "git"
repository = {quote(repository)}
revision = {quote(revision)}
metadata_path = {quote(metadata_path)}
metadata_sha256 = {quote(metadata_sha256)}
submodules = false
'''
    return text.encode("utf-8")


def render_meta_target(package: str) -> bytes:
    text = f'''format = 1
package = {quote(package)}
architecture = "x86-64"
scope = "system"
publish_authority = "arach-native"
build_system = "meta"
build_commands = []
outputs = []
network = false
sandbox = true
reproducible = true
'''
    return text.encode("utf-8")


def render_target_draft(
    package: str,
    version: str,
    release: int,
    variant: dict[str, str] | None,
) -> bytes:
    document: dict[str, Any] = {
        "format": FORMAT,
        "state": "target-policy-required",
        "distribution": DISTRIBUTION,
        "package": package,
        "version": version,
        "release": release,
        "architecture": ARCHITECTURE,
        "scope": "system",
        "publish_authority": "arach-native",
        "network": False,
        "sandbox": True,
        "reproducible": True,
    }
    if variant is not None:
        document["selection"] = variant
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def render_worker_plan(
    candidate_id: str,
    package: str,
    version: str,
    release: int,
    pkgbuild_path: str,
    pkgbuild_sha256: str,
    pkgbuild_size: int,
    reasons: list[str],
    variant: dict[str, str] | None,
) -> bytes:
    document: dict[str, Any] = {
        "format": FORMAT,
        "state": "toolchain-binding-required",
        "request_id": candidate_id,
        "ecosystem": "cachyos-pkgbuild",
        "package": package,
        "version": version,
        "release": release,
        "capabilities": ["read-inputs", "execute-tools", "write-outputs"],
        "inputs": [
            {
                "path": pkgbuild_path,
                "sha256": pkgbuild_sha256,
                "size": pkgbuild_size,
            }
        ],
        "required_tools": [
            {
                "name": "bash",
                "binding": "exact-artifact-required",
            },
            {
                "name": "corinth-pkgbuild-adapter",
                "binding": "exact-artifact-required",
            },
        ],
        "declared_outputs": [
            "canonical-package-recipe",
            "recipe-import-receipt",
            "package-semantics",
        ],
        "network": {"mode": "denied"},
        "reproducibility_runs": 2,
        "classification_reasons": reasons,
    }
    if variant is not None:
        document["selection"] = variant
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def render_quarantine(
    candidate_id: str,
    package: str,
    version: str,
    release: int,
    record: dict[str, Any],
    variant: dict[str, str] | None,
) -> bytes:
    document: dict[str, Any] = {
        "format": FORMAT,
        "state": "quarantined",
        "candidate_id": candidate_id,
        "package": package,
        "version": version,
        "release": release,
        "pkgbuild_path": record["path"],
        "pkgbuild_sha256": record["pkgbuild_sha256"],
        "srcinfo_sha256": record.get("srcinfo_sha256"),
        "reason_codes": record["reason_codes"],
        "required_resolution": "immutable-source-or-semantics-review",
    }
    if variant is not None:
        document["selection"] = variant
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def render_template(
    candidate_id: str,
    package: str,
    version: str,
    release: int,
    record: dict[str, Any],
    variant: dict[str, str] | None,
) -> bytes:
    document: dict[str, Any] = {
        "format": FORMAT,
        "state": "template-review-required",
        "candidate_id": candidate_id,
        "package": package,
        "version": version,
        "release": release,
        "pkgbuild_path": record["path"],
        "pkgbuild_sha256": record["pkgbuild_sha256"],
        "reason_codes": record["reason_codes"],
        "kernel_authority_replacement": False,
    }
    if variant is not None:
        document["selection"] = variant
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def artifact_entry(root: Path, relative: str, data: bytes) -> dict[str, Any]:
    sha256 = write_new(root / relative, data)
    return {
        "path": relative,
        "sha256": sha256,
        "size": len(data),
    }


def prepare(
    mirror: Path,
    policy: dict[str, Any],
    records: dict[str, Any],
    variants: dict[str, Any],
    output: Path,
) -> dict[str, Any]:
    mirror = mirror.resolve()
    if mirror.is_symlink() or not mirror.is_dir():
        raise OverlayError("CachyOS mirror is not a regular directory")
    output = output.resolve()
    if output.exists():
        if output.is_symlink() or not output.is_dir() or any(output.iterdir()):
            raise OverlayError("staging output must be an empty regular directory")
    else:
        output.mkdir(parents=True)

    repository = policy["upstream_repository"]
    revision = policy["mirror_revision"]
    if records.get("repository") != repository or records.get("revision") != revision:
        raise OverlayError("retained records differ from the ingress policy")
    mapping = VARIANTS.validate(variants, records, repository, revision)
    details = variant_details(variants)
    if set(mapping) != set(details):
        raise OverlayError("variant detail map differs from validated alternatives")

    entries: list[dict[str, Any]] = []
    candidate_ids: set[str] = set()
    dispositions: Counter[str] = Counter()
    package_names: set[str] = set()
    variant_entries = 0

    record_list = records.get("records")
    if not isinstance(record_list, list):
        raise OverlayError("retained snapshot records are invalid")
    for record in record_list:
        pkgbuild_path = record["path"]
        pkgbuild = mirror / pkgbuild_path
        pkgbuild_bytes = INVENTORY.ensure_contained_regular(
            mirror, pkgbuild, policy["max_pkgbuild_bytes"]
        )
        if digest(pkgbuild_bytes) != record["pkgbuild_sha256"]:
            raise OverlayError(f"PKGBUILD digest differs from retained record: {pkgbuild_path}")
        for package in record["packages"]:
            metadata = CANDIDATES.record_metadata(
                mirror, pkgbuild, package, policy["max_pkgbuild_bytes"]
            )
            version, release, epoch = candidate_version(metadata)
            architectures = normalize_architectures(metadata.get("architectures", []))
            if not architectures:
                architectures = [ARCHITECTURE]
            variant = details.get((pkgbuild_path, package))
            if variant is None:
                candidate_id = package
                variant_name = "default"
            else:
                candidate_id = f"{package}--{variant['variant']}"
                variant_name = variant["variant"]
                variant_entries += 1
            if not ID_RE.fullmatch(candidate_id) or candidate_id in candidate_ids:
                raise OverlayError(f"candidate identity is invalid or duplicated: {candidate_id}")
            candidate_ids.add(candidate_id)
            package_names.add(package)
            shard = digest(candidate_id.encode("utf-8"))[:2]
            base = f"{shard}/{candidate_id}"

            candidate_text = CANDIDATES.render_candidate(
                package, record, metadata, records_authority(records)
            ).rstrip() + "\n\n[selection]\n"
            candidate_text += f"variant = {quote(variant_name)}\n"
            candidate_text += f"required = {'true' if variant is not None else 'false'}\n"
            if variant is not None:
                candidate_text += f"group = {quote(variant['group'])}\n"
                candidate_text += f"dimension = {quote(variant['dimension'])}\n"
                candidate_text += f"policy_value = {quote(variant['policy_value'])}\n"
                candidate_text += f"build_identity = {quote(variant['build_identity'])}\n"
            artifacts: dict[str, Any] = {
                "candidate": artifact_entry(
                    output, f"candidates/{base}.toml", candidate_text.encode("utf-8")
                ),
                "ingress_lock": artifact_entry(
                    output,
                    f"locks/{base}.toml",
                    render_lock(package, repository, revision, pkgbuild_path, record["pkgbuild_sha256"]),
                ),
            }

            admission = record["admission_class"]
            if ARCHITECTURE not in architectures and "any" not in architectures:
                disposition = "quarantined"
                reasons = sorted(set(record["reason_codes"] + ["UNSUPPORTED_ARCHITECTURE"]))
                quarantine_record = dict(record)
                quarantine_record["reason_codes"] = reasons
                artifacts["quarantine"] = artifact_entry(
                    output,
                    f"quarantine/{base}.json",
                    render_quarantine(
                        candidate_id, package, version, release, quarantine_record, variant
                    ),
                )
            elif admission == "meta":
                disposition = "meta-target-ready"
                artifacts["target_policy"] = artifact_entry(
                    output, f"targets/{base}.toml", render_meta_target(package)
                )
            elif admission == "static":
                disposition = "target-policy-required"
                artifacts["target_draft"] = artifact_entry(
                    output,
                    f"target-drafts/{base}.json",
                    render_target_draft(package, version, release, variant),
                )
            elif admission == "sealed-script":
                disposition = "worker-required"
                artifacts["worker_plan"] = artifact_entry(
                    output,
                    f"worker-plans/{base}.json",
                    render_worker_plan(
                        candidate_id,
                        package,
                        version,
                        release,
                        pkgbuild_path,
                        record["pkgbuild_sha256"],
                        len(pkgbuild_bytes),
                        record["reason_codes"],
                        variant,
                    ),
                )
            elif admission == "template":
                disposition = "template-review-required"
                artifacts["template"] = artifact_entry(
                    output,
                    f"templates/{base}.json",
                    render_template(candidate_id, package, version, release, record, variant),
                )
            elif admission == "rejected":
                disposition = "quarantined"
                artifacts["quarantine"] = artifact_entry(
                    output,
                    f"quarantine/{base}.json",
                    render_quarantine(candidate_id, package, version, release, record, variant),
                )
            else:
                raise OverlayError(f"unsupported admission class: {admission}")
            dispositions[disposition] += 1
            entries.append(
                {
                    "candidate_id": candidate_id,
                    "package": package,
                    "version": version,
                    "release": release,
                    "epoch": epoch,
                    "architecture": ARCHITECTURE,
                    "source_architectures": architectures,
                    "variant": variant_name,
                    "variant_policy": variant,
                    "pkgbuild_path": pkgbuild_path,
                    "pkgbuild_sha256": record["pkgbuild_sha256"],
                    "srcinfo_sha256": record.get("srcinfo_sha256"),
                    "admission_class": admission,
                    "disposition": disposition,
                    "reason_codes": record["reason_codes"],
                    "artifacts": artifacts,
                }
            )

    entries.sort(
        key=lambda entry: (
            entry["package"],
            entry["version"],
            entry["variant"],
            entry["pkgbuild_path"],
        )
    )
    for ordinal, entry in enumerate(entries):
        entry["ordinal"] = ordinal
    expected = policy["target_package_outputs"]
    if len(entries) != expected:
        raise OverlayError(f"staging output count differs: {len(entries)}/{expected}")
    manifest = {
        "format": FORMAT,
        "distribution": DISTRIBUTION,
        "kind": "cachyos-overlay-staging",
        "repository": repository,
        "revision": revision,
        "pkgbuild_count": records["pkgbuild_count"],
        "expected_package_outputs": expected,
        "package_output_count": len(entries),
        "canonical_package_name_count": len(package_names),
        "variant_entry_count": variant_entries,
        "variant_collision_count": len(entries) - len(package_names),
        "production_ready": False,
        "counts": dict(sorted(dispositions.items())),
        "entries": entries,
    }
    return manifest


def records_authority(records: dict[str, Any]) -> dict[str, str]:
    return {
        "repository": records["repository"],
        "revision": records["revision"],
    }


def verify(manifest: dict[str, Any], root: Path) -> None:
    expected_top = {
        "format",
        "distribution",
        "kind",
        "repository",
        "revision",
        "pkgbuild_count",
        "expected_package_outputs",
        "package_output_count",
        "canonical_package_name_count",
        "variant_entry_count",
        "variant_collision_count",
        "production_ready",
        "counts",
        "entries",
    }
    if set(manifest) != expected_top:
        raise OverlayError("staging manifest has missing or unknown fields")
    if (
        manifest["format"] != FORMAT
        or manifest["distribution"] != DISTRIBUTION
        or manifest["kind"] != "cachyos-overlay-staging"
        or manifest["production_ready"] is not False
    ):
        raise OverlayError("staging manifest identity is invalid")
    entries = manifest["entries"]
    if (
        not isinstance(entries, list)
        or len(entries) != manifest["expected_package_outputs"]
        or len(entries) != manifest["package_output_count"]
    ):
        raise OverlayError("staging manifest output count is invalid")
    previous: tuple[str, str, str, str] | None = None
    candidate_ids: set[str] = set()
    packages: set[str] = set()
    variants = 0
    dispositions: Counter[str] = Counter()
    for index, entry in enumerate(entries):
        if entry.get("ordinal") != index:
            raise OverlayError(f"entries[{index}] ordinal is not canonical")
        candidate_id = entry.get("candidate_id")
        package = entry.get("package")
        version = entry.get("version")
        variant = entry.get("variant")
        path = entry.get("pkgbuild_path")
        if (
            not isinstance(candidate_id, str)
            or not ID_RE.fullmatch(candidate_id)
            or candidate_id in candidate_ids
            or not isinstance(package, str)
            or not ID_RE.fullmatch(package)
            or not isinstance(version, str)
            or not version
            or not isinstance(variant, str)
            or not variant
            or not isinstance(path, str)
            or not safe_relative(path)
        ):
            raise OverlayError(f"entries[{index}] identity is invalid")
        candidate_ids.add(candidate_id)
        packages.add(package)
        identity = (package, version, variant, path)
        if previous is not None and previous >= identity:
            raise OverlayError(f"entries[{index}] is not in canonical order")
        previous = identity
        if variant != "default":
            variants += 1
        disposition = entry.get("disposition")
        if not isinstance(disposition, str) or not disposition:
            raise OverlayError(f"entries[{index}] disposition is invalid")
        dispositions[disposition] += 1
        artifacts = entry.get("artifacts")
        if not isinstance(artifacts, dict) or not artifacts:
            raise OverlayError(f"entries[{index}] artifacts are invalid")
        for label, artifact in artifacts.items():
            if (
                not isinstance(label, str)
                or not isinstance(artifact, dict)
                or set(artifact) != {"path", "sha256", "size"}
                or not isinstance(artifact["path"], str)
                or not safe_relative(artifact["path"])
                or not isinstance(artifact["sha256"], str)
                or not DIGEST_RE.fullmatch(artifact["sha256"])
                or not isinstance(artifact["size"], int)
                or artifact["size"] <= 0
            ):
                raise OverlayError(f"entries[{index}].artifacts.{label} is invalid")
            data = regular_beneath(root, artifact["path"])
            if len(data) != artifact["size"] or digest(data) != artifact["sha256"]:
                raise OverlayError(
                    f"entries[{index}].artifacts.{label} differs from retained bytes"
                )
    if manifest["canonical_package_name_count"] != len(packages):
        raise OverlayError("canonical package name count differs from entries")
    if manifest["variant_entry_count"] != variants:
        raise OverlayError("variant entry count differs from entries")
    if manifest["variant_collision_count"] != len(entries) - len(packages):
        raise OverlayError("variant collision count differs from entries")
    if manifest["counts"] != dict(sorted(dispositions.items())):
        raise OverlayError("disposition counts differ from entries")


def write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    data = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if path.exists() or path.is_symlink():
        raise OverlayError(f"manifest already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mirror", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--variants", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--verify-only", action="store_true")
    arguments = parser.parse_args()
    try:
        if arguments.verify_only:
            manifest = json.loads(arguments.manifest.read_text(encoding="utf-8"))
            verify(manifest, arguments.output.resolve())
        else:
            policy = INVENTORY.load_policy(arguments.policy)
            records = VARIANTS.load_json(arguments.records)
            variants = VARIANTS.load_toml(arguments.variants)
            manifest = prepare(
                arguments.mirror,
                policy,
                records,
                variants,
                arguments.output,
            )
            verify(manifest, arguments.output.resolve())
            write_manifest(arguments.manifest, manifest)
    except (OSError, json.JSONDecodeError, OverlayError, INVENTORY.InventoryError, VARIANTS.VariantError) as error:
        print(error, file=sys.stderr)
        return 1
    print(f"prepared {manifest['package_output_count']} CachyOS overlay staging records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
