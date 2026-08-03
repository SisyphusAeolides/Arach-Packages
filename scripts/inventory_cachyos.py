#!/usr/bin/env python3
"""Inventory and conservatively classify a pinned CachyOS PKGBUILD mirror."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
import tomllib
from collections import Counter
from pathlib import Path
from typing import Any

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+_.@-]*$")
KNOWN_CLASSES = {"static", "sealed-script", "meta", "template", "rejected"}
FUNCTION_RE = re.compile(
    r"(?m)^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*\)\s*\{"
)


class InventoryError(ValueError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_git(mirror: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(mirror), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise InventoryError(result.stderr.strip() or "git command failed")
    return result.stdout.strip()


def load_policy(path: Path) -> dict[str, Any]:
    try:
        policy = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise InventoryError(f"cannot read ingress policy: {error}") from error
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
        raise InventoryError("ingress policy has missing or unknown fields")
    if policy["format"] != 1:
        raise InventoryError("unsupported ingress policy format")
    if policy["upstream_repository"] != "https://github.com/CachyOS/CachyOS-PKGBUILDS.git":
        raise InventoryError("unexpected CachyOS repository authority")
    if not isinstance(policy["mirror_revision"], str) or not REVISION_RE.fullmatch(
        policy["mirror_revision"]
    ):
        raise InventoryError("mirror revision must be a full lowercase Git object ID")
    if not isinstance(policy["target_package_outputs"], int) or policy["target_package_outputs"] <= 0:
        raise InventoryError("target package count must be positive")
    if not isinstance(policy["max_pkgbuild_bytes"], int) or not (
        1024 <= policy["max_pkgbuild_bytes"] <= 4 * 1024 * 1024
    ):
        raise InventoryError("PKGBUILD byte bound is invalid")
    if set(policy["classes"]) != KNOWN_CLASSES or len(policy["classes"]) != len(KNOWN_CLASSES):
        raise InventoryError("ingress classes differ from the canonical set")
    for field in ("reason_codes", "kernel_package_prefixes"):
        values = policy[field]
        if not isinstance(values, list) or not values or len(values) != len(set(values)):
            raise InventoryError(f"{field} must be a non-empty unique array")
        if not all(isinstance(value, str) and value for value in values):
            raise InventoryError(f"{field} contains an invalid value")
    return policy


def ensure_contained_regular(root: Path, path: Path, maximum: int) -> bytes:
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise InventoryError(f"path escapes mirror: {path}") from error
    cursor = root
    for component in relative.parts:
        if component in {"", ".", ".."}:
            raise InventoryError(f"unsafe mirror path: {relative.as_posix()}")
        cursor = cursor / component
        try:
            metadata = cursor.lstat()
        except OSError as error:
            raise InventoryError(f"cannot inspect mirror path: {relative.as_posix()}: {error}") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise InventoryError(f"mirror path traverses a symlink: {relative.as_posix()}")
    final = path.lstat()
    if not stat.S_ISREG(final.st_mode):
        raise InventoryError(f"mirror input is not a regular file: {relative.as_posix()}")
    if path.stat().st_size > maximum:
        raise InventoryError(f"PKGBUILD exceeds byte bound: {relative.as_posix()}")
    data = path.read_bytes()
    if len(data) > maximum:
        raise InventoryError(f"PKGBUILD exceeds byte bound: {relative.as_posix()}")
    return data


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


def assignment_value(text: str, key: str) -> str | None:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        code = strip_comment(line).strip()
        match = re.match(rf"^{re.escape(key)}\s*=\s*(.*)$", code)
        if match is None:
            continue
        value = match.group(1).strip()
        quote: str | None = None
        depth = 0
        for character in value:
            if quote is not None:
                if character == quote:
                    quote = None
            elif character in {"'", '"'}:
                quote = character
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
        cursor = index + 1
        while (quote is not None or depth > 0) and cursor < len(lines):
            continuation = strip_comment(lines[cursor]).strip()
            value += " " + continuation
            for character in continuation:
                if quote is not None:
                    if character == quote:
                        quote = None
                elif character in {"'", '"'}:
                    quote = character
                elif character == "(":
                    depth += 1
                elif character == ")":
                    depth -= 1
            cursor += 1
        return value if quote is None and depth == 0 else None
    return None


def parse_tokens(value: str) -> list[str] | None:
    value = value.strip()
    if "$" in value or "`" in value or "${" in value:
        return None
    if value.startswith("("):
        if not value.endswith(")"):
            return None
        value = value[1:-1]
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
                return None
            token = value[cursor + 1 : end]
            cursor = end + 1
        else:
            end = cursor
            while end < len(value) and not value[end].isspace():
                end += 1
            token = value[cursor:end]
            cursor = end
        if not token or any(character in token for character in "();|&<>"):
            return None
        output.append(token)
    return output


def srcinfo_packages(path: Path, root: Path, maximum: int) -> tuple[list[str], str | None]:
    if not path.exists():
        return [], None
    data = ensure_contained_regular(root, path, maximum)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise InventoryError(f".SRCINFO is not UTF-8: {path}") from error
    packages = []
    for line in text.splitlines():
        match = re.match(r"^\s*pkgname\s*=\s*([^\s#]+)\s*$", line)
        if match:
            packages.append(match.group(1))
    return sorted(set(packages)), sha256_bytes(data)


def package_names(text: str, pkgbuild: Path, root: Path, maximum: int) -> tuple[list[str], str | None]:
    packages, srcinfo_digest = srcinfo_packages(pkgbuild.with_name(".SRCINFO"), root, maximum)
    if packages:
        return packages, srcinfo_digest
    value = assignment_value(text, "pkgname")
    if value is None:
        return [], srcinfo_digest
    parsed = parse_tokens(value)
    if parsed is None or not parsed or any(not PACKAGE_RE.fullmatch(item) for item in parsed):
        return [], srcinfo_digest
    return sorted(set(parsed)), srcinfo_digest


def has_checksum_assignment(text: str) -> bool:
    for key in ("sha256sums", "b2sums", "sha512sums", "sha384sums", "sha224sums"):
        value = assignment_value(text, key)
        if value is not None:
            tokens = parse_tokens(value)
            return tokens is not None and bool(tokens) and all(token.upper() != "SKIP" for token in tokens)
    return False


def source_tokens(text: str) -> list[str]:
    value = assignment_value(text, "source")
    if value is None:
        return []
    return parse_tokens(value) or []


def classify(text: str, packages: list[str], path: str, policy: dict[str, Any]) -> tuple[str, list[str], dict[str, Any]]:
    reasons: set[str] = set()
    functions = sorted(set(FUNCTION_RE.findall(text)))
    sources = source_tokens(text)
    lower_path = path.lower()
    is_kernel = any(
        package.startswith(prefix) for package in packages for prefix in policy["kernel_package_prefixes"]
    ) or any(prefix in lower_path for prefix in policy["kernel_package_prefixes"])
    pkgver_function = "pkgver" in functions
    split_package = len(packages) > 1 or any(name.startswith("package_") for name in functions)
    eval_present = re.search(r"(?m)(^|[;&|\s])eval(\s|$)", text) is not None
    shell_substitution = "$(" in text or "`" in text
    install_hook = assignment_value(text, "install") is not None
    pacman_hook = "/usr/share/libalpm/hooks" in text or any(token.endswith(".hook") for token in sources)
    vcs_sources = [
        token
        for token in sources
        if token.startswith(("git+", "hg+", "svn+", "bzr+"))
    ]
    floating_vcs = any(
        not re.search(r"#(?:commit|tag)=[0-9a-f]{40}$", token, re.IGNORECASE)
        for token in vcs_sources
    )
    missing_checksum = bool(sources) and not has_checksum_assignment(text) and not (
        vcs_sources and len(vcs_sources) == len(sources) and not floating_vcs
    )
    arbitrary_functions = [
        name
        for name in functions
        if name not in {"prepare", "build", "check", "package", "pkgver"}
        and not name.startswith("package_")
    ]

    if not packages:
        reasons.add("UNRESOLVED_PACKAGE_NAMES")
    if is_kernel:
        reasons.add("KERNEL_TEMPLATE")
    if pkgver_function:
        reasons.add("DYNAMIC_PKGVER")
    if eval_present:
        reasons.add("EVAL")
    if shell_substitution:
        reasons.add("SHELL_SUBSTITUTION")
    if install_hook:
        reasons.add("INSTALL_HOOK")
    if pacman_hook:
        reasons.add("PACMAN_HOOK")
    if floating_vcs:
        reasons.add("FLOATING_VCS")
    if missing_checksum:
        reasons.add("MISSING_CHECKSUM")
    if split_package:
        reasons.add("SPLIT_PACKAGE")
    if arbitrary_functions:
        reasons.add("UNPARSED_FUNCTION")

    fatal = {
        "UNRESOLVED_PACKAGE_NAMES",
        "EVAL",
        "FLOATING_VCS",
        "INSTALL_HOOK",
        "MISSING_CHECKSUM",
        "PACMAN_HOOK",
    }
    if is_kernel:
        admission = "template"
    elif reasons & fatal:
        admission = "rejected"
    elif functions or shell_substitution or split_package:
        admission = "sealed-script"
    elif not sources and assignment_value(text, "depends") is not None:
        admission = "meta"
    else:
        admission = "static"

    signals = {
        "functions": functions,
        "has_sources": bool(sources),
        "vcs_source_count": len(vcs_sources),
        "pkgver_function": pkgver_function,
        "split_package": split_package,
        "shell_substitution": shell_substitution,
        "install_hook": install_hook,
        "pacman_hook": pacman_hook,
        "floating_vcs": floating_vcs,
        "missing_checksum": missing_checksum,
    }
    return admission, sorted(reasons), signals


def inventory(mirror: Path, policy: dict[str, Any]) -> dict[str, Any]:
    mirror = mirror.resolve()
    if not mirror.is_dir() or mirror.is_symlink():
        raise InventoryError("mirror must be a real directory")
    head = run_git(mirror, "rev-parse", "HEAD")
    if head != policy["mirror_revision"]:
        raise InventoryError(f"mirror HEAD {head} differs from policy revision")
    dirty = run_git(mirror, "status", "--porcelain", "--untracked-files=no")
    if dirty:
        raise InventoryError("mirror has tracked modifications")

    records: list[dict[str, Any]] = []
    class_counts: Counter[str] = Counter()
    reason_counts: Counter[str] = Counter()
    package_owners: dict[str, str] = {}
    duplicate_packages: list[dict[str, str]] = []
    maximum = policy["max_pkgbuild_bytes"]

    for pkgbuild in sorted(mirror.rglob("PKGBUILD"), key=lambda item: item.relative_to(mirror).as_posix()):
        data = ensure_contained_regular(mirror, pkgbuild, maximum)
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = ""
        relative = pkgbuild.relative_to(mirror).as_posix()
        packages, srcinfo_digest = package_names(text, pkgbuild, mirror, maximum) if text else ([], None)
        admission, reasons, signals = classify(text, packages, relative, policy) if text else (
            "rejected",
            ["UNSUPPORTED_SYNTAX", "UNRESOLVED_PACKAGE_NAMES"],
            {"invalid_utf8": True},
        )
        for package in packages:
            previous = package_owners.setdefault(package, relative)
            if previous != relative:
                duplicate_packages.append({"package": package, "first": previous, "second": relative})
        class_counts[admission] += len(packages) if packages else 1
        reason_counts.update(reasons)
        record = {
            "path": relative,
            "pkgbuild_sha256": sha256_bytes(data),
            "srcinfo_sha256": srcinfo_digest,
            "packages": packages,
            "admission_class": admission,
            "reason_codes": reasons,
            "line_count": len(text.splitlines()) if text else 0,
            "signals": signals,
        }
        records.append(record)

    resolved_outputs = sum(len(record["packages"]) for record in records)
    unresolved_pkgbuilds = sum(not record["packages"] for record in records)
    complete = (
        resolved_outputs == policy["target_package_outputs"]
        and unresolved_pkgbuilds == 0
        and not duplicate_packages
    )
    return {
        "format": 1,
        "upstream": {
            "repository": policy["upstream_repository"],
            "revision": policy["mirror_revision"],
        },
        "target_package_outputs": policy["target_package_outputs"],
        "pkgbuild_count": len(records),
        "resolved_package_outputs": resolved_outputs,
        "unresolved_pkgbuilds": unresolved_pkgbuilds,
        "complete": complete,
        "summary": {
            "classes": dict(sorted(class_counts.items())),
            "reasons": dict(sorted(reason_counts.items())),
        },
        "duplicate_packages": duplicate_packages,
        "records": records,
    }


def write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    if path.is_symlink():
        raise InventoryError("manifest output cannot be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mirror", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        policy = load_policy(arguments.policy)
        manifest = inventory(arguments.mirror, policy)
        write_manifest(arguments.output, manifest)
    except (OSError, InventoryError) as error:
        print(error, file=sys.stderr)
        return 1
    print(
        f"inventoried {manifest['pkgbuild_count']} PKGBUILDs and "
        f"{manifest['resolved_package_outputs']}/{manifest['target_package_outputs']} package outputs"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
