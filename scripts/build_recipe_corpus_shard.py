#!/usr/bin/env python3
"""Build one deterministic shard of the signed Arach recipe corpus."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT_MODULE = Path(__file__).resolve().with_name("validate_recipe_corpus.py")
SPEC = importlib.util.spec_from_file_location("validate_recipe_corpus", ROOT_MODULE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load recipe corpus validator")
CORPUS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CORPUS
SPEC.loader.exec_module(CORPUS)


class ShardBuildError(RuntimeError):
    pass


def regular_executable(path: Path) -> Path:
    if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
        raise ShardBuildError(f"tool is not a regular executable: {path}")
    return path.resolve()


def canonical_directory(path: Path, create: bool = False) -> Path:
    if create:
        path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise ShardBuildError(f"path is not a regular directory: {path}")
    return path.resolve()


def run_command(arguments: list[str], maximum_output: int = 256 * 1024) -> str:
    result = subprocess.run(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        env={
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "/bin/false",
        },
    )
    output = result.stdout[-maximum_output:]
    error = result.stderr[-maximum_output:]
    if result.returncode != 0:
        raise ShardBuildError(
            f"command failed with status {result.returncode}: {arguments[0]}\n{error or output}"
        )
    return output.strip()


def ensure_new_pair(recipe: Path, receipt: Path, resume: bool) -> str | None:
    recipe_exists = recipe.exists()
    receipt_exists = receipt.exists()
    if recipe_exists != receipt_exists:
        raise ShardBuildError(
            f"partial existing output: recipe={recipe_exists}, receipt={receipt_exists}"
        )
    if not recipe_exists:
        return None
    if not resume:
        raise ShardBuildError("output already exists without --resume")
    if recipe.is_symlink() or receipt.is_symlink() or not recipe.is_file() or not receipt.is_file():
        raise ShardBuildError("existing output is not a regular recipe and receipt pair")
    return hashlib.sha256(recipe.read_bytes()).hexdigest()


def write_report(path: Path, report: dict[str, Any]) -> None:
    if path.is_symlink():
        raise ShardBuildError(f"report path cannot be a symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ShardBuildError(f"temporary report path already exists: {temporary}")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def build_shard(
    root: Path,
    shard: int,
    corinth_corpus: Path,
    corinth_ingest: Path,
    keyring: Path,
    work: Path,
    report_path: Path,
    allow_network: bool,
    resume: bool,
    require_complete: bool,
) -> dict[str, Any]:
    plan = CORPUS.load_json(root / CORPUS.PLAN_PATH, 1024 * 1024)
    CORPUS.validate_plan(plan)
    manifest_path = root / plan["paths"]["manifest"]
    signature_path = root / plan["paths"]["manifest_signature"]
    corpus_root = canonical_directory(root / plan["paths"]["corpus_root"])
    manifest_bytes = manifest_path.read_bytes()
    manifest = CORPUS.load_json(manifest_path)
    entries = CORPUS.validate_manifest(manifest)
    if shard < 0 or shard >= manifest["shard_count"]:
        raise ShardBuildError("shard is outside the signed corpus")

    preflight = work / f"preflight-{shard:03}.json"
    if preflight.exists() or preflight.is_symlink():
        preflight.unlink()
    run_command(
        [
            str(corinth_corpus),
            "--manifest",
            str(manifest_path),
            "--manifest-signature",
            str(signature_path),
            "--keyring",
            str(keyring),
            "--root",
            str(corpus_root),
            "--report",
            str(preflight),
            "--production",
            "--shard",
            str(shard),
        ]
    )
    if preflight.is_symlink() or not preflight.is_file():
        raise ShardBuildError("corpus preflight report was not produced")
    preflight_document = json.loads(preflight.read_text(encoding="utf-8"))

    selected = [entry for entry in entries if entry["shard"] == shard]
    results: list[dict[str, Any]] = []
    counts = {
        "generated": 0,
        "resumed": 0,
        "worker-required": 0,
        "failed": 0,
    }
    for entry in selected:
        base_result: dict[str, Any] = {
            "ordinal": entry["ordinal"],
            "upstream": entry["upstream"],
            "package": entry["package"],
            "version": entry["version"],
            "strategy": entry["strategy"],
            "recipe": entry["recipe"],
            "receipt": entry["receipt"],
        }
        try:
            if entry["strategy"] == "deterministic-worker":
                base_result["status"] = "worker-required"
                base_result["reason"] = entry["fallback_reason"]
                counts["worker-required"] += 1
                results.append(base_result)
                continue

            recipe = corpus_root / entry["recipe"]
            receipt = corpus_root / entry["receipt"]
            recipe.parent.mkdir(parents=True, exist_ok=True)
            receipt.parent.mkdir(parents=True, exist_ok=True)
            existing_sha256 = ensure_new_pair(recipe, receipt, resume)
            if existing_sha256 is not None:
                CORPUS.validate_recipe(recipe, entry)
                base_result["status"] = "resumed"
                base_result["recipe_sha256"] = existing_sha256
                counts["resumed"] += 1
                results.append(base_result)
                continue

            package_work = canonical_directory(
                work / f"entry-{entry['ordinal']:05}-{entry['package']}",
                create=True,
            )
            command = [
                str(corinth_ingest),
                "--lock",
                str(corpus_root / entry["ingress_lock"]),
                "--lock-signature",
                str(corpus_root / entry["ingress_signature"]),
                "--target",
                str(corpus_root / entry["target_policy"]),
                "--target-signature",
                str(corpus_root / entry["target_signature"]),
                "--keyring",
                str(keyring),
                "--work",
                str(package_work),
                "--output",
                str(recipe),
                "--receipt",
                str(receipt),
            ]
            if allow_network:
                command.append("--allow-network")
            output = run_command(command)
            recipe_sha256 = CORPUS.validate_recipe(recipe, entry)
            if receipt.is_symlink() or not receipt.is_file():
                raise ShardBuildError("corinth-ingest did not produce a regular receipt")
            base_result["status"] = "generated"
            base_result["recipe_sha256"] = recipe_sha256
            base_result["ingest_output"] = output
            counts["generated"] += 1
        except Exception as error:  # retain all shard failures in one bounded report
            base_result["status"] = "failed"
            base_result["error"] = str(error)[:4096]
            counts["failed"] += 1
        results.append(base_result)

    report = {
        "format": 1,
        "corpus_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "target_count": manifest["target_count"],
        "shard_count": manifest["shard_count"],
        "shard": shard,
        "selected_entries": len(selected),
        "preflight": preflight_document,
        "counts": counts,
        "entries": results,
    }
    write_report(report_path, report)
    if counts["failed"]:
        raise ShardBuildError(f"shard {shard} contains {counts['failed']} failed entries")
    if require_complete and counts["worker-required"]:
        raise ShardBuildError(
            f"shard {shard} still requires {counts['worker-required']} deterministic workers"
        )
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--shard", type=int, required=True)
    parser.add_argument("--corinth-corpus", type=Path, required=True)
    parser.add_argument("--corinth-ingest", type=Path, required=True)
    parser.add_argument("--keyring", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--require-complete", action="store_true")
    arguments = parser.parse_args()

    try:
        root = canonical_directory(arguments.root)
        corinth_corpus = regular_executable(arguments.corinth_corpus)
        corinth_ingest = regular_executable(arguments.corinth_ingest)
        if arguments.keyring.is_symlink() or not arguments.keyring.is_file():
            raise ShardBuildError("keyring is not a regular file")
        keyring = arguments.keyring.resolve()
        work = canonical_directory(arguments.work, create=True)
        report = arguments.report if arguments.report.is_absolute() else root / arguments.report
        build_shard(
            root=root,
            shard=arguments.shard,
            corinth_corpus=corinth_corpus,
            corinth_ingest=corinth_ingest,
            keyring=keyring,
            work=work,
            report_path=report,
            allow_network=arguments.allow_network,
            resume=arguments.resume,
            require_complete=arguments.require_complete,
        )
    except (CORPUS.CorpusError, ShardBuildError, OSError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    print(f"recipe corpus shard {arguments.shard} completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
