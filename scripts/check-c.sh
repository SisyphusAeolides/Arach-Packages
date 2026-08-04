#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/arach-packages-c.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT

compiler="${CC:-cc}"
"$compiler" \
    -std=c17 \
    -Wall \
    -Wextra \
    -Werror \
    -pedantic \
    -O2 \
    -I "$root/native" \
    "$root/native/pkgmeta_probe.c" \
    "$root/native/pkgmeta_probe_test.c" \
    -o "$scratch/pkgmeta-probe-test"
"$scratch/pkgmeta-probe-test"
