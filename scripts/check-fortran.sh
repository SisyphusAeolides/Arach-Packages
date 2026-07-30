#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/arach-packages-fortran.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT

gfortran -std=f2018 -Wall -Wextra -Werror \
    -J "$scratch" \
    "$root/native/build_rank.f90" \
    "$root/native/build_rank_test.f90" \
    -o "$scratch/build-rank-test"
"$scratch/build-rank-test"

