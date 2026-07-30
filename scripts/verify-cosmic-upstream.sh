#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
revision="$(sed -n 's/^revision = "\([0-9a-f]\{40\}\)"$/\1/p' "$root/locks/cosmic-epoch.toml" | head -n 1)"
test -n "$revision"

scratch="$(mktemp -d "${TMPDIR:-/tmp}/arach-cosmic-upstream.XXXXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT
git init --quiet "$scratch/repository"
git -C "$scratch/repository" fetch --quiet --depth 1 --filter=blob:none \
    https://github.com/pop-os/cosmic-epoch.git "$revision"
git -C "$scratch/repository" checkout --quiet --detach FETCH_HEAD

cargo run --quiet --locked --manifest-path "$root/Cargo.toml" -- \
    --root "$root" --verify-cosmic-repository "$scratch/repository"
