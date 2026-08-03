# Arach Packages

Arach Packages is the recipe, patch, license, source-lock, SBOM, and package-corpus authority for ArachOS. Corinth consumes validated records from this repository and turns them into measured packages, signed indexes, transactional generations, and retained build evidence.

Build availability and installation authority are separate. Upstream Git repositories, archives, crates.io, and fixed local mirrors may provide immutable build inputs. Only signed Arach native metadata may publish system packages. Drivers and firmware additionally require the signed Arach hardware authority, a compatible Arach Driver ABI, health checks, and rollback policy.

## Canonical recipe

An admitted package is stored at:

```text
recipes/CATEGORY/NAME/package.toml
```

Recipe format 1 binds:

- package identity, release, architecture, license, scope, and publishing authority;
- every source to a full Git object ID or cryptographic digest;
- an allow-listed build adapter, build dependencies, and declared outputs;
- runtime dependencies, capabilities, conflicts, and package semantics;
- offline, sandboxed, reproducible policy; and
- typed hardware policy for driver and firmware packages.

Unknown fields, mutable source references, undeclared outputs, shell syntax in native commands, dependency cycles, ambiguous providers, and authority mismatches fail closed.

## CachyOS PKGBUILD ingress

The CachyOS overlay is pinned to an immutable `CachyOS/CachyOS-PKGBUILDS` commit. The current snapshot contains 175 PKGBUILDs and 326 package outputs. Every output is tracked as one of:

- a static importer candidate;
- a source-less metadata bundle;
- a deterministic compatibility-worker candidate;
- a target-specific template; or
- a quarantine record with stable reason codes.

The overlay includes mutually exclusive build variants, such as OpenBLAS x86-64-v3/x86-64-v4 and zstd plain/PGO. Variant policy must select one canonical publisher for a package identity; alternatives cannot silently overwrite one another.

The ingress design and acceptance rules are documented in [docs/PKGBUILD_INGRESS.md](docs/PKGBUILD_INGRESS.md). Pinned census and record evidence is retained under `ingress/cachyos/snapshots/`.

A candidate is not automatically an admitted package. Static candidates still require a signed target policy. Dynamic PKGBUILDs require a capability-bounded Corinth worker and repeated byte-identical output. Rejected records remain quarantined until their mutable sources, hooks, or unsupported semantics are resolved.

## Universal recipe corpus

The production corpus target is 39,191 package identities across Arch, AUR, Fedora, Debian, Alpine, Gentoo, CRUX, Nix, Cargo, GitHub, and the pinned CachyOS overlay. It is separate from the 326-output CachyOS overlay census.

The corpus is divided into 256 deterministic shards. Completion requires:

- exactly 39,191 canonical identities;
- signed manifest and entry inputs;
- immutable source locks;
- static-importer-first routing;
- deterministic-worker fallback with at least two identical runs;
- zero blocked entries;
- one recipe and receipt per identity; and
- a complete recipe Merkle root.

The production plan is `production/recipe-corpus-plan.json`. Validation and resumable shard construction are implemented by `scripts/validate_recipe_corpus.py` and `scripts/build_recipe_corpus_shard.py`.

## Package semantics

Corinth's typed semantics contract covers replacements, optional dependencies, split outputs, multilib, configuration merge policy, ownership, symlinks and hardlinks, xattrs, ACLs, file capabilities, users and groups, Push services, desktop registration, and controlled cache triggers.

Target-install shell scripts are not part of the native package path. Installation behavior must be expressed through typed package semantics or an explicitly reviewed, measured compatibility route.

## Hardware boundary

The signed hardware catalog carries profiles, package intents, keyring inputs, binary indexes, and target-kernel driver evidence. Arach HWD may discover and rank eligible profiles, but it cannot invent package names or grant installation authority. Corinth verifies the signed plan and all package digests before mutation.

## Security and reproducibility

The repository generates a deterministic SPDX source SBOM and retains recipe, source, worker, and corpus evidence. Package builds run with network disabled after immutable inputs are acquired. Production publication requires signed metadata, measured outputs, monotonic sequences, rollback-capable generations, and reproducibility evidence.

## Validation

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo run --locked -- --root .
cargo run --locked --bin arach-package-lint -- --root .
python3 scripts/verify_cachyos_ingress.py --policy ingress/cachyos/policy.toml
python3 scripts/validate_recipe_corpus.py --root .
scripts/check-fortran.sh
scripts/check-formal-models.sh
```

Passing recipe validation proves schema, source, dependency, and policy correctness. It does not by itself prove that every package builds, runs on Arach Kernel, or belongs in an ArachOS release image.
