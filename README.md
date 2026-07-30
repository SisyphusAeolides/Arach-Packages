# Arach Packages

Arach Packages is the recipe, patch, license, and immutable source-lock
authority for Arach OS. Corinth consumes validated recipes from this repository;
the Arach build service turns them into signed native packages, source
manifests, software bills of materials, and attestations.

The repository deliberately separates build availability from installation
trust. crates.io, upstream Git, archives, and local mirrors can supply locked
build inputs. Only the signed Arach native repository may publish system
packages. Drivers and firmware additionally require the signed Arach hardware
repository and a compatible hardware profile.

The current foundation contains locked recipes for the five native boot and
userspace components, the signed Arach HWD planner, and a complete source lock
for the 28 components pinned by the upstream COSMIC Epoch integration
repository. That lock is a source baseline, not yet a claim that every
component builds or runs on Arach Kernel.

Recipe build systems cover Cargo/Rust, C, Fortran, Idris 2, Agda, Make,
CMake, Meson, and metadata-only packages. Corinth consumes the same locked
source fields and executes only the corresponding allow-listed compiler
programs; it does not invoke a shell. Build dependencies are recorded
separately from runtime dependencies so imported recipes can be scheduled
without treating a compiler as a runtime requirement. crates.io and archive
sources must carry SHA-256 checksums, while Git sources use full object IDs.

## Validation

    cargo fmt --all -- --check
    cargo test --locked
    cargo run --locked -- --root .
    scripts/check-fortran.sh
    scripts/check-formal-models.sh

Recipe format and trust rules are documented in
[docs/RECIPE_FORMAT.md](docs/RECIPE_FORMAT.md).
