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

The current foundation contains locked recipes for the native boot/userspace
components, the signed Arach HWD planner, libinput-rs, elan-guardian, tuned-rs,
ccze-rs, the D-Bus broker, a pinned `greetd` display-manager recipe, and a `cosmic-desktop`
workspace recipe bound to the complete 28-component COSMIC Epoch lock. The
COSMIC recipe also carries the upstream `cosmic-greeter.toml` into its measured
install tree so greetd can launch the greeter without a second display-manager
stack. The `arach-os-installer` recipe also emits the
journaled installer binary and canonical Arach branding used by the live-image
contract. The COSMIC recipe uses a fixed compatibility adapter and emits a
measured install tree; these are build contracts, not a claim that every
component has already been certified on Arach Kernel hardware.

The live-image contract consumes a separately signed `firefox-*` binary
artifact from Corinth's native package index. This keeps the large upstream
Firefox runtime out of the source-recipe checkout while still making its
presence, digest, and `/usr/bin/firefox` path mandatory during live-root
materialization.

Recipe build systems cover Cargo/Rust, C, COSMIC workspace, Fortran, Idris 2,
Agda, Make, CMake, Meson, and metadata-only packages. Corinth consumes the same locked
source fields and executes only the corresponding allow-listed compiler
programs; it does not invoke a shell. Build dependencies are recorded
separately from runtime dependencies so imported recipes can be scheduled
without treating a compiler as a runtime requirement. crates.io and archive
sources must carry SHA-256 checksums, while Git sources use full object IDs.

## Validation

    cargo fmt --all -- --check
    cargo test --locked
    cargo run --locked -- --root .
    cargo run --locked --bin arach-package-lint -- --root .

Recipe format and trust rules are documented in
[docs/RECIPE_FORMAT.md](docs/RECIPE_FORMAT.md).

The signed `arach-hardware-catalog` artifact must also ship the four hashed
driver evidence tables under `etc/arach/hwd/driver-sources/`:
`modules.alias`, `modules.dep`, `modules.builtin`, and `modules.firmware`.
This keeps Calamares hardware discovery target-aware and reproducible while
leaving profile and package signatures as the only installation authority.

Hardware profile, binary-index, and source-fallback rules are documented in
[docs/HARDWARE_REPOSITORY.md](docs/HARDWARE_REPOSITORY.md).
