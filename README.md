# Arach Packages

Arach Packages is the recipe, patch, license, and immutable source-lock
authority for Arach OS. Corinth consumes validated recipes from this repository;
the Arach build service turns them into measured native packages, source
manifests, software bills of materials, and attestations.

The repository deliberately separates build availability from installation
trust. crates.io, upstream Git, archives, and local mirrors can supply locked
build inputs. Only the signed Arach native repository may publish system
packages. Drivers and firmware additionally require the signed Arach hardware
repository and a compatible hardware profile.

## Current release closure

The Arach OS component lock records the exact package-authority revision beside
every integration update; symbolic branches are never package inputs.

Two recipes close the current kernel-to-installer release graph:

- `arach-kernel` release 31 pins Arach Kernel
  `8559a34ac79d23c0074686d3522568207444967f` and Push
  `5bd361b86c048b60b6a8422a8e173ea0ec867bff`. The kernel revision contains the
  measured Akashic VFS-backed Linux file bridge, generation-bound
  `set_tid_address` exit clearing, address-space-bound private futex
  compare/block/wake, generation-safe x86-64 FS-base TLS, and measured
  shared-address-space clone, robust owner-death wake, descriptor sharing,
  independent clear-child-tid wake, bounded x86-64 self-signal delivery and
  exact-frame return, measured multi-member `exit_group`, and one dense,
  generation-bound descriptor/open-object table with `dup`, bounded `fcntl`,
  anonymous pipes, poll/epoll readiness, last-close watch removal, and
  descriptor-local close-on-exec paths. The same table now carries bounded
  Unix stream socketpairs and named listeners with full-duplex and vector
  transfer, peer identity, half-close, poll/epoll readiness, bounded
  `SCM_RIGHTS` transfer across process generations, generation-bound memfds,
  shared physical mappings that outlive descriptor close, and a bounded
  eight-object dynamic dependency engine. Its measured four-object diamond
  proves breadth-first closure, duplicate SONAME coalescing, cycle-free
  provider-first relocation, deterministic global symbol scope, five relative
  relocations, one static-TLS relocation, four eager PLT bindings, final W^X
  sealing, four dependency-first initializers, and cross-object execution that
  consumes FS-relative TLS state under QEMU/OVMF.
- `arach-os-installer` release 24 pins Arach OS
  `b6ef9982d5cb8dd9df0f1203f0759c689a359cd2` and publishes the journaled
  installer binary, canonical branding, Calamares settings, hardware preflight,
  transaction modules, partition/user/unpack configuration, and protocol
  helpers declared by the live-image contract.

The normal package matrix validates recipe policy, Rust, Fortran, Idris 2,
Agda, exact Corinth outputs, and every declared installer output. A separate
kernel package gate fetches the exact source revisions, prefetches the locked
Cargo graph, disables network access, builds the custom Arach target and its
bounded exec, runtime-linker, and shared-object probes offline, and checks that
the checkout remains clean.

Those gates prove recipe identity, declared output production, and offline
kernel buildability. They do not by themselves prove persistent storage, a
complete COSMIC runtime, or physical hardware operation.

## Package foundation

The current foundation contains locked recipes for the native boot/userspace
components, the signed Arach HWD planner, libinput-rs, elan-guardian, tuned-rs,
ccze-rs, the D-Bus broker, PipeWire, WirePlumber, seatd/libseat, a pinned
`greetd` display-manager recipe, and a `cosmic-desktop` workspace recipe bound
to the complete 28-component COSMIC Epoch lock.

The COSMIC recipe carries the upstream `cosmic-greeter.toml` into its measured
install tree so greetd can launch the greeter without a second display-manager
stack. It uses a fixed compatibility adapter and emits a recursively measured
install tree. These are build contracts, not a claim that every desktop
component has completed runtime qualification on Arach Kernel.

The live-image contract consumes a separately signed `firefox-*` binary
artifact from Corinth's native package index. This keeps the large upstream
Firefox runtime out of the source-recipe checkout while making its digest,
size, and `/usr/bin/firefox` path mandatory during live-root materialization.

## Recipe and source policy

Recipe build systems cover Cargo/Rust, C, COSMIC workspace, Fortran, Idris 2,
Agda, Make, CMake, Meson, and metadata-only packages. Corinth consumes the same
locked source fields and executes only the corresponding allow-listed compiler
programs; ordinary recipes do not invoke a shell.

Build dependencies are recorded separately from runtime dependencies so
imported recipes can be scheduled without treating a compiler as a runtime
requirement. crates.io and archive sources must carry SHA-256 checksums, while
Git sources use full object IDs. A source lock proves input identity; it does
not grant system, driver, or firmware installation authority.

Recipe format and trust rules are documented in
[docs/RECIPE_FORMAT.md](docs/RECIPE_FORMAT.md).

## Hardware catalog boundary

The signed `arach-hardware-catalog` artifact must ship five hashed driver
evidence tables under `etc/arach/hwd/driver-sources/`:

- `modules.alias`
- `modules.dep`
- `modules.builtin`
- `modules.firmware`
- `modules.builtin.modinfo`

The final table carries NUL-separated firmware and alias metadata for built-in
Linux drivers. This keeps Calamares hardware discovery target-aware and
reproducible while leaving signed profiles, package intents, and payloads as
the only installation authority.

Hardware profile, binary-index, and source-fallback rules are documented in
[docs/HARDWARE_REPOSITORY.md](docs/HARDWARE_REPOSITORY.md).

## Validation

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo run --locked -- --root .
cargo run --locked --bin arach-package-lint -- --root .
scripts/check-fortran.sh
scripts/check-formal-models.sh
```

The repository workflows additionally build the exact declared Corinth and
installer artifacts and run the proof-bound hard-offline kernel package gate.
