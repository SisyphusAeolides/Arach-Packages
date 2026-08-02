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

Three recipes close the current kernel-to-installer release graph:

- `arach-kernel` release 40 pins Arach Kernel
  `46a8b9ce1b8cbcf6b645456ac46bde7a10156c54` and Push
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
  provider-first relocation, deterministic global symbol scope, seven explicit
  relative relocations, two root writes decoded from one immutable canonical
  `DT_RELR` address/bitmap pair, one exact-version 24-byte main-executable
  `R_X86_64_COPY`, one static `R_X86_64_TPOFF64`, and one
  general-dynamic `R_X86_64_DTPMOD64`/`R_X86_64_DTPOFF64` pair. The startup
  loader publishes a bounded dynamic-thread vector at `FS:8` and admits only
  the exact unversioned compiler-emitted `__tls_get_addr` edge. It validates
  the module and offset against the owned TLS arena. The measured Linux
  directory slice
  creates `/runpath` through `mkdirat`, proves duplicate `mkdir` rejection, and
  places all three providers below that directory. Canonical bounded
  `DT_RUNPATH` entries on the root and middle objects resolve only their direct
  dependencies, record the exact opened paths, and reject relative, duplicate,
  empty, dot-segment, legacy `DT_RPATH`, and over-capacity input. Seven
  exact-version eager PLT bindings, the resolver, one unversioned weak-function
  binding, and one unresolved weak-function-to-zero slot are measured. Four
  eager `R_X86_64_GLOB_DAT` writes bind one exact-version global object,
  select the earlier weak data provider over a later strong definition, and
  write one unresolved unversioned weak data slot as zero. The observer's
  fourth binding resolves to the executable copy while the root's
  `DT_SYMBOLIC` lookup retains its original provider object. Four bounded
  `R_X86_64_64` writes bind a versioned function pointer, a versioned provider
  object at an eight-byte interior addend, the earlier weak data provider, and
  one unresolved weak slot as zero. Normal Linux first-definition scope
  governs function, data, and absolute-symbol lookup. Packed-relative decoding
  bounds expansion, proves monotonically increasing disjoint targets and mapped
  implicit addends, and writes only after a complete validation pass. The
  linker reconstructs the bounded immutable main PIE from `AT_PHDR`, accepts
  only COPY relocations in its dynamic relocation table, proves exact provider
  versions and extents, pairwise-disjoint writable targets, and non-aliasing
  readable sources, then prevalidates the complete batch before copying any
  byte. Executable copies precede ordinary shared objects in process-global
  data scope without overriding a requesting object's `DT_SYMBOLIC` local
  priority. Weak TLS, GNU-unique and IFUNC binding, and unresolved versioned
  weak symbols remain rejected. Cross-object
  execution consumes both FS-relative and general-dynamic TLS state, the
  selected weak function and data, exact-version global data, the independent
  executable copy, the relocated function pointer, and the checked interior
  object pointer before four
  dependency-first initializers and eight reverse-order finalizers complete
  under QEMU/OVMF. Its C0 and desktop constructors explicitly load Granite's
  target configuration, compare two isolated UEFI builds, and verify
  deterministic PE metadata. The C0 image constructor also produces
  byte-identical invariant FAT boot volumes.
- `granite` release 4 pins Granite
  `1e7110ffee23900cbec480b1cea90abd8c9dc3e8`. Its UEFI target removes the
  varying CodeView signature, fixes the PE timestamp, and requires two
  independent production builds to be byte-identical. A reusable strict PE32+
  verifier lets downstream release builders enforce the same artifact contract.
- `arach-os-installer` release 24 pins Arach OS
  `b6ef9982d5cb8dd9df0f1203f0759c689a359cd2` and publishes the journaled
  installer binary, canonical branding, Calamares settings, hardware preflight,
  transaction modules, partition/user/unpack configuration, and protocol
  helpers declared by the live-image contract.

The normal package matrix validates recipe policy, Rust, Fortran, Idris 2,
Agda, exact Corinth and Granite outputs, Granite's independent UEFI
reproducibility gate, and every declared installer output. A separate kernel
package gate fetches the exact source revisions, prefetches the locked Cargo
graph, disables network access, builds the custom Arach target and its bounded
exec, runtime-linker, and shared-object probes offline, validates the main
PIE's bounded W^X layout and exact versioned COPY metadata, and checks that
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
