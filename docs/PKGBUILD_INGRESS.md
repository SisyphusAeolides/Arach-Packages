# CachyOS PKGBUILD ingress

This document defines the fail-closed path from a pinned
`CachyOS/CachyOS-PKGBUILDS` snapshot to canonical Arach package recipes.
It adapts the CachyOS PKGBUILD blueprint to the existing Arach-Packages and
Corinth authorities instead of introducing a second recipe language.

## Goal

For every `PKGBUILD` path in one immutable upstream snapshot, publish exactly
one classification artifact:

- an admitted canonical Arach recipe;
- a measured compatibility-worker candidate;
- a hand-maintained template candidate; or
- a quarantine record with stable reason codes.

Recipe conversion does not imply that a package builds, installs, runs on
Arach Kernel, or belongs in the live image. Those are separate Corinth and
Arach OS qualification gates.

## Non-goals

The initial ingress does not:

- claim full Arch or CachyOS binary-repository parity;
- execute `makepkg` or source a `PKGBUILD` on an installation host;
- replace Arach Kernel with `linux-cachyos`;
- admit floating branches, tags, dynamic `pkgver()`, unchecked downloads,
  install hooks, or unknown shell constructs;
- place package artifact URLs in `components.lock.toml`.

Arach OS pins the Arach-Packages and Corinth source authorities. Signed Corinth
indexes and generations bind package artifact URLs, digests, and monotonic
sequences.

## Authorities

| Authority | Owns |
|---|---|
| Pinned CachyOS mirror | Upstream PKGBUILD bytes and repository paths |
| Corinth static importer | Bounded assignment parsing and canonical recipe emission |
| Corinth compatibility worker | Declared-capability execution with repeated measured output |
| Arach-Packages | Canonical recipes, ingress records, quarantine records, policies, and examples |
| Corinth repository service | Signed indexes, dependency closure, journals, generations, and artifacts |
| Arach OS | Exact component revisions and composed release gates |

No authority may silently absorb another authority's role.

## Canonical artifacts

A successfully admitted package remains:

```text
recipes/CATEGORY/NAME/package.toml
```

The recipe uses format 1 and embeds every immutable source as `[[source]]`.
Corinth computes `source_lock_sha256` over that canonical source set. A second
`recipe.toml` or `sources.lock.toml` is not introduced.

Ingress provenance is separate from the recipe:

```text
ingress/cachyos/policy.toml
ingress/cachyos/snapshots/REVISION.toml
ingress/cachyos/classifications/UPSTREAM_PATH.toml
quarantine/cachyos/UPSTREAM_PATH.toml
```

This keeps import bookkeeping out of the signed package schema while retaining
which upstream bytes produced each decision.

## Admission classes

### `static`

The bounded Corinth parser accepts the metadata and all sources are immutable.
Build commands and outputs come from a separately signed target policy. No
PKGBUILD function body is executed.

### `meta`

The package is a source-less capability or dependency bundle. It emits a
canonical `build.system = "meta"` recipe with no build commands or outputs.

### `sealed-script`

The package requires `prepare()`, `build()`, `check()`, `package()`, or another
reviewed build function. It cannot enter the native recipe path merely because
a script file was hashed. Admission requires:

1. a Corinth `WorkerRequest` with immutable inputs, pinned tools, declared
   outputs, denied or fixed-output network access, and bounded resources;
2. at least two byte-identical worker runs;
3. measured output evidence;
4. a newly emitted canonical recipe whose source and output identities match
   the worker evidence.

Sealed scripts run only in a builder. They are never target-install scripts.

### `template`

The package belongs to a policy-heavy family requiring a reviewed generator or
configuration matrix. CachyOS kernel packages are templates by default; they
are never automatically promoted into the Arach boot-kernel authority.

### `rejected`

The input cannot be safely represented. It receives a quarantine record and
one or more stable reason codes. Unknown syntax is rejected rather than
best-effort translated.

## Stable reason codes

The first policy vocabulary is:

- `DYNAMIC_PKGVER`
- `EVAL`
- `FLOATING_VCS`
- `INSTALL_HOOK`
- `MISSING_CHECKSUM`
- `PACMAN_HOOK`
- `SHELL_SUBSTITUTION`
- `SPLIT_PACKAGE`
- `UNPARSED_FUNCTION`
- `UNSUPPORTED_ARCHITECTURE`
- `UNSUPPORTED_SOURCE`
- `UNSUPPORTED_SYNTAX`
- `KERNEL_TEMPLATE`

New codes require a policy-format revision. Existing meanings cannot be
silently reused.

## Snapshot invariant

For mirror revision `S`, every discovered `PKGBUILD` path must appear exactly
once in the snapshot manifest and exactly once as either:

- an admitted or candidate classification bound to `S` and the SHA-256 of the
  PKGBUILD bytes; or
- a quarantine record bound to the same values.

No path may disappear between inventory and classification. Duplicate paths,
symbolic revisions, symlink traversal, and records from another revision fail
the gate.

## Deterministic emission

Given identical:

- upstream repository URL;
- full upstream commit;
- repository-relative PKGBUILD path and bytes;
- signed target policy; and
- importer revision,

Corinth must emit byte-identical recipe bytes and identical metadata and source
lock digests. Timestamps are excluded from canonical recipe bytes.

## CI gates

Arach-Packages must enforce:

1. ingress policy and snapshot schema validation;
2. complete path coverage for snapshots marked `classified`;
3. immutable source pins in every admitted recipe;
4. deterministic classification and recipe-emission golden fixtures;
5. stable quarantine reason codes;
6. no `rejected` record presented as an admitted recipe;
7. measured compatibility-worker evidence for `sealed-script` promotion;
8. dependency graph closure before a recipe is production-qualified;
9. monotonic recipe release numbers; and
10. exact Corinth importer revision binding.

## Phased implementation

1. Freeze policy, mapping, dependency-atom, and kernel-overlay documents.
2. Pin a CachyOS mirror revision and inventory every PKGBUILD path.
3. Add classification and quarantine output to the existing Corinth importer.
4. Prove deterministic output with golden fixtures.
5. Normalize dependency atoms into exact Corinth constraints and capabilities.
6. Add the measured compatibility-worker promotion path.
7. Classify the complete pinned tree.
8. Admit a narrow seed closure and build it through Corinth.
9. Publish signed generations without overwriting prior sequences.
10. Repeat from a new mirror commit and retain the prior snapshot.

## Definition of done

“Every CachyOS PKGBUILD converted” means every path at a named mirror commit
has an admitted recipe, a measured candidate, a template record, or a
quarantine record, and CI proves complete one-to-one coverage.

It does not mean every package builds, runs natively, or ships in Arach OS.
