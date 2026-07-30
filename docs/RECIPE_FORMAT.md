# Recipe format version 1

Each recipe is stored as recipes/CATEGORY/NAME/package.toml and has six
responsibilities:

1. identify one package, architecture set, license, scope, and publishing
   authority;
2. lock every source to a full Git object ID or SHA-256 digest;
3. declare deterministic build commands, build dependencies, and output paths;
4. define runtime dependencies, capabilities, and conflicts;
5. require an offline sandboxed reproducible build;
6. attach hardware matches, ABI bounds, health checks, and rollback behavior
   to every driver or firmware package.

System and user packages may only be published by arach-native. Driver and
firmware packages may only be published by arach-hardware. A recipe records
the intended authority, but the build service must still sign the repository
metadata and artifact before Corinth admits an installation.

Git branch and tag names are forbidden because they can move. Archive,
crates.io, and local sources require a full SHA-256 checksum. Local paths must
remain inside the repository. Network access is forbidden during the build;
all sources and dependency registries are fetched and measured before entering
the builder.

Every runtime dependency must resolve to exactly one package name or provided
capability in this repository. Self-dependencies, duplicate capability
providers, unresolved dependencies, and dependency cycles fail validation.

The COSMIC lock records the exact upstream integration revision and all 28
gitlink revisions that upstream tested together. The `cosmic-desktop` recipe
binds that lock to one native workspace build: it checks out every submodule,
uses only the fixed `just build`/`just install` adapter, and publishes a
bounded install tree. Corinth measures that tree before staging it; no
unlocked component recipe can silently replace one of the pinned gitlinks.
