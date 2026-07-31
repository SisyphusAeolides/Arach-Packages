# Arach hardware repository contract

Arach-HWD is the authority for hardware identity.  A profile binds a stable
bus/modalias identity to a driver or firmware package, its Arach Driver ABI
range, metadata digest, artifact digest, source-lock digest, health checks, and
rollback policy.  Corinth installs an intent only after the profile and the
package record have both been verified.

Hardware recipes belong under `recipes/` and must use the strict Corinth
recipe format.  Driver and firmware recipes must declare `scope = "driver"`
or `scope = "firmware"`, `publish_authority = "arach-hardware"`,
`policy.sandbox = true`, `policy.reproducible = true`, and the single measured
output `@install-tree`.  The output tree contains only regular files destined
for the target root (for example kernel modules, firmware, or a signed helper);
it must not contain post-install scripts, device nodes, or symlinks.

Prebuilt artifacts are published in a separately signed `packages.toml` index
with one record per package.  The index is keyed by exact package name,
version, release, metadata digest, artifact digest, and source-lock digest.
The release builder creates that index from the measured payload and signs it
with the `package-index` key; the private signing key never enters this
repository.  The same profile can therefore use a prebuilt payload during a
networked or offline install, or fall back to the pinned source recipe when no
matching binary is available.

Do not add a guessed package name for an unrecognized PCI, USB, I2C, ACPI, or
class device.  Add a signed profile and its exact recipe/index record instead.
This is what lets the catalog grow to new Wi-Fi, audio, graphics, storage,
Bluetooth, input, and firmware devices without making an installation
non-reproducible.
