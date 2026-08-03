use arach_package_lint::{BuildSystem, PackageScope, parse_recipe, validate_recipe};

fn recipe(text: &str) -> arach_package_lint::Recipe {
    let value = parse_recipe(text).expect("promoted recipe must parse");
    validate_recipe(&value).expect("promoted recipe must satisfy the canonical schema");
    value
}

#[test]
fn gaming_applications_is_source_less_user_meta() {
    let value = recipe(include_str!(
        "../ingress/cachyos/promoted/cachyos-gaming-applications/package.toml"
    ));
    assert_eq!(value.package.name, "cachyos-gaming-applications");
    assert_eq!(value.package.scope, PackageScope::User);
    assert_eq!(value.build.system, BuildSystem::Meta);
    assert!(value.source.is_empty());
    assert!(value.build.commands.is_empty());
    assert!(value.build.outputs.is_empty());
    assert_eq!(value.runtime.depends.len(), 10);
}

#[test]
fn zfs_meta_is_source_less_system_capability_bundle() {
    let value = recipe(include_str!(
        "../ingress/cachyos/promoted/zfs-meta/package.toml"
    ));
    assert_eq!(value.package.name, "zfs-meta");
    assert_eq!(value.package.scope, PackageScope::System);
    assert_eq!(value.build.system, BuildSystem::Meta);
    assert!(value.source.is_empty());
    assert_eq!(value.runtime.depends, ["zfs-module", "zfs-utils"]);
    assert_eq!(value.runtime.provides, ["zfs"]);
}
