//! Strict validation for Arach package recipes and upstream source locks.

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const RECIPE_FORMAT: u32 = 1;
pub const COSMIC_LOCK_FORMAT: u32 = 1;

pub const COSMIC_REQUIRED_COMPONENTS: &[&str] = &[
    "cosmic-applets",
    "cosmic-applibrary",
    "cosmic-bg",
    "cosmic-comp",
    "cosmic-edit",
    "cosmic-files",
    "cosmic-greeter",
    "cosmic-icons",
    "cosmic-idle",
    "cosmic-initial-setup",
    "cosmic-launcher",
    "cosmic-monitor",
    "cosmic-notifications",
    "cosmic-osd",
    "cosmic-panel",
    "cosmic-player",
    "cosmic-randr",
    "cosmic-screenshot",
    "cosmic-session",
    "cosmic-settings",
    "cosmic-settings-daemon",
    "cosmic-sound-theme",
    "cosmic-store",
    "cosmic-term",
    "cosmic-wallpapers",
    "cosmic-workspaces-epoch",
    "pop-launcher",
    "xdg-desktop-portal-cosmic",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Recipe {
    pub format: u32,
    pub package: Package,
    #[serde(default)]
    pub source: Vec<Source>,
    pub build: Build,
    #[serde(default)]
    pub runtime: Runtime,
    pub policy: Policy,
    pub hardware: Option<Hardware>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub release: u32,
    pub summary: String,
    pub license: String,
    pub scope: PackageScope,
    pub publish_authority: PublishAuthority,
    pub architectures: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum PackageScope {
    User,
    System,
    Driver,
    Firmware,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum PublishAuthority {
    ArachNative,
    ArachHardware,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub kind: SourceKind,
    pub url: Option<String>,
    pub revision: Option<String>,
    pub checksum: Option<String>,
    pub package: Option<String>,
    pub version: Option<String>,
    #[serde(default)]
    pub submodules: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    Git,
    Archive,
    CratesIo,
    Local,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Build {
    pub system: BuildSystem,
    #[serde(default)]
    pub depends: Vec<String>,
    #[serde(default)]
    pub commands: Vec<String>,
    #[serde(default)]
    pub outputs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum BuildSystem {
    Cargo,
    #[serde(rename = "c")]
    C,
    Fortran,
    Idris2,
    Agda,
    Make,
    Meson,
    Cmake,
    Custom,
    Meta,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Runtime {
    #[serde(default)]
    pub depends: Vec<String>,
    #[serde(default)]
    pub provides: Vec<String>,
    #[serde(default)]
    pub conflicts: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub network: bool,
    pub sandbox: bool,
    pub reproducible: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Hardware {
    pub matches: Vec<String>,
    pub driver_abi_min: String,
    pub driver_abi_max: String,
    pub health_checks: Vec<String>,
    pub rollback: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CosmicLock {
    pub format: u32,
    pub upstream: CosmicUpstream,
    pub component: Vec<CosmicComponent>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CosmicUpstream {
    pub repository: String,
    pub revision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CosmicComponent {
    pub name: String,
    pub repository: String,
    pub revision: String,
    pub required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationError {
    pub path: String,
    pub message: String,
}

impl ValidationError {
    fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

impl std::error::Error for ValidationError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationReport {
    pub recipes: usize,
    pub locks: usize,
    pub cosmic_components: usize,
}

pub fn parse_recipe(text: &str) -> Result<Recipe, ValidationError> {
    toml::from_str(text).map_err(|error| ValidationError::new("recipe", error.to_string()))
}

pub fn validate_recipe(recipe: &Recipe) -> Result<(), ValidationError> {
    if recipe.format != RECIPE_FORMAT {
        return Err(ValidationError::new("format", "unsupported recipe format"));
    }
    validate_name("package.name", &recipe.package.name)?;
    require_text("package.version", &recipe.package.version)?;
    if recipe.package.release == 0 {
        return Err(ValidationError::new(
            "package.release",
            "release must be greater than zero",
        ));
    }
    require_text("package.summary", &recipe.package.summary)?;
    require_text("package.license", &recipe.package.license)?;
    validate_authority(recipe.package.scope, recipe.package.publish_authority)?;
    validate_unique_names("package.architectures", &recipe.package.architectures)?;

    if recipe.source.is_empty() && recipe.build.system != BuildSystem::Meta {
        return Err(ValidationError::new(
            "source",
            "non-meta packages require at least one locked source",
        ));
    }
    for (index, source) in recipe.source.iter().enumerate() {
        validate_source(index, source)?;
    }

    if recipe.build.system == BuildSystem::Meta {
        if !recipe.build.commands.is_empty() || !recipe.build.outputs.is_empty() {
            return Err(ValidationError::new(
                "build",
                "meta packages cannot run build commands or publish files",
            ));
        }
    } else {
        if recipe.build.commands.is_empty() {
            return Err(ValidationError::new(
                "build.commands",
                "build commands cannot be empty",
            ));
        }
        if recipe.build.outputs.is_empty() {
            return Err(ValidationError::new(
                "build.outputs",
                "build outputs cannot be empty",
            ));
        }
    }
    validate_nonempty_strings("build.commands", &recipe.build.commands, true)?;
    validate_nonempty_strings("build.outputs", &recipe.build.outputs, true)?;
    validate_unique_names("build.depends", &recipe.build.depends)?;
    validate_build_commands(&recipe.build)?;
    validate_unique_names("runtime.depends", &recipe.runtime.depends)?;
    validate_unique_names("runtime.provides", &recipe.runtime.provides)?;
    validate_unique_names("runtime.conflicts", &recipe.runtime.conflicts)?;

    if recipe.policy.network {
        return Err(ValidationError::new(
            "policy.network",
            "builds must use pre-fetched locked sources",
        ));
    }
    if !recipe.policy.sandbox || !recipe.policy.reproducible {
        return Err(ValidationError::new(
            "policy",
            "sandbox and reproducible must both be enabled",
        ));
    }

    match recipe.package.scope {
        PackageScope::Driver | PackageScope::Firmware => {
            let hardware = recipe.hardware.as_ref().ok_or_else(|| {
                ValidationError::new(
                    "hardware",
                    "driver and firmware recipes require hardware policy",
                )
            })?;
            validate_hardware(hardware)?;
        }
        PackageScope::User | PackageScope::System => {
            if recipe.hardware.is_some() {
                return Err(ValidationError::new(
                    "hardware",
                    "hardware policy is reserved for driver and firmware scopes",
                ));
            }
        }
    }
    Ok(())
}

pub fn parse_cosmic_lock(text: &str) -> Result<CosmicLock, ValidationError> {
    toml::from_str(text).map_err(|error| ValidationError::new("cosmic-lock", error.to_string()))
}

pub fn validate_cosmic_lock(lock: &CosmicLock) -> Result<(), ValidationError> {
    if lock.format != COSMIC_LOCK_FORMAT {
        return Err(ValidationError::new("format", "unsupported lock format"));
    }
    validate_https_url("upstream.repository", &lock.upstream.repository)?;
    validate_git_revision("upstream.revision", &lock.upstream.revision)?;

    let expected: BTreeSet<&str> = COSMIC_REQUIRED_COMPONENTS.iter().copied().collect();
    let mut actual = BTreeSet::new();
    for (index, component) in lock.component.iter().enumerate() {
        validate_name(&format!("component[{index}].name"), &component.name)?;
        if !actual.insert(component.name.as_str()) {
            return Err(ValidationError::new(
                format!("component[{index}].name"),
                "duplicate COSMIC component",
            ));
        }
        validate_https_url(
            &format!("component[{index}].repository"),
            &component.repository,
        )?;
        validate_git_revision(&format!("component[{index}].revision"), &component.revision)?;
        if !component.required {
            return Err(ValidationError::new(
                format!("component[{index}].required"),
                "the full desktop lock cannot contain optional components",
            ));
        }
    }
    if actual != expected {
        let missing: Vec<_> = expected.difference(&actual).copied().collect();
        let extra: Vec<_> = actual.difference(&expected).copied().collect();
        return Err(ValidationError::new(
            "component",
            format!("COSMIC component set differs; missing={missing:?}, extra={extra:?}"),
        ));
    }
    Ok(())
}

pub fn verify_cosmic_repository(
    lock: &CosmicLock,
    repository: &Path,
) -> Result<usize, ValidationError> {
    validate_cosmic_lock(lock)?;
    let revision = git_output(repository, &["rev-parse", "HEAD"])?;
    if revision.trim() != lock.upstream.revision {
        return Err(ValidationError::new(
            "upstream.revision",
            "checked-out COSMIC repository does not match the lock",
        ));
    }

    let tree = git_output(repository, &["ls-tree", "HEAD"])?;
    let mut gitlinks = BTreeMap::new();
    for line in tree.lines() {
        let Some((metadata, name)) = line.split_once('\t') else {
            continue;
        };
        let mut fields = metadata.split_whitespace();
        let mode = fields.next();
        let kind = fields.next();
        let revision = fields.next();
        if mode == Some("160000") && kind == Some("commit") {
            let revision = revision.ok_or_else(|| {
                ValidationError::new("upstream.tree", "gitlink revision is missing")
            })?;
            gitlinks.insert(name.to_owned(), revision.to_owned());
        }
    }

    let modules = git_output(repository, &["show", "HEAD:.gitmodules"])?;
    let urls = parse_gitmodules(&modules);
    let expected: BTreeMap<_, _> = lock
        .component
        .iter()
        .map(|component| (component.name.clone(), component.revision.clone()))
        .collect();
    if gitlinks != expected {
        return Err(ValidationError::new(
            "component",
            "locked COSMIC components do not match upstream gitlinks",
        ));
    }
    for component in &lock.component {
        let upstream_url = urls.get(&component.name).ok_or_else(|| {
            ValidationError::new(
                format!("component.{}.repository", component.name),
                "component has no upstream submodule URL",
            )
        })?;
        if normalize_repository_url(upstream_url) != normalize_repository_url(&component.repository)
        {
            return Err(ValidationError::new(
                format!("component.{}.repository", component.name),
                "locked repository differs from the upstream submodule URL",
            ));
        }
    }
    Ok(gitlinks.len())
}

pub fn validate_tree(root: &Path) -> Result<ValidationReport, ValidationError> {
    let recipe_dir = root.join("recipes");
    let lock_dir = root.join("locks");
    let mut package_paths = Vec::new();
    collect_named_files(&recipe_dir, "package.toml", &mut package_paths)?;
    package_paths.sort();
    if package_paths.is_empty() {
        return Err(ValidationError::new("recipes", "no package recipes found"));
    }

    let mut package_names = BTreeMap::new();
    let mut recipes = Vec::new();
    for path in &package_paths {
        let text = read(path)?;
        let recipe = parse_recipe(&text).map_err(|error| at_file(path, error))?;
        validate_recipe(&recipe).map_err(|error| at_file(path, error))?;
        if let Some(previous) = package_names.insert(recipe.package.name.clone(), path.clone()) {
            return Err(ValidationError::new(
                display(path),
                format!(
                    "duplicate package name also declared by {}",
                    previous.display()
                ),
            ));
        }
        recipes.push((path.clone(), recipe));
    }
    validate_dependency_graph(&recipes)?;

    let cosmic_path = lock_dir.join("cosmic-epoch.toml");
    let cosmic_text = read(&cosmic_path)?;
    let cosmic = parse_cosmic_lock(&cosmic_text).map_err(|error| at_file(&cosmic_path, error))?;
    validate_cosmic_lock(&cosmic).map_err(|error| at_file(&cosmic_path, error))?;

    Ok(ValidationReport {
        recipes: package_paths.len(),
        locks: 1,
        cosmic_components: cosmic.component.len(),
    })
}

fn validate_dependency_graph(recipes: &[(PathBuf, Recipe)]) -> Result<(), ValidationError> {
    let mut providers = BTreeMap::<String, String>::new();
    for (_, recipe) in recipes {
        providers.insert(recipe.package.name.clone(), recipe.package.name.clone());
    }
    for (path, recipe) in recipes {
        for capability in &recipe.runtime.provides {
            if let Some(previous) = providers.get(capability) {
                if previous != &recipe.package.name {
                    return Err(ValidationError::new(
                        display(path),
                        format!(
                            "runtime capability {capability} is already provided by {previous}"
                        ),
                    ));
                }
            } else {
                providers.insert(capability.clone(), recipe.package.name.clone());
            }
        }
    }

    let mut dependencies = BTreeMap::<String, BTreeSet<String>>::new();
    for (path, recipe) in recipes {
        let package = &recipe.package.name;
        let mut resolved = BTreeSet::new();
        for dependency in &recipe.runtime.depends {
            let provider = providers.get(dependency).ok_or_else(|| {
                ValidationError::new(
                    display(path),
                    format!(
                        "runtime dependency {dependency} has no package or capability provider"
                    ),
                )
            })?;
            if provider == package {
                return Err(ValidationError::new(
                    display(path),
                    format!("runtime dependency {dependency} resolves to the package itself"),
                ));
            }
            resolved.insert(provider.clone());
        }
        dependencies.insert(package.clone(), resolved);
    }

    while let Some(ready) = dependencies
        .iter()
        .find_map(|(package, required)| required.is_empty().then(|| package.clone()))
    {
        dependencies.remove(&ready);
        for required in dependencies.values_mut() {
            required.remove(&ready);
        }
    }
    if !dependencies.is_empty() {
        return Err(ValidationError::new(
            "runtime.depends",
            format!(
                "dependency cycle among {:?}",
                dependencies.keys().collect::<Vec<_>>()
            ),
        ));
    }
    Ok(())
}

fn validate_authority(
    scope: PackageScope,
    authority: PublishAuthority,
) -> Result<(), ValidationError> {
    let valid = match scope {
        PackageScope::User | PackageScope::System => authority == PublishAuthority::ArachNative,
        PackageScope::Driver | PackageScope::Firmware => {
            authority == PublishAuthority::ArachHardware
        }
    };
    if valid {
        Ok(())
    } else {
        Err(ValidationError::new(
            "package.publish_authority",
            "publish authority is forbidden for this package scope",
        ))
    }
}

fn validate_source(index: usize, source: &Source) -> Result<(), ValidationError> {
    let base = format!("source[{index}]");
    match source.kind {
        SourceKind::Git => {
            let url = source.url.as_deref().ok_or_else(|| {
                ValidationError::new(format!("{base}.url"), "Git source requires URL")
            })?;
            validate_https_url(&format!("{base}.url"), url)?;
            let revision = source.revision.as_deref().ok_or_else(|| {
                ValidationError::new(
                    format!("{base}.revision"),
                    "Git source requires full revision",
                )
            })?;
            validate_git_revision(&format!("{base}.revision"), revision)?;
            reject_present(&base, "checksum", source.checksum.as_ref())?;
            reject_present(&base, "package", source.package.as_ref())?;
            reject_present(&base, "version", source.version.as_ref())?;
        }
        SourceKind::Archive => {
            let url = source.url.as_deref().ok_or_else(|| {
                ValidationError::new(format!("{base}.url"), "archive source requires URL")
            })?;
            validate_https_url(&format!("{base}.url"), url)?;
            validate_checksum_option(&format!("{base}.checksum"), source.checksum.as_deref())?;
            reject_present(&base, "revision", source.revision.as_ref())?;
            reject_present(&base, "package", source.package.as_ref())?;
            reject_present(&base, "version", source.version.as_ref())?;
        }
        SourceKind::CratesIo => {
            let package = source.package.as_deref().ok_or_else(|| {
                ValidationError::new(
                    format!("{base}.package"),
                    "crates.io source requires package name",
                )
            })?;
            validate_name(&format!("{base}.package"), package)?;
            let version = source.version.as_deref().ok_or_else(|| {
                ValidationError::new(
                    format!("{base}.version"),
                    "crates.io source requires exact version",
                )
            })?;
            if version.trim().is_empty()
                || version.contains('*')
                || version.contains('^')
                || version.contains('~')
            {
                return Err(ValidationError::new(
                    format!("{base}.version"),
                    "version requirements are not immutable versions",
                ));
            }
            validate_checksum_option(&format!("{base}.checksum"), source.checksum.as_deref())?;
            reject_present(&base, "url", source.url.as_ref())?;
            reject_present(&base, "revision", source.revision.as_ref())?;
        }
        SourceKind::Local => {
            let url = source.url.as_deref().ok_or_else(|| {
                ValidationError::new(format!("{base}.url"), "local source requires path")
            })?;
            if url.is_empty() || Path::new(url).is_absolute() || url.contains("..") {
                return Err(ValidationError::new(
                    format!("{base}.url"),
                    "local source must be a repository-relative path",
                ));
            }
            validate_checksum_option(&format!("{base}.checksum"), source.checksum.as_deref())?;
            reject_present(&base, "revision", source.revision.as_ref())?;
            reject_present(&base, "package", source.package.as_ref())?;
            reject_present(&base, "version", source.version.as_ref())?;
        }
    }
    if source.kind != SourceKind::Git && source.submodules {
        return Err(ValidationError::new(
            format!("{base}.submodules"),
            "only Git sources may request submodules",
        ));
    }
    Ok(())
}

fn validate_build_commands(build: &Build) -> Result<(), ValidationError> {
    if build.system == BuildSystem::Meta {
        return Ok(());
    }
    for (index, command) in build.commands.iter().enumerate() {
        let path = format!("build.commands[{index}]");
        if command.bytes().any(|byte| {
            matches!(
                byte,
                b';' | b'|'
                    | b'&'
                    | b'>'
                    | b'<'
                    | b'$'
                    | b'`'
                    | b'('
                    | b')'
                    | b'{'
                    | b'}'
                    | b'*'
                    | b'?'
                    | b'\\'
            )
        }) {
            return Err(ValidationError::new(path, "shell syntax is forbidden"));
        }
        let Some(program) = command.split_ascii_whitespace().next() else {
            return Err(ValidationError::new(path, "command cannot be empty"));
        };
        let allowed = match build.system {
            BuildSystem::Cargo => matches!(program, "cargo" | "rustc"),
            BuildSystem::C => matches!(program, "cc" | "gcc" | "clang" | "make"),
            BuildSystem::Fortran => matches!(program, "gfortran" | "flang" | "make"),
            BuildSystem::Idris2 => matches!(program, "idris2" | "make"),
            BuildSystem::Agda => matches!(program, "agda" | "make"),
            BuildSystem::Make => program == "make",
            BuildSystem::Meson => matches!(program, "meson" | "ninja"),
            BuildSystem::Cmake => matches!(program, "cmake" | "make"),
            BuildSystem::Custom => matches!(
                program,
                "cargo"
                    | "rustc"
                    | "cc"
                    | "gcc"
                    | "clang"
                    | "gfortran"
                    | "flang"
                    | "idris2"
                    | "agda"
                    | "make"
                    | "cmake"
                    | "meson"
                    | "ninja"
            ),
            BuildSystem::Meta => false,
        };
        if !allowed {
            return Err(ValidationError::new(
                path,
                "program is not allowed by build.system",
            ));
        }
    }
    Ok(())
}

fn validate_hardware(hardware: &Hardware) -> Result<(), ValidationError> {
    validate_nonempty_strings("hardware.matches", &hardware.matches, false)?;
    require_text("hardware.driver_abi_min", &hardware.driver_abi_min)?;
    require_text("hardware.driver_abi_max", &hardware.driver_abi_max)?;
    validate_nonempty_strings("hardware.health_checks", &hardware.health_checks, false)?;
    require_text("hardware.rollback", &hardware.rollback)
}

fn validate_name(path: &str, value: &str) -> Result<(), ValidationError> {
    let bytes = value.as_bytes();
    let valid = !bytes.is_empty()
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-');
    if valid {
        Ok(())
    } else {
        Err(ValidationError::new(
            path,
            "must use lowercase ASCII letters, digits, and interior hyphens",
        ))
    }
}

fn validate_https_url(path: &str, value: &str) -> Result<(), ValidationError> {
    if value.starts_with("https://") && !value.contains(char::is_whitespace) {
        Ok(())
    } else {
        Err(ValidationError::new(path, "must be an HTTPS URL"))
    }
}

fn validate_git_revision(path: &str, value: &str) -> Result<(), ValidationError> {
    if value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ValidationError::new(
            path,
            "must be a full 40-character Git object ID",
        ))
    }
}

fn validate_checksum_option(path: &str, value: Option<&str>) -> Result<(), ValidationError> {
    let value = value.ok_or_else(|| ValidationError::new(path, "SHA-256 checksum required"))?;
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ValidationError::new(
            path,
            "checksum must contain 64 hexadecimal characters",
        ))
    }
}

fn require_text(path: &str, value: &str) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        Err(ValidationError::new(path, "cannot be empty"))
    } else {
        Ok(())
    }
}

fn validate_nonempty_strings(
    path: &str,
    values: &[String],
    allow_empty_list: bool,
) -> Result<(), ValidationError> {
    if values.is_empty() {
        return if allow_empty_list {
            Ok(())
        } else {
            Err(ValidationError::new(path, "cannot be empty"))
        };
    }
    for (index, value) in values.iter().enumerate() {
        require_text(&format!("{path}[{index}]"), value)?;
    }
    Ok(())
}

fn validate_unique_names(path: &str, values: &[String]) -> Result<(), ValidationError> {
    if values.is_empty() {
        if path == "package.architectures" {
            return Err(ValidationError::new(path, "cannot be empty"));
        }
        return Ok(());
    }
    let mut seen = BTreeSet::new();
    for (index, value) in values.iter().enumerate() {
        validate_name(&format!("{path}[{index}]"), value)?;
        if !seen.insert(value) {
            return Err(ValidationError::new(
                format!("{path}[{index}]"),
                "duplicate value",
            ));
        }
    }
    Ok(())
}

fn reject_present<T>(base: &str, name: &str, value: Option<&T>) -> Result<(), ValidationError> {
    if value.is_some() {
        Err(ValidationError::new(
            format!("{base}.{name}"),
            "field is invalid for this source kind",
        ))
    } else {
        Ok(())
    }
}

fn collect_named_files(
    directory: &Path,
    name: &str,
    output: &mut Vec<PathBuf>,
) -> Result<(), ValidationError> {
    let entries = fs::read_dir(directory)
        .map_err(|error| ValidationError::new(display(directory), error.to_string()))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| ValidationError::new(display(directory), error.to_string()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_named_files(&path, name, output)?;
        } else if path.file_name().is_some_and(|candidate| candidate == name) {
            output.push(path);
        }
    }
    Ok(())
}

fn read(path: &Path) -> Result<String, ValidationError> {
    fs::read_to_string(path).map_err(|error| ValidationError::new(display(path), error.to_string()))
}

fn git_output(repository: &Path, arguments: &[&str]) -> Result<String, ValidationError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .output()
        .map_err(|error| ValidationError::new("upstream.git", error.to_string()))?;
    if !output.status.success() {
        return Err(ValidationError::new(
            "upstream.git",
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| ValidationError::new("upstream.git", error.to_string()))
}

fn parse_gitmodules(text: &str) -> BTreeMap<String, String> {
    let mut output = BTreeMap::new();
    let mut path: Option<String> = None;
    let mut url: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            if let (Some(path), Some(url)) = (path.take(), url.take()) {
                output.insert(path, url);
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim() {
            "path" => path = Some(value.trim().to_owned()),
            "url" => url = Some(value.trim().to_owned()),
            _ => {}
        }
    }
    if let (Some(path), Some(url)) = (path, url) {
        output.insert(path, url);
    }
    output
}

fn normalize_repository_url(value: &str) -> &str {
    value.trim_end_matches('/').trim_end_matches(".git")
}

fn at_file(path: &Path, error: ValidationError) -> ValidationError {
    ValidationError::new(format!("{}:{}", display(path), error.path), error.message)
}

fn display(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_recipe() -> Recipe {
        Recipe {
            format: RECIPE_FORMAT,
            package: Package {
                name: "example-system".into(),
                version: "1.0.0".into(),
                release: 1,
                summary: "Example".into(),
                license: "MIT".into(),
                scope: PackageScope::System,
                publish_authority: PublishAuthority::ArachNative,
                architectures: vec!["x86-64".into()],
            },
            source: vec![Source {
                kind: SourceKind::Git,
                url: Some("https://example.invalid/source.git".into()),
                revision: Some("0123456789abcdef0123456789abcdef01234567".into()),
                checksum: None,
                package: None,
                version: None,
                submodules: false,
            }],
            build: Build {
                system: BuildSystem::Cargo,
                depends: Vec::new(),
                commands: vec!["cargo build --release --locked".into()],
                outputs: vec!["target/release/example".into()],
            },
            runtime: Runtime::default(),
            policy: Policy {
                network: false,
                sandbox: true,
                reproducible: true,
            },
            hardware: None,
        }
    }

    #[test]
    fn valid_system_recipe_is_admitted() {
        assert_eq!(validate_recipe(&valid_recipe()), Ok(()));
    }

    #[test]
    fn system_recipe_cannot_publish_as_hardware() {
        let mut recipe = valid_recipe();
        recipe.package.publish_authority = PublishAuthority::ArachHardware;
        assert_eq!(
            validate_recipe(&recipe).unwrap_err().path,
            "package.publish_authority"
        );
    }

    #[test]
    fn symbolic_git_revision_is_rejected() {
        let mut recipe = valid_recipe();
        recipe.source[0].revision = Some("main".into());
        assert_eq!(
            validate_recipe(&recipe).unwrap_err().path,
            "source[0].revision"
        );
    }

    #[test]
    fn driver_recipe_requires_hardware_policy() {
        let mut recipe = valid_recipe();
        recipe.package.scope = PackageScope::Driver;
        recipe.package.publish_authority = PublishAuthority::ArachHardware;
        assert_eq!(validate_recipe(&recipe).unwrap_err().path, "hardware");
    }

    #[test]
    fn repository_tree_is_valid() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let report = validate_tree(root).expect("repository must validate");
        assert!(report.recipes >= 5);
        assert_eq!(report.locks, 1);
        assert_eq!(report.cosmic_components, COSMIC_REQUIRED_COMPONENTS.len());
    }

    #[test]
    fn gitmodule_paths_map_to_normalized_urls() {
        let modules = r#"
            [submodule "example"]
                path = cosmic-example
                url = https://example.invalid/cosmic-example.git
        "#;
        let parsed = parse_gitmodules(modules);
        assert_eq!(
            normalize_repository_url(&parsed["cosmic-example"]),
            "https://example.invalid/cosmic-example"
        );
    }

    #[test]
    fn unresolved_runtime_dependency_is_rejected() {
        let mut recipe = valid_recipe();
        recipe.runtime.depends = vec!["missing-capability".into()];
        let recipes = vec![(PathBuf::from("example.toml"), recipe)];
        let error = validate_dependency_graph(&recipes).unwrap_err();
        assert!(
            error
                .message
                .contains("has no package or capability provider")
        );
    }

    #[test]
    fn runtime_dependency_cycle_is_rejected() {
        let mut first = valid_recipe();
        first.package.name = "first-package".into();
        first.runtime.depends = vec!["second-package".into()];
        let mut second = valid_recipe();
        second.package.name = "second-package".into();
        second.runtime.depends = vec!["first-package".into()];
        let recipes = vec![
            (PathBuf::from("first.toml"), first),
            (PathBuf::from("second.toml"), second),
        ];
        assert_eq!(
            validate_dependency_graph(&recipes).unwrap_err().path,
            "runtime.depends"
        );
    }
}
