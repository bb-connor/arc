//! Schema-to-Rust codegen for the Chio wire protocol.
//!
//! This crate is the Rust half of the four-language codegen pipeline gated by
//! `cargo xtask codegen` (see `xtask/codegen-tools.lock.toml` for the pinned
//! tool set per language). It walks
//! `spec/schemas/chio-wire/v1/**/*.schema.json`, parses each file as a
//! `schemars::schema::RootSchema`, registers every schema with a single
//! `typify::TypeSpace`, and emits one Rust source file per top-level schema
//! group (`agent/`, `capability/`, `error/`, ...). Each emitted file carries
//! the canonical `// DO NOT EDIT` header so downstream tooling and humans can
//! tell at a glance that the file is a regeneration target.
//!
//! # Output layout
//!
//! For an input tree like
//!
//! ```text
//! spec/schemas/chio-wire/v1/
//!   agent/heartbeat.schema.json
//!   agent/list_capabilities.schema.json
//!   jsonrpc/request.schema.json
//!   ...
//! ```
//!
//! the generator produces:
//!
//! ```text
//! crates/core/chio-core-types/src/_generated/
//!   chio_wire_v1.rs   (one module per unreferenced root schema)
//!   mod.rs            (header-only module marker; not pulled into lib.rs yet)
//! ```
//!
//! The single-file emission keeps downstream consumers pointing at one
//! well-known file.
//!
//! # Header policy
//!
//! Every regenerated file begins with [`GENERATED_HEADER`]. The companion
//! `crates/core/chio-core-types/tests/_generated_check.rs` integration test scans
//! every `*.rs` file under `_generated/` and fails the build if any file is
//! missing the header.
//!
//! # Determinism
//!
//! Schema files are sorted lexicographically before being added to the
//! `TypeSpace`, and the resulting token stream is fed through `prettyplease`
//! so the byte output is reproducible across machines. The xtask
//! `codegen --check` mode compares the freshly regenerated output against the
//! on-disk file and exits non-zero on drift.
//!
//! # House rules
//!
//! - No `unwrap()` / `expect()` in non-test code (workspace clippy denies).
//! - All errors are surfaced as [`CodegenError`]; the crate never panics on
//!   malformed input.
//! - Absolute URI `$ref`s fail closed before typify generation; Rust codegen
//!   only accepts internal fragments and local schema-tree references.
//! - No em dashes (U+2014); use `-` or parentheses.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use typify::{TypeSpace, TypeSpaceSettings};

mod duplicate_types;
mod errors_pass;
mod schema_catalog;
mod schema_docs;
mod shared_types;
pub use schema_catalog::LocalSchemaCatalog;
pub mod statemachines_pass;
pub mod threat_coverage_doc;
pub mod threat_model;

pub use errors_pass::{
    codegen_error_codes, render_error_codes, ERRORS_GENERATED_DIR, ERROR_CODES_OUTPUT,
    ERROR_REGISTRY_INPUT,
};
pub use statemachines_pass::{
    check_statemachine_outputs, codegen_statemachines, load_statemachines,
    render_statemachine_outputs, StateMachine, CONFORMANCE_ORDERING_DIR, STATEMACHINES_INPUT,
    STATE_MACHINES_DOC_OUTPUT,
};
pub use threat_coverage_doc::{
    codegen_threat_coverage_doc, codegen_threat_coverage_doc_default, render_threat_coverage_doc,
    ThreatCoverageInputs, ADVERSARIAL_MANIFEST, ESCAPE_HARNESS_DIR, THREAT_COVERAGE_DOC,
    THREAT_STUBS_DIR,
};
pub use threat_model::{
    codegen_threat_model, load_threat_model, render_threat_stub, render_threats_mod,
    validate_threat_model_against_schema, ThreatEntry, ThreatModelDoc, THREAT_MODEL_INPUT,
    THREAT_MODEL_SCHEMA, THREAT_STUBS_OUTPUT,
};

/// Canonical header stamped onto every regenerated Rust source file.
///
/// The phrasing is matched exactly by
/// `crates/core/chio-core-types/tests/_generated_check.rs`. Keep this string in
/// sync with that test and with `xtask::codegen` if either is updated.
pub const GENERATED_HEADER: &str = "\
// DO NOT EDIT - regenerate via 'make regen-rust' or 'cargo xtask codegen rust'.
//
// Source: spec/schemas/chio-wire/v1/**/*.schema.json
// Tool:   typify =0.4.3 (see xtask/codegen-tools.lock.toml)
// Crate:  chio-spec-codegen
//
// Manual edits will be overwritten by the next regeneration; the
// `_generated_check` integration test enforces this header on every file
// under `crates/core/chio-core-types/src/_generated/`.
";

/// File name for the consolidated chio-wire/v1 Rust output.
pub const CHIO_WIRE_V1_OUTPUT: &str = "chio_wire_v1.rs";

/// File name for the header-only module marker under `_generated/`.
pub const MOD_FILE: &str = "mod.rs";

/// Upper bound on the rendered chio-wire/v1 Rust bindings.
pub const MAX_CHIO_WIRE_V1_BYTES: usize = 9 * 1024 * 1024;

/// Errors raised by the codegen pipeline.
#[derive(Debug)]
pub enum CodegenError {
    /// Failed to read or write a file.
    Io(PathBuf, io::Error),
    /// A schema file did not parse as JSON.
    Json(PathBuf, serde_json::Error),
    /// A schema file parsed as JSON but not as a `schemars::RootSchema`.
    SchemaShape(PathBuf, serde_json::Error),
    /// `typify::TypeSpace::add_root_schema` rejected the schema.
    Typify(PathBuf, String),
    /// A local JSON Schema reference could not be resolved for typify.
    SchemaRef(PathBuf, String),
    /// The token stream emitted by typify did not parse as a `syn::File`.
    SynParse(syn::Error),
    /// `rustfmt` could not format generated Rust source.
    Rustfmt(PathBuf, String),
    /// The error registry YAML could not be loaded or validated.
    Registry(PathBuf, String),
    /// The schemas directory did not exist on disk.
    SchemasDirMissing(PathBuf),
    /// A state-machine table could not be loaded or validated.
    StateMachine(PathBuf, String),
    /// Committed state-machine outputs differ from regenerated bytes.
    GeneratedDrift(String),
    /// rustfmt rejected generated Rust source.
    Formatter(String),
    /// Two generated types have the same body.
    DuplicateTypes(String),
    /// The rendered bindings exceed [`MAX_CHIO_WIRE_V1_BYTES`].
    OutputTooLarge(usize),
}

impl fmt::Display for CodegenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "io error on {}: {err}", path.display()),
            Self::Json(path, err) => write!(f, "json parse error in {}: {err}", path.display()),
            Self::SchemaShape(path, err) => {
                write!(f, "schema shape error in {}: {err}", path.display())
            }
            Self::Typify(path, msg) => {
                write!(f, "typify rejected schema {}: {msg}", path.display())
            }
            Self::SchemaRef(path, msg) => {
                write!(f, "schema reference error in {}: {msg}", path.display())
            }
            Self::SynParse(err) => write!(f, "generated tokens did not parse: {err}"),
            Self::Rustfmt(path, msg) => {
                write!(f, "rustfmt failed for {}: {msg}", path.display())
            }
            Self::Registry(path, msg) => {
                write!(
                    f,
                    "error registry load failed for {}: {msg}",
                    path.display()
                )
            }
            Self::SchemasDirMissing(path) => {
                write!(f, "schemas directory does not exist: {}", path.display())
            }
            Self::StateMachine(path, msg) => {
                write!(f, "state machine error in {}: {msg}", path.display())
            }
            Self::GeneratedDrift(msg) => write!(f, "generated state machine drift: {msg}"),
            Self::Formatter(msg) => write!(f, "generated Rust formatting failed: {msg}"),
            Self::DuplicateTypes(msg) => {
                write!(f, "generated types with identical bodies: {msg}")
            }
            Self::OutputTooLarge(bytes) => write!(
                f,
                "generated chio-wire/v1 bindings are {bytes} bytes, over {MAX_CHIO_WIRE_V1_BYTES}"
            ),
        }
    }
}

impl std::error::Error for CodegenError {}

/// Result alias for the public API.
pub type Result<T> = core::result::Result<T, CodegenError>;

/// Generate Rust types from every schema under `schemas_dir` and write them
/// to `out_dir`.
///
/// This is the single entry point used by both the `chio-spec-codegen` binary
/// and `cargo xtask codegen rust`. The pipeline is:
///
/// 1. Walk `schemas_dir` recursively, collecting every `*.schema.json` file
///    in lexicographic order.
/// 2. Parse each file as `schemars::schema::RootSchema` and register it with
///    a shared `typify::TypeSpace`.
/// 3. Render the `TypeSpace` to a `proc_macro2::TokenStream`, parse it as a
///    `syn::File`, and pretty-print via `prettyplease`.
/// 4. Prepend [`GENERATED_HEADER`] and write to
///    `out_dir/CHIO_WIRE_V1_OUTPUT`.
/// 5. Refresh the header-only `out_dir/MOD_FILE` with [`GENERATED_HEADER`] so
///    the integration test's header check stays green.
///
/// The function creates `out_dir` (and parents) if it does not already exist.
pub fn codegen_rust(schemas_dir: &Path, out_dir: &Path) -> Result<()> {
    if !schemas_dir.exists() {
        return Err(CodegenError::SchemasDirMissing(schemas_dir.to_path_buf()));
    }

    let mut schema_files: Vec<PathBuf> = Vec::new();
    walk_schema_files(schemas_dir, &mut schema_files)?;
    schema_files.sort();
    let catalog = LocalSchemaCatalog::load(schemas_dir)?;
    let referenced_schema_roots = collect_local_schema_ref_roots(&schema_files, &catalog)?;

    let pretty = render_schema_modules(
        &schema_files,
        schemas_dir,
        &catalog,
        &referenced_schema_roots,
    )?;

    fs::create_dir_all(out_dir).map_err(|err| CodegenError::Io(out_dir.to_path_buf(), err))?;

    let mut body = String::with_capacity(GENERATED_HEADER.len() + pretty.len() + 1);
    body.push_str(GENERATED_HEADER);
    body.push('\n');
    body.push_str(&pretty);

    let out_path = out_dir.join(CHIO_WIRE_V1_OUTPUT);
    let formatted = rustfmt_generated(&out_path, &body)?;
    write_if_changed(&out_path, formatted.as_bytes())?;

    // Refresh mod.rs so the header check passes on a fresh clone.
    // mod.rs intentionally does not re-export `chio_wire_v1`; the generated
    // bindings stay quarantined until the public API surface is settled.
    let mod_body = format!(
        "{GENERATED_HEADER}\n\
         //! Header-only module marker for the chio-wire/v1 generated types.\n\
         //!\n\
         //! This file intentionally declares no submodules. Generated wire\n\
         //! bindings remain quarantined until the public API and no_std story\n\
         //! are explicitly settled. The header is required by\n\
         //! `crates/core/chio-core-types/tests/_generated_check.rs`.\n"
    );
    let mod_path = out_dir.join(MOD_FILE);
    write_if_changed(&mod_path, mod_body.as_bytes())?;

    Ok(())
}

/// Render the chio-wire/v1 codegen to an in-memory string without touching
/// the filesystem. Used by the xtask `--check` mode to detect drift.
pub fn render_chio_wire_v1(schemas_dir: &Path) -> Result<String> {
    if !schemas_dir.exists() {
        return Err(CodegenError::SchemasDirMissing(schemas_dir.to_path_buf()));
    }
    let mut schema_files: Vec<PathBuf> = Vec::new();
    walk_schema_files(schemas_dir, &mut schema_files)?;
    schema_files.sort();
    let catalog = LocalSchemaCatalog::load(schemas_dir)?;
    let referenced_schema_roots = collect_local_schema_ref_roots(&schema_files, &catalog)?;

    let pretty = render_schema_modules(
        &schema_files,
        schemas_dir,
        &catalog,
        &referenced_schema_roots,
    )?;
    let mut body = String::with_capacity(GENERATED_HEADER.len() + pretty.len() + 1);
    body.push_str(GENERATED_HEADER);
    body.push('\n');
    body.push_str(&pretty);
    rustfmt_generated(Path::new(CHIO_WIRE_V1_OUTPUT), &body)
}

pub(crate) fn rustfmt_generated(path: &Path, source: &str) -> Result<String> {
    let mut child = Command::new("rustfmt")
        .args(["--emit", "stdout", "--edition", "2021"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| CodegenError::Io(PathBuf::from("rustfmt"), err))?;

    let Some(mut stdin) = child.stdin.take() else {
        return Err(CodegenError::Rustfmt(
            path.to_path_buf(),
            "stdin unavailable".to_string(),
        ));
    };
    stdin
        .write_all(source.as_bytes())
        .map_err(|err| CodegenError::Io(PathBuf::from("rustfmt stdin"), err))?;
    drop(stdin);

    let output = child
        .wait_with_output()
        .map_err(|err| CodegenError::Io(PathBuf::from("rustfmt"), err))?;
    if !output.status.success() {
        return Err(CodegenError::Rustfmt(
            path.to_path_buf(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|err| CodegenError::Rustfmt(path.to_path_buf(), err.to_string()))
}

fn render_schema_modules(
    schema_files: &[PathBuf],
    schemas_dir: &Path,
    catalog: &LocalSchemaCatalog,
    referenced_schema_roots: &BTreeSet<PathBuf>,
) -> Result<String> {
    let mut paths = Vec::new();
    let mut modules = Vec::new();
    for path in schema_files {
        if should_skip_referenced_root(path, referenced_schema_roots)? {
            continue;
        }
        let module_name = schema_module_name(path, schemas_dir)?;
        if module_name == shared_types::SHARED_MODULE {
            return Err(CodegenError::SchemaRef(
                path.clone(),
                "module name is reserved for shared types".to_string(),
            ));
        }
        paths.push(path.clone());
        modules.push((module_name, load_schema_value(path, catalog)?));
    }
    let shared = shared_types::share_types(modules);

    let mut source = String::new();
    if !shared.shared.is_empty() {
        let shared_path = schemas_dir.join(shared_types::SHARED_MODULE);
        let mut defs = serde_json::Map::new();
        for (name, schema) in &shared.shared {
            defs.insert(name.clone(), schema.clone());
        }
        let root = serde_json::json!({ "$defs": defs });
        let rendered = render_module(&shared_path, root, &TypeSpaceSettings::default())?;
        let declared = declared_type_names(&rendered);
        let missing: Vec<&String> = shared
            .shared
            .keys()
            .filter(|name| !declared.contains(name.as_str()))
            .collect();
        if !missing.is_empty() {
            return Err(CodegenError::SchemaRef(
                shared_path,
                format!("typify renamed shared types: {missing:?}"),
            ));
        }
        push_module(&mut source, shared_types::SHARED_MODULE, &rendered);
    }
    for ((path, (module_name, mut schema)), uses) in
        paths.iter().zip(shared.modules).zip(&shared.uses)
    {
        let mut settings = TypeSpaceSettings::default();
        if !uses.is_empty() {
            let Some(root) = schema.as_object_mut() else {
                return Err(CodegenError::SchemaRef(
                    path.clone(),
                    "shared types need an object root schema".to_string(),
                ));
            };
            let defs = root
                .entry("$defs".to_string())
                .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
            let Some(defs) = defs.as_object_mut() else {
                return Err(CodegenError::SchemaRef(
                    path.clone(),
                    "root $defs is not an object".to_string(),
                ));
            };
            for name in shared_closure(&shared.shared, uses) {
                if defs.contains_key(&name) {
                    return Err(CodegenError::SchemaRef(
                        path.clone(),
                        format!("shared type {name} collides with a local definition"),
                    ));
                }
                let Some(body) = shared.shared.get(&name) else {
                    return Err(CodegenError::SchemaRef(
                        path.clone(),
                        format!("shared type {name} has no schema"),
                    ));
                };
                defs.insert(name.clone(), body.clone());
                settings.with_replacement(
                    &name,
                    format!("super::{}::{name}", shared_types::SHARED_MODULE),
                    std::iter::empty(),
                );
            }
        }
        let rendered = render_module(path, schema, &settings)?;
        push_module(&mut source, &module_name, &rendered);
    }

    let mut file = syn::parse_file(&source).map_err(CodegenError::SynParse)?;
    duplicate_types::alias_duplicate_types(&mut file);
    check_no_duplicate_types(&file)?;
    schema_docs::strip_schema_docs(&mut file);
    let pretty = prettyplease::unparse(&file);
    if pretty.len() > MAX_CHIO_WIRE_V1_BYTES {
        return Err(CodegenError::OutputTooLarge(pretty.len()));
    }
    Ok(pretty)
}

/// Shared type names reachable from `uses` through references between
/// shared schemas.
fn shared_closure(
    shared: &BTreeMap<String, serde_json::Value>,
    uses: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut reached = BTreeSet::new();
    let mut pending: Vec<String> = uses.iter().cloned().collect();
    while let Some(name) = pending.pop() {
        if !reached.insert(name.clone()) {
            continue;
        }
        if let Some(body) = shared.get(&name) {
            collect_local_refs(body, &mut pending);
        }
    }
    reached
}

fn collect_local_refs(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(name) = map
                .get("$ref")
                .and_then(serde_json::Value::as_str)
                .and_then(|reference| reference.strip_prefix("#/$defs/"))
            {
                out.push(name.to_string());
            }
            for item in map.values() {
                collect_local_refs(item, out);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_local_refs(item, out);
            }
        }
        _ => {}
    }
}

fn render_module(
    path: &Path,
    value: serde_json::Value,
    settings: &TypeSpaceSettings,
) -> Result<String> {
    let schema: schemars::schema::RootSchema = serde_json::from_value(value)
        .map_err(|err| CodegenError::SchemaShape(path.to_path_buf(), err))?;
    let tokens = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut type_space = TypeSpace::new(settings);
        type_space
            .add_root_schema(schema)
            .map(|_| type_space.to_stream())
    }))
    .map_err(|_| CodegenError::Typify(path.to_path_buf(), "typify panicked".to_string()))?
    .map_err(|err| CodegenError::Typify(path.to_path_buf(), err.to_string()))?;
    let file: syn::File = syn::parse2(tokens).map_err(CodegenError::SynParse)?;
    Ok(prettyplease::unparse(&file))
}

fn push_module(source: &mut String, name: &str, body: &str) {
    source.push_str("pub mod ");
    source.push_str(name);
    source.push_str(" {\n");
    source.push_str(body);
    source.push_str("}\n");
}

fn declared_type_names(rendered: &str) -> BTreeSet<String> {
    let Ok(file) = syn::parse_file(rendered) else {
        return BTreeSet::new();
    };
    file.items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Struct(item) => Some(item.ident.to_string()),
            syn::Item::Enum(item) => Some(item.ident.to_string()),
            syn::Item::Type(item) => Some(item.ident.to_string()),
            _ => None,
        })
        .collect()
}

/// Fails when two struct-with-fields or enum items render the same; see
/// [`duplicate_types`].
fn check_no_duplicate_types(file: &syn::File) -> Result<()> {
    let duplicates = duplicate_types::duplicate_groups(file);
    if duplicates.is_empty() {
        Ok(())
    } else {
        Err(CodegenError::DuplicateTypes(format!(
            "{} groups, first: {}",
            duplicates.len(),
            duplicates
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        )))
    }
}

fn schema_module_name(path: &Path, schemas_dir: &Path) -> Result<String> {
    let relative = path.strip_prefix(schemas_dir).map_err(|_| {
        CodegenError::SchemaRef(
            path.to_path_buf(),
            format!("schema is outside {}", schemas_dir.display()),
        )
    })?;
    let relative = relative.to_string_lossy();
    let stem = relative
        .strip_suffix(".schema.json")
        .unwrap_or(relative.as_ref());
    Ok(stem
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect())
}

fn walk_schema_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = fs::read_dir(dir).map_err(|err| CodegenError::Io(dir.to_path_buf(), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| CodegenError::Io(dir.to_path_buf(), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| CodegenError::Io(path.clone(), err))?;
        if file_type.is_symlink() {
            return Err(CodegenError::SchemaRef(
                path,
                "refusing symlink in schema tree".to_string(),
            ));
        }
        if file_type.is_dir() {
            walk_schema_files(&path, out)?;
        } else if file_type.is_file() && is_schema_json(&path) {
            out.push(path);
        }
    }
    Ok(())
}

fn is_schema_json(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    name.ends_with(".schema.json")
}

fn load_schema_value(path: &Path, catalog: &LocalSchemaCatalog) -> Result<serde_json::Value> {
    load_schema_value_recursive(path, catalog, &mut BTreeSet::new())
}

fn load_schema_value_recursive(
    path: &Path,
    catalog: &LocalSchemaCatalog,
    active: &mut BTreeSet<PathBuf>,
) -> Result<serde_json::Value> {
    let canonical = fs::canonicalize(path).map_err(|err| CodegenError::Io(path.into(), err))?;
    if !active.insert(canonical.clone()) {
        return Err(CodegenError::SchemaRef(
            path.into(),
            "cyclic cross-file schema reference".into(),
        ));
    }
    let mut value = catalog.resource(path)?;
    let mut extra_defs = serde_json::Map::new();
    inline_local_schema_refs(&mut value, path, catalog, &mut extra_defs, active)?;
    merge_extra_defs_into_root(&mut value, extra_defs, path)?;
    strip_typify_unsupported_conditionals(&mut value);
    active.remove(&canonical);
    Ok(value)
}

fn collect_local_schema_ref_roots(
    schema_files: &[PathBuf],
    catalog: &LocalSchemaCatalog,
) -> Result<BTreeSet<PathBuf>> {
    let mut referenced_roots = BTreeSet::new();

    for path in schema_files {
        let value = catalog.resource(path)?;
        collect_local_schema_ref_roots_from_value(&value, path, catalog, &mut referenced_roots)?;
    }

    Ok(referenced_roots)
}

fn read_schema_file(path: &Path) -> Result<serde_json::Value> {
    let raw = fs::read_to_string(path).map_err(|err| CodegenError::Io(path.to_path_buf(), err))?;
    serde_json::from_str(&raw).map_err(|err| CodegenError::Json(path.to_path_buf(), err))
}

fn collect_local_schema_ref_roots_from_value(
    value: &serde_json::Value,
    base_path: &Path,
    catalog: &LocalSchemaCatalog,
    referenced_roots: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(reference)) = map.get("$ref") {
                if let Some((target_path, fragment)) = catalog.resolve(reference, base_path)? {
                    let targets_root = match fragment.as_deref() {
                        None | Some("") => true,
                        Some(_) => false,
                    };
                    if targets_root {
                        referenced_roots.insert(target_path);
                    }
                }
            }
            for item in map.values() {
                collect_local_schema_ref_roots_from_value(
                    item,
                    base_path,
                    catalog,
                    referenced_roots,
                )?;
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_local_schema_ref_roots_from_value(
                    item,
                    base_path,
                    catalog,
                    referenced_roots,
                )?;
            }
        }
        _ => {}
    }

    Ok(())
}

fn should_skip_referenced_root(
    path: &Path,
    referenced_schema_roots: &BTreeSet<PathBuf>,
) -> Result<bool> {
    let path = fs::canonicalize(path).map_err(|err| CodegenError::Io(path.to_path_buf(), err))?;
    Ok(referenced_schema_roots.contains(&path))
}

fn inline_local_schema_refs(
    value: &mut serde_json::Value,
    base_path: &Path,
    catalog: &LocalSchemaCatalog,
    extra_defs: &mut serde_json::Map<String, serde_json::Value>,
    active: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(reference)) = map.get("$ref") {
                if let Some((target_path, fragment)) = catalog.resolve(reference, base_path)? {
                    let target = load_schema_value_recursive(&target_path, catalog, active)?;
                    merge_referenced_defs(&target, extra_defs, base_path, reference)?;
                    let mut resolved = resolve_json_pointer(&target, fragment.as_deref())
                        .map_err(|msg| {
                            CodegenError::SchemaRef(
                                base_path.to_path_buf(),
                                format!("{reference}: {msg}"),
                            )
                        })?
                        .clone();
                    strip_inlined_resource_keywords(&mut resolved);
                    *value = resolved;
                    return Ok(());
                }
            }
            for item in map.values_mut() {
                inline_local_schema_refs(item, base_path, catalog, extra_defs, active)?;
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                inline_local_schema_refs(item, base_path, catalog, extra_defs, active)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn has_uri_scheme(value: &str) -> bool {
    let Some((scheme, _)) = value.split_once(':') else {
        return false;
    };
    !scheme.is_empty()
        && scheme
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '+' || ch == '-' || ch == '.')
}

fn merge_referenced_defs(
    target: &serde_json::Value,
    extra_defs: &mut serde_json::Map<String, serde_json::Value>,
    base_path: &Path,
    reference: &str,
) -> Result<()> {
    let Some(defs) = target
        .as_object()
        .and_then(|object| object.get("$defs"))
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(());
    };

    for (key, value) in defs {
        merge_schema_def(extra_defs, key, value.clone(), base_path, reference)?;
    }

    Ok(())
}

fn merge_extra_defs_into_root(
    root: &mut serde_json::Value,
    extra_defs: serde_json::Map<String, serde_json::Value>,
    path: &Path,
) -> Result<()> {
    if extra_defs.is_empty() {
        return Ok(());
    }

    let Some(root_object) = root.as_object_mut() else {
        return Err(CodegenError::SchemaRef(
            path.to_path_buf(),
            "cannot merge referenced definitions into a non-object schema".to_string(),
        ));
    };

    let defs = root_object
        .entry("$defs".to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    let Some(defs_object) = defs.as_object_mut() else {
        return Err(CodegenError::SchemaRef(
            path.to_path_buf(),
            "root $defs is not an object".to_string(),
        ));
    };

    for (key, value) in extra_defs {
        merge_schema_def(defs_object, &key, value, path, "$defs")?;
    }

    Ok(())
}

fn merge_schema_def(
    defs: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: serde_json::Value,
    base_path: &Path,
    reference: &str,
) -> Result<()> {
    match defs.get(key) {
        Some(existing) if existing == &value => Ok(()),
        Some(_) => Err(CodegenError::SchemaRef(
            base_path.to_path_buf(),
            format!("{reference} collides with existing $defs/{key}"),
        )),
        None => {
            defs.insert(key.to_string(), value);
            Ok(())
        }
    }
}

fn resolve_json_pointer<'a>(
    value: &'a serde_json::Value,
    fragment: Option<&str>,
) -> core::result::Result<&'a serde_json::Value, String> {
    let Some(fragment) = fragment else {
        return Ok(value);
    };
    if fragment.is_empty() {
        return Ok(value);
    }
    if !fragment.starts_with('/') {
        return Err(format!("unsupported fragment #{fragment}"));
    }

    let mut current = value;
    for token in fragment.trim_start_matches('/').split('/') {
        let token = token.replace("~1", "/").replace("~0", "~");
        current = match current {
            serde_json::Value::Object(map) => map
                .get(&token)
                .ok_or_else(|| format!("missing object key {token}"))?,
            serde_json::Value::Array(items) => {
                let index = token
                    .parse::<usize>()
                    .map_err(|_| format!("array index {token} is not numeric"))?;
                items
                    .get(index)
                    .ok_or_else(|| format!("array index {index} is out of bounds"))?
            }
            _ => {
                return Err(format!(
                    "cannot descend through non-container token {token}"
                ))
            }
        };
    }

    Ok(current)
}

fn strip_inlined_resource_keywords(value: &mut serde_json::Value) {
    if let serde_json::Value::Object(map) = value {
        map.remove("$schema");
        map.remove("$id");
        map.remove("$defs");
    }
}

fn strip_typify_unsupported_conditionals(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let remove_all_of = map
                .get("allOf")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|items| {
                    items.iter().any(|item| {
                        item.as_object()
                            .is_some_and(|object| object.contains_key("if"))
                    })
                });
            if remove_all_of {
                map.remove("allOf");
            }
            for item in map.values_mut() {
                strip_typify_unsupported_conditionals(item);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                strip_typify_unsupported_conditionals(item);
            }
        }
        _ => {}
    }
}

pub(crate) fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Ok(existing) = fs::read(path) {
        if existing == bytes {
            return Ok(());
        }
    }
    fs::write(path, bytes).map_err(|err| CodegenError::Io(path.to_path_buf(), err))?;
    Ok(())
}

#[cfg(test)]
mod tests;
