use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use typify::{TypeSpace, TypeSpaceSettings};

/// Canonical URI prefix whose references are mirrored from the local wire tree.
pub const CANONICAL_CHIO_WIRE_SCHEMA_PREFIX: &str = "https://chio.world/schemas/chio-wire/v1/";


pub use errors_pass::{
    codegen_error_codes, render_error_codes, ERRORS_GENERATED_DIR, ERROR_CODES_OUTPUT,
    ERROR_REGISTRY_INPUT,
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

/// File name for the consolidated chio-wire/v1 Rust output.
pub const CHIO_WIRE_V1_OUTPUT: &str = "chio_wire_v1.rs";

/// File name for the header-only module marker under `_generated/`.
pub const MOD_FILE: &str = "mod.rs";

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
    /// A deterministic generated-binding hardening pattern was missing.
    GeneratedHardening(String),
    /// `rustfmt` rejected or could not decode generated Rust source.
    Rustfmt(PathBuf, String),
    /// The error registry YAML could not be loaded or validated.
    Registry(PathBuf, String),
    /// The schemas directory did not exist on disk.
    SchemasDirMissing(PathBuf),
    /// Two schema paths normalized to the same generated Rust module name.
    ModuleNameCollision {
        /// The colliding Rust module name.
        module: String,
        /// The lexicographically first schema path.
        first: PathBuf,
        /// The second schema path.
        second: PathBuf,
    },
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
            Self::GeneratedHardening(msg) => {
                write!(f, "generated binding hardening failed: {msg}")
            }
            Self::Rustfmt(path, msg) => {
                write!(f, "rustfmt rejected generated source {}: {msg}", path.display())
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
            Self::ModuleNameCollision {
                module,
                first,
                second,
            } => write!(
                f,
                "schema paths {} and {} both normalize to Rust module `{module}`",
                first.display(),
                second.display()
            ),
        }
    }
}

impl std::error::Error for CodegenError {}

/// Result alias for the public API.
pub type Result<T> = core::result::Result<T, CodegenError>;

pub(crate) fn rustfmt_generated(path: &Path, source: &str) -> Result<String> {
    use std::io::Write as _;

    let mut child = std::process::Command::new("rustfmt")
        .args(["--emit", "stdout", "--edition", "2021"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| CodegenError::Io(PathBuf::from("rustfmt"), error))?;
    let Some(mut stdin) = child.stdin.take() else {
        return Err(CodegenError::Rustfmt(
            path.to_path_buf(),
            "stdin unavailable".to_string(),
        ));
    };
    stdin
        .write_all(source.as_bytes())
        .map_err(|error| CodegenError::Io(PathBuf::from("rustfmt stdin"), error))?;
    drop(stdin);

    let output = child
        .wait_with_output()
        .map_err(|error| CodegenError::Io(PathBuf::from("rustfmt"), error))?;
    if !output.status.success() {
        return Err(CodegenError::Rustfmt(
            path.to_path_buf(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| CodegenError::Rustfmt(path.to_path_buf(), error.to_string()))
}

/// Generate Rust types from every schema under `schemas_dir` and write them
/// to `out_dir`.
///
/// This is the single entry point used by both the `chio-spec-codegen` binary
/// and `cargo xtask codegen rust`. The pipeline is:
///
/// 1. Walk `schemas_dir` recursively, collecting every `*.schema.json` file
///    in lexicographic order.
/// 2. Parse each file as `schemars::schema::RootSchema`, inline its local
///    schema-tree references, and register it with an independent
///    `typify::TypeSpace`.
/// 3. Wrap each `TypeSpace` in a deterministic path-named Rust module, build a
///    consolidated `syn::File`, and pretty-print via `prettyplease`.
/// 4. Prepend [`GENERATED_HEADER`] and write to
///    `out_dir/CHIO_WIRE_V1_OUTPUT`.
/// 5. Refresh the header-only `out_dir/MOD_FILE` with [`GENERATED_HEADER`] so
///    the integration test's header check stays green.
///
/// The function creates `out_dir` (and parents) if it does not already exist.
pub fn codegen_rust(schemas_dir: &Path, out_dir: &Path) -> Result<()> {
    let body = render_chio_wire_v1(schemas_dir)?;
    write_rust_codegen_outputs(out_dir, &body)
}

/// Generate Rust bindings from an explicit, caller-authenticated schema inventory.
pub fn codegen_rust_with_inventory(
    schemas_dir: &Path,
    out_dir: &Path,
    schema_files: &[PathBuf],
) -> Result<()> {
    let body = render_chio_wire_v1_with_inventory(schemas_dir, schema_files)?;
    write_rust_codegen_outputs(out_dir, &body)
}

fn write_rust_codegen_outputs(out_dir: &Path, body: &str) -> Result<()> {
    fs::create_dir_all(out_dir).map_err(|err| CodegenError::Io(out_dir.to_path_buf(), err))?;

    let out_path = out_dir.join(CHIO_WIRE_V1_OUTPUT);
    write_if_changed(&out_path, body.as_bytes())?;

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
         //! `crates/chio-core-types/tests/_generated_check.rs`.\n"
    );
    let mod_path = out_dir.join(MOD_FILE);
    write_if_changed(&mod_path, mod_body.as_bytes())?;

    Ok(())
}

/// Render the chio-wire/v1 codegen to an in-memory string without touching
/// the filesystem. Used by the xtask `--check` mode to detect drift.
pub fn render_chio_wire_v1(schemas_dir: &Path) -> Result<String> {
    let canonical_schemas_dir = validate_schema_root(schemas_dir)?;
    let mut schema_files = Vec::new();
    walk_schema_files(schemas_dir, &mut schema_files)?;
    schema_files.sort();
    render_chio_wire_v1_from_files(schemas_dir, &canonical_schemas_dir, &schema_files)
}

/// Render Rust bindings from an explicit, caller-authenticated schema inventory.
pub fn render_chio_wire_v1_with_inventory(
    schemas_dir: &Path,
    schema_files: &[PathBuf],
) -> Result<String> {
    let canonical_schemas_dir = validate_schema_root(schemas_dir)?;
    render_chio_wire_v1_from_files(schemas_dir, &canonical_schemas_dir, schema_files)
}

fn validate_schema_root(schemas_dir: &Path) -> Result<PathBuf> {
    if !schemas_dir.exists() {
        return Err(CodegenError::SchemasDirMissing(schemas_dir.to_path_buf()));
    }
    let root_metadata = fs::symlink_metadata(schemas_dir)
        .map_err(|err| CodegenError::Io(schemas_dir.to_path_buf(), err))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(CodegenError::SchemaRef(
            schemas_dir.to_path_buf(),
            "schema root is not a real directory".to_string(),
        ));
    }
    fs::canonicalize(schemas_dir).map_err(|err| CodegenError::Io(schemas_dir.to_path_buf(), err))
}

fn render_chio_wire_v1_from_files(
    schemas_dir: &Path,
    canonical_schemas_dir: &Path,
    schema_files: &[PathBuf],
) -> Result<String> {
    let schema_inventory =
        build_schema_inventory(schema_files, schemas_dir, canonical_schemas_dir)?;

    let mut module_paths = BTreeMap::new();
    let mut items = Vec::with_capacity(schema_files.len());
    for path in schema_files {
        let module_name = schema_module_name(path, schemas_dir)?;
        if let Some(first) = module_paths.insert(module_name.clone(), path.clone()) {
            return Err(CodegenError::ModuleNameCollision {
                module: module_name,
                first,
                second: path.clone(),
            });
        }
        items.push(syn::Item::Mod(render_schema_module(
            path,
            schemas_dir,
            &module_name,
            &schema_inventory,
        )?));
    }

    let file = syn::File {
        shebang: None,
        attrs: Vec::new(),
        items,
    };
    let pretty = prettyplease::unparse(&file);
    let pretty = harden_active_defense_receipts_rust(pretty)?;
    let pretty = harden_detector_health_rust(pretty)?;
    let pretty = harden_admission_capture_guarantee_rust(pretty)?;
    let mut body = String::with_capacity(GENERATED_HEADER.len() + pretty.len() + 1);
    body.push_str(GENERATED_HEADER);
    body.push('\n');
    body.push_str(&pretty);
    Ok(body)
}

fn harden_active_defense_receipts_rust(mut body: String) -> Result<String> {
    const MODULES: &[&str] = &[
        "security__correlated_finding_receipt_body_v1",
        "security__declassification_consumption_receipt_body_v1",
        "security__declassification_outcome_receipt_body_v1",
        "security__effect_transition_receipt_body_v1",
        "security__flow_denial_receipt_body_v1",
        "security__lift_rollback_completion_receipt_body_v1",
        "security__response_completion_receipt_body_v1",
        "security__response_plan_receipt_body_v1",
        "security__response_state_transition_receipt_body_v1",
        "security__scheduler_health_receipt_body_v1",
        "security__tripwire_observation_receipt_body_v1",
    ];
    const MODULE_SUPPORT: &str = r#"
    const ACTIVE_DEFENSE_MAX_JSON_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
"#;
    const JSON_SAFE_INTEGER_SUPPORT: &str = r#"
    #[derive(Clone, Debug)]
    #[repr(transparent)]
    pub struct JsonSafePositiveInteger(::std::num::NonZeroU64);
    impl JsonSafePositiveInteger {
        pub fn new(
            value: ::std::num::NonZeroU64,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            if value.get() > ACTIVE_DEFENSE_MAX_JSON_SAFE_INTEGER {
                return Err("active-defense integer exceeds the JSON-safe range".into());
            }
            Ok(Self(value))
        }
        #[must_use]
        pub const fn get(&self) -> u64 {
            self.0.get()
        }
    }
    impl ::std::convert::TryFrom<::std::num::NonZeroU64> for JsonSafePositiveInteger {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::num::NonZeroU64,
        ) -> ::std::result::Result<Self, Self::Error> {
            Self::new(value)
        }
    }
    impl ::std::str::FromStr for JsonSafePositiveInteger {
        type Err = self::error::ConversionError;
        fn from_str(value: &str) -> ::std::result::Result<Self, Self::Err> {
            let parsed = value
                .parse::<::std::num::NonZeroU64>()
                .map_err(|error| self::error::ConversionError::from(error.to_string()))?;
            Self::new(parsed)
        }
    }
    impl<'de> ::serde::Deserialize<'de> for JsonSafePositiveInteger {
        fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            let value = <::std::num::NonZeroU64 as ::serde::Deserialize>::deserialize(
                deserializer,
            )?;
            Self::new(value).map_err(<D::Error as ::serde::de::Error>::custom)
        }
    }
    impl ::serde::Serialize for JsonSafePositiveInteger {
        fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
        where
            S: ::serde::Serializer,
        {
            if self.0.get() > ACTIVE_DEFENSE_MAX_JSON_SAFE_INTEGER {
                return Err(<S::Error as ::serde::ser::Error>::custom(
                    "active-defense integer exceeds the JSON-safe range",
                ));
            }
            ::serde::Serialize::serialize(&self.0, serializer)
        }
    }
"#;
    const TIME_NEEDLE: &str = r#"    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    #[serde(transparent)]
    pub struct Time(pub ::std::num::NonZeroU64);
"#;
    const TIME_REPLACEMENT: &str = r#"    #[derive(Clone, Debug)]
    #[repr(transparent)]
    pub struct Time(::std::num::NonZeroU64);
    impl Time {
        pub fn new(
            value: ::std::num::NonZeroU64,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            if value.get() > ACTIVE_DEFENSE_MAX_JSON_SAFE_INTEGER {
                return Err("active-defense time exceeds the JSON-safe range".into());
            }
            Ok(Self(value))
        }
        #[must_use]
        pub const fn get(&self) -> u64 {
            self.0.get()
        }
    }
    impl<'de> ::serde::Deserialize<'de> for Time {
        fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            let value = <::std::num::NonZeroU64 as ::serde::Deserialize>::deserialize(
                deserializer,
            )?;
            Self::new(value).map_err(<D::Error as ::serde::de::Error>::custom)
        }
    }
    impl ::serde::Serialize for Time {
        fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
        where
            S: ::serde::Serializer,
        {
            if self.0.get() > ACTIVE_DEFENSE_MAX_JSON_SAFE_INTEGER {
                return Err(<S::Error as ::serde::ser::Error>::custom(
                    "active-defense time exceeds the JSON-safe range",
                ));
            }
            ::serde::Serialize::serialize(&self.0, serializer)
        }
    }
"#;
    const TIME_CONVERSIONS_NEEDLE: &str = r#"    impl ::std::convert::From<::std::num::NonZeroU64> for Time {
        fn from(value: ::std::num::NonZeroU64) -> Self {
            Self(value)
        }
    }
    impl ::std::str::FromStr for Time {
        type Err = <::std::num::NonZeroU64 as ::std::str::FromStr>::Err;
        fn from_str(value: &str) -> ::std::result::Result<Self, Self::Err> {
            Ok(Self(value.parse()?))
        }
    }
    impl ::std::convert::TryFrom<&str> for Time {
        type Error = <::std::num::NonZeroU64 as ::std::str::FromStr>::Err;
        fn try_from(value: &str) -> ::std::result::Result<Self, Self::Error> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&String> for Time {
        type Error = <::std::num::NonZeroU64 as ::std::str::FromStr>::Err;
        fn try_from(value: &String) -> ::std::result::Result<Self, Self::Error> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<String> for Time {
        type Error = <::std::num::NonZeroU64 as ::std::str::FromStr>::Err;
        fn try_from(value: String) -> ::std::result::Result<Self, Self::Error> {
            value.parse()
        }
    }
"#;
    const TIME_CONVERSIONS_REPLACEMENT: &str = r#"    impl ::std::convert::TryFrom<::std::num::NonZeroU64> for Time {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::num::NonZeroU64,
        ) -> ::std::result::Result<Self, Self::Error> {
            Self::new(value)
        }
    }
    impl ::std::str::FromStr for Time {
        type Err = self::error::ConversionError;
        fn from_str(value: &str) -> ::std::result::Result<Self, Self::Err> {
            let parsed = value
                .parse::<::std::num::NonZeroU64>()
                .map_err(|error| self::error::ConversionError::from(error.to_string()))?;
            Self::new(parsed)
        }
    }
    impl ::std::convert::TryFrom<&str> for Time {
        type Error = self::error::ConversionError;
        fn try_from(value: &str) -> ::std::result::Result<Self, Self::Error> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&String> for Time {
        type Error = self::error::ConversionError;
        fn try_from(value: &String) -> ::std::result::Result<Self, Self::Error> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<String> for Time {
        type Error = self::error::ConversionError;
        fn try_from(value: String) -> ::std::result::Result<Self, Self::Error> {
            value.parse()
        }
    }
"#;

    for module_name in MODULES {
        let module_start = format!("pub mod {module_name} {{");
        let Some(start) = body.find(&module_start) else {
            continue;
        };
        let search_start = start + module_start.len();
        let end = body[search_start..]
            .find("\npub mod ")
            .map_or(body.len(), |relative_end| search_start + relative_end);
        let mut module = body[start..end].to_string();
        let module_support = if matches!(
            *module_name,
            "security__response_state_transition_receipt_body_v1"
                | "security__effect_transition_receipt_body_v1"
                | "security__scheduler_health_receipt_body_v1"
        ) {
            format!("{MODULE_SUPPORT}{JSON_SAFE_INTEGER_SUPPORT}")
        } else {
            MODULE_SUPPORT.to_string()
        };
        module = module.replacen(&module_start, &format!("{module_start}{module_support}"), 1);
        replace_generated_hardening_once(
            &mut module,
            TIME_NEEDLE,
            TIME_REPLACEMENT,
            &format!("{module_name} time"),
        )?;
        replace_generated_hardening_once(
            &mut module,
            TIME_CONVERSIONS_NEEDLE,
            TIME_CONVERSIONS_REPLACEMENT,
            &format!("{module_name} time conversions"),
        )?;

        match *module_name {
            "security__correlated_finding_receipt_body_v1" => {
                replace_generated_hardening_once(
                    &mut module,
                    "        pub first_event_time_unix_ms: ::std::num::NonZeroU64,\n",
                    "        pub first_event_time_unix_ms: Time,\n",
                    "correlated finding first event time",
                )?;
                replace_generated_hardening_once(
                    &mut module,
                    "        pub last_event_time_unix_ms: ::std::num::NonZeroU64,\n",
                    "        pub last_event_time_unix_ms: Time,\n",
                    "correlated finding last event time",
                )?;
            }
            "security__response_plan_receipt_body_v1" => {
                replace_generated_hardening_once(
                    &mut module,
                    "        pub plan_created_at_unix_ms: ::std::num::NonZeroU64,\n",
                    "        pub plan_created_at_unix_ms: Time,\n",
                    "response plan creation time",
                )?;
            }
            "security__response_state_transition_receipt_body_v1" => {
                replace_generated_hardening_once(
                    &mut module,
                    "        pub generation: ::std::num::NonZeroU64,\n",
                    "        pub generation: JsonSafePositiveInteger,\n",
                    "response state generation",
                )?;
            }
            "security__effect_transition_receipt_body_v1" => {
                replace_generated_hardening_once(
                    &mut module,
                    "        pub generation: ::std::num::NonZeroU64,\n",
                    "        pub generation: JsonSafePositiveInteger,\n",
                    "effect transition generation",
                )?;
                replace_generated_hardening_once(
                    &mut module,
                    "        pub scheduler_fencing_token: ::std::num::NonZeroU64,\n",
                    "        pub scheduler_fencing_token: JsonSafePositiveInteger,\n",
                    "effect transition fencing token",
                )?;
            }
            "security__scheduler_health_receipt_body_v1" => {
                replace_generated_hardening_once(
                    &mut module,
                    "        pub attempts: ::std::num::NonZeroU64,\n",
                    "        pub attempts: ::std::num::NonZeroU32,\n",
                    "scheduler health attempts",
                )?;
                replace_generated_hardening_once(
                    &mut module,
                    "        pub first_failure_at_unix_ms: ::std::num::NonZeroU64,\n",
                    "        pub first_failure_at_unix_ms: Time,\n",
                    "scheduler health first failure time",
                )?;
                replace_generated_hardening_once(
                    &mut module,
                    "        pub scheduler_fencing_token: ::std::num::NonZeroU64,\n",
                    "        pub scheduler_fencing_token: JsonSafePositiveInteger,\n",
                    "scheduler health fencing token",
                )?;
            }
            _ => {}
        }

        body.replace_range(start..end, &module);
    }
    Ok(body)
}

fn harden_detector_health_rust(mut body: String) -> Result<String> {
    const MODULE_START: &str = "pub mod security__detector_health_receipt_body_v1 {";
    let Some(start) = body.find(MODULE_START) else {
        return Ok(body);
    };
    let search_start = start + MODULE_START.len();
    let end = body[search_start..]
        .find("\npub mod ")
        .map_or(body.len(), |relative_end| search_start + relative_end);
    let mut module = body[start..end].to_string();

    const ROOT_NEEDLE: &str = r#"    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct ChioDetectorHealthReceiptBodyV1 {
        pub event_id: Identifier,
        pub evidence_hash: Digest,
        pub group_binding: GroupBinding,
        pub header: Header,
        pub health_kind: ChioDetectorHealthReceiptBodyV1HealthKind,
        pub policy: Policy,
        pub rule_id: Identifier,
        pub rule_version_hash: Digest,
        pub watermark: Watermark,
    }
"#;
    const ROOT_REPLACEMENT: &str = r#"    const DETECTOR_HEALTH_MAX_JSON_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

    #[derive(Clone, Debug)]
    pub struct ChioDetectorHealthReceiptBodyV1 {
        pub event_id: Identifier,
        pub evidence_hash: Digest,
        pub group_binding: GroupBinding,
        pub header: Header,
        pub health_kind: ChioDetectorHealthReceiptBodyV1HealthKind,
        pub policy: Policy,
        pub rule_id: Identifier,
        pub rule_version_hash: Digest,
        pub watermark: Watermark,
    }
    #[derive(::serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ChioDetectorHealthReceiptBodyV1Wire {
        event_id: Identifier,
        evidence_hash: Digest,
        group_binding: GroupBinding,
        header: Header,
        health_kind: ChioDetectorHealthReceiptBodyV1HealthKind,
        policy: Policy,
        rule_id: Identifier,
        rule_version_hash: Digest,
        watermark: Watermark,
    }
    impl ChioDetectorHealthReceiptBodyV1 {
        fn validate(&self) -> ::std::result::Result<(), &'static str> {
            for digest in [
                &self.evidence_hash,
                &self.policy.policy_hash,
                &self.rule_version_hash,
            ] {
                if digest.0.iter().all(|byte| *byte == 0) {
                    return Err("detector health digest must not be all zero");
                }
            }
            if let GroupBinding::Resolved(group_key_hash) = &self.group_binding {
                if group_key_hash.0.iter().all(|byte| *byte == 0) {
                    return Err("resolved detector group hash must not be all zero");
                }
            }
            let observed = self.header.occurred_at_unix_ms.0.get();
            if observed > DETECTOR_HEALTH_MAX_JSON_SAFE_INTEGER {
                return Err("detector health observation time exceeds the JSON-safe range");
            }
            match (&self.group_binding, &self.watermark) {
                (GroupBinding::Unresolved, Watermark::Unknown) => {}
                (GroupBinding::Unresolved, _) => {
                    return Err("unresolved detector group cannot assert watermark knowledge");
                }
                (_, Watermark::Committed { unix_ms }) => {
                    let committed = unix_ms.0.get();
                    if committed > DETECTOR_HEALTH_MAX_JSON_SAFE_INTEGER {
                        return Err("committed detector watermark exceeds the JSON-safe range");
                    }
                    if committed > observed {
                        return Err("committed detector watermark is after the observation");
                    }
                }
                (
                    GroupBinding::Resolved(_),
                    Watermark::Contradictory { claimed_unix_ms },
                ) => {
                    if !matches!(
                        self.health_kind,
                        ChioDetectorHealthReceiptBodyV1HealthKind::CorruptState
                    ) {
                        return Err(
                            "contradictory detector watermark requires corrupt state",
                        );
                    }
                    let claimed = claimed_unix_ms
                        .0
                        .parse::<u64>()
                        .map_err(|_| "contradictory detector watermark exceeds u64")?;
                    if claimed != 0
                        && claimed <= observed
                        && claimed <= DETECTOR_HEALTH_MAX_JSON_SAFE_INTEGER
                    {
                        return Err(
                            "contradictory detector watermark carries a valid committed value",
                        );
                    }
                }
                (GroupBinding::Resolved(_), Watermark::Unknown) => {}
            }
            Ok(())
        }
    }
    impl<'de> ::serde::Deserialize<'de> for ChioDetectorHealthReceiptBodyV1 {
        fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            let wire = <ChioDetectorHealthReceiptBodyV1Wire as ::serde::Deserialize>::deserialize(
                deserializer,
            )?;
            let value = Self {
                event_id: wire.event_id,
                evidence_hash: wire.evidence_hash,
                group_binding: wire.group_binding,
                header: wire.header,
                health_kind: wire.health_kind,
                policy: wire.policy,
                rule_id: wire.rule_id,
                rule_version_hash: wire.rule_version_hash,
                watermark: wire.watermark,
            };
            value
                .validate()
                .map_err(<D::Error as ::serde::de::Error>::custom)?;
            Ok(value)
        }
    }
    impl ::serde::Serialize for ChioDetectorHealthReceiptBodyV1 {
        fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
        where
            S: ::serde::Serializer,
        {
            self.validate()
                .map_err(<S::Error as ::serde::ser::Error>::custom)?;
            let mut state = serializer.serialize_struct(
                "ChioDetectorHealthReceiptBodyV1",
                9,
            )?;
            ::serde::ser::SerializeStruct::serialize_field(
                &mut state,
                "event_id",
                &self.event_id,
            )?;
            ::serde::ser::SerializeStruct::serialize_field(
                &mut state,
                "evidence_hash",
                &self.evidence_hash,
            )?;
            ::serde::ser::SerializeStruct::serialize_field(
                &mut state,
                "group_binding",
                &self.group_binding,
            )?;
            ::serde::ser::SerializeStruct::serialize_field(
                &mut state,
                "header",
                &self.header,
            )?;
            ::serde::ser::SerializeStruct::serialize_field(
                &mut state,
                "health_kind",
                &self.health_kind,
            )?;
            ::serde::ser::SerializeStruct::serialize_field(
                &mut state,
                "policy",
                &self.policy,
            )?;
            ::serde::ser::SerializeStruct::serialize_field(
                &mut state,
                "rule_id",
                &self.rule_id,
            )?;
            ::serde::ser::SerializeStruct::serialize_field(
                &mut state,
                "rule_version_hash",
                &self.rule_version_hash,
            )?;
            ::serde::ser::SerializeStruct::serialize_field(
                &mut state,
                "watermark",
                &self.watermark,
            )?;
            ::serde::ser::SerializeStruct::end(state)
        }
    }
"#;
    replace_generated_hardening_once(&mut module, ROOT_NEEDLE, ROOT_REPLACEMENT, "root")?;

    const GROUP_BINDING_NEEDLE: &str =
        "    #[serde(tag = \"kind\", content = \"group_key_hash\")]\n    pub enum GroupBinding {\n";
    const GROUP_BINDING_REPLACEMENT: &str = "    #[serde(\n        tag = \"kind\",\n        content = \"group_key_hash\",\n        deny_unknown_fields\n    )]\n    pub enum GroupBinding {\n";
    replace_generated_hardening_once(
        &mut module,
        GROUP_BINDING_NEEDLE,
        GROUP_BINDING_REPLACEMENT,
        "group binding strictness",
    )?;

    const TIME_NEEDLE: &str = r#"    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    #[serde(transparent)]
    pub struct Time(pub ::std::num::NonZeroU64);
"#;
    const TIME_REPLACEMENT: &str = r#"    #[derive(Clone, Debug)]
    #[repr(transparent)]
    pub struct Time(::std::num::NonZeroU64);
    impl Time {
        pub fn new(
            value: ::std::num::NonZeroU64,
        ) -> ::std::result::Result<Self, self::error::ConversionError> {
            if value.get() > DETECTOR_HEALTH_MAX_JSON_SAFE_INTEGER {
                return Err("detector health time exceeds the JSON-safe range".into());
            }
            Ok(Self(value))
        }
        #[must_use]
        pub const fn get(&self) -> u64 {
            self.0.get()
        }
    }
    impl<'de> ::serde::Deserialize<'de> for Time {
        fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            let value = <::std::num::NonZeroU64 as ::serde::Deserialize>::deserialize(
                deserializer,
            )?;
            Self::new(value).map_err(<D::Error as ::serde::de::Error>::custom)
        }
    }
    impl ::serde::Serialize for Time {
        fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
        where
            S: ::serde::Serializer,
        {
            if self.0.get() > DETECTOR_HEALTH_MAX_JSON_SAFE_INTEGER {
                return Err(<S::Error as ::serde::ser::Error>::custom(
                    "detector health time exceeds the JSON-safe range",
                ));
            }
            ::serde::Serialize::serialize(&self.0, serializer)
        }
    }
"#;
    replace_generated_hardening_once(&mut module, TIME_NEEDLE, TIME_REPLACEMENT, "time")?;

    const TIME_CONVERSIONS_NEEDLE: &str = r#"    impl ::std::convert::From<::std::num::NonZeroU64> for Time {
        fn from(value: ::std::num::NonZeroU64) -> Self {
            Self(value)
        }
    }
    impl ::std::str::FromStr for Time {
        type Err = <::std::num::NonZeroU64 as ::std::str::FromStr>::Err;
        fn from_str(value: &str) -> ::std::result::Result<Self, Self::Err> {
            Ok(Self(value.parse()?))
        }
    }
    impl ::std::convert::TryFrom<&str> for Time {
        type Error = <::std::num::NonZeroU64 as ::std::str::FromStr>::Err;
        fn try_from(value: &str) -> ::std::result::Result<Self, Self::Error> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&String> for Time {
        type Error = <::std::num::NonZeroU64 as ::std::str::FromStr>::Err;
        fn try_from(value: &String) -> ::std::result::Result<Self, Self::Error> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<String> for Time {
        type Error = <::std::num::NonZeroU64 as ::std::str::FromStr>::Err;
        fn try_from(value: String) -> ::std::result::Result<Self, Self::Error> {
            value.parse()
        }
    }
"#;
    const TIME_CONVERSIONS_REPLACEMENT: &str = r#"    impl ::std::convert::TryFrom<::std::num::NonZeroU64> for Time {
        type Error = self::error::ConversionError;
        fn try_from(
            value: ::std::num::NonZeroU64,
        ) -> ::std::result::Result<Self, Self::Error> {
            Self::new(value)
        }
    }
    impl ::std::str::FromStr for Time {
        type Err = self::error::ConversionError;
        fn from_str(value: &str) -> ::std::result::Result<Self, Self::Err> {
            let parsed = value
                .parse::<::std::num::NonZeroU64>()
                .map_err(|error| self::error::ConversionError::from(error.to_string()))?;
            Self::new(parsed)
        }
    }
    impl ::std::convert::TryFrom<&str> for Time {
        type Error = self::error::ConversionError;
        fn try_from(value: &str) -> ::std::result::Result<Self, Self::Error> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<&String> for Time {
        type Error = self::error::ConversionError;
        fn try_from(value: &String) -> ::std::result::Result<Self, Self::Error> {
            value.parse()
        }
    }
    impl ::std::convert::TryFrom<String> for Time {
        type Error = self::error::ConversionError;
        fn try_from(value: String) -> ::std::result::Result<Self, Self::Error> {
            value.parse()
        }
    }
"#;
    replace_generated_hardening_once(
        &mut module,
        TIME_CONVERSIONS_NEEDLE,
        TIME_CONVERSIONS_REPLACEMENT,
        "time conversions",
    )?;

    body.replace_range(start..end, &module);
    Ok(body)
}

fn harden_admission_capture_guarantee_rust(mut body: String) -> Result<String> {
    const MODULE_START: &str = "pub mod trust_control__admission_capture_metadata {";
    let Some(start) = body.find(MODULE_START) else {
        return Ok(body);
    };
    let search_start = start + MODULE_START.len();
    let end = body[search_start..]
        .find("\npub mod ")
        .map_or(body.len(), |relative_end| search_start + relative_end);
    let mut module = body[start..end].to_string();

    const ROOT_NEEDLE: &str = r#"    #[derive(::serde::Deserialize, ::serde::Serialize, Clone, Debug)]
    #[serde(deny_unknown_fields)]
    pub struct ChioAuthoritativeAdmissionCaptureReceiptProjection {
        #[serde(
            rename = "aggregateRootBindingDigest",
            default,
            skip_serializing_if = "::std::option::Option::is_none"
        )]
        pub aggregate_root_binding_digest: ::std::option::Option<Digest>,
        #[serde(
            rename = "aggregateRootCapabilityId",
            default,
            skip_serializing_if = "::std::option::Option::is_none"
        )]
        pub aggregate_root_capability_id: ::std::option::Option<Identifier>,
        pub authority: Authority,
        #[serde(rename = "authorityCommitIndex")]
        pub authority_commit_index: u64,
        #[serde(rename = "authorizationArtifactDigests")]
        pub authorization_artifact_digests: Vec<Digest>,
        #[serde(rename = "budgetCommitIndex")]
        pub budget_commit_index: ::std::num::NonZeroU64,
        #[serde(rename = "checkedRevocationSetDigest")]
        pub checked_revocation_set_digest: Digest,
        #[serde(rename = "eventId")]
        pub event_id: Identifier,
        #[serde(rename = "guaranteeLevel")]
        pub guarantee_level: ChioAuthoritativeAdmissionCaptureReceiptProjectionGuaranteeLevel,
        #[serde(rename = "holdId")]
        pub hold_id: Identifier,
        #[serde(rename = "invocationQuotas")]
        pub invocation_quotas: ::std::vec::Vec<InvocationQuotaTransition>,
        #[serde(rename = "invocationState")]
        pub invocation_state: ::serde_json::Value,
        #[serde(
            rename = "leaderEpoch",
            default,
            skip_serializing_if = "::std::option::Option::is_none"
        )]
        pub leader_epoch: ::std::option::Option<::std::num::NonZeroU64>,
        #[serde(rename = "monetaryState")]
        pub monetary_state: ChioAuthoritativeAdmissionCaptureReceiptProjectionMonetaryState,
        #[serde(rename = "operationId")]
        pub operation_id: Identifier,
        #[serde(
            rename = "partitionEscrowEvidence",
            default,
            skip_serializing_if = "::std::option::Option::is_none"
        )]
        pub partition_escrow_evidence: ::std::option::Option<
            ChioAuthoritativeAdmissionCaptureReceiptProjectionPartitionEscrowEvidence,
        >,
        #[serde(rename = "revocationCommitIndex")]
        pub revocation_commit_index: u64,
    }
"#;
    const ROOT_REPLACEMENT: &str = r#"    #[derive(Clone, Debug)]
    pub struct ChioAuthoritativeAdmissionCaptureReceiptProjection {
        pub aggregate_root_binding_digest: ::std::option::Option<Digest>,
        pub aggregate_root_capability_id: ::std::option::Option<Identifier>,
        pub authority: Authority,
        pub authority_commit_index: u64,
        pub authorization_artifact_digests: Vec<Digest>,
        pub budget_commit_index: ::std::num::NonZeroU64,
        pub checked_revocation_set_digest: Digest,
        pub event_id: Identifier,
        pub guarantee_level: ChioAuthoritativeAdmissionCaptureReceiptProjectionGuaranteeLevel,
        pub hold_id: Identifier,
        pub invocation_quotas: ::std::vec::Vec<InvocationQuotaTransition>,
        pub invocation_state: ::serde_json::Value,
        pub leader_epoch: ::std::option::Option<::std::num::NonZeroU64>,
        pub monetary_state: ChioAuthoritativeAdmissionCaptureReceiptProjectionMonetaryState,
        pub operation_id: Identifier,
        pub partition_escrow_evidence: ::std::option::Option<
            ChioAuthoritativeAdmissionCaptureReceiptProjectionPartitionEscrowEvidence,
        >,
        pub revocation_commit_index: u64,
    }
"#;
    replace_generated_hardening_once(
        &mut module,
        ROOT_NEEDLE,
        ROOT_REPLACEMENT,
        "admission capture root",
    )?;

    const GUARANTEE_ENUM_NEEDLE: &str = r#"    pub enum ChioAuthoritativeAdmissionCaptureReceiptProjectionGuaranteeLevel {
        #[serde(rename = "single_node_atomic")]
        SingleNodeAtomic,
        #[serde(rename = "partition_escrowed")]
        PartitionEscrowed,
        #[serde(rename = "ha_linearizable")]
        HaLinearizable,
    }
"#;
    ensure_generated_hardening_once(
        &module,
        GUARANTEE_ENUM_NEEDLE,
        "admission capture guarantee enum",
    )?;

    const ROOT_FROM_NEEDLE: &str = r#"    impl ::std::convert::From<&ChioAuthoritativeAdmissionCaptureReceiptProjection>
    for ChioAuthoritativeAdmissionCaptureReceiptProjection {
"#;
    const ROOT_FROM_REPLACEMENT: &str = r#"    struct AdmissionCaptureOptionalField<T> {
        value: ::std::option::Option<T>,
        was_present: bool,
    }
    impl<T> ::std::default::Default for AdmissionCaptureOptionalField<T> {
        fn default() -> Self {
            Self {
                value: None,
                was_present: false,
            }
        }
    }
    impl<'de, T> ::serde::Deserialize<'de> for AdmissionCaptureOptionalField<T>
    where
        T: ::serde::Deserialize<'de>,
    {
        fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            let value = <::std::option::Option<T> as ::serde::Deserialize>::deserialize(
                deserializer,
            )?;
            Ok(Self {
                value,
                was_present: true,
            })
        }
    }
    #[derive(::serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ChioAuthoritativeAdmissionCaptureReceiptProjectionWire {
        #[serde(rename = "aggregateRootBindingDigest", default)]
        aggregate_root_binding_digest: ::std::option::Option<Digest>,
        #[serde(rename = "aggregateRootCapabilityId", default)]
        aggregate_root_capability_id: ::std::option::Option<Identifier>,
        authority: Authority,
        #[serde(rename = "authorityCommitIndex")]
        authority_commit_index: u64,
        #[serde(rename = "authorizationArtifactDigests")]
        authorization_artifact_digests: Vec<Digest>,
        #[serde(rename = "budgetCommitIndex")]
        budget_commit_index: ::std::num::NonZeroU64,
        #[serde(rename = "checkedRevocationSetDigest")]
        checked_revocation_set_digest: Digest,
        #[serde(rename = "eventId")]
        event_id: Identifier,
        #[serde(rename = "guaranteeLevel")]
        guarantee_level: ChioAuthoritativeAdmissionCaptureReceiptProjectionGuaranteeLevel,
        #[serde(rename = "holdId")]
        hold_id: Identifier,
        #[serde(rename = "invocationQuotas")]
        invocation_quotas: ::std::vec::Vec<InvocationQuotaTransition>,
        #[serde(rename = "invocationState")]
        invocation_state: ::serde_json::Value,
        #[serde(rename = "leaderEpoch", default)]
        leader_epoch: AdmissionCaptureOptionalField<::std::num::NonZeroU64>,
        #[serde(rename = "monetaryState")]
        monetary_state: ChioAuthoritativeAdmissionCaptureReceiptProjectionMonetaryState,
        #[serde(rename = "operationId")]
        operation_id: Identifier,
        #[serde(rename = "partitionEscrowEvidence", default)]
        partition_escrow_evidence: AdmissionCaptureOptionalField<
            ChioAuthoritativeAdmissionCaptureReceiptProjectionPartitionEscrowEvidence,
        >,
        #[serde(rename = "revocationCommitIndex")]
        revocation_commit_index: u64,
    }
    impl ChioAuthoritativeAdmissionCaptureReceiptProjection {
        fn validate_guarantee_evidence(
            &self,
            leader_epoch_present: bool,
            partition_escrow_evidence_present: bool,
        ) -> ::std::result::Result<(), &'static str> {
            use ChioAuthoritativeAdmissionCaptureReceiptProjectionGuaranteeLevel::{
                HaLinearizable, PartitionEscrowed, SingleNodeAtomic,
            };
            match self.guarantee_level {
                SingleNodeAtomic => {
                    if leader_epoch_present {
                        return Err("single_node_atomic admission capture forbids leaderEpoch");
                    }
                    if partition_escrow_evidence_present {
                        return Err(
                            "single_node_atomic admission capture forbids partitionEscrowEvidence",
                        );
                    }
                }
                PartitionEscrowed => {
                    if leader_epoch_present {
                        return Err("partition_escrowed admission capture forbids leaderEpoch");
                    }
                    if self.partition_escrow_evidence.is_none() {
                        return Err(
                            "partition_escrowed admission capture requires partitionEscrowEvidence",
                        );
                    }
                }
                HaLinearizable => {
                    if self.leader_epoch.is_none() {
                        return Err("ha_linearizable admission capture requires leaderEpoch");
                    }
                    if partition_escrow_evidence_present {
                        return Err(
                            "ha_linearizable admission capture forbids partitionEscrowEvidence",
                        );
                    }
                }
            }
            Ok(())
        }
    }
    impl<'de> ::serde::Deserialize<'de>
    for ChioAuthoritativeAdmissionCaptureReceiptProjection {
        fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
        where
            D: ::serde::Deserializer<'de>,
        {
            let wire = <ChioAuthoritativeAdmissionCaptureReceiptProjectionWire as ::serde::Deserialize>::deserialize(
                deserializer,
            )?;
            let leader_epoch_present = wire.leader_epoch.was_present;
            let partition_escrow_evidence_present = wire.partition_escrow_evidence.was_present;
            let value = Self {
                aggregate_root_binding_digest: wire.aggregate_root_binding_digest,
                aggregate_root_capability_id: wire.aggregate_root_capability_id,
                authority: wire.authority,
                authority_commit_index: wire.authority_commit_index,
                authorization_artifact_digests: wire.authorization_artifact_digests,
                budget_commit_index: wire.budget_commit_index,
                checked_revocation_set_digest: wire.checked_revocation_set_digest,
                event_id: wire.event_id,
                guarantee_level: wire.guarantee_level,
                hold_id: wire.hold_id,
                invocation_quotas: wire.invocation_quotas,
                invocation_state: wire.invocation_state,
                leader_epoch: wire.leader_epoch.value,
                monetary_state: wire.monetary_state,
                operation_id: wire.operation_id,
                partition_escrow_evidence: wire.partition_escrow_evidence.value,
                revocation_commit_index: wire.revocation_commit_index,
            };
            value
                .validate_guarantee_evidence(
                    leader_epoch_present,
                    partition_escrow_evidence_present,
                )
                .map_err(<D::Error as ::serde::de::Error>::custom)?;
            Ok(value)
        }
    }
    impl ::serde::Serialize for ChioAuthoritativeAdmissionCaptureReceiptProjection {
        fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
        where
            S: ::serde::Serializer,
        {
            self.validate_guarantee_evidence(
                self.leader_epoch.is_some(),
                self.partition_escrow_evidence.is_some(),
            )
                .map_err(<S::Error as ::serde::ser::Error>::custom)?;
            let mut state = serializer.serialize_struct(
                "ChioAuthoritativeAdmissionCaptureReceiptProjection",
                17,
            )?;
            if let Some(value) = &self.aggregate_root_binding_digest {
                ::serde::ser::SerializeStruct::serialize_field(
                    &mut state,
                    "aggregateRootBindingDigest",
                    value,
                )?;
            }
            if let Some(value) = &self.aggregate_root_capability_id {
                ::serde::ser::SerializeStruct::serialize_field(
                    &mut state,
                    "aggregateRootCapabilityId",
                    value,
                )?;
            }
            ::serde::ser::SerializeStruct::serialize_field(
                &mut state,
                "authority",
                &self.authority,
            )?;
            ::serde::ser::SerializeStruct::serialize_field(
                &mut state,
                "authorityCommitIndex",
                &self.authority_commit_index,
            )?;
            ::serde::ser::SerializeStruct::serialize_field(
                &mut state,
                "authorizationArtifactDigests",
                &self.authorization_artifact_digests,
            )?;
            ::serde::ser::SerializeStruct::serialize_field(
                &mut state,
                "budgetCommitIndex",
                &self.budget_commit_index,
            )?;
            ::serde::ser::SerializeStruct::serialize_field(
                &mut state,
                "checkedRevocationSetDigest",
                &self.checked_revocation_set_digest,
            )?;
            ::serde::ser::SerializeStruct::serialize_field(
                &mut state,
                "eventId",
                &self.event_id,
            )?;
            ::serde::ser::SerializeStruct::serialize_field(
                &mut state,
                "guaranteeLevel",
                &self.guarantee_level,
            )?;
            ::serde::ser::SerializeStruct::serialize_field(
                &mut state,
                "holdId",
                &self.hold_id,
            )?;
            ::serde::ser::SerializeStruct::serialize_field(
                &mut state,
                "invocationQuotas",
                &self.invocation_quotas,
            )?;
            ::serde::ser::SerializeStruct::serialize_field(
                &mut state,
                "invocationState",
                &self.invocation_state,
            )?;
            if let Some(value) = &self.leader_epoch {
                ::serde::ser::SerializeStruct::serialize_field(
                    &mut state,
                    "leaderEpoch",
                    value,
                )?;
            }
            ::serde::ser::SerializeStruct::serialize_field(
                &mut state,
                "monetaryState",
                &self.monetary_state,
            )?;
            ::serde::ser::SerializeStruct::serialize_field(
                &mut state,
                "operationId",
                &self.operation_id,
            )?;
            if let Some(value) = &self.partition_escrow_evidence {
                ::serde::ser::SerializeStruct::serialize_field(
                    &mut state,
                    "partitionEscrowEvidence",
                    value,
                )?;
            }
            ::serde::ser::SerializeStruct::serialize_field(
                &mut state,
                "revocationCommitIndex",
                &self.revocation_commit_index,
            )?;
            ::serde::ser::SerializeStruct::end(state)
        }
    }
    impl ::std::convert::From<&ChioAuthoritativeAdmissionCaptureReceiptProjection>
    for ChioAuthoritativeAdmissionCaptureReceiptProjection {
"#;
    replace_generated_hardening_once(
        &mut module,
        ROOT_FROM_NEEDLE,
        ROOT_FROM_REPLACEMENT,
        "admission capture validation",
    )?;

    body.replace_range(start..end, &module);
    Ok(body)
}

fn replace_generated_hardening_once(
    body: &mut String,
    needle: &str,
    replacement: &str,
    context: &str,
) -> Result<()> {
    ensure_generated_hardening_once(body, needle, context)?;
    *body = body.replacen(needle, replacement, 1);
    Ok(())
}

fn ensure_generated_hardening_once(body: &str, needle: &str, context: &str) -> Result<()> {
    if body.matches(needle).count() != 1 {
        return Err(CodegenError::GeneratedHardening(format!(
            "generated Rust {context} pattern is missing or ambiguous"
        )));
    }
    Ok(())
}

fn render_schema_module(
    path: &Path,
    schemas_dir: &Path,
    module_name: &str,
    schema_inventory: &BTreeSet<PathBuf>,
) -> Result<syn::ItemMod> {
    let value = load_schema_value(path, schemas_dir, schema_inventory)?;
    let schema: schemars::schema::RootSchema = serde_json::from_value(value)
        .map_err(|err| CodegenError::SchemaShape(path.to_path_buf(), err))?;
    let settings = TypeSpaceSettings::default();
    let mut type_space = TypeSpace::new(&settings);
    type_space
        .add_root_schema(schema)
        .map_err(|err| CodegenError::Typify(path.to_path_buf(), err.to_string()))?;

    let module_source = format!("pub mod {module_name} {{ {} }}", type_space.to_stream());
    syn::parse_str(&module_source).map_err(CodegenError::SynParse)
}

fn schema_module_name(path: &Path, schemas_dir: &Path) -> Result<String> {
    let relative = path.strip_prefix(schemas_dir).map_err(|_| {
        CodegenError::SchemaRef(
            path.to_path_buf(),
            format!("schema is outside {}", schemas_dir.display()),
        )
    })?;
    let components: Vec<&OsStr> = relative.iter().collect();
    let Some((file_name, directories)) = components.split_last() else {
        return Err(CodegenError::SchemaRef(
            path.to_path_buf(),
            "schema path has no file name".to_string(),
        ));
    };
    let file_name = file_name.to_str().ok_or_else(|| {
        CodegenError::SchemaRef(
            path.to_path_buf(),
            "schema file name is not valid UTF-8".to_string(),
        )
    })?;
    let stem = file_name.strip_suffix(".schema.json").ok_or_else(|| {
        CodegenError::SchemaRef(
            path.to_path_buf(),
            "schema file name does not end in .schema.json".to_string(),
        )
    })?;

    let mut module_parts = Vec::with_capacity(components.len());
    for directory in directories {
        let directory = directory.to_str().ok_or_else(|| {
            CodegenError::SchemaRef(
                path.to_path_buf(),
                "schema directory name is not valid UTF-8".to_string(),
            )
        })?;
        module_parts.push(normalize_module_component(directory));
    }
    module_parts.push(normalize_module_component(stem));

    let mut module_name = module_parts.join("__");
    if module_name.is_empty() {
        return Err(CodegenError::SchemaRef(
            path.to_path_buf(),
            "schema path normalizes to an empty Rust module name".to_string(),
        ));
    }
    if module_name
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_digit)
        || is_rust_keyword(&module_name)
    {
        module_name.insert_str(0, "schema_");
    }
    Ok(module_name)
}

fn normalize_module_component(component: &str) -> String {
    component
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn is_rust_keyword(value: &str) -> bool {
    matches!(
        value,
        "as" | "async"
            | "await"
            | "break"
            | "const"
            | "continue"
            | "crate"
            | "dyn"
            | "else"
            | "enum"
            | "extern"
            | "false"
            | "final"
            | "fn"
            | "for"
            | "if"
            | "impl"
            | "in"
            | "let"
            | "loop"
            | "macro"
            | "match"
            | "mod"
            | "move"
            | "override"
            | "priv"
            | "pub"
            | "ref"
            | "return"
            | "self"
            | "static"
            | "struct"
            | "super"
            | "trait"
            | "true"
            | "try"
            | "type"
            | "typeof"
            | "union"
            | "unsafe"
            | "unsized"
            | "use"
            | "virtual"
            | "where"
            | "while"
            | "yield"
    )
}
