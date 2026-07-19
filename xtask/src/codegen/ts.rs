use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::support::{
    authoritative_schema_json_inventory, display_path, hash_schema_inventory,
    validate_workspace_subdirectory, workspace_root, TempDir,
};
use crate::XtaskError;

use super::CHIO_WIRE_V1_SCHEMAS;

/// Relative path (from workspace root) of the directory that hosts the
/// pinned json-schema-to-typescript install. The xtask invokes
/// `<scripts>/node_modules/.bin/json2ts` directly so the dispatcher does not
/// depend on `npx` resolution; the caller is responsible for running
/// `npm ci` (or equivalent) inside the scripts dir before invoking codegen.
const TS_CODEGEN_SCRIPTS_DIR: &str = "sdks/typescript/scripts";
/// Relative path (from workspace root) of the generated TS output file.
const CHIO_WIRE_V1_TS_OUT: &str = "sdks/typescript/packages/conformance/src/_generated/index.ts";
/// Pinned json-schema-to-typescript version stamped into the file header so
/// auditors can confirm the generator without opening the lockfile. Must
/// match the [typescript] block in `xtask/codegen-tools.lock.toml`.
const TS_CODEGEN_TOOL_VERSION: &str = "json-schema-to-typescript 15.0.4";

pub(super) fn codegen_ts(check_only: bool) -> Result<(), XtaskError> {
    let workspace_root = workspace_root()?;
    let schemas_dir = workspace_root.join(CHIO_WIRE_V1_SCHEMAS);
    let out_path = workspace_root.join(CHIO_WIRE_V1_TS_OUT);
    let scripts_dir = workspace_root.join(TS_CODEGEN_SCRIPTS_DIR);

    if !schemas_dir.exists() {
        return Err(XtaskError::Usage(format!(
            "codegen ts: schemas directory missing: {}",
            display_path(&schemas_dir)
        )));
    }
    validate_workspace_subdirectory(&workspace_root, &schemas_dir)?;
    let json2ts = scripts_dir.join("node_modules/.bin/json2ts");
    if !json2ts.exists() {
        return Err(XtaskError::Usage(format!(
            "codegen ts: json2ts not installed at {}; run `npm ci` in {} first \
             (toolchain pin: {} per xtask/codegen-tools.lock.toml)",
            display_path(&json2ts),
            display_path(&scripts_dir),
            TS_CODEGEN_TOOL_VERSION
        )));
    }

    let schema_files = authoritative_schema_json_inventory(&workspace_root, &schemas_dir)?;
    if schema_files.is_empty() {
        return Err(XtaskError::Usage(format!(
            "codegen ts: no *.schema.json files under {}",
            display_path(&schemas_dir)
        )));
    }

    let schema_sha = hash_schema_inventory(&workspace_root, &schema_files)?;

    let staging = TempDir::new("chio-codegen-ts")
        .map_err(|err| XtaskError::Io("<temp staging dir for codegen ts>".to_string(), err))?;
    let clean_input = staging.path().join("input");
    super::python::mirror_schema_tree(&schemas_dir, &clean_input, &schema_files)?;

    // Render each schema in isolation, then wrap each emitted file in a
    // namespace keyed by its `<group>/<name>` path so the cross-schema name
    // collisions (e.g., `Operation` between capability/grant and
    // capability/token) do not surface at the module top level.
    let mut body = String::with_capacity(64 * 1024);
    body.push_str(&ts_header(&schema_sha));
    let mut namespace_sources = BTreeMap::new();
    for path in &schema_files {
        let rel = path.strip_prefix(&workspace_root).map_err(|_| {
            XtaskError::Usage(format!(
                "codegen ts: schema {} is not under workspace root",
                display_path(path)
            ))
        })?;
        let rel_str = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        let ns_name = ts_namespace_name(path).ok_or_else(|| {
            XtaskError::Usage(format!(
                "codegen ts: cannot derive namespace name from {}",
                display_path(path)
            ))
        })?;
        if let Some(first) = namespace_sources.insert(ns_name.clone(), rel_str.clone()) {
            return Err(XtaskError::Usage(format!(
                "codegen ts: schema paths {first} and {rel_str} both normalize to namespace {ns_name}"
            )));
        }
        let schema_relative_path = path.strip_prefix(&schemas_dir).map_err(|_| {
            XtaskError::Usage(format!(
                "codegen ts: schema {} is not under schema root {}",
                display_path(path),
                display_path(&schemas_dir)
            ))
        })?;
        let raw_ts = run_json2ts(&json2ts, &clean_input.join(schema_relative_path))?;
        let normalized = normalize_ts_chunk(&raw_ts);
        let normalized = if ns_name == "Security_DetectorHealthReceiptBodyV1" {
            harden_detector_health_ts_chunk(&normalized)?
        } else {
            normalized
        };
        body.push_str(
            "// -----------------------------------------------------------------------------\n",
        );
        body.push_str(&format!("// Source: {rel_str}\n"));
        body.push_str(&format!("export namespace {ns_name} {{\n"));
        for line in normalized.lines() {
            if line.is_empty() {
                body.push('\n');
            } else {
                body.push_str("  ");
                body.push_str(line);
                body.push('\n');
            }
        }
        body.push_str("}\n\n");
    }
    // Trim the trailing extra newline so the file ends with exactly one '\n'.
    while body.ends_with("\n\n") {
        body.pop();
    }

    if check_only {
        if !out_path.exists() {
            return Err(XtaskError::Drift(format!(
                "{} is missing; rerun `cargo xtask codegen --lang ts`",
                display_path(&out_path)
            )));
        }
        let existing = fs::read_to_string(&out_path)
            .map_err(|err| XtaskError::Io(display_path(&out_path), err))?;
        if existing != body {
            return Err(XtaskError::Drift(format!(
                "{} is stale; rerun `cargo xtask codegen --lang ts` (computed {} bytes, on-disk {} bytes)",
                display_path(&out_path),
                body.len(),
                existing.len()
            )));
        }
        println!(
            "codegen ts: {} in sync ({} bytes, {} schemas, schema-sha {})",
            display_path(&out_path),
            existing.len(),
            schema_files.len(),
            &schema_sha[..16]
        );
        return Ok(());
    }

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).map_err(|err| XtaskError::Io(display_path(parent), err))?;
    }
    fs::write(&out_path, body.as_bytes())
        .map_err(|err| XtaskError::Io(display_path(&out_path), err))?;
    println!(
        "codegen ts: wrote {} ({} bytes, {} schemas, schema-sha {})",
        display_path(&out_path),
        body.len(),
        schema_files.len(),
        &schema_sha[..16]
    );
    Ok(())
}

/// Render the canonical header for the generated TypeScript file. The
/// phrasing mirrors `chio_spec_codegen::GENERATED_HEADER` so an auditor
/// scanning either tree sees the same shape.
pub(crate) fn ts_header(schema_sha: &str) -> String {
    let mut header = String::new();
    header.push_str("// DO NOT EDIT - regenerate via 'cargo xtask codegen --lang ts'.\n");
    header.push_str("//\n");
    header.push_str("// Source:     spec/schemas/chio-wire/v1/**/*.schema.json\n");
    header.push_str(&format!(
        "// Tool:       {TS_CODEGEN_TOOL_VERSION} (see xtask/codegen-tools.lock.toml)\n"
    ));
    header.push_str("// Pin file:   sdks/typescript/scripts/package.json\n");
    header.push_str(&format!("// Schema SHA: {schema_sha}\n"));
    header.push_str("//\n");
    header.push_str("// The schema-sha above is sha256 of `<rel-path>\\0<bytes>\\0` for every\n");
    header.push_str("// schema in lex order. It changes whenever any schema under\n");
    header.push_str("// spec/schemas/chio-wire/v1/ changes. The spec-drift CI lane\n");
    header.push_str("// asserts byte-equality of this entire file via `--check` mode.\n");
    header.push('\n');
    header.push_str("/* eslint-disable */\n");
    header.push('\n');
    header
}

/// Derive a TypeScript namespace name from a schema path under
/// `spec/schemas/chio-wire/v1/`. The schema at
/// `chio-wire/v1/capability/grant.schema.json` becomes `Capability_Grant`;
/// `trust-control/lease.schema.json` becomes `TrustControl_Lease`. The
/// underscore separator keeps the group prefix readable while remaining a
/// valid TypeScript identifier.
pub(crate) fn ts_namespace_name(schema_path: &Path) -> Option<String> {
    let stem = schema_path
        .file_name()
        .and_then(OsStr::to_str)?
        .strip_suffix(".schema.json")?;
    let group = schema_path
        .parent()
        .and_then(Path::file_name)
        .and_then(OsStr::to_str)?;
    let group_pascal = pascal_case(group);
    let stem_pascal = pascal_case(stem);
    if group_pascal.is_empty() || stem_pascal.is_empty() {
        return None;
    }
    Some(format!("{group_pascal}_{stem_pascal}"))
}

/// Convert a kebab/snake-cased identifier to PascalCase. Non-alphanumeric
/// characters split words; the first char of each word is upper-cased.
pub(crate) fn pascal_case(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut upper_next = true;
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            if upper_next {
                for u in ch.to_uppercase() {
                    out.push(u);
                }
                upper_next = false;
            } else {
                out.push(ch);
            }
        } else {
            upper_next = true;
        }
    }
    out
}

/// Run `json2ts` against a single schema file and return the captured
/// stdout. Errors include the schema path so deviations surface clearly.
fn run_json2ts(json2ts: &Path, schema: &Path) -> Result<String, XtaskError> {
    let output = Command::new(json2ts)
        .arg("-i")
        .arg(schema)
        // Resolve the schema's own directory as the working directory so cross-file
        // relative `$ref`s (e.g. `../receipt/record.schema.json`) resolve against the
        // schema file rather than the process working directory. The json2ts CLI
        // defaults its cwd to the process cwd (unlike the library's compileFromFile),
        // so without this a cross-file ref fails with ENOENT when xtask runs from the
        // workspace root.
        .arg("--cwd")
        .arg(schema.parent().unwrap_or_else(|| Path::new(".")))
        .arg("--no-bannerComment")
        .arg("--unreachableDefinitions=false")
        .arg("--strictIndexSignatures=false")
        .arg("--additionalProperties=false")
        .output()
        .map_err(|err| {
            XtaskError::Process(format!(
                "failed to spawn {} for schema {}: {err}",
                display_path(json2ts),
                display_path(schema)
            ))
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(XtaskError::Process(format!(
            "json2ts exited {} for schema {}: {}",
            output.status,
            display_path(schema),
            stderr.trim()
        )));
    }
    let stdout = String::from_utf8(output.stdout).map_err(|err| {
        XtaskError::Process(format!(
            "json2ts produced non-UTF8 output for {}: {err}",
            display_path(schema)
        ))
    })?;
    Ok(stdout)
}

/// Normalize a json2ts emission so it composes inside a namespace block.
/// `run_json2ts` passes `--no-bannerComment`, so per-chunk banner comments
/// are already absent; this function only collapses the trailing blank-line
/// padding that `prettier` (the json2ts formatter) appends.
pub(crate) fn normalize_ts_chunk(raw: &str) -> String {
    let trimmed = raw.trim_end_matches(['\n', '\r']);
    trimmed.to_string()
}

fn harden_detector_health_ts_chunk(raw: &str) -> Result<String, XtaskError> {
    let needle = r#"export type ChioDetectorHealthReceiptBodyV1 = {
  [k: string]: unknown;
} & {
  event_id: Identifier;
  evidence_hash: Digest;
  group_binding: GroupBinding;
  header: Header;
  health_kind:
    | "corrupt_event"
    | "corrupt_state"
    | "state_overflow"
    | "store_conflict"
    | "store_unavailable"
    | "truncated_scan";
  policy: Policy;
  rule_id: Identifier;
  rule_version_hash: Digest;
  watermark: Watermark;
};"#;
    let replacement = r#"export type HealthKind =
  | "corrupt_event"
  | "corrupt_state"
  | "state_overflow"
  | "store_conflict"
  | "store_unavailable"
  | "truncated_scan";
export interface DetectorHealthReceiptBase {
  event_id: Identifier;
  evidence_hash: Digest;
  header: Header;
  policy: Policy;
  rule_id: Identifier;
  rule_version_hash: Digest;
}
export type ChioDetectorHealthReceiptBodyV1 = DetectorHealthReceiptBase &
  (
    | {
        group_binding: Extract<GroupBinding, { kind: "unresolved" }>;
        health_kind: HealthKind;
        watermark: Extract<Watermark, { kind: "unknown" }>;
      }
    | {
        group_binding: Extract<GroupBinding, { kind: "resolved" }>;
        health_kind: HealthKind;
        watermark: Exclude<Watermark, { kind: "contradictory" }>;
      }
    | {
        group_binding: Extract<GroupBinding, { kind: "resolved" }>;
        health_kind: "corrupt_state";
        watermark: Extract<Watermark, { kind: "contradictory" }>;
      }
  );"#;
    if !raw.contains(needle) {
        return Err(XtaskError::ToolFailed(
            "codegen ts detector health hardening pattern missing".to_string(),
        ));
    }
    if raw.matches(needle).count() != 1 {
        return Err(XtaskError::ToolFailed(
            "codegen ts detector health hardening pattern is ambiguous".to_string(),
        ));
    }
    Ok(raw.replacen(needle, replacement, 1))
}
