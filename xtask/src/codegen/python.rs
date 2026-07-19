use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::support::{
    authoritative_schema_json_inventory, copy_dir_recursive, display_path, hash_schema_inventory,
    validate_workspace_subdirectory, workspace_root, TempDir,
};
use crate::XtaskError;

use super::CHIO_WIRE_V1_SCHEMAS;

/// Pinned tool spec for the Python codegen target. Reflected in
/// `[python]` in `xtask/codegen-tools.lock.toml`. Bumping this is a
/// spec-affecting change and must regenerate every `_generated/*.py` byte.
const PYTHON_CODEGEN_TOOL_PIN: &str = "datamodel-code-generator==0.34.0";

/// Relative path (from workspace root) of the generated Python output dir.
const CHIO_WIRE_V1_PYTHON_OUT: &str = "sdks/python/chio-sdk-python/src/chio_sdk/_generated";

/// Filename of the per-package `__init__.py` re-export written under each
/// generated subpackage. The xtask does not author these; datamodel-codegen
/// emits them as part of its directory-mode output.
const PYTHON_INIT_FILE: &str = "__init__.py";

pub(super) fn codegen_python(check_only: bool) -> Result<(), XtaskError> {
    let workspace_root = workspace_root()?;
    let schemas_dir = workspace_root.join(CHIO_WIRE_V1_SCHEMAS);
    let final_out_dir = workspace_root.join(CHIO_WIRE_V1_PYTHON_OUT);

    if !schemas_dir.exists() {
        return Err(XtaskError::Codegen(
            chio_spec_codegen::CodegenError::SchemasDirMissing(schemas_dir.clone()),
        ));
    }
    validate_workspace_subdirectory(&workspace_root, &schemas_dir)?;

    let schema_files = authoritative_schema_json_inventory(&workspace_root, &schemas_dir)?;
    let expected_modules = python_module_inventory(&schemas_dir, &schema_files)?;
    let schema_digest = hash_schema_inventory(&workspace_root, &schema_files)?;

    let staging = TempDir::new("chio-codegen-py")
        .map_err(|err| XtaskError::Io("<temp staging dir for codegen python>".to_string(), err))?;

    let clean_input = staging.path().join("input");
    mirror_schema_tree(&schemas_dir, &clean_input, &schema_files)?;

    let staging_out = staging.path().join("output");
    fs::create_dir_all(&staging_out)
        .map_err(|err| XtaskError::Io(display_path(&staging_out), err))?;

    let header_path = staging.path().join("file-header.txt");
    fs::write(&header_path, build_python_file_header(&schema_digest))
        .map_err(|err| XtaskError::Io(display_path(&header_path), err))?;

    invoke_datamodel_codegen(&clean_input, &staging_out, &header_path)?;
    validate_python_generated_inventory(&staging_out, &expected_modules)?;
    harden_python_generated_models(&staging_out)?;

    // Walk the freshly-generated tree and rewrite each subpackage's
    // `__init__.py` to re-export its top-level model classes. The
    // top-level `__init__.py` then star-imports every subpackage. Together
    // these provide the documented `from chio_sdk._generated import
    // CapabilityToken` import path; without this step datamodel-codegen's
    // empty subpackage init files cause that import to raise `ImportError`.
    let subpackage_exports = rewrite_python_subpackage_inits(&staging_out, &schema_digest)?;

    let top_init = staging_out.join(PYTHON_INIT_FILE);
    fs::write(
        &top_init,
        build_python_top_init(&schema_digest, &subpackage_exports),
    )
    .map_err(|err| XtaskError::Io(display_path(&top_init), err))?;

    if check_only {
        let drift = diff_python_trees(&staging_out, &final_out_dir)?;
        if let Some(detail) = drift {
            return Err(XtaskError::Drift(format!(
                "{} is stale; rerun `cargo xtask codegen python` ({} schema files inspected)\n{}",
                display_path(&final_out_dir),
                schema_files.len(),
                detail
            )));
        }
        println!(
            "codegen python: {} in sync ({} schema files, {} python files)",
            display_path(&final_out_dir),
            schema_files.len(),
            count_python_files(&staging_out)?
        );
        return Ok(());
    }

    if final_out_dir.exists() {
        fs::remove_dir_all(&final_out_dir)
            .map_err(|err| XtaskError::Io(display_path(&final_out_dir), err))?;
    }
    if let Some(parent) = final_out_dir.parent() {
        fs::create_dir_all(parent).map_err(|err| XtaskError::Io(display_path(parent), err))?;
    }
    copy_dir_recursive(&staging_out, &final_out_dir)?;
    let py_count = count_python_files(&final_out_dir)?;
    println!(
        "codegen python: wrote {} ({} python files; {} schema files; sha256={})",
        display_path(&final_out_dir),
        py_count,
        schema_files.len(),
        schema_digest
    );
    Ok(())
}

fn build_python_file_header(schema_digest: &str) -> String {
    format!(
        "# DO NOT EDIT - regenerate via 'cargo xtask codegen --lang python'.\n\
         #\n\
         # Source: spec/schemas/chio-wire/v1/**/*.schema.json\n\
         # Tool:   {PYTHON_CODEGEN_TOOL_PIN} (see xtask/codegen-tools.lock.toml)\n\
         # Schema sha256: {schema_digest}\n\
         #\n\
         # Manual edits will be overwritten by the next regeneration; the\n\
         # spec-drift CI lane enforces this header on every file\n\
         # under sdks/python/chio-sdk-python/src/chio_sdk/_generated/.\n"
    )
}

fn harden_python_generated_models(root_dir: &Path) -> Result<(), XtaskError> {
    harden_python_jsonrpc_response(&root_dir.join("jsonrpc").join("response_schema.py"))?;
    harden_python_receipt_record(&root_dir.join("receipt").join("record_schema.py"))?;
    harden_python_provenance_verdict_link(
        &root_dir.join("provenance").join("verdict_link_schema.py"),
    )?;
    harden_python_capability_negotiation(
        &root_dir.join("capability").join("capabilities_schema.py"),
    )?;
    harden_python_detector_health(
        &root_dir
            .join("security")
            .join("detector_health_receipt_body_v1_schema.py"),
    )?;
    Ok(())
}

fn harden_python_detector_health(path: &Path) -> Result<(), XtaskError> {
    let mut body =
        fs::read_to_string(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "from pydantic import BaseModel, ConfigDict, Field, RootModel",
        "from pydantic import (\n    BaseModel,\n    ConfigDict,\n    Field,\n    RootModel,\n    model_serializer,\n    model_validator,\n)",
    )?;
    insert_python_class_member(
        path,
        &mut body,
        "Digest",
        "    model_config = ConfigDict(validate_assignment=True)\n\n    @model_validator(mode=\"after\")\n    def _reject_zero_digest(self) -> \"Digest\":\n        if all(item.root == 0 for item in self.root):\n            raise ValueError(\"detector health digest must not be all zero\")\n        return self",
    )?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "class ChioDetectorHealthReceiptBodyV1(BaseModel):\n    model_config = ConfigDict(\n        extra=\"forbid\",\n    )",
        "class ChioDetectorHealthReceiptBodyV1(BaseModel):\n    model_config = ConfigDict(\n        extra=\"forbid\",\n        validate_assignment=True,\n    )",
    )?;
    insert_python_class_member(
        path,
        &mut body,
        "ChioDetectorHealthReceiptBodyV1",
        "    @model_validator(mode=\"after\")\n    def _validate_detector_health(self) -> \"ChioDetectorHealthReceiptBodyV1\":\n        group = self.group_binding.root\n        group_kind = group.kind\n        watermark = self.watermark.root\n        watermark_kind = watermark.kind\n        observed = self.header.occurred_at_unix_ms.root\n        if observed < 1 or observed > 9007199254740991:\n            raise ValueError(\"detector health observation time is outside the portable range\")\n        digests = (\n            self.evidence_hash,\n            self.policy.policy_hash,\n            self.rule_version_hash,\n        )\n        if any(all(item.root == 0 for item in digest.root) for digest in digests):\n            raise ValueError(\"detector health digest must not be all zero\")\n        if group_kind == \"resolved\" and all(\n            item.root == 0 for item in group.group_key_hash.root\n        ):\n            raise ValueError(\"resolved detector group hash must not be all zero\")\n        if group_kind == \"unresolved\" and watermark_kind != \"unknown\":\n            raise ValueError(\"unresolved detector group cannot assert watermark knowledge\")\n        if watermark_kind == \"committed\":\n            committed = watermark.unix_ms.root\n            if committed < 1 or committed > 9007199254740991:\n                raise ValueError(\"committed detector watermark is outside the portable range\")\n            if committed > observed:\n                raise ValueError(\"committed detector watermark is after the observation\")\n        if watermark_kind == \"contradictory\":\n            if group_kind != \"resolved\" or self.health_kind is not HealthKind.corrupt_state:\n                raise ValueError(\"contradictory detector watermark requires resolved corrupt state\")\n            claimed = int(watermark.claimed_unix_ms)\n            if claimed > 18446744073709551615:\n                raise ValueError(\"contradictory detector watermark exceeds u64\")\n            if claimed != 0 and claimed <= observed and claimed <= 9007199254740991:\n                raise ValueError(\"contradictory detector watermark carries a valid committed value\")\n        return self\n\n    @model_serializer(mode=\"wrap\")\n    def _serialize_validated(self, handler):\n        self._validate_detector_health()\n        return handler(self)",
    )?;
    fs::write(path, body).map_err(|err| XtaskError::Io(display_path(path), err))
}

/// Enforce receipt schema constraints that datamodel-code-generator does not
/// currently express for dependent BBS fields.
fn harden_python_receipt_record(path: &Path) -> Result<(), XtaskError> {
    let mut body =
        fs::read_to_string(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "from pydantic import BaseModel, ConfigDict, Field, RootModel",
        "from pydantic import BaseModel, ConfigDict, Field, RootModel, model_validator",
    )?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "    bbs_projection_version: Annotated[\n        Literal[\"chio.bbs-projection.receipt.v1\"],\n        Field(\n            description=\"Receipt-body BBS projection version bound into the receipt id when bbs_signature is present.\"\n        ),\n    ] = \"chio.bbs-projection.receipt.v1\"\n",
        "    bbs_projection_version: Annotated[\n        Literal[\"chio.bbs-projection.receipt.v1\"] | None,\n        Field(\n            description=\"Receipt-body BBS projection version bound into the receipt id when bbs_signature is present.\"\n        ),\n    ] = None\n",
    )?;
    insert_python_class_member(
        path,
        &mut body,
        "ChioReceiptRecord",
        "    @model_validator(mode=\"after\")\n    def _validate_bbs_pairing(self) -> \"ChioReceiptRecord\":\n        has_projection = self.bbs_projection_version is not None\n        has_signature = self.bbs_signature is not None\n        if has_projection != has_signature:\n            raise ValueError(\n                \"bbs_projection_version and bbs_signature must be present together\"\n            )\n        return self",
    )?;
    fs::write(path, body).map_err(|err| XtaskError::Io(display_path(path), err))
}

/// Inject a `model_validator` on `ChioCapabilityNegotiationV1` that
/// enforces the schema's `propertyNames` regex pattern on each feature
/// key. `datamodel-code-generator` drops `propertyNames` constraints,
/// which would let a Python peer accept negotiation payloads that the
/// Rust verifier rejects (`CapabilityNegotiation::validate`). Mirror
/// the wire-side check here so cross-language consumers fail closed
/// in the same place.
fn harden_python_capability_negotiation(path: &Path) -> Result<(), XtaskError> {
    let mut body =
        fs::read_to_string(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "from pydantic import BaseModel, ConfigDict, Field",
        "import re\n\nfrom pydantic import BaseModel, ConfigDict, Field, model_validator",
    )?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "from pydantic import BaseModel, ConfigDict, Field, model_validator\n",
        "from pydantic import BaseModel, ConfigDict, Field, model_validator\n\n_CHIO_FEATURE_NAME_RE = re.compile(r\"^[a-z0-9_.-]{1,96}$\")\n",
    )?;
    insert_python_class_member(
        path,
        &mut body,
        "ChioCapabilityNegotiationV1",
        "    @model_validator(mode=\"after\")\n    def _validate_feature_names(self) -> \"ChioCapabilityNegotiationV1\":\n        if self.features is None:\n            return self\n        for name in self.features:\n            if not _CHIO_FEATURE_NAME_RE.match(name):\n                raise ValueError(\n                    f\"capability feature name {name!r} does not match \"\n                    f\"propertyNames pattern ^[a-z0-9_.-]{{1,96}}$\"\n                )\n        return self",
    )?;
    fs::write(path, body).map_err(|err| XtaskError::Io(display_path(path), err))
}

fn harden_python_jsonrpc_response(path: &Path) -> Result<(), XtaskError> {
    let mut body =
        fs::read_to_string(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "from pydantic import BaseModel, ConfigDict, Field, RootModel",
        "from pydantic import BaseModel, ConfigDict, Field, RootModel, model_validator",
    )?;
    insert_python_class_member(
        path,
        &mut body,
        "ChioJsonRpc20Response1",
        "    @model_validator(mode=\"after\")\n    def _success_excludes_error(self) -> \"ChioJsonRpc20Response1\":\n        if \"error\" in self.model_fields_set:\n            raise ValueError(\"JSON-RPC success response must not include error\")\n        return self",
    )?;
    insert_python_class_member(
        path,
        &mut body,
        "ChioJsonRpc20Response2",
        "    @model_validator(mode=\"after\")\n    def _error_excludes_result(self) -> \"ChioJsonRpc20Response2\":\n        if \"result\" in self.model_fields_set:\n            raise ValueError(\"JSON-RPC error response must not include result\")\n        return self",
    )?;
    fs::write(path, body).map_err(|err| XtaskError::Io(display_path(path), err))
}

fn harden_python_provenance_verdict_link(path: &Path) -> Result<(), XtaskError> {
    let mut body =
        fs::read_to_string(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
    replace_python_codegen_snippet(
        path,
        &mut body,
        "from pydantic import BaseModel, ConfigDict, Field, RootModel",
        "from pydantic import BaseModel, ConfigDict, Field, RootModel, model_validator",
    )?;
    insert_python_class_member(
        path,
        &mut body,
        "ChioProvenanceVerdictLink1",
        "    @model_validator(mode=\"after\")\n    def _allow_excludes_rejection_fields(self) -> \"ChioProvenanceVerdictLink1\":\n        if \"reason\" in self.model_fields_set or \"guard\" in self.model_fields_set:\n            raise ValueError(\"allow verdict must not include reason or guard\")\n        return self",
    )?;
    insert_python_class_member(
        path,
        &mut body,
        "ChioProvenanceVerdictLink3",
        "    @model_validator(mode=\"after\")\n    def _cancel_excludes_guard(self) -> \"ChioProvenanceVerdictLink3\":\n        if \"guard\" in self.model_fields_set:\n            raise ValueError(\"cancel verdict must not include guard\")\n        return self",
    )?;
    insert_python_class_member(
        path,
        &mut body,
        "ChioProvenanceVerdictLink4",
        "    @model_validator(mode=\"after\")\n    def _incomplete_excludes_guard(self) -> \"ChioProvenanceVerdictLink4\":\n        if \"guard\" in self.model_fields_set:\n            raise ValueError(\"incomplete verdict must not include guard\")\n        return self",
    )?;
    fs::write(path, body).map_err(|err| XtaskError::Io(display_path(path), err))
}

fn replace_python_codegen_snippet(
    path: &Path,
    body: &mut String,
    needle: &str,
    replacement: &str,
) -> Result<(), XtaskError> {
    if !body.contains(needle) {
        return Err(XtaskError::ToolFailed(format!(
            "codegen python hardening pattern missing in {}",
            display_path(path)
        )));
    }
    *body = body.replacen(needle, replacement, 1);
    Ok(())
}

fn insert_python_class_member(
    path: &Path,
    body: &mut String,
    class_name: &str,
    member: &str,
) -> Result<(), XtaskError> {
    let class_marker = format!("class {class_name}(");
    let class_start = body.find(&class_marker).ok_or_else(|| {
        XtaskError::ToolFailed(format!(
            "codegen python class {class_name} missing in {}",
            display_path(path)
        ))
    })?;
    if body[class_start + class_marker.len()..].contains(&class_marker) {
        return Err(XtaskError::ToolFailed(format!(
            "codegen python class {class_name} is ambiguous in {}",
            display_path(path)
        )));
    }
    let class_body_start = body[class_start..]
        .find('\n')
        .map(|offset| class_start + offset + 1)
        .ok_or_else(|| {
            XtaskError::ToolFailed(format!(
                "codegen python class {class_name} has no body in {}",
                display_path(path)
            ))
        })?;
    let class_end = body[class_body_start..]
        .find("\nclass ")
        .map_or(body.len(), |offset| class_body_start + offset);
    let member_name = member
        .lines()
        .find_map(|line| line.trim_start().strip_prefix("def "))
        .and_then(|line| line.split_once('(').map(|(name, _)| name));
    if member_name.is_some_and(|name| body[class_body_start..class_end].contains(name)) {
        return Err(XtaskError::ToolFailed(format!(
            "codegen python class {class_name} already contains injected member in {}",
            display_path(path)
        )));
    }
    body.insert_str(class_end, &format!("\n{member}\n"));
    Ok(())
}

/// Per-subpackage re-export plan built by [`rewrite_python_subpackage_inits`].
///
/// Each entry is `(subpackage_dir_name, [class_name, ...])` sorted by
/// `subpackage_dir_name`. Class names are sorted within each subpackage so
/// the output is byte-stable across regenerations on different filesystems.
type PythonSubpackageExports = Vec<(String, Vec<String>)>;

fn build_python_top_init(schema_digest: &str, subpackages: &PythonSubpackageExports) -> String {
    let header = build_python_file_header(schema_digest);

    // Build the deterministic re-export block. Each line is
    // `from .<subpkg> import <Class1>, <Class2>` plus an `__all__` listing
    // every re-exported name and the SCHEMA_SHA256 constant.
    //
    // Names that collide across subpackages (e.g. `Kind` defined in both
    // `anchor` and `capability`) are imported with a `<Subpkg><Name>` alias
    // so the top-level `__init__.py` does not silently shadow one with the
    // other. Both aliases are listed in `__all__`. The unaliased name is
    // kept only when a single subpackage owns it.
    let mut name_owners: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (subpkg, classes) in subpackages {
        for class in classes {
            if subpkg == "agent" && class == "CapabilityToken" {
                continue;
            }
            name_owners
                .entry(class.clone())
                .or_default()
                .push(subpkg.clone());
        }
    }

    let mut imports = String::new();
    let mut all_names: Vec<String> = vec!["SCHEMA_SHA256".to_string()];
    for (subpkg, classes) in subpackages {
        let mut entries: Vec<String> = Vec::new();
        for class in classes {
            if subpkg == "agent" && class == "CapabilityToken" {
                continue;
            }
            let owners = name_owners.get(class).map(Vec::as_slice).unwrap_or(&[]);
            if owners.len() > 1 {
                // Collision across subpackages: alias as <Subpkg><Class>.
                let alias = format!("{}{}", capitalize_subpkg(subpkg), class);
                entries.push(format!("{class} as {alias}"));
                all_names.push(alias);
            } else {
                entries.push(class.clone());
                all_names.push(class.clone());
            }
        }
        if entries.is_empty() {
            continue;
        }
        imports.push_str(&format!(
            "from .{subpkg} import {names}\n",
            names = entries.join(", ")
        ));
    }
    let has_capability_v1 = subpackages.iter().any(|(subpkg, classes)| {
        subpkg == "capability" && classes.iter().any(|name| name == "ChioCapabilitytoken")
    });
    if has_capability_v1 {
        imports.push_str("\nCapabilityToken = ChioCapabilitytoken\n");
        all_names.push("CapabilityToken".to_string());
    }
    all_names.sort();
    all_names.dedup();

    let mut all_block = String::from("__all__ = [\n");
    for name in &all_names {
        all_block.push_str(&format!("    \"{name}\",\n"));
    }
    all_block.push_str("]\n");

    format!(
        "{header}\n\
         \"\"\"Generated Pydantic v2 models for the Chio wire protocol (chio-wire/v1).\n\
         \n\
         Re-exports every subpackage so callers can write\n\
         ``from chio_sdk._generated import CapabilityToken`` for the canonical\n\
         capability token shapes without knowing the per-subpackage layout. Class\n\
         names that collide across subpackages (for example ``Kind`` defined in\n\
         both ``anchor`` and ``capability``) are re-exported under a\n\
         ``<Subpkg><Class>`` alias (``AnchorKind``, ``CapabilityKind``) so\n\
         neither definition silently shadows the other. The SCHEMA_SHA256\n\
         constant pins the schema set this build was generated from; the\n\
         spec-drift CI lane reads it to detect tampering.\n\
         \"\"\"\n\
         \n\
         from __future__ import annotations\n\
         \n\
         from pydantic import TypeAdapter\n\
         from pydantic_core import core_schema\n\
         \n\
         #: SHA-256 of the lexicographically sorted concatenation of every\n\
         #: ``spec/schemas/chio-wire/v1/**/*.schema.json`` byte stream that was\n\
         #: fed into datamodel-code-generator at build time.\n\
         SCHEMA_SHA256 = \"{schema_digest}\"\n\
         \n\
         {imports}\n\
         {all_block}"
    )
}

/// Convert a snake_case subpackage directory name (e.g. `trust_control`) into
/// a CamelCase prefix (e.g. `TrustControl`) used to disambiguate class names
/// that collide across subpackages in the top-level `__init__.py`.
fn capitalize_subpkg(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut next_upper = true;
    for ch in name.chars() {
        if ch == '_' || ch == '-' {
            next_upper = true;
            continue;
        }
        if next_upper {
            for upper in ch.to_uppercase() {
                out.push(upper);
            }
            next_upper = false;
        } else {
            out.push(ch);
        }
    }
    out
}

/// Walk every subpackage directory under `root_dir`, scan each `*.py` module
/// (other than `__init__.py`) for top-level `class Name(...):` declarations,
/// rewrite the subpackage's `__init__.py` to re-export those classes, and
/// return the (sorted) plan so the top-level `__init__.py` can re-export
/// each subpackage in turn.
fn rewrite_python_subpackage_inits(
    root_dir: &Path,
    schema_digest: &str,
) -> Result<PythonSubpackageExports, XtaskError> {
    let header = build_python_file_header(schema_digest);
    let mut subpackages: PythonSubpackageExports = Vec::new();
    let entries =
        fs::read_dir(root_dir).map_err(|err| XtaskError::Io(display_path(root_dir), err))?;
    let mut subdirs: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display_path(root_dir), err))?;
        let path = entry.path();
        if path.is_dir() {
            subdirs.push(path);
        }
    }
    subdirs.sort();

    for subdir in subdirs {
        let Some(name) = subdir.file_name().and_then(OsStr::to_str) else {
            continue;
        };
        if name.starts_with('_') {
            continue;
        }
        let mut module_classes: Vec<(String, Vec<String>)> = Vec::new();
        let module_entries =
            fs::read_dir(&subdir).map_err(|err| XtaskError::Io(display_path(&subdir), err))?;
        let mut modules: Vec<PathBuf> = Vec::new();
        for me in module_entries {
            let me = me.map_err(|err| XtaskError::Io(display_path(&subdir), err))?;
            let p = me.path();
            if !p.is_file() {
                continue;
            }
            let Some(stem) = p.file_stem().and_then(OsStr::to_str) else {
                continue;
            };
            if p.extension().and_then(OsStr::to_str) != Some("py") {
                continue;
            }
            if stem == "__init__" {
                continue;
            }
            modules.push(p);
        }
        modules.sort();

        let mut all_classes: Vec<String> = Vec::new();
        for module in &modules {
            let stem = module
                .file_stem()
                .and_then(OsStr::to_str)
                .unwrap_or_default()
                .to_string();
            let body = fs::read_to_string(module)
                .map_err(|err| XtaskError::Io(display_path(module), err))?;
            let classes = extract_top_level_python_classes(&body);
            if !classes.is_empty() {
                all_classes.extend(classes.iter().cloned());
                module_classes.push((stem, classes));
            }
        }
        all_classes.sort();
        all_classes.dedup();

        // Rewrite the subpackage __init__.py with explicit imports per
        // module and a deterministic __all__. The header is preserved so
        // the spec-drift CI lane's per-file header check still
        // passes.
        let init_path = subdir.join(PYTHON_INIT_FILE);
        let mut body = header.clone();
        body.push('\n');
        body.push_str("from __future__ import annotations\n\n");
        for (module_stem, classes) in &module_classes {
            body.push_str(&format!(
                "from .{module_stem} import {names}\n",
                names = classes.join(", ")
            ));
        }
        body.push('\n');
        body.push_str("__all__ = [\n");
        for name in &all_classes {
            body.push_str(&format!("    \"{name}\",\n"));
        }
        body.push_str("]\n");
        fs::write(&init_path, body).map_err(|err| XtaskError::Io(display_path(&init_path), err))?;

        subpackages.push((name.to_string(), all_classes));
    }
    Ok(subpackages)
}

/// Extract top-level `class Name(...):` declarations from a Python module
/// source. Datamodel-codegen output uses 4-space indentation and never
/// nests classes at the module top level beyond a single colon-suffix
/// declaration line, so a string-prefix scan is sufficient (and avoids
/// adding a Python-AST dependency to xtask).
fn extract_top_level_python_classes(body: &str) -> Vec<String> {
    let mut classes: Vec<String> = Vec::new();
    for line in body.lines() {
        // Must begin in column zero (top-level), with `class ` then the
        // identifier, optionally followed by a parenthesized base list
        // and a trailing colon.
        let Some(rest) = line.strip_prefix("class ") else {
            continue;
        };
        let mut name = String::new();
        for ch in rest.chars() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                name.push(ch);
            } else {
                break;
            }
        }
        if name.is_empty() {
            continue;
        }
        // Skip private (leading-underscore) classes.
        if name.starts_with('_') {
            continue;
        }
        classes.push(name);
    }
    classes.sort();
    classes.dedup();
    classes
}

pub(super) fn mirror_schema_tree(
    src_root: &Path,
    dst_root: &Path,
    schema_files: &[PathBuf],
) -> Result<(), XtaskError> {
    fs::create_dir_all(dst_root).map_err(|err| XtaskError::Io(display_path(dst_root), err))?;

    let root_metadata = fs::symlink_metadata(src_root)
        .map_err(|err| XtaskError::Io(display_path(src_root), err))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(XtaskError::Usage(format!(
            "codegen schema root is not a real directory: {}",
            display_path(src_root)
        )));
    }
    let canonical_src_root =
        fs::canonicalize(src_root).map_err(|err| XtaskError::Io(display_path(src_root), err))?;
    let mut inventory = BTreeMap::new();
    for path in schema_files {
        let relative = schema_relative_path(path, src_root)?;
        normal_schema_path_segments(relative)?;
        let canonical =
            fs::canonicalize(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
        if !canonical.starts_with(&canonical_src_root) {
            return Err(XtaskError::Usage(format!(
                "codegen schema escapes the schema root: {}",
                display_path(path)
            )));
        }
        if canonical != canonical_src_root.join(relative) {
            return Err(XtaskError::Usage(format!(
                "codegen schema inventory contains a symlink or path alias: {}",
                display_path(path)
            )));
        }
        if inventory
            .insert(canonical, relative.to_path_buf())
            .is_some()
        {
            return Err(XtaskError::Usage(format!(
                "codegen schema inventory contains a duplicate file: {}",
                display_path(path)
            )));
        }
    }

    for path in schema_files {
        let rel = schema_relative_path(path, src_root)?;
        let dest = dst_root.join(rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|err| XtaskError::Io(display_path(parent), err))?;
        }
        let raw =
            fs::read_to_string(path).map_err(|err| XtaskError::Io(display_path(path), err))?;
        let mut schema: serde_json::Value =
            serde_json::from_str(&raw).map_err(|err| XtaskError::Json(display_path(path), err))?;
        localize_schema_refs(&mut schema, rel, path, &inventory)?;
        let mut rendered = serde_json::to_string_pretty(&schema)
            .map_err(|err| XtaskError::Json(display_path(path), err))?;
        rendered.push('\n');
        fs::write(&dest, rendered).map_err(|err| XtaskError::Io(display_path(&dest), err))?;
    }
    Ok(())
}

fn schema_relative_path<'a>(path: &'a Path, src_root: &Path) -> Result<&'a Path, XtaskError> {
    path.strip_prefix(src_root).map_err(|_| {
        XtaskError::Usage(format!(
            "codegen schema file {} is not under {}",
            display_path(path),
            display_path(src_root)
        ))
    })
}

fn localize_schema_refs(
    value: &mut serde_json::Value,
    source_relative_path: &Path,
    source_path: &Path,
    inventory: &BTreeMap<PathBuf, PathBuf>,
) -> Result<(), XtaskError> {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(reference_value) = object.get("$ref") {
                let reference = reference_value.as_str().ok_or_else(|| {
                    XtaskError::Usage(format!(
                        "codegen schema $ref is not a string in {}",
                        display_path(source_path)
                    ))
                })?;
                let localized =
                    localize_schema_ref(reference, source_relative_path, source_path, inventory)?;
                object.insert("$ref".to_string(), serde_json::Value::String(localized));
            }
            for nested in object.values_mut() {
                localize_schema_refs(nested, source_relative_path, source_path, inventory)?;
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                localize_schema_refs(item, source_relative_path, source_path, inventory)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn localize_schema_ref(
    reference: &str,
    source_relative_path: &Path,
    source_path: &Path,
    inventory: &BTreeMap<PathBuf, PathBuf>,
) -> Result<String, XtaskError> {
    let (path_part, fragment) = reference
        .split_once('#')
        .map_or((reference, None), |(path, fragment)| (path, Some(fragment)));

    if path_part.is_empty() {
        return Ok(reference.to_string());
    }

    let target_relative_path = if let Some(canonical_target) =
        path_part.strip_prefix(chio_spec_codegen::CANONICAL_CHIO_WIRE_SCHEMA_PREFIX)
    {
        exact_canonical_schema_target(canonical_target).map_err(|message| {
            XtaskError::Usage(format!(
                "codegen schema uses a non-normalized canonical $ref in {}: {reference}: {message}",
                display_path(source_path)
            ))
        })?
    } else {
        if has_uri_scheme(path_part) || path_part.starts_with("//") || path_part.contains('\\') {
            return Err(XtaskError::Usage(format!(
                "codegen schema uses an external $ref in {}: {reference}",
                display_path(source_path)
            )));
        }
        normalize_relative_schema_target(source_relative_path, path_part).map_err(|message| {
            XtaskError::Usage(format!(
                "codegen schema $ref is invalid in {}: {reference}: {message}",
                display_path(source_path)
            ))
        })?
    };

    let target_relative_path = inventory
        .values()
        .find(|relative| *relative == &target_relative_path)
        .ok_or_else(|| {
            XtaskError::Usage(format!(
            "codegen schema $ref targets a file outside the schema inventory in {}: {reference}",
            display_path(source_path)
        ))
        })?;
    let localized = relative_schema_reference(source_relative_path, target_relative_path)?;
    Ok(fragment.map_or(localized.clone(), |fragment| {
        format!("{localized}#{fragment}")
    }))
}

fn exact_canonical_schema_target(reference_path: &str) -> Result<PathBuf, String> {
    if reference_path.contains('\\') {
        return Err("backslash separators are forbidden".to_string());
    }
    let segments = reference_path.split('/').collect::<Vec<_>>();
    if segments.is_empty()
        || segments
            .iter()
            .any(|segment| segment.is_empty() || matches!(*segment, "." | ".."))
    {
        return Err("URI path must contain only nonempty normal segments".to_string());
    }
    Ok(segments.into_iter().collect())
}

fn normalize_relative_schema_target(
    source_relative_path: &Path,
    reference_path: &str,
) -> Result<PathBuf, String> {
    let source_parent = source_relative_path
        .parent()
        .ok_or_else(|| "source schema has no parent".to_string())?;
    let mut segments =
        normal_schema_path_segments(source_parent).map_err(|error| error.to_string())?;
    if reference_path.starts_with('/') {
        return Err("absolute reference paths are forbidden".to_string());
    }
    for segment in reference_path.split('/') {
        if segment.is_empty() || segment == "." {
            return Err("reference path is not normalized".to_string());
        }
        if segment == ".." {
            if segments.pop().is_none() {
                return Err("reference escapes the schema root".to_string());
            }
        } else {
            segments.push(segment.to_string());
        }
    }
    if segments.is_empty() {
        return Err("reference does not identify a schema file".to_string());
    }
    Ok(segments.iter().collect())
}

fn has_uri_scheme(value: &str) -> bool {
    let Some((scheme, _)) = value.split_once(':') else {
        return false;
    };
    let mut bytes = scheme.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

fn relative_schema_reference(
    source_relative_path: &Path,
    target_relative_path: &Path,
) -> Result<String, XtaskError> {
    let source_parent = source_relative_path.parent().ok_or_else(|| {
        XtaskError::Usage(format!(
            "codegen schema has no parent: {}",
            display_path(source_relative_path)
        ))
    })?;
    let source_segments = normal_schema_path_segments(source_parent)?;
    let target_segments = normal_schema_path_segments(target_relative_path)?;
    if target_segments.is_empty() {
        return Err(XtaskError::Usage(
            "canonical Chio schema reference has an empty target".to_string(),
        ));
    }
    let shared = source_segments
        .iter()
        .zip(&target_segments)
        .take_while(|(source, target)| source == target)
        .count();
    let mut segments = Vec::new();
    segments.extend(std::iter::repeat_n(
        "..".to_string(),
        source_segments.len().saturating_sub(shared),
    ));
    segments.extend(target_segments.into_iter().skip(shared));
    Ok(segments.join("/"))
}

fn normal_schema_path_segments(path: &Path) -> Result<Vec<String>, XtaskError> {
    path.components()
        .map(|component| match component {
            std::path::Component::Normal(segment) => {
                segment.to_str().map(str::to_string).ok_or_else(|| {
                    XtaskError::Usage(format!(
                        "schema reference path is not valid UTF-8: {}",
                        display_path(path)
                    ))
                })
            }
            _ => Err(XtaskError::Usage(format!(
                "schema reference path is not a normalized relative path: {}",
                display_path(path)
            ))),
        })
        .collect()
}

fn invoke_datamodel_codegen(
    input_dir: &Path,
    output_dir: &Path,
    header_path: &Path,
) -> Result<(), XtaskError> {
    let mut cmd = Command::new("uv");
    cmd.arg("tool")
        .arg("run")
        .arg("--from")
        .arg(PYTHON_CODEGEN_TOOL_PIN)
        .arg("datamodel-codegen")
        .arg("--input")
        .arg(input_dir)
        .arg("--input-file-type")
        .arg("jsonschema")
        .arg("--output")
        .arg(output_dir)
        .arg("--output-model-type")
        .arg("pydantic_v2.BaseModel")
        .arg("--target-python-version")
        .arg("3.11")
        .arg("--use-double-quotes")
        .arg("--use-standard-collections")
        .arg("--use-union-operator")
        // Keep constraints on model fields instead of embedding them in a
        // RootModel generic argument. Pydantic constructs generic arguments
        // before it can apply the generated model's `regex_engine` config;
        // patterns with JSON Schema look-arounds would therefore be compiled
        // by pydantic-core's Rust regex engine and make the generated package
        // unimportable. Annotated fields are compiled with the owning model's
        // Python regex configuration and preserve the schema semantics.
        .arg("--use-annotated")
        .arg("--use-schema-description")
        .arg("--disable-timestamp")
        .arg("--custom-file-header-path")
        .arg(header_path);

    let output = cmd.output().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            XtaskError::ToolMissing(format!(
                "`uv` not found on PATH; install via https://docs.astral.sh/uv/ then rerun (underlying error: {err})"
            ))
        } else {
            XtaskError::Io("uv tool run datamodel-codegen".to_string(), err)
        }
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(XtaskError::ToolFailed(format!(
            "datamodel-codegen exited {}\nstdout: {}\nstderr: {}",
            output.status,
            stdout.trim(),
            stderr.trim()
        )));
    }
    Ok(())
}

fn python_module_inventory(
    schemas_dir: &Path,
    schema_files: &[PathBuf],
) -> Result<BTreeMap<PathBuf, PathBuf>, XtaskError> {
    let mut modules = BTreeMap::new();
    for schema_path in schema_files {
        let relative = schema_path.strip_prefix(schemas_dir).map_err(|_| {
            XtaskError::Usage(format!(
                "codegen python: schema is outside the schema root: {}",
                display_path(schema_path)
            ))
        })?;
        let mut module = PathBuf::new();
        let components = relative.components().collect::<Vec<_>>();
        let Some((file_component, directories)) = components.split_last() else {
            return Err(XtaskError::Usage(format!(
                "codegen python: schema has no file name: {}",
                display_path(schema_path)
            )));
        };
        for directory in directories {
            let std::path::Component::Normal(directory) = directory else {
                return Err(XtaskError::Usage(format!(
                    "codegen python: schema path is not normalized: {}",
                    display_path(schema_path)
                )));
            };
            module.push(normalize_python_module_segment(directory, schema_path)?);
        }
        let std::path::Component::Normal(file_name) = file_component else {
            return Err(XtaskError::Usage(format!(
                "codegen python: schema path is not normalized: {}",
                display_path(schema_path)
            )));
        };
        let file_name = file_name.to_str().ok_or_else(|| {
            XtaskError::Usage(format!(
                "codegen python: schema file name is not valid UTF-8: {}",
                display_path(schema_path)
            ))
        })?;
        let stem = file_name.strip_suffix(".json").ok_or_else(|| {
            XtaskError::Usage(format!(
                "codegen python: schema file lacks .json suffix: {}",
                display_path(schema_path)
            ))
        })?;
        let normalized_file = normalize_python_module_name(stem, schema_path)?;
        module.push(format!("{normalized_file}.py"));
        if let Some(first) = modules.insert(module.clone(), relative.to_path_buf()) {
            return Err(XtaskError::Usage(format!(
                "codegen python: schema paths {} and {} both normalize to module {}",
                display_path(&first),
                display_path(relative),
                display_path(&module)
            )));
        }
    }
    Ok(modules)
}

fn normalize_python_module_segment(
    segment: &OsStr,
    schema_path: &Path,
) -> Result<String, XtaskError> {
    let segment = segment.to_str().ok_or_else(|| {
        XtaskError::Usage(format!(
            "codegen python: schema path is not valid UTF-8: {}",
            display_path(schema_path)
        ))
    })?;
    normalize_python_module_name(segment, schema_path)
}

fn normalize_python_module_name(value: &str, schema_path: &Path) -> Result<String, XtaskError> {
    let mut normalized = String::new();
    let mut last_was_separator = false;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() || character == '_' {
            normalized.push(character.to_ascii_lowercase());
            last_was_separator = character == '_';
        } else if !last_was_separator {
            normalized.push('_');
            last_was_separator = true;
        }
    }
    if normalized.is_empty()
        || normalized
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_digit)
    {
        return Err(XtaskError::Usage(format!(
            "codegen python: schema path cannot form a safe Python module: {}",
            display_path(schema_path)
        )));
    }
    Ok(normalized)
}

fn validate_python_generated_inventory(
    output_dir: &Path,
    expected_modules: &BTreeMap<PathBuf, PathBuf>,
) -> Result<(), XtaskError> {
    let mut actual_modules = Vec::new();
    walk_python_module_files(output_dir, output_dir, &mut actual_modules)?;
    actual_modules.sort();
    let expected = expected_modules.keys().cloned().collect::<Vec<_>>();
    if actual_modules != expected {
        let extra = actual_modules
            .iter()
            .find(|path| expected.binary_search(path).is_err())
            .map(|path| display_path(path));
        let missing = expected
            .iter()
            .find(|path| actual_modules.binary_search(path).is_err())
            .map(|path| display_path(path));
        return Err(XtaskError::Usage(format!(
            "codegen python: generated module inventory differs from schema inventory (extra: {}; missing: {})",
            extra.as_deref().unwrap_or("none"),
            missing.as_deref().unwrap_or("none")
        )));
    }
    Ok(())
}

fn walk_python_module_files(
    root: &Path,
    directory: &Path,
    modules: &mut Vec<PathBuf>,
) -> Result<(), XtaskError> {
    let entries =
        fs::read_dir(directory).map_err(|err| XtaskError::Io(display_path(directory), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display_path(directory), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| XtaskError::Io(display_path(&path), err))?;
        if file_type.is_symlink() {
            return Err(XtaskError::Usage(format!(
                "codegen python: generated tree contains a symlink: {}",
                display_path(&path)
            )));
        }
        if file_type.is_dir() {
            walk_python_module_files(root, &path, modules)?;
        } else if file_type.is_file()
            && path.extension().and_then(OsStr::to_str) == Some("py")
            && path.file_name().and_then(OsStr::to_str) != Some(PYTHON_INIT_FILE)
        {
            let relative = path.strip_prefix(root).map_err(|_| {
                XtaskError::Usage(format!(
                    "codegen python: generated module is outside staging root: {}",
                    display_path(&path)
                ))
            })?;
            modules.push(relative.to_path_buf());
        }
    }
    Ok(())
}

fn count_python_files(dir: &Path) -> Result<usize, XtaskError> {
    let mut count = 0usize;
    walk_python_files(dir, &mut count)?;
    Ok(count)
}

fn walk_python_files(dir: &Path, count: &mut usize) -> Result<(), XtaskError> {
    if !dir.exists() {
        return Ok(());
    }
    let entries = fs::read_dir(dir).map_err(|err| XtaskError::Io(display_path(dir), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display_path(dir), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| XtaskError::Io(display_path(&path), err))?;
        if file_type.is_dir() {
            walk_python_files(&path, count)?;
        } else if file_type.is_file() {
            if let Some(ext) = path.extension().and_then(OsStr::to_str) {
                if ext == "py" {
                    *count += 1;
                }
            }
        }
    }
    Ok(())
}

fn diff_python_trees(expected: &Path, actual: &Path) -> Result<Option<String>, XtaskError> {
    if !actual.exists() {
        return Ok(Some(format!(
            "  on-disk dir {} is missing entirely",
            display_path(actual)
        )));
    }
    let mut expected_files: Vec<PathBuf> = Vec::new();
    let mut actual_files: Vec<PathBuf> = Vec::new();
    collect_relative_files(expected, expected, &mut expected_files)?;
    collect_relative_files(actual, actual, &mut actual_files)?;
    expected_files.sort();
    actual_files.sort();

    let mut diff_lines: Vec<String> = Vec::new();
    let limit = 12usize;
    let mut differing = 0usize;

    let exp_set: std::collections::BTreeSet<_> = expected_files.iter().cloned().collect();
    let act_set: std::collections::BTreeSet<_> = actual_files.iter().cloned().collect();
    for missing in exp_set.difference(&act_set) {
        differing += 1;
        if diff_lines.len() < limit {
            diff_lines.push(format!("  + missing on disk: {}", missing.display()));
        }
    }
    for extra in act_set.difference(&exp_set) {
        differing += 1;
        if diff_lines.len() < limit {
            diff_lines.push(format!(
                "  - present on disk but not regenerated: {}",
                extra.display()
            ));
        }
    }
    for rel in exp_set.intersection(&act_set) {
        let exp_bytes = fs::read(expected.join(rel))
            .map_err(|err| XtaskError::Io(display_path(&expected.join(rel)), err))?;
        let act_bytes = fs::read(actual.join(rel))
            .map_err(|err| XtaskError::Io(display_path(&actual.join(rel)), err))?;
        if exp_bytes != act_bytes {
            differing += 1;
            if diff_lines.len() < limit {
                diff_lines.push(format!(
                    "  ! bytes differ: {} (expected {} bytes, on-disk {} bytes)",
                    rel.display(),
                    exp_bytes.len(),
                    act_bytes.len()
                ));
            }
        }
    }

    if differing == 0 {
        return Ok(None);
    }
    let mut summary = diff_lines.join("\n");
    if differing > limit {
        summary.push_str(&format!(
            "\n  ... ({} more differing entries)",
            differing - limit
        ));
    }
    Ok(Some(summary))
}

fn collect_relative_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<PathBuf>,
) -> Result<(), XtaskError> {
    let entries = fs::read_dir(dir).map_err(|err| XtaskError::Io(display_path(dir), err))?;
    for entry in entries {
        let entry = entry.map_err(|err| XtaskError::Io(display_path(dir), err))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| XtaskError::Io(display_path(&path), err))?;
        let name = path.file_name().and_then(OsStr::to_str).unwrap_or("");
        if name == "__pycache__" {
            continue;
        }
        if file_type.is_dir() {
            collect_relative_files(root, &path, out)?;
        } else if file_type.is_file() {
            if let Some(ext) = path.extension().and_then(OsStr::to_str) {
                if ext == "pyc" || ext == "pyo" {
                    continue;
                }
            }
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(rel.to_path_buf());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    trait TestRequire<T> {
        fn require(self, context: &str) -> T;
    }

    impl<T, E: std::fmt::Debug> TestRequire<T> for Result<T, E> {
        fn require(self, context: &str) -> T {
            self.unwrap_or_else(|error| panic!("{context}: {error:?}"))
        }
    }

    impl<T> TestRequire<T> for Option<T> {
        fn require(self, context: &str) -> T {
            self.unwrap_or_else(|| panic!("{context}"))
        }
    }

    fn write_schema(root: &Path, relative: &str, body: &str) -> PathBuf {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().require("schema path has a parent"))
            .require("create schema directory");
        fs::write(&path, body).require("write schema");
        path
    }

    #[test]
    fn mirror_localizes_only_structural_refs() {
        let temp = TempDir::new("chio-codegen-ref-localization").require("temp dir");
        let source_root = temp.path().join("source");
        let target = write_schema(
            &source_root,
            "shared/target.schema.json",
            r#"{"$defs":{"Thing":{"type":"string"}}}"#,
        );
        let source = write_schema(
            &source_root,
            "group/source.schema.json",
            r#"{
  "$ref": "https:\/\/chio.world\/schemas\/chio-wire\/v1\/shared\/target.schema.json#\/$defs\/Thing",
  "const": "https://chio.world/schemas/chio-wire/v1/shared/target.schema.json"
}"#,
        );
        let destination = temp.path().join("mirror");

        mirror_schema_tree(&source_root, &destination, &[source.clone(), target])
            .require("mirror schema tree");

        let mirrored: serde_json::Value = serde_json::from_slice(
            &fs::read(destination.join("group/source.schema.json")).require("read mirror"),
        )
        .require("parse mirrored schema");
        assert_eq!(
            mirrored["$ref"],
            serde_json::json!("../shared/target.schema.json#/$defs/Thing")
        );
        assert_eq!(
            mirrored["const"],
            serde_json::json!("https://chio.world/schemas/chio-wire/v1/shared/target.schema.json")
        );
    }

    #[test]
    fn mirror_rejects_external_and_escaping_refs() {
        let temp = TempDir::new("chio-codegen-ref-rejection").require("temp dir");
        let source_root = temp.path().join("source");
        let outside = temp.path().join("outside.schema.json");
        fs::write(&outside, r#"{"type":"string"}"#).require("write outside schema");
        let source = write_schema(
            &source_root,
            "group/source.schema.json",
            r#"{"type":"string"}"#,
        );

        for (index, reference) in [
            "https://evil.example/outside.schema.json",
            "file:///tmp/outside.schema.json",
            "urn:evil:schema",
            "../../outside.schema.json",
            "/etc/passwd",
            "//evil.example/outside.schema.json",
            r"\\server\share\outside.schema.json",
            "https://chio.world/schemas/chio-wire/v1/../outside.schema.json",
            "https://chio.world/schemas/chio-wire/v1/security//outside.schema.json",
            "https://chio.world/schemas/chio-wire/v1/security/./outside.schema.json",
            r"https://chio.world/schemas/chio-wire/v1/security\outside.schema.json",
        ]
        .iter()
        .enumerate()
        {
            fs::write(
                &source,
                serde_json::to_vec(&serde_json::json!({ "$ref": reference }))
                    .require("serialize hostile schema"),
            )
            .require("write hostile schema");
            let result = mirror_schema_tree(
                &source_root,
                &temp.path().join(format!("mirror-{index}")),
                std::slice::from_ref(&source),
            );
            assert!(result.is_err(), "accepted hostile schema ref {reference}");
        }
    }

    #[test]
    fn mirror_rejects_targets_outside_the_schema_inventory() {
        let temp = TempDir::new("chio-codegen-ref-inventory").require("temp dir");
        let source_root = temp.path().join("source");
        let source = write_schema(
            &source_root,
            "group/source.schema.json",
            r#"{"$ref":"unregistered.schema.json"}"#,
        );
        write_schema(
            &source_root,
            "group/unregistered.schema.json",
            r#"{"type":"string"}"#,
        );

        let result = mirror_schema_tree(
            &source_root,
            &temp.path().join("mirror"),
            std::slice::from_ref(&source),
        );
        assert!(result.is_err());
    }

    #[test]
    fn python_module_inventory_rejects_normalization_collisions() {
        let temp = TempDir::new("chio-codegen-python-module-collision").require("temp dir");
        let schemas = temp.path().join("schemas");
        let hyphenated = write_schema(
            &schemas,
            "group/foo-bar.schema.json",
            r#"{"type":"string"}"#,
        );
        let underscored = write_schema(
            &schemas,
            "group/foo_bar.schema.json",
            r#"{"type":"string"}"#,
        );

        let result = python_module_inventory(&schemas, &[hyphenated, underscored]);
        assert!(result.is_err(), "accepted colliding Python module paths");
    }

    #[test]
    fn relative_schema_refs_require_exact_lexical_segments() {
        assert_eq!(
            normalize_relative_schema_target(
                Path::new("agent/request.schema.json"),
                "../capability/token.schema.json",
            ),
            Ok(PathBuf::from("capability/token.schema.json"))
        );
        for reference in [
            "./token.schema.json",
            "capability//token.schema.json",
            "capability/token.schema.json/",
        ] {
            assert!(
                normalize_relative_schema_target(
                    Path::new("agent/request.schema.json"),
                    reference,
                )
                .is_err(),
                "accepted non-normalized relative ref {reference}"
            );
        }
    }
}
