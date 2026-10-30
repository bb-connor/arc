use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn unique_temp_dir(prefix: &str) -> Result<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| CodegenError::Io(PathBuf::from(prefix), std::io::Error::other(err)))?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("{prefix}-{nanos}")))
}

#[test]
fn header_is_non_empty() {
    assert!(GENERATED_HEADER.starts_with("// DO NOT EDIT"));
    assert!(GENERATED_HEADER.contains("typify =0.4.3"));
}

#[test]
fn is_schema_json_recognises_canonical_extension() {
    assert!(is_schema_json(Path::new("foo/bar.schema.json")));
    assert!(!is_schema_json(Path::new("foo/bar.json")));
    assert!(!is_schema_json(Path::new("foo/bar.schema.yaml")));
}

#[test]
fn missing_schemas_dir_is_error() {
    let nonexistent = Path::new("/tmp/chio-spec-codegen-does-not-exist-xyz");
    match render_chio_wire_v1(nonexistent) {
        Err(CodegenError::SchemasDirMissing(_)) => {}
        Err(other) => panic!("expected SchemasDirMissing, got {other}"),
        Ok(_) => panic!("expected error, got Ok"),
    }
}

#[cfg(unix)]
#[test]
fn walk_schema_files_rejects_symlinked_schema_file() -> Result<()> {
    let dir = unique_temp_dir("chio-spec-codegen-schemas")?;
    let outside = unique_temp_dir("chio-spec-codegen-outside")?;
    fs::create_dir_all(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;
    fs::create_dir_all(&outside).map_err(|err| CodegenError::Io(outside.clone(), err))?;
    fs::write(outside.join("escape.schema.json"), "{}")
        .map_err(|err| CodegenError::Io(outside.join("escape.schema.json"), err))?;
    let link_path = dir.join("escape.schema.json");
    std::os::unix::fs::symlink(outside.join("escape.schema.json"), &link_path)
        .map_err(|err| CodegenError::Io(link_path.clone(), err))?;

    let mut files = Vec::new();
    let result = walk_schema_files(&dir, &mut files);

    let _ = fs::remove_dir_all(dir);
    let _ = fs::remove_dir_all(outside);
    match result {
        Err(CodegenError::SchemaRef(path, message)) => {
            assert!(path.ends_with("escape.schema.json"));
            assert!(message.contains("symlink"));
        }
        Err(error) => panic!("expected SchemaRef symlink error, got {error}"),
        Ok(paths) => panic!("symlinked schema should fail closed: {paths:?}"),
    }
    Ok(())
}

#[test]
fn render_chio_wire_v1_rejects_external_schema_ref() -> Result<()> {
    let dir = unique_temp_dir("chio-spec-codegen-external-ref")?;
    fs::create_dir_all(&dir).map_err(|err| CodegenError::Io(dir.clone(), err))?;
    let schema_path = dir.join("external_ref.schema.json");
    fs::write(
        &schema_path,
        br#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://chio.world/schemas/test/v1/external-ref.schema.json",
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "remote": {
      "$ref": "https://example.invalid/not-local.schema.json"
    }
  }
}"#,
    )
    .map_err(|err| CodegenError::Io(schema_path.clone(), err))?;

    let result = render_chio_wire_v1(&dir);
    let _ = fs::remove_dir_all(&dir);
    match result {
        Err(CodegenError::SchemaRef(path, message)) => {
            assert!(path.ends_with("external_ref.schema.json"));
            assert!(
                message.contains("external schema reference"),
                "unexpected message: {message}"
            );
        }
        Err(error) => panic!("expected SchemaRef external-ref error, got {error}"),
        Ok(rendered) => panic!("external schema ref should fail closed: {rendered}"),
    }
    Ok(())
}

#[test]
fn tool_call_response_receipt_keeps_record_type(
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or_else(|| std::io::Error::other("missing workspace"))?;
    let schemas_dir = workspace_root.join("spec/schemas/chio-wire/v1");

    let rendered = render_chio_wire_v1(&schemas_dir)?;

    assert!(
        rendered.contains("pub receipt: super::shared::ChioReceiptRecord,"),
        "tool_call_response.receipt must use the shared typed receipt record"
    );
    assert!(
        !rendered.contains("External schema reference erased for Rust typify codegen"),
        "local cross-file refs must not be erased before typify"
    );
    let file = syn::parse_file(&rendered).map_err(CodegenError::SynParse)?;
    let mut receipt_modules = Vec::new();
    for item in &file.items {
        if let syn::Item::Mod(module) = item {
            if let Some((_, items)) = &module.content {
                for item in items {
                    if matches!(item, syn::Item::Struct(item) if item.ident == "ChioReceiptRecord")
                    {
                        receipt_modules.push(module.ident.to_string());
                    }
                }
            }
        }
    }
    assert_eq!(
        receipt_modules,
        vec!["shared".to_owned()],
        "the receipt record is emitted once, in the shared module"
    );
    assert_eq!(
        rustfmt_generated(Path::new(CHIO_WIRE_V1_OUTPUT), &rendered)?,
        rendered,
        "wire bindings must already match rustfmt output"
    );
    Ok(())
}
