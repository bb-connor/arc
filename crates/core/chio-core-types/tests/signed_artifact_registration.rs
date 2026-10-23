#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repo root")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(
        &fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn registry_rows() -> Vec<Value> {
    read_json(&repo_root().join("spec/schemas/registry.json"))["artifacts"]
        .as_array()
        .expect("registry artifacts array")
        .clone()
}

/// The example directory name of a schema id, as
/// `scripts/gen-signed-artifact-schemas.py` writes it.
fn escape_schema_id(schema_id: &str) -> String {
    let mut out = String::new();
    for byte in schema_id.bytes() {
        if byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    if out.starts_with('.') {
        out.replace_range(0..1, "%2E");
    }
    out
}

fn file_uri(path: &Path) -> String {
    let mut text = path.to_string_lossy().replace('\\', "/");
    if !text.starts_with('/') {
        text.insert(0, '/');
    }
    format!("file://{text}")
}

/// Hosts under which schema files cite one another by their path below
/// `spec/schemas/`.
const SCHEMA_URI_BASES: &[&str] = &[
    "https://chio.world/schemas/",
    "https://chio-protocol.dev/schemas/",
];

fn schema_resources(
    schemas_root: &Path,
    directory: &Path,
    resources: &mut BTreeMap<String, Value>,
) {
    for entry in fs::read_dir(directory).expect("schema directory is readable") {
        let path = entry.expect("schema directory entry is readable").path();
        if path.is_dir() {
            if path
                .file_name()
                .is_some_and(|name| name == "signed-artifact-examples")
            {
                continue;
            }
            schema_resources(schemas_root, &path, resources);
        } else if path.extension().is_some_and(|ext| ext == "json") {
            let value = read_json(&path);
            let rel = path
                .strip_prefix(schemas_root)
                .expect("schema below the root")
                .to_string_lossy()
                .replace('\\', "/");
            for base in SCHEMA_URI_BASES {
                resources.insert(format!("{base}{rel}"), value.clone());
            }
            resources.insert(
                file_uri(&path.canonicalize().expect("canonical")),
                value.clone(),
            );
            if let Some(id) = value["$id"].as_str() {
                resources.insert(id.to_string(), value);
            }
        }
    }
}

fn validator(registry: &jsonschema::Registry, schema_path: &Path) -> jsonschema::Validator {
    let schema = read_json(schema_path);
    let mut base = file_uri(
        &schema_path
            .parent()
            .expect("schema parent")
            .canonicalize()
            .expect("canonical"),
    );
    base.push('/');
    jsonschema::options()
        .with_registry(registry)
        .with_base_uri(base)
        .build(&schema)
        .unwrap_or_else(|error| panic!("{} compiles: {error}", schema_path.display()))
}

#[test]
fn known_ids_are_registered() {
    let registered: BTreeSet<String> = registry_rows()
        .iter()
        .map(|row| row["schema"].as_str().expect("row schema").to_string())
        .collect();
    let missing: Vec<&str> = chio_core_types::KNOWN_SIGNED_ARTIFACT_SCHEMAS
        .iter()
        .copied()
        .filter(|id| !registered.contains(*id))
        .collect();
    for id in &missing {
        println!("unregistered wrapper id: {id}");
    }
    assert!(
        missing.is_empty(),
        "{} wrapper ids have no registry row",
        missing.len()
    );
}

#[test]
fn wrapper_ids_are_unique_per_type() {
    let mut seen = BTreeSet::new();
    let duplicates: Vec<&str> = chio_core_types::KNOWN_SIGNED_ARTIFACT_SCHEMAS
        .iter()
        .copied()
        .filter(|id| !seen.insert(*id))
        .collect();
    assert!(
        duplicates.is_empty(),
        "duplicate wrapper ids: {duplicates:?}"
    );
    let mut rows = BTreeMap::new();
    for row in registry_rows() {
        let id = row["schema"].as_str().expect("row schema").to_string();
        assert!(
            rows.insert(id.clone(), row).is_none(),
            "duplicate registry row {id}"
        );
    }
}

/// Every wrapper id has at least one recorded body under
/// `spec/schemas/signed-artifact-examples/<escaped id>/`, and every recorded
/// body validates against its registry row's `payloadSchemaFile`, or its
/// `schemaFile` when the row has no separate payload schema.
#[test]
fn registered_rows_validate_live_serialization() {
    let root = repo_root();
    let schemas_root = root.join("spec/schemas");
    let mut resources = BTreeMap::new();
    schema_resources(&schemas_root, &schemas_root, &mut resources);
    let mut registry = jsonschema::Registry::new();
    for (uri, resource) in &resources {
        registry = registry
            .add(uri.as_str(), resource)
            .expect("schema resource registers");
    }
    let registry = registry.prepare().expect("schema registry prepares");

    let examples_root = root.join("spec/schemas/signed-artifact-examples");
    let mut failures = Vec::new();
    let mut directories = BTreeSet::new();
    let rows: BTreeMap<String, Value> = registry_rows()
        .into_iter()
        .map(|row| (row["schema"].as_str().expect("row schema").to_string(), row))
        .collect();
    for id in chio_core_types::KNOWN_SIGNED_ARTIFACT_SCHEMAS {
        let Some(row) = rows.get(*id) else {
            failures.push(format!("{id}: no registry row"));
            continue;
        };
        let body_schema = row["payloadSchemaFile"]
            .as_str()
            .or_else(|| row["schemaFile"].as_str())
            .expect("row schemaFile");
        let directory = examples_root.join(escape_schema_id(id));
        directories.insert(escape_schema_id(id));
        let mut examples: Vec<PathBuf> = fs::read_dir(&directory)
            .map(|entries| {
                entries
                    .map(|entry| entry.expect("example entry").path())
                    .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
                    .collect()
            })
            .unwrap_or_default();
        examples.sort();
        if examples.is_empty() {
            failures.push(format!("{id}: no recorded body"));
            continue;
        }
        let compiled = validator(&registry, &root.join(body_schema));
        for example in examples {
            let instance = read_json(&example);
            let first_error = compiled
                .iter_errors(&instance)
                .next()
                .map(|error| error.to_string());
            if let Some(error) = first_error {
                failures.push(format!(
                    "{id}: {} fails {body_schema}: {error}",
                    example.display()
                ));
            }
        }
    }
    if examples_root.is_dir() {
        for entry in fs::read_dir(&examples_root).expect("examples root") {
            let name = entry.expect("examples entry").file_name();
            let name = name.to_string_lossy().to_string();
            if !directories.contains(&name) {
                failures.push(format!("{name}: example directory names no wrapper id"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
