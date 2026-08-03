//! Vector domain to schema coverage test.
//!
//! Asserts that every vector domain shipped under `tests/bindings/vectors/<domain>/v1.json`
//! is represented in a hardcoded mapping table that pairs the domain with either
//! a wire-schema family file under `spec/schemas/chio-wire/v1/...` or `None` when
//! the domain is purely an in-memory algorithmic concern (canonical-JSON
//! encoding, manifest construction, hashing, signing) without a wire schema of
//! its own.
//!
//! The test is intentionally narrow: it does NOT validate every case against
//! every schema (that is the job of vectors_oracle.rs and downstream per-schema
//! conformance tests). It only checks that the domain-to-schema MAPPING is
//! complete: no orphan vector subtree is missing from the table, no table entry
//! references a missing vector file, and any referenced schema actually exists
//! and parses as JSON.
//!
//! Fail-closed: an unrecognized vector subtree, a missing file, or invalid JSON
//! trips a build break so new domains cannot land without an explicit decision
//! about their wire-schema pairing.

#![forbid(clippy::unwrap_used)]
#![forbid(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;

/// Repository root, computed from the crate manifest dir.
///
/// The crate lives at `<repo>/crates/<group>/chio-conformance`, so three
/// `parent()` hops land on the repo root that holds `tests/bindings/vectors/`
/// and `spec/`.
fn repo_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(group_dir) = manifest_dir.parent() else {
        panic!(
            "CARGO_MANIFEST_DIR has no parent: {}",
            manifest_dir.display()
        );
    };
    let Some(crates_dir) = group_dir.parent() else {
        panic!("crate group dir has no parent: {}", group_dir.display());
    };
    let Some(root) = crates_dir.parent() else {
        panic!("crates dir has no parent: {}", crates_dir.display());
    };
    root.to_path_buf()
}

fn vectors_root() -> PathBuf {
    repo_root().join("tests/bindings/vectors")
}

fn schemas_root() -> PathBuf {
    repo_root().join("spec/schemas")
}

/// Non-panicking JSON validator used inside the per-domain loop in
/// `every_mapping_entry_resolves_to_existing_files`. The loop accumulates
/// failures across every domain so the operator gets a single batched report.
/// Returns a human-readable error string on failure.
fn try_load_json(path: &Path) -> Result<Value, String> {
    let bytes =
        fs::read(path).map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    serde_json::from_slice::<Value>(&bytes)
        .map_err(|err| format!("failed to parse {} as JSON: {err}", path.display()))
}

/// The hardcoded domain-to-schema mapping.
///
/// `None` means the domain is a pure algorithmic / in-memory contract with no
/// wire-schema family of its own; the canonical-JSON form, manifest-tree
/// construction, hashing, and signing tests are validated against the Rust
/// implementation directly via `vectors_oracle.rs`. `Some(path)` ties the
/// domain to a representative wire schema under `spec/schemas/`; the test only
/// asserts that the schema file exists and is valid JSON, leaving per-case
/// validation to other suites.
const DOMAIN_SCHEMA_MAP: &[(&str, Option<&str>)] = &[
    ("canonical", None),
    ("manifest", None),
    ("hashing", None),
    ("signing", None),
    ("receipt", Some("chio-wire/v1/receipt/record.schema.json")),
    (
        "capability",
        Some("chio-wire/v1/capability/token.schema.json"),
    ),
    (
        "declassification",
        Some("chio-wire/v1/security/declassification-grant.schema.json"),
    ),
    // The security subtree is a recursive multi-schema corpus. Each nested
    // index binds every positive fixture to its exact wire schema.
    ("security", None),
    // The eval-report schema lives under `spec/eval` because it is a
    // partner-evidence format rather than a wire transport schema.
    ("eval", Some("../eval/receipt-format.v1.json")),
];

#[test]
fn every_vector_domain_has_a_schema_mapping_entry() {
    let vectors_dir = vectors_root();
    let entries = match fs::read_dir(&vectors_dir) {
        Ok(entries) => entries,
        Err(error) => panic!(
            "failed to read vectors directory {}: {error}",
            vectors_dir.display()
        ),
    };

    let mut on_disk: BTreeSet<String> = BTreeSet::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => panic!("failed to enumerate {}: {error}", vectors_dir.display()),
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => panic!("failed to stat {}: {error}", entry.path().display()),
        };
        if !file_type.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            panic!("non-UTF8 directory name under {}", vectors_dir.display());
        };
        on_disk.insert(name);
    }

    let mapped: BTreeSet<String> = DOMAIN_SCHEMA_MAP
        .iter()
        .map(|(domain, _)| (*domain).to_string())
        .collect();

    let orphan_subtrees: Vec<&String> = on_disk.difference(&mapped).collect();
    assert!(
        orphan_subtrees.is_empty(),
        "vector subtree(s) without a schema-mapping entry: {orphan_subtrees:?}; \
         add an entry to DOMAIN_SCHEMA_MAP in vectors_schema_pair.rs"
    );

    let missing_subtrees: Vec<&String> = mapped.difference(&on_disk).collect();
    assert!(
        missing_subtrees.is_empty(),
        "DOMAIN_SCHEMA_MAP entries without a corresponding vector subtree: \
         {missing_subtrees:?}; either land the vectors or remove the mapping"
    );
}

#[test]
fn every_mapping_entry_resolves_to_existing_files() {
    let vectors_dir = vectors_root();
    let schemas_dir = schemas_root();

    let mut failures: Vec<String> = Vec::new();
    for (domain, schema_rel) in DOMAIN_SCHEMA_MAP {
        let vector_path = vectors_dir.join(domain).join("v1.json");
        if !vector_path.is_file() {
            failures.push(format!(
                "domain `{domain}`: missing vector file {}",
                vector_path.display()
            ));
            continue;
        }
        // Validate the vector file parses as JSON before declaring success.
        // Use the non-panicking variant so a malformed vector file in one
        // domain does not short-circuit the loop and hide failures in
        // subsequent domains.
        if let Err(err) = try_load_json(&vector_path) {
            failures.push(format!("domain `{domain}` vector: {err}"));
            continue;
        }

        match schema_rel {
            None => {}
            Some(rel) => {
                let schema_path = schemas_dir.join(rel);
                if !schema_path.is_file() {
                    failures.push(format!(
                        "domain `{domain}`: missing schema file {}",
                        schema_path.display()
                    ));
                    continue;
                }
                if let Err(err) = try_load_json(&schema_path) {
                    failures.push(format!("domain `{domain}` schema: {err}"));
                }
            }
        }
    }

    if !failures.is_empty() {
        panic!(
            "schema-pair coverage failures ({}):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

#[derive(Debug, Deserialize)]
struct RequiredSchemaInventory {
    schema: String,
    schemas: Vec<RequiredSchemaEntry>,
}

#[derive(Debug, Deserialize)]
struct RequiredSchemaEntry {
    file: String,
    schema_id: String,
}

#[derive(Debug, Deserialize)]
struct SecurityRootIndex {
    schema: String,
    indexes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SecurityIndex {
    schema: String,
    #[serde(default)]
    indexes: Vec<String>,
    positive: Vec<SecurityPositive>,
    negative: Vec<SecurityNegativeSet>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityPositive {
    id: String,
    file: String,
    schema_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SecurityNegativeSet {
    DirectWithMerge(SecurityDirectNegativeWithMerge),
    Direct(SecurityDirectNegative),
    Mutation(SecurityMutationSet),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityDirectNegativeWithMerge {
    id: String,
    file: String,
    schema_id: String,
    exact_merge_of: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityDirectNegative {
    id: String,
    file: String,
    schema_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityMutationSet {
    id: String,
    file: String,
}

type SecurityNegativeParts<'a> = (&'a str, &'a str, Option<(&'a str, Option<&'a [String]>)>);

impl SecurityNegativeSet {
    fn parts(&self) -> SecurityNegativeParts<'_> {
        match self {
            Self::DirectWithMerge(negative) => (
                &negative.id,
                &negative.file,
                Some((&negative.schema_id, Some(&negative.exact_merge_of))),
            ),
            Self::Direct(negative) => (
                &negative.id,
                &negative.file,
                Some((&negative.schema_id, None)),
            ),
            Self::Mutation(negative) => (&negative.id, &negative.file, None),
        }
    }
}

fn load_typed_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("parse {}: {error}", path.display()))
}

fn collect_schema_files(directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("read schema directory {}: {error}", directory.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "enumerate schema directory {}: {error}",
                directory.display()
            )
        })?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("stat {}: {error}", entry.path().display()))?;
        let path = entry.path();
        if file_type.is_dir() {
            collect_schema_files(&path, files)?;
        } else if file_type.is_file()
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".schema.json"))
        {
            files.push(path);
        }
    }
    Ok(())
}

fn safe_corpus_path(base: &Path, relative: &str, corpus_root: &Path) -> Result<PathBuf, String> {
    let relative_path = Path::new(relative);
    if relative.is_empty()
        || relative_path.is_absolute()
        || relative_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("unsafe corpus-relative path {relative:?}"));
    }
    let path = base.join(relative_path);
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("resolve {}: {error}", path.display()))?;
    let canonical_root = corpus_root
        .canonicalize()
        .map_err(|error| format!("resolve {}: {error}", corpus_root.display()))?;
    if !canonical.starts_with(canonical_root) || !canonical.is_file() {
        return Err(format!(
            "corpus path escapes root or is not a file: {relative}"
        ));
    }
    Ok(canonical)
}

fn load_exact_wire_schemas() -> Result<BTreeMap<String, (PathBuf, Value)>, String> {
    let wire_root = schemas_root().join("chio-wire/v1");
    let mut paths = Vec::new();
    collect_schema_files(&wire_root, &mut paths)?;
    paths.sort();
    let mut schemas = BTreeMap::new();
    for path in paths {
        let schema = try_load_json(&path)?;
        let Some(schema_id) = schema.get("$id").and_then(Value::as_str).map(str::to_owned) else {
            continue;
        };
        if let Some((first, _)) = schemas.insert(schema_id.clone(), (path.clone(), schema)) {
            return Err(format!(
                "duplicate wire schema ID {schema_id} in {} and {}",
                first.display(),
                path.display()
            ));
        }
    }
    Ok(schemas)
}

fn check_closed_security_schema_inventory(
    schemas: &BTreeMap<String, (PathBuf, Value)>,
) -> Result<(), String> {
    let security_root = schemas_root().join("chio-wire/v1/security");
    let inventory_path = security_root.join("required-schema-inventory.json");
    let inventory: RequiredSchemaInventory = load_typed_json(&inventory_path)?;
    if inventory.schema != "chio.security-required-schema-inventory.v1" {
        return Err(format!(
            "{} has invalid schema discriminator {}",
            inventory_path.display(),
            inventory.schema
        ));
    }
    if inventory.schemas.is_empty() {
        return Err(format!(
            "{} must contain at least one schema",
            inventory_path.display()
        ));
    }

    let declared_files = inventory
        .schemas
        .iter()
        .map(|entry| entry.file.clone())
        .collect::<BTreeSet<_>>();
    if declared_files.len() != inventory.schemas.len() {
        return Err(format!(
            "{} contains duplicate schema files",
            inventory_path.display()
        ));
    }
    let actual_files = fs::read_dir(&security_root)
        .map_err(|error| format!("read {}: {error}", security_root.display()))?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            path.file_name()
                .and_then(|name| name.to_str())
                .filter(|name| name.ends_with(".schema.json"))
                .map(str::to_owned)
        })
        .collect::<BTreeSet<_>>();
    if declared_files != actual_files {
        return Err(format!(
            "{} is not closed over the security schema directory: declared={declared_files:?}, actual={actual_files:?}",
            inventory_path.display()
        ));
    }

    let mut declared_ids = BTreeSet::new();
    let mut ordered_files = Vec::new();
    for entry in &inventory.schemas {
        if Path::new(&entry.file)
            .file_name()
            .and_then(|name| name.to_str())
            != Some(entry.file.as_str())
            || !entry.file.ends_with(".schema.json")
        {
            return Err(format!("unsafe inventory file {}", entry.file));
        }
        if !declared_ids.insert(entry.schema_id.clone()) {
            return Err(format!("duplicate inventory schema ID {}", entry.schema_id));
        }
        let Some((path, schema)) = schemas.get(&entry.schema_id) else {
            return Err(format!(
                "inventory schema ID {} is absent from the exact schema loader",
                entry.schema_id
            ));
        };
        if path.file_name().and_then(|name| name.to_str()) != Some(entry.file.as_str())
            || schema.get("$id").and_then(Value::as_str) != Some(entry.schema_id.as_str())
        {
            return Err(format!(
                "inventory binding {} -> {} is not exact",
                entry.file, entry.schema_id
            ));
        }
        ordered_files.push(entry.file.clone());
    }
    let mut sorted_files = ordered_files.clone();
    sorted_files.sort();
    if ordered_files != sorted_files {
        return Err(format!(
            "{} entries are not sorted by file",
            inventory_path.display()
        ));
    }
    Ok(())
}

struct SecurityCorpusCounts {
    indexes: usize,
    positives: usize,
    negative_cases: usize,
}

fn visit_security_index(
    index_path: &Path,
    corpus_root: &Path,
    schemas: &BTreeMap<String, (PathBuf, Value)>,
    registry: &jsonschema::Registry<'static>,
    visited: &mut BTreeSet<PathBuf>,
    counts: &mut SecurityCorpusCounts,
) -> Result<(), String> {
    let canonical_index = index_path
        .canonicalize()
        .map_err(|error| format!("resolve {}: {error}", index_path.display()))?;
    if !visited.insert(canonical_index) {
        return Err(format!(
            "duplicate or cyclic security index {}",
            index_path.display()
        ));
    }
    let index: SecurityIndex = load_typed_json(index_path)?;
    if index.schema.is_empty() {
        return Err(format!(
            "{} has an empty schema discriminator",
            index_path.display()
        ));
    }
    if index.positive.is_empty() || index.negative.is_empty() {
        return Err(format!(
            "{} must contain non-zero positive and negative entries",
            index_path.display()
        ));
    }
    counts.indexes += 1;

    for child in &index.indexes {
        let child_path = safe_corpus_path(
            index_path.parent().unwrap_or(corpus_root),
            child,
            corpus_root,
        )?;
        visit_security_index(&child_path, corpus_root, schemas, registry, visited, counts)?;
    }

    let mut positive_ids = BTreeSet::new();
    let mut positive_files = BTreeMap::new();
    let mut positive_paths = BTreeSet::new();
    for positive in &index.positive {
        if positive.id.is_empty() || !positive_ids.insert(positive.id.clone()) {
            return Err(format!(
                "{} contains an empty or duplicate positive ID",
                index_path.display()
            ));
        }
        let Some((schema_path, schema)) = schemas.get(&positive.schema_id) else {
            return Err(format!(
                "{} positive {} names unknown exact schema ID {}",
                index_path.display(),
                positive.id,
                positive.schema_id
            ));
        };
        let fixture_path = safe_corpus_path(
            index_path.parent().unwrap_or(corpus_root),
            &positive.file,
            corpus_root,
        )?;
        if positive_files.contains_key(&positive.file)
            || !positive_paths.insert(fixture_path.clone())
        {
            return Err(format!(
                "{} contains a duplicate positive fixture path {}",
                index_path.display(),
                positive.file
            ));
        }
        let fixture = try_load_json(&fixture_path)?;
        let validator = jsonschema::options()
            .with_registry(registry)
            .build(schema)
            .map_err(|error| format!("compile exact schema {}: {error}", schema_path.display()))?;
        if !validator.is_valid(&fixture) {
            let errors = validator
                .iter_errors(&fixture)
                .take(5)
                .map(|error| error.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(format!(
                "{} rejected by exact schema {}: {errors}",
                fixture_path.display(),
                schema_path.display()
            ));
        }
        positive_files.insert(
            positive.file.clone(),
            (positive.schema_id.clone(), fixture_path),
        );
        counts.positives += 1;
    }

    let mut negative_ids = BTreeSet::new();
    for negative in &index.negative {
        let (negative_id, negative_file, direct) = negative.parts();
        if negative_id.is_empty() || !negative_ids.insert(negative_id.to_string()) {
            return Err(format!(
                "{} contains an empty or duplicate negative ID",
                index_path.display()
            ));
        }
        let mutation_path = safe_corpus_path(
            index_path.parent().unwrap_or(corpus_root),
            negative_file,
            corpus_root,
        )?;
        let mutation_document = try_load_json(&mutation_path)?;
        if let Some((schema_id, exact_merge_of)) = direct {
            let Some((schema_path, schema)) = schemas.get(schema_id) else {
                return Err(format!(
                    "{} negative {} names unknown exact schema ID {}",
                    index_path.display(),
                    negative_id,
                    schema_id
                ));
            };
            if let Some(merge_sources) = exact_merge_of {
                if merge_sources.len() < 2 {
                    return Err(format!(
                        "{} negative {} exact_merge_of must name at least two fixtures",
                        index_path.display(),
                        negative_id
                    ));
                }
                let mut seen_sources = BTreeSet::new();
                let mut merged = serde_json::Map::new();
                for relative in merge_sources {
                    if !seen_sources.insert(relative) {
                        return Err(format!(
                            "{} negative {} exact_merge_of contains duplicate source {}",
                            index_path.display(),
                            negative_id,
                            relative
                        ));
                    }
                    let Some((source_schema_id, source_path)) = positive_files.get(relative) else {
                        return Err(format!(
                            "{} negative {} exact_merge_of source {} is not a positive fixture in the same index",
                            index_path.display(),
                            negative_id,
                            relative
                        ));
                    };
                    if source_schema_id != schema_id {
                        return Err(format!(
                            "{} negative {} exact_merge_of source {} uses schema ID {} instead of {}",
                            index_path.display(),
                            negative_id,
                            relative,
                            source_schema_id,
                            schema_id
                        ));
                    }
                    let source = try_load_json(source_path)?;
                    let Value::Object(fields) = source else {
                        return Err(format!(
                            "{} exact-merge source {} is not an object",
                            index_path.display(),
                            source_path.display()
                        ));
                    };
                    for (key, value) in fields {
                        if merged.get(&key).is_some_and(|existing| existing != &value) {
                            return Err(format!(
                                "{} negative {} exact_merge_of source {} conflicts on member {}",
                                index_path.display(),
                                negative_id,
                                relative,
                                key
                            ));
                        }
                        merged.insert(key, value);
                    }
                }
                if mutation_document != Value::Object(merged) {
                    return Err(format!(
                        "{} is not the exact ordered object merge declared by {} negative {}",
                        mutation_path.display(),
                        index_path.display(),
                        negative_id
                    ));
                }
            }
            let validator = jsonschema::options()
                .with_registry(registry)
                .build(schema)
                .map_err(|error| {
                    format!("compile exact schema {}: {error}", schema_path.display())
                })?;
            if validator.is_valid(&mutation_document) {
                return Err(format!(
                    "{} is accepted by exact schema {} but is registered as a negative fixture",
                    mutation_path.display(),
                    schema_path.display()
                ));
            }
            counts.negative_cases += 1;
            continue;
        }
        let Some(cases) = mutation_document.get("cases").and_then(Value::as_array) else {
            return Err(format!("{} has no cases array", mutation_path.display()));
        };
        if cases.is_empty() {
            return Err(format!(
                "{} must contain at least one negative case",
                mutation_path.display()
            ));
        }
        counts.negative_cases += cases.len();
    }
    Ok(())
}

#[test]
fn recursive_security_corpus_uses_closed_exact_schema_ids() {
    let schemas = match load_exact_wire_schemas() {
        Ok(schemas) => schemas,
        Err(error) => panic!("load exact wire schemas: {error}"),
    };
    if let Err(error) = check_closed_security_schema_inventory(&schemas) {
        panic!("closed security schema inventory: {error}");
    }

    let mut registry_builder = jsonschema::Registry::new();
    for (schema_id, (_, schema)) in &schemas {
        registry_builder = match registry_builder.add(schema_id, schema.clone()) {
            Ok(builder) => builder,
            Err(error) => panic!("register exact wire schema {schema_id}: {error}"),
        };
    }
    let registry = match registry_builder.prepare() {
        Ok(registry) => registry,
        Err(error) => panic!("prepare exact wire schema registry: {error}"),
    };

    let corpus_root = vectors_root().join("security");
    let root_path = corpus_root.join("v1.json");
    let root_index: SecurityRootIndex = match load_typed_json(&root_path) {
        Ok(index) => index,
        Err(error) => panic!("load security root index: {error}"),
    };
    assert_eq!(root_index.schema, "chio.test-vector.security.v1");
    assert!(
        !root_index.indexes.is_empty(),
        "security root index must contain at least one nested index"
    );

    let mut visited = BTreeSet::new();
    let mut counts = SecurityCorpusCounts {
        indexes: 0,
        positives: 0,
        negative_cases: 0,
    };
    for relative in &root_index.indexes {
        let child = match safe_corpus_path(&corpus_root, relative, &corpus_root) {
            Ok(path) => path,
            Err(error) => panic!("resolve security child index: {error}"),
        };
        if let Err(error) = visit_security_index(
            &child,
            &corpus_root,
            &schemas,
            &registry,
            &mut visited,
            &mut counts,
        ) {
            panic!("validate recursive security corpus: {error}");
        }
    }
    assert!(counts.indexes > 0, "security corpus loaded zero indexes");
    assert!(
        counts.positives > 0,
        "security corpus loaded zero positives"
    );
    assert!(
        counts.negative_cases > 0,
        "security corpus loaded zero negative cases"
    );
}
