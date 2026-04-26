//! Chio JSON Schema validator.
//!
//! Loads a JSON Schema from disk, compiles it via the `jsonschema` crate, and
//! validates a target document against it. Used by `cargo xtask
//! validate-scenarios` and by downstream M04+ goldens to confirm that wire
//! artifacts conform to the published `spec/schemas/` definitions.
//!
//! All errors are surfaced via [`ValidateError`]; the crate never panics on
//! malformed input. The workspace clippy lints (`unwrap_used`, `expect_used`)
//! are enforced.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

/// Errors surfaced by [`validate`] and helpers.
#[derive(Debug)]
pub enum ValidateError {
    /// Failed to read a file from disk.
    Io(PathBuf, std::io::Error),
    /// The file did not parse as JSON.
    Json(PathBuf, serde_json::Error),
    /// The schema document could not be compiled.
    SchemaCompile(PathBuf, String),
    /// The document did not satisfy the schema.
    SchemaViolation(PathBuf, PathBuf, Vec<String>),
}

impl fmt::Display for ValidateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "io error reading {}: {err}", path.display()),
            Self::Json(path, err) => write!(f, "json parse error in {}: {err}", path.display()),
            Self::SchemaCompile(path, err) => {
                write!(f, "failed to compile schema {}: {err}", path.display())
            }
            Self::SchemaViolation(schema, doc, errors) => write!(
                f,
                "document {} violates schema {}: {}",
                doc.display(),
                schema.display(),
                errors.join(" | ")
            ),
        }
    }
}

impl std::error::Error for ValidateError {}

/// Read and parse a JSON file from disk.
pub fn load_json(path: &Path) -> Result<Value, ValidateError> {
    let raw = fs::read_to_string(path).map_err(|err| ValidateError::Io(path.to_path_buf(), err))?;
    serde_json::from_str(&raw).map_err(|err| ValidateError::Json(path.to_path_buf(), err))
}

/// Validate a JSON document against a JSON Schema, both loaded from disk.
///
/// Returns `Ok(())` when the document passes; otherwise a
/// [`ValidateError::SchemaViolation`] enumerating every reported error.
pub fn validate(schema_path: &Path, doc_path: &Path) -> Result<(), ValidateError> {
    let schema = load_json(schema_path)?;
    let doc = load_json(doc_path)?;
    validate_value(schema_path, &schema, doc_path, &doc)
}

/// Validate an in-memory document against an in-memory schema.
///
/// `schema_path` and `doc_path` are used only for diagnostics and may be any
/// representative path (for example, a synthetic `<inline>`).
pub fn validate_value(
    schema_path: &Path,
    schema: &Value,
    doc_path: &Path,
    doc: &Value,
) -> Result<(), ValidateError> {
    let validator = jsonschema::validator_for(schema)
        .map_err(|err| ValidateError::SchemaCompile(schema_path.to_path_buf(), err.to_string()))?;
    if validator.is_valid(doc) {
        return Ok(());
    }
    let errors: Vec<String> = validator
        .iter_errors(doc)
        .map(|err| err.to_string())
        .collect();
    Err(ValidateError::SchemaViolation(
        schema_path.to_path_buf(),
        doc_path.to_path_buf(),
        errors,
    ))
}
