//! OpenAPI 3.x spec parser and Chio `ToolManifest` generator.
//!
//! This crate parses OpenAPI 3.0 and 3.1 specifications (both YAML and JSON)
//! and generates Chio `ToolManifest` values where each route becomes a
//! `ToolDefinition` with input schema derived from path, query, and body
//! parameters.

#![forbid(unsafe_code)]

mod extensions;
mod generator;
mod input;
mod parser;
pub use input::MAX_OPENAPI_BYTES;
mod policy;

pub use extensions::{export_tool_flow_extension, ChioExtensions, Sensitivity};
pub use generator::{GeneratorConfig, ManifestGenerator};
pub use parser::{OpenApiSpec, Operation, Parameter, ParameterLocation, PathItem};
pub use policy::{DefaultPolicy, PolicyDecision};

use thiserror::Error;

/// Errors produced by the OpenAPI parser and manifest generator.
#[derive(Error)]
pub enum OpenApiError {
    /// Original JSON bytes were malformed, duplicated or oversized.
    #[error("{0}")]
    UntrustedInput(#[from] chio_core_types::canonical::UntrustedJsonError),
    /// Original bytes were not UTF-8.
    #[error("urn:chio:error:transport:invalid-request-shape")]
    Utf8(#[from] std::str::Utf8Error),
    /// No YAML document was present.
    #[error("urn:chio:error:transport:invalid-request-shape")]
    EmptyDocument,
    /// Multiple YAML documents are not one OpenAPI specification.
    #[error("urn:chio:error:transport:invalid-request-shape")]
    MultipleDocuments,
    /// The input is not valid JSON.
    #[error("urn:chio:error:transport:invalid-request-shape")]
    InvalidJson(#[from] serde_json::Error),

    /// The input is not valid YAML.
    #[error("urn:chio:error:transport:invalid-request-shape")]
    InvalidYaml(#[from] serde_yaml::Error),

    /// The OpenAPI spec is missing a required field.
    #[error("urn:chio:error:transport:invalid-request-shape")]
    MissingField(String),

    /// The OpenAPI version is not supported.
    #[error("urn:chio:error:transport:invalid-request-shape")]
    UnsupportedVersion(String),

    /// A `$ref` could not be resolved.
    #[error("urn:chio:error:transport:invalid-request-shape")]
    UnresolvedRef(String),

    /// The OpenAPI document contains an invalid value.
    #[error("urn:chio:error:transport:invalid-request-shape")]
    InvalidSpec(String),
}

impl std::fmt::Debug for OpenApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, OpenApiError>;

/// Convenience function: parse an OpenAPI spec from a string (auto-detecting
/// JSON vs YAML) and generate a list of `ToolDefinition` values.
///
/// For more control, use `OpenApiSpec::parse` and `ManifestGenerator`
/// directly.
pub fn tools_from_spec(input: &str) -> Result<Vec<chio_core_types::ToolDefinition>> {
    let spec = OpenApiSpec::parse(input)?;
    let generator = ManifestGenerator::new(GeneratorConfig::default());
    generator.generate_tools(&spec)
}
