use serde::{Deserialize, Serialize};

use crate::computer::{ContentRef, ResourceOperation, SchemaShape};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceRequirement {
    pub namespace: String,
    pub resource_id: String,
    pub owner_domain: String,
    pub generation: u64,
    pub operations: Vec<ResourceOperation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum LeafDescriptor {
    Task {
        contract: ContentRef,
        input_schema: SchemaShape,
        output_schema: ContentRef,
        acceptance: ContentRef,
        harness_requirements: Vec<ContentRef>,
        resources: Vec<ResourceRequirement>,
    },
    Program {
        bundle: ContentRef,
        entrypoint: String,
        input_schema: SchemaShape,
        output_schema: ContentRef,
        resources: Vec<ResourceRequirement>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProgramExpr {
    Leaf { leaf: Box<LeafDescriptor> },
    Parallel { items: Vec<Self> },
    Sequence { items: Vec<Self> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProgramOccurrence {
    pub occurrence_id: String,
    pub path: Vec<usize>,
    pub parents: Vec<String>,
    pub leaf: LeafDescriptor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompiledDescription {
    pub schema: String,
    pub request_id: String,
    pub computer_id: String,
    pub owner_domain: String,
    pub revision_id: String,
    pub lifecycle_generation: u64,
    pub program_digest: String,
    pub expression: ProgramExpr,
    pub occurrences: Vec<ProgramOccurrence>,
    pub output_schema: SchemaShape,
    pub digest: String,
}

/// Structural validation grants no current authority or execution rights.
///
/// ```compile_fail
/// fn deserializable<T: for<'de> serde::Deserialize<'de>>() {}
/// deserializable::<chio_runtime_core::program::CheckedProgram>();
/// ```
///
/// ```compile_fail
/// fn forge(raw: chio_runtime_core::program::CompiledDescription) {
///     let _checked = chio_runtime_core::program::CheckedProgram(raw);
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckedProgram(pub(super) CompiledDescription);

impl CheckedProgram {
    #[must_use]
    pub fn description(&self) -> &CompiledDescription {
        &self.0
    }
}
