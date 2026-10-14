use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContentRef {
    pub owner_domain: String,
    pub artifact_id: String,
    pub sha256: String,
    pub byte_length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SchemaShape {
    Value { schema: ContentRef },
    AllSuccess { schemas: Vec<ContentRef> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceOperation {
    Read,
    Write,
    Invoke,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceVersion {
    Pinned { content: ContentRef },
    Live,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceBinding {
    pub namespace: String,
    pub resource_id: String,
    pub owner_domain: String,
    pub generation: u64,
    pub provider: ContentRef,
    pub operations: Vec<ResourceOperation>,
    pub version: ResourceVersion,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComputerRecord {
    pub computer_id: String,
    pub owner_domain: String,
    #[serde(deserialize_with = "required_parent")]
    pub parent_revision: Option<String>,
    pub head_revision: String,
    pub lifecycle_generation: u64,
    pub profile_refs: Vec<ContentRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComputerRevision {
    pub computer_id: String,
    pub owner_domain: String,
    pub revision_id: String,
    pub namespace_digest: String,
    pub boot: ContentRef,
    pub input: ContentRef,
    pub input_schema: SchemaShape,
    pub resources: Vec<ResourceBinding>,
    pub profile_refs: Vec<ContentRef>,
    pub creation_operation: String,
}

fn required_parent<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComputerImage {
    pub revision_id: String,
    pub boot: ContentRef,
    pub input: ContentRef,
    pub resource_manifest_digest: String,
    pub requirements: Vec<ContentRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComputerDescription {
    pub schema: String,
    pub record: ComputerRecord,
    pub revision: ComputerRevision,
    pub image: ComputerImage,
}
