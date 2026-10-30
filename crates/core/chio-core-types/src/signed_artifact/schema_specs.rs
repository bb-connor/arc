//! Signed-artifact catalogs grouped by schema ownership.

use super::SignedArtifactSchemaSpec;

#[path = "schema_specs/core_artifacts.rs"]
mod core_artifacts;
#[path = "schema_specs/ecosystem_artifacts.rs"]
mod ecosystem_artifacts;

pub(super) const SCHEMA_GROUPS: &[&[SignedArtifactSchemaSpec]] =
    &[core_artifacts::SCHEMAS, ecosystem_artifacts::SCHEMAS];
pub(super) const SCHEMA_COUNT: usize =
    core_artifacts::SCHEMAS.len() + ecosystem_artifacts::SCHEMAS.len();
