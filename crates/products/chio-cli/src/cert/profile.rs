//! Operator-configured checks and independent local signing pins.

use crate::CliError;
use chio_acp_proxy::{ComplianceConfig, ComplianceProfile};
use chio_core::crypto::PublicKey;
use std::{collections::BTreeSet, path::Path};

pub(super) fn load_profile(
    path: Option<&Path>,
    trusted_key: &PublicKey,
    budget_override: Option<u64>,
) -> Result<ComplianceConfig, CliError> {
    let mut profile: ComplianceProfile = match path {
        Some(path) => crate::input::text(&crate::input::read_text(path)?)?,
        None => ComplianceProfile::default(),
    };
    if let Some(limit) = budget_override {
        if path.is_some() && profile.budget_limit != limit {
            return Err(CliError::cli_other_error(
                "--budget-limit differs from the explicit compliance profile",
            ));
        }
        profile.budget_limit = limit;
    }
    Ok(profile.into_config(BTreeSet::from([trusted_key.to_hex()])))
}
