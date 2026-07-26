//! Capability tokens, scoped grants, attenuation, and governed execution metadata.
//!
//! Capability submodules are the public API. This root intentionally contains
//! no flat re-export layer so callers import the domain they depend on.

pub mod aggregate_budget;
pub mod aggregate_invocation {
    pub use super::aggregate_budget::AggregateBudgetDelegationMarker;
}
pub mod attenuation;
pub mod caveat;
pub mod crypto_floor;
pub mod cumulative_approval {
    use alloc::format;
    use alloc::string::String;
    use alloc::vec::Vec;

    use serde::{Deserialize, Serialize};

    use crate::error::{Error, Result};

    use super::scope::ChioScope;

    pub const MAX_CUMULATIVE_APPROVAL_BINDINGS_PER_MARKER: usize = 64;

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct CumulativeApprovalBindingMarker {
        approval_budget_id: String,
        approval_budget_epoch: u64,
        currency: String,
        root_binding_digest: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct CumulativeApprovalDelegationMarker {
        bindings: Vec<CumulativeApprovalBindingMarker>,
    }

    impl CumulativeApprovalDelegationMarker {
        pub fn bindings(&self) -> &[CumulativeApprovalBindingMarker] {
            &self.bindings
        }

        pub(crate) fn validate(&self) -> Result<()> {
            if self.bindings.is_empty()
                || self.bindings.len() > MAX_CUMULATIVE_APPROVAL_BINDINGS_PER_MARKER
            {
                return Err(Error::AttenuationViolation {
                    reason: format!(
                        "cumulative approval delegation marker must contain 1 to {} bindings",
                        MAX_CUMULATIVE_APPROVAL_BINDINGS_PER_MARKER
                    ),
                });
            }
            for binding in &self.bindings {
                if binding.approval_budget_id.trim().is_empty()
                    || binding.currency.trim().is_empty()
                    || binding.root_binding_digest.len() != 64
                    || !binding
                        .root_binding_digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(Error::AttenuationViolation {
                        reason: "cumulative approval delegation marker is malformed".to_string(),
                    });
                }
            }
            if self.bindings.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err(Error::AttenuationViolation {
                    reason: "cumulative approval delegation bindings must be sorted and unique"
                        .to_string(),
                });
            }
            Ok(())
        }
    }

    pub(crate) fn cumulative_approval_delegation_marker(
        _scope: &ChioScope,
    ) -> Result<Option<CumulativeApprovalDelegationMarker>> {
        Ok(None)
    }
}
pub mod features;
pub mod governance;
pub mod runtime_attestation;
pub mod scope;
pub mod threshold_approval;
pub mod token;
pub mod trust_policy;
pub mod validation;
pub mod workload_identity;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod caveat_and_delegation_guard_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod delegation_trust_root_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod delegation_family_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod aggregate_invocation_attenuation_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
