//! Aggregate invocation budget wire types and structural validation.

use alloc::string::{String, ToString};

use serde::{Deserialize, Serialize};

use crate::crypto::{is_default_optional_algorithm, PublicKey, Signature, SigningAlgorithm};
use crate::error::{Error, Result};

use super::attenuation::ScopeHash;
use super::scope::ChioScope;

/// Schema carried by aggregate delegation-family root binding bodies.
pub const CHIO_AGGREGATE_BUDGET_ROOT_SCHEMA: &str = "chio.aggregate-budget-root.v1";

/// Domain for hashing a pre-binding aggregate-budget root commitment.
pub const CHIO_AGGREGATE_BUDGET_ROOT_COMMITMENT_DOMAIN: &str =
    "chio.aggregate-budget-root-commitment.v1\0";

/// Domain for signing an aggregate-budget root binding body.
pub const CHIO_AGGREGATE_BUDGET_ROOT_SIGNATURE_DOMAIN: &str = "chio.aggregate-budget-root.v1\0";

/// Domain for deriving an aggregate delegation-family quota owner.
pub const CHIO_AGGREGATE_BUDGET_FAMILY_KEY_DOMAIN: &str = "chio.aggregate-budget-family-key.v1\0";

/// Domain for hashing a complete aggregate-budget root binding envelope.
pub const CHIO_AGGREGATE_BUDGET_ROOT_BINDING_DOMAIN: &str =
    "chio.aggregate-budget-root-binding.v1\0";

/// Scope over which an aggregate invocation maximum is shared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregateInvocationScope {
    /// The maximum belongs only to this capability token.
    Capability,
    /// The maximum is shared by a root capability and its descendants.
    DelegationFamily,
}

/// Optional invocation maximum carried by a capability token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateInvocationBudget {
    pub scope: AggregateInvocationScope,
    pub max_invocations: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_binding: Option<AggregateBudgetRootBinding>,
}

impl AggregateInvocationBudget {
    /// Validate the budget's non-cryptographic relationship to a token scope.
    ///
    /// A zero maximum is valid. Root-binding signature and field verification
    /// is outside this structural validator.
    pub fn validate_for_scope(&self, token_scope: &ChioScope) -> Result<()> {
        match self.scope {
            AggregateInvocationScope::Capability => {
                if self.root_binding.is_some() {
                    return Err(Error::AttenuationViolation {
                        reason: "capability-scoped aggregate budget must not carry a root binding"
                            .to_string(),
                    });
                }
                if token_scope.authorizes_delegation() {
                    return Err(Error::AttenuationViolation {
                        reason: "capability-scoped aggregate budget cannot authorize delegation"
                            .to_string(),
                    });
                }
            }
            AggregateInvocationScope::DelegationFamily => {
                if self.root_binding.is_none() {
                    return Err(Error::AttenuationViolation {
                        reason: "delegation-family aggregate budget requires a root binding"
                            .to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Pre-binding commitment for a direct aggregate delegation-family root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateBudgetRootCommitment {
    pub root_capability_id: String,
    pub root_issuer: PublicKey,
    pub root_subject: PublicKey,
    pub root_scope_hash: ScopeHash,
    pub root_issued_at: u64,
    pub root_expires_at: u64,
    pub aggregate_scope: AggregateInvocationScope,
    pub max_invocations: u32,
}

/// Signed aggregate delegation-family root facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateBudgetRootBindingBody {
    pub schema: String,
    pub root_capability_id: String,
    pub root_capability_hash: String,
    pub root_issuer: PublicKey,
    pub root_subject: PublicKey,
    pub max_invocations: u32,
    pub root_expires_at: u64,
    pub root_scope_hash: ScopeHash,
}

/// Signature envelope carrying aggregate delegation-family root facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateBudgetRootBinding {
    pub body: AggregateBudgetRootBindingBody,
    #[serde(default, skip_serializing_if = "is_default_optional_algorithm")]
    pub algorithm: Option<SigningAlgorithm>,
    pub signature: Signature,
}
