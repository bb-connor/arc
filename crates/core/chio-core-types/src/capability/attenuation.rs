use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json_bytes;
use crate::crypto::{sha256_hex, Keypair, PublicKey, Signature};
use crate::error::{Error, Result};
use crate::signer_binding::ensure_keypair_matches_embedded_key;

use super::caveat::GrantSubsetRelation;
use super::scope::{ChioScope, Constraint, MonetaryAmount, Operation};
use super::token::CapabilityToken;
use super::validation::validate_parent_relative_budget_share_bps;

/// Hash of a canonicalized scope, encoded as lowercase SHA-256 hex.
pub type ScopeHash = String;

/// On-wire attenuation witness. The normalized scope encodings are included
/// so verifiers can hash and check the already-normalized relation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttenuationWitness {
    pub normalized_parent_scope: String,
    pub normalized_child_scope: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subset_relations: Vec<GrantSubsetRelation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub restricted_predicates: Vec<String>,
}

/// Wire proof carried by `CapabilityToken.attenuation_proof`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttenuationProof {
    pub parent_scope_hash: ScopeHash,
    pub child_scope_hash: ScopeHash,
    pub normalized_subset_proof: AttenuationWitness,
}

/// A link in the delegation chain, recording that `delegator` granted a
/// narrowed capability to `delegatee`.
///
/// Delegation chain-binding: `scope_hash` records the hash of the canonical scope
/// that the delegator authorized at this step. When set, it ties the
/// delegation chain to the underlying capability lineage so a verifier
/// can check `proof.parent_scope_hash == chain.last().scope_hash` and
/// reject inflated parent-scope claims (the parent-scope-inflation
/// soundness bug).
///
/// Links omit `scope_hash`; verifiers must reject attenuated tokens
/// whose chain links lack this field via
/// [`validate_delegation_chain_with_trust_root`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationLink {
    /// Capability ID of the ancestor token delegated at this step.
    pub capability_id: String,
    /// Public key of the agent that delegated.
    pub delegator: PublicKey,
    /// Public key of the agent that received the delegation.
    pub delegatee: PublicKey,
    /// How the scope was narrowed in this delegation step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attenuations: Vec<Attenuation>,
    /// Unix timestamp of the delegation.
    pub timestamp: u64,
    /// Delegation chain-binding: SHA-256 hash of the canonical scope authorized
    /// at this hop. Absent on older links; verifiers can enforce presence via
    /// feature gate. Verifiers gated behind the `delegation_chain_binding`
    /// feature flag enforce that this matches the parent_scope_hash carried by
    /// the next hop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_hash: Option<ScopeHash>,
    /// Ed25519 signature by the delegator over the canonical form of the
    /// other fields in this link.
    pub signature: Signature,
}

/// The body of a delegation link, used as the signing input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationLinkBody {
    pub capability_id: String,
    pub delegator: PublicKey,
    pub delegatee: PublicKey,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attenuations: Vec<Attenuation>,
    pub timestamp: u64,
    /// Delegation chain-binding: see [`DelegationLink::scope_hash`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_hash: Option<ScopeHash>,
}

impl DelegationLink {
    /// Sign a delegation link body.
    pub fn sign(body: DelegationLinkBody, keypair: &Keypair) -> Result<Self> {
        ensure_keypair_matches_embedded_key(
            &body.delegator,
            keypair,
            "delegation link",
            "delegator",
        )?;
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            capability_id: body.capability_id,
            delegator: body.delegator,
            delegatee: body.delegatee,
            attenuations: body.attenuations,
            timestamp: body.timestamp,
            scope_hash: body.scope_hash,
            signature,
        })
    }

    /// Extract the signable body.
    #[must_use]
    pub fn body(&self) -> DelegationLinkBody {
        DelegationLinkBody {
            capability_id: self.capability_id.clone(),
            delegator: self.delegator.clone(),
            delegatee: self.delegatee.clone(),
            attenuations: self.attenuations.clone(),
            timestamp: self.timestamp,
            scope_hash: self.scope_hash.clone(),
        }
    }

    /// Verify this link's signature against the delegator's key.
    pub fn verify_signature(&self) -> Result<bool> {
        let body = self.body();
        self.delegator.verify_canonical(&body, &self.signature)
    }
}

/// Describes how a scope was narrowed during delegation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Attenuation {
    /// A tool was removed from the scope.
    RemoveTool {
        server_id: String,
        tool_name: String,
    },
    /// An operation was removed from a tool grant.
    RemoveOperation {
        server_id: String,
        tool_name: String,
        operation: Operation,
    },
    /// A constraint was added to a tool grant.
    AddConstraint {
        server_id: String,
        tool_name: String,
        constraint: Constraint,
    },
    /// The invocation budget was reduced.
    ReduceBudget {
        server_id: String,
        tool_name: String,
        max_invocations: u32,
    },
    /// The expiration was shortened.
    ShortenExpiry { new_expires_at: u64 },
    /// The per-invocation cost cap was tightened during delegation.
    ReduceCostPerInvocation {
        server_id: String,
        tool_name: String,
        max_cost_per_invocation: MonetaryAmount,
    },
    /// The total cost budget was reduced during delegation.
    ReduceTotalCost {
        server_id: String,
        tool_name: String,
        max_total_cost: MonetaryAmount,
    },
}

/// Validate an entire delegation chain.
///
/// Checks that:
/// 1. Each link's signature is valid.
/// 2. Adjacent links are connected (link[i].delegatee == link[i+1].delegator).
/// 3. Timestamps are non-decreasing.
/// 4. The chain length does not exceed `max_depth` (if provided).
///
/// Note: this compatibility entry point does NOT enforce chain-binding
/// (the `parent_scope_hash` invariant). Callers verifying attenuated
/// tokens must use [`validate_delegation_chain_with_trust_root`] to close
/// the parent-scope-inflation soundness gap.
pub fn validate_delegation_chain(chain: &[DelegationLink], max_depth: Option<u32>) -> Result<()> {
    if let Some(max) = max_depth {
        let len = u32::try_from(chain.len()).unwrap_or(u32::MAX);
        if len > max {
            return Err(Error::DelegationDepthExceeded { depth: len, max });
        }
    }

    for (i, link) in chain.iter().enumerate() {
        let sig_valid = link.verify_signature()?;
        if !sig_valid {
            return Err(Error::DelegationChainBroken {
                reason: format!("signature invalid at link index {i}"),
            });
        }

        if i > 0 {
            let prev = &chain[i - 1];
            if prev.delegatee != link.delegator {
                return Err(Error::DelegationChainBroken {
                    reason: format!("link {i} delegator does not match link {} delegatee", i - 1),
                });
            }
            if link.timestamp < prev.timestamp {
                return Err(Error::DelegationChainBroken {
                    reason: format!(
                        "link {i} timestamp ({}) precedes link {} timestamp ({})",
                        link.timestamp,
                        i - 1,
                        prev.timestamp
                    ),
                });
            }
        }
    }

    Ok(())
}

/// Validate a delegation chain under the chain-binding rule.
///
/// Defends against parent-scope inflation: an issuer with true authority
/// `scope_X` must not be able to mint an attenuated token claiming
/// `parent_scope = scope_BIGGER` with an internally-consistent
/// `attenuation_proof`, which is possible whenever nothing ties
/// `parent_scope_hash` to the issuer's actual upstream parent capability.
/// This verifier requires:
///
/// 1. Every link in the chain populates `scope_hash` (chains lacking
///    chain-binding are rejected fail-closed).
/// 2. The first hop's `scope_hash` equals `trust_root_scope_hash`.
/// 3. Multi-hop attenuated chains are rejected until delegation links carry
///    per-hop child-scope witnesses. With only one `scope_hash` per link, a
///    verifier cannot prove that link N's advertised parent scope was actually
///    received from link N-1.
/// 4. The leaf capability token's `attenuation_proof.parent_scope_hash`
///    is checked against `chain.last().scope_hash` by
///    [`CapabilityToken::validate_chain_binding`].
///
/// Scope hashes alone cannot prove per-hop subset relations because the
/// full parent and child scopes are not carried on every delegation link.
/// Callers that need per-hop semantic attenuation must carry explicit
/// witnesses for each hop.
///
/// The signature, connectivity, and timestamp checks from the v1 entry
/// point are also enforced.
pub fn validate_delegation_chain_with_trust_root(
    chain: &[DelegationLink],
    max_depth: Option<u32>,
    trust_root_scope_hash: &ScopeHash,
) -> Result<()> {
    validate_delegation_chain(chain, max_depth)?;

    if chain.is_empty() {
        return Ok(());
    }

    if chain.len() > 1 {
        return Err(Error::DelegationChainBroken {
            reason: "multi-hop attenuated delegation chains require per-hop child-scope witnesses"
                .to_string(),
        });
    }

    for (i, link) in chain.iter().enumerate() {
        let Some(link_hash) = link.scope_hash.as_ref() else {
            return Err(Error::DelegationChainBroken {
                reason: format!(
                    "delegation chain link {i} omits scope_hash; Chio delegation requires every hop to bind its authorized scope"
                ),
            });
        };

        if i == 0 && link_hash != trust_root_scope_hash {
            return Err(Error::DelegationChainBroken {
                reason: "delegation chain link 0 scope_hash does not match trust root scope hash"
                    .to_string(),
            });
        }
    }

    Ok(())
}

/// Locate the parent tool grant that an attenuation step targets.
///
/// Steps are addressed by `(server_id, tool_name)`. A step that references a
/// grant the parent never held is itself a widening (it asserts authority over
/// a tool outside the parent's scope) and must be rejected fail-closed.
///
/// Wildcard parent grants are honored with the same coverage semantics as
/// [`super::scope::ToolGrant::is_subset_of`]: a parent grant whose
/// `server_id` or `tool_name` is `"*"` covers a concrete child step. A
/// concrete-child step against a `*:*` parent grant is therefore a legitimate
/// narrowing, not a widening.
fn find_parent_tool_grant<'a>(
    parent: &'a ChioScope,
    server_id: &str,
    tool_name: &str,
) -> Result<&'a super::scope::ToolGrant> {
    parent
        .grants
        .iter()
        .find(|grant| {
            (grant.server_id == "*" || grant.server_id == server_id)
                && (grant.tool_name == "*" || grant.tool_name == tool_name)
        })
        .ok_or_else(|| Error::AttenuationViolation {
            reason: format!(
                "attenuation step targets tool {server_id}:{tool_name} not present in parent scope"
            ),
        })
}

/// Validate that a single attenuation step is a TRUE narrowing of the parent.
///
/// Each step is checked reduce-only against the parent capability's scope and
/// expiry. A step that would widen the parent (raise a cap, target a tool the
/// parent never held, or extend expiry) is rejected with
/// [`Error::AttenuationViolation`]. Removing tools, removing operations, and
/// adding constraints are narrowings by construction, but the targeted grant
/// must still exist in the parent so a step cannot smuggle in fresh authority.
fn validate_attenuation_step(
    parent_scope: &ChioScope,
    parent_expires_at: u64,
    step: &Attenuation,
) -> Result<()> {
    match step {
        Attenuation::RemoveTool {
            server_id,
            tool_name,
        }
        | Attenuation::AddConstraint {
            server_id,
            tool_name,
            ..
        } => {
            // Removing a tool or adding a constraint is a narrowing; the grant
            // must exist in the parent so the step cannot fabricate authority.
            find_parent_tool_grant(parent_scope, server_id, tool_name)?;
            Ok(())
        }
        Attenuation::RemoveOperation {
            server_id,
            tool_name,
            operation,
        } => {
            let grant = find_parent_tool_grant(parent_scope, server_id, tool_name)?;
            if !grant.operations.contains(operation) {
                return Err(Error::AttenuationViolation {
                    reason: format!(
                        "attenuation step removes operation {operation:?} from {server_id}:{tool_name} but the parent grant does not hold it"
                    ),
                });
            }
            Ok(())
        }
        Attenuation::ReduceBudget {
            server_id,
            tool_name,
            max_invocations,
        } => {
            let grant = find_parent_tool_grant(parent_scope, server_id, tool_name)?;
            if let Some(parent_max) = grant.max_invocations {
                if *max_invocations > parent_max {
                    return Err(Error::AttenuationViolation {
                        reason: format!(
                            "attenuation step raises max_invocations for {server_id}:{tool_name} to {max_invocations}, above parent cap {parent_max}"
                        ),
                    });
                }
            }
            // Parent uncapped (None) accepts any finite child cap: that narrows.
            Ok(())
        }
        Attenuation::ReduceCostPerInvocation {
            server_id,
            tool_name,
            max_cost_per_invocation,
        } => {
            let grant = find_parent_tool_grant(parent_scope, server_id, tool_name)?;
            validate_cost_narrowing(
                grant.max_cost_per_invocation.as_ref(),
                max_cost_per_invocation,
                server_id,
                tool_name,
                "max_cost_per_invocation",
            )
        }
        Attenuation::ReduceTotalCost {
            server_id,
            tool_name,
            max_total_cost,
        } => {
            let grant = find_parent_tool_grant(parent_scope, server_id, tool_name)?;
            validate_cost_narrowing(
                grant.max_total_cost.as_ref(),
                max_total_cost,
                server_id,
                tool_name,
                "max_total_cost",
            )
        }
        Attenuation::ShortenExpiry { new_expires_at } => {
            if *new_expires_at > parent_expires_at {
                return Err(Error::AttenuationViolation {
                    reason: format!(
                        "attenuation step extends expiry to {new_expires_at}, beyond parent expires_at {parent_expires_at}"
                    ),
                });
            }
            Ok(())
        }
    }
}

/// Shared reduce-only check for the two monetary-cost attenuation steps.
///
/// A cost cap narrows only when it is denominated in the same currency as the
/// parent's cap and does not exceed it. A parent with no cap (`None`) accepts
/// any child cap as a narrowing.
fn validate_cost_narrowing(
    parent_cap: Option<&MonetaryAmount>,
    child_cap: &MonetaryAmount,
    server_id: &str,
    tool_name: &str,
    field: &str,
) -> Result<()> {
    let Some(parent_cap) = parent_cap else {
        // Parent uncapped: introducing any finite cap is a narrowing.
        return Ok(());
    };
    if child_cap.currency != parent_cap.currency {
        return Err(Error::AttenuationViolation {
            reason: format!(
                "attenuation step changes {field} currency for {server_id}:{tool_name} from {} to {}; same currency required",
                parent_cap.currency, child_cap.currency
            ),
        });
    }
    if child_cap.units > parent_cap.units {
        return Err(Error::AttenuationViolation {
            reason: format!(
                "attenuation step raises {field} for {server_id}:{tool_name} to {} {}, above parent cap {} {}",
                child_cap.units, child_cap.currency, parent_cap.units, parent_cap.currency
            ),
        });
    }
    Ok(())
}

/// Validate every attenuation step against the parent capability, fail-closed.
///
/// Returns `Ok(())` only when all steps are true narrowings. The first
/// widening step short-circuits with an [`Error::AttenuationViolation`].
fn validate_attenuation_steps(
    parent_scope: &ChioScope,
    parent_expires_at: u64,
    steps: &[Attenuation],
) -> Result<()> {
    for step in steps {
        validate_attenuation_step(parent_scope, parent_expires_at, step)?;
    }
    Ok(())
}

/// Validate that a child scope is a valid attenuation of a parent scope.
///
/// Returns Ok(()) if child is a subset of parent. Returns an error otherwise.
pub fn validate_attenuation(parent: &ChioScope, child: &ChioScope) -> Result<()> {
    if child.is_subset_of(parent) {
        Ok(())
    } else {
        Err(Error::AttenuationViolation {
            reason: "child scope is not a subset of parent scope".to_string(),
        })
    }
}

/// Compute the stable SHA-256 hash of a canonicalized scope.
pub fn scope_hash(scope: &ChioScope) -> Result<ScopeHash> {
    let canonical = canonical_json_bytes(scope)?;
    Ok(sha256_hex(&canonical))
}

pub(crate) fn canonical_scope_string(scope: &ChioScope) -> Result<String> {
    let canonical = canonical_json_bytes(scope)?;
    core::str::from_utf8(&canonical)
        .map(ToString::to_string)
        .map_err(|err| Error::CanonicalJson(format!("canonical scope utf8 error: {err}")))
}

/// Compute an on-wire witness for a parent-to-child attenuation.
pub fn compute_attenuation_witness(
    parent: &ChioScope,
    child: &ChioScope,
) -> Result<AttenuationWitness> {
    validate_attenuation(parent, child)?;

    let mut subset_relations = Vec::new();
    let mut restricted_predicates = Vec::new();

    for (child_index, child_grant) in child.grants.iter().enumerate() {
        let Some(parent_index) = parent
            .grants
            .iter()
            .position(|parent_grant| child_grant.is_subset_of(parent_grant))
        else {
            return Err(Error::AttenuationViolation {
                reason: format!("tool grant {child_index} has no parent subset witness"),
            });
        };
        subset_relations.push(GrantSubsetRelation {
            grant_kind: "tool".to_string(),
            child_index: u32::try_from(child_index).unwrap_or(u32::MAX),
            parent_index: u32::try_from(parent_index).unwrap_or(u32::MAX),
            subset: true,
        });
        let parent_grant = &parent.grants[parent_index];
        for constraint in &child_grant.constraints {
            if !parent_grant.constraints.contains(constraint) {
                restricted_predicates.push(format!(
                    "tool:{}:{}:constraint:{:?}",
                    child_grant.server_id, child_grant.tool_name, constraint
                ));
            }
        }
        for operation in &parent_grant.operations {
            if !child_grant.operations.contains(operation) {
                restricted_predicates.push(format!(
                    "tool:{}:{}:removed_operation:{:?}",
                    child_grant.server_id, child_grant.tool_name, operation
                ));
            }
        }
    }

    for (child_index, child_grant) in child.resource_grants.iter().enumerate() {
        let Some(parent_index) = parent
            .resource_grants
            .iter()
            .position(|parent_grant| child_grant.is_subset_of(parent_grant))
        else {
            return Err(Error::AttenuationViolation {
                reason: format!("resource grant {child_index} has no parent subset witness"),
            });
        };
        subset_relations.push(GrantSubsetRelation {
            grant_kind: "resource".to_string(),
            child_index: u32::try_from(child_index).unwrap_or(u32::MAX),
            parent_index: u32::try_from(parent_index).unwrap_or(u32::MAX),
            subset: true,
        });
    }

    for (child_index, child_grant) in child.prompt_grants.iter().enumerate() {
        let Some(parent_index) = parent
            .prompt_grants
            .iter()
            .position(|parent_grant| child_grant.is_subset_of(parent_grant))
        else {
            return Err(Error::AttenuationViolation {
                reason: format!("prompt grant {child_index} has no parent subset witness"),
            });
        };
        subset_relations.push(GrantSubsetRelation {
            grant_kind: "prompt".to_string(),
            child_index: u32::try_from(child_index).unwrap_or(u32::MAX),
            parent_index: u32::try_from(parent_index).unwrap_or(u32::MAX),
            subset: true,
        });
    }

    Ok(AttenuationWitness {
        normalized_parent_scope: canonical_scope_string(parent)?,
        normalized_child_scope: canonical_scope_string(child)?,
        subset_relations,
        restricted_predicates,
    })
}

/// Verify a previously-computed attenuation witness against scope hashes.
pub fn verify_attenuation_witness(
    parent_hash: &ScopeHash,
    child_hash: &ScopeHash,
    witness: &AttenuationWitness,
) -> Result<()> {
    validate_attenuation_proof(parent_hash, child_hash, witness)
}

/// Verify the wire `attenuation_proof` payload.
pub fn validate_attenuation_proof(
    parent_hash: &ScopeHash,
    child_hash: &ScopeHash,
    witness: &AttenuationWitness,
) -> Result<()> {
    let computed_parent_hash = sha256_hex(witness.normalized_parent_scope.as_bytes());
    if &computed_parent_hash != parent_hash {
        return Err(Error::AttenuationViolation {
            reason: "attenuation witness parent_scope_hash mismatch".to_string(),
        });
    }
    let computed_child_hash = sha256_hex(witness.normalized_child_scope.as_bytes());
    if &computed_child_hash != child_hash {
        return Err(Error::AttenuationViolation {
            reason: "attenuation witness child_scope_hash mismatch".to_string(),
        });
    }
    if witness
        .subset_relations
        .iter()
        .any(|relation| !relation.subset)
    {
        return Err(Error::AttenuationViolation {
            reason: "attenuation witness carries a non-subset relation".to_string(),
        });
    }
    let parent_scope: ChioScope =
        serde_json::from_str(&witness.normalized_parent_scope).map_err(|err| {
            Error::AttenuationViolation {
                reason: format!("attenuation witness parent scope is invalid: {err}"),
            }
        })?;
    let child_scope: ChioScope =
        serde_json::from_str(&witness.normalized_child_scope).map_err(|err| {
            Error::AttenuationViolation {
                reason: format!("attenuation witness child scope is invalid: {err}"),
            }
        })?;
    validate_attenuation(&parent_scope, &child_scope)?;
    Ok(())
}

fn validate_delegable_child_scope(parent: &ChioScope, child: &ChioScope) -> Result<()> {
    let has_delegable_parent_grant = parent
        .grants
        .iter()
        .any(|grant| grant.operations.contains(&Operation::Delegate))
        || parent
            .resource_grants
            .iter()
            .any(|grant| grant.operations.contains(&Operation::Delegate))
        || parent
            .prompt_grants
            .iter()
            .any(|grant| grant.operations.contains(&Operation::Delegate));
    if !has_delegable_parent_grant {
        return Err(Error::AttenuationViolation {
            reason: "parent capability scope does not authorize delegation".to_string(),
        });
    }

    for (index, child_grant) in child.grants.iter().enumerate() {
        let covered_by_delegable_parent = parent.grants.iter().any(|parent_grant| {
            parent_grant.operations.contains(&Operation::Delegate)
                && child_grant.is_subset_of(parent_grant)
        });
        if !covered_by_delegable_parent {
            return Err(Error::AttenuationViolation {
                reason: format!(
                    "tool grant {index} is not covered by a parent grant that authorizes delegation"
                ),
            });
        }
    }

    for (index, child_grant) in child.resource_grants.iter().enumerate() {
        let covered_by_delegable_parent = parent.resource_grants.iter().any(|parent_grant| {
            parent_grant.operations.contains(&Operation::Delegate)
                && child_grant.is_subset_of(parent_grant)
        });
        if !covered_by_delegable_parent {
            return Err(Error::AttenuationViolation {
                reason: format!(
                    "resource grant {index} is not covered by a parent grant that authorizes delegation"
                ),
            });
        }
    }

    for (index, child_grant) in child.prompt_grants.iter().enumerate() {
        let covered_by_delegable_parent = parent.prompt_grants.iter().any(|parent_grant| {
            parent_grant.operations.contains(&Operation::Delegate)
                && child_grant.is_subset_of(parent_grant)
        });
        if !covered_by_delegable_parent {
            return Err(Error::AttenuationViolation {
                reason: format!(
                    "prompt grant {index} is not covered by a parent grant that authorizes delegation"
                ),
            });
        }
    }

    Ok(())
}

/// Recursive-delegation mint helper.
///
/// `delegate` wraps [`DelegationLink::sign`] with fail-closed attenuation
/// enforcement and emits a [`DelegationReceipt`] alongside the signed
/// link. Returns `Err` (denying the mint) when any of:
///
/// * The parent token's scope does not explicitly authorize
///   [`Operation::Delegate`].
/// * The proposed `child_scope` is not a subset of the parent token's
///   scope (rejected by [`validate_attenuation`]).
/// * Any `attenuation.steps` entry is not a true narrowing of the parent
///   (raises a cap, targets a tool outside the parent scope, or extends
///   expiry). Steps are validated reduce-only rather than copied verbatim.
/// * `attenuation.budget_share_bps` exceeds the parent's share. The share is
///   parent-relative: a child can never claim a larger fraction of the budget
///   than the parent holds (an absent parent share is treated as 100%). When
///   the parent itself holds a reduced share, the child MUST state an explicit
///   `budget_share_bps`: omission is rejected fail-closed because downstream
///   admission treats a missing share as the full budget (a widening).
/// * The requested `child_expires_at` is greater than the parent's
///   `expires_at` (rejected as an [`Error::AttenuationViolation`]).
/// * `delegator_keypair.public_key() != parent.subject` (the mint helper
///   is fail-closed: only the parent capability's bound subject may
///   delegate further).
///
/// The helper is intentionally pure with respect to the local clock:
/// callers pass `signed_at` and `nonce` explicitly so unit tests, replay
/// proofs, and proptest-driven invariants stay deterministic.
///
/// This function is gated behind the `delegation` feature flag. Callers
/// must opt in explicitly.
pub fn delegate(
    parent: &CapabilityToken,
    child_scope: &ChioScope,
    delegator_keypair: &Keypair,
    delegatee: &PublicKey,
    attenuation: crate::delegation_receipt::ScopeAttenuation,
    signed_at: u64,
    nonce: [u8; 16],
) -> Result<crate::delegation_receipt::DelegationReceipt> {
    if !parent.verify_signature()? {
        return Err(Error::SignatureVerificationFailed);
    }
    if signed_at < parent.issued_at {
        return Err(Error::CapabilityNotYetValid {
            not_before: parent.issued_at,
        });
    }
    if delegator_keypair.public_key() != parent.subject {
        return Err(Error::AttenuationViolation {
            reason: alloc::format!(
                "delegator key {} does not match parent capability subject {}",
                delegator_keypair.public_key().to_hex(),
                parent.subject.to_hex()
            ),
        });
    }

    validate_attenuation(&parent.scope, child_scope)?;
    validate_delegable_child_scope(&parent.scope, child_scope)?;

    // Each attenuation step must be a TRUE narrowing of the parent: previously
    // the steps were copied onto the signed link verbatim, so a widening step
    // (raise a cap, target a tool outside the parent, extend expiry) could ride
    // through unchecked. Validate reduce-only, fail-closed.
    validate_attenuation_steps(&parent.scope, parent.expires_at, &attenuation.steps)?;

    // `budget_share_bps` is parent-relative: a delegated share is a fraction of
    // the parent's remaining/granted budget and can never widen it.
    //
    // Fail-closed on omission when the parent is budget-attenuated. Downstream
    // delegated-budget admission treats a missing child share as the full
    // ceiling (MAX_BUDGET_SHARE_BPS, 100%). If the parent already holds a
    // reduced share, a child that omits its own share would therefore inherit
    // an unrestricted (effectively 100%) share, a widening. Require the child
    // to state an explicit share that is `<=` the parent's whenever the parent
    // carries a reduced share.
    match attenuation.budget_share_bps {
        Some(child_share) => {
            validate_parent_relative_budget_share_bps(parent.budget_share_bps, child_share)?;
        }
        None => {
            if let Some(parent_share) = parent.budget_share_bps {
                return Err(Error::AttenuationViolation {
                    reason: alloc::format!(
                        "parent holds a reduced budget_share_bps {parent_share}; the child must state an explicit budget_share_bps <= {parent_share} (an omitted share would widen to the full budget)"
                    ),
                });
            }
        }
    }

    let child_expires_at = attenuation.child_expires_at.unwrap_or(parent.expires_at);
    if child_expires_at > parent.expires_at {
        return Err(Error::AttenuationViolation {
            reason: alloc::format!(
                "child expires_at {} exceeds parent expires_at {}",
                child_expires_at,
                parent.expires_at
            ),
        });
    }
    if signed_at >= parent.expires_at {
        return Err(Error::AttenuationViolation {
            reason: alloc::format!(
                "signed_at {} is at or beyond parent expires_at {}",
                signed_at,
                parent.expires_at
            ),
        });
    }

    // Delegation chain-binding: emit the parent authorized scope_hash on the
    // delegation link. A child token proving parent -> child attenuation binds
    // attenuation_proof.parent_scope_hash to this predecessor link.
    let parent_scope_hash = scope_hash(&parent.scope)?;
    let body = DelegationLinkBody {
        capability_id: parent.id.clone(),
        delegator: parent.subject.clone(),
        delegatee: delegatee.clone(),
        attenuations: attenuation.steps.clone(),
        timestamp: signed_at,
        scope_hash: Some(parent_scope_hash),
    };
    let link = DelegationLink::sign(body, delegator_keypair)?;

    Ok(crate::delegation_receipt::DelegationReceipt {
        parent_chain: parent.delegation_chain.clone(),
        attenuation,
        signed_at,
        nonce,
        link,
        parent_capability_id: parent.id.clone(),
    })
}
