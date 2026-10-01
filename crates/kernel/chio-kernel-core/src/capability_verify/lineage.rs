//! Pure verification of signed intermediate scopes for recursive delegation.

use super::*;
use chio_core_types::capability::attenuation::{scope_hash, validate_attenuation};
use chio_core_types::capability::scope::Operation;
use chio_core_types::crypto::canonical_json_bytes;

pub(super) fn verify_signed_lineage(
    token: &CapabilityToken,
    ancestors: &[CapabilityToken],
    trusted: &[PublicKey],
    clock: &dyn Clock,
    floor: CapabilityCryptoFloor,
    features: CapabilityFeatureContext<'_>,
    resolver: &dyn TrustRootResolver,
) -> Result<(), CapabilityError> {
    let invalid = |message: &str| CapabilityError::AttenuationViolation(message.to_string());
    if ancestors.len() != token.delegation_chain.len() || ancestors.len() > 64 {
        return Err(invalid(
            "signed lineage must cover every delegation hop, at most 64",
        ));
    }
    let root = ancestors
        .first()
        .ok_or_else(|| invalid("signed lineage is empty"))?;
    let issuer_root = resolver
        .trust_root_scope_hash(&token.issuer)
        .ok_or_else(|| invalid("signed lineage has no pinned issuer scope"))?;
    if let Some(direct_root) = features.direct_root {
        if canonical_json_bytes(direct_root).map_err(map_optional_feature_error)?
            != canonical_json_bytes(root).map_err(map_optional_feature_error)?
        {
            return Err(invalid(
                "signed lineage differs from the negotiated family root",
            ));
        }
    }
    let aggregate = features.peer.supports(AGGREGATE_INVOCATION_BUDGET);
    let cumulative = features.peer.supports(CUMULATIVE_APPROVAL_BUDGET);
    let binding_enabled = features
        .peer
        .features
        .get(chio_core_types::capability::features::DELEGATION_CHAIN_BINDING)
        .copied()
        .unwrap_or(true);
    let mut identifiers = alloc::collections::BTreeSet::new();
    identifiers.insert(token.id.as_str());

    for (index, parent) in ancestors.iter().enumerate() {
        if !identifiers.insert(parent.id.as_str()) {
            return Err(invalid("signed lineage repeats a capability identity"));
        }
        verify_capability_base(parent, trusted, clock, floor, aggregate, cumulative)?;
        verify_delegation_chain_shape(parent)?;
        let child = ancestors.get(index + 1).unwrap_or(token);
        let link = &token.delegation_chain[index];
        if parent.issuer != token.issuer
            || parent.id != link.capability_id
            || parent.subject != link.delegator
            || child.subject != link.delegatee
            || canonical_json_bytes(&parent.delegation_chain).map_err(map_optional_feature_error)?
                != canonical_json_bytes(&&token.delegation_chain[..index])
                    .map_err(map_optional_feature_error)?
        {
            return Err(invalid(
                "signed ancestor does not match the exact delegation prefix",
            ));
        }
        let parent_scope_hash = scope_hash(&parent.scope).map_err(map_optional_feature_error)?;
        if link.scope_hash.as_ref() != Some(&parent_scope_hash) {
            return Err(invalid(
                "delegation link scope differs from its signed ancestor scope",
            ));
        }
        if index == 0 && !parent.requires_chain_binding() && parent_scope_hash != issuer_root {
            return Err(invalid(
                "signed root scope differs from the pinned issuer scope",
            ));
        }
        if parent.requires_chain_binding() || child.requires_chain_binding() {
            if !binding_enabled {
                return Err(invalid("peer disabled delegation_chain_binding"));
            }
            parent
                .validate_chain_binding(&issuer_root)
                .map_err(map_optional_feature_error)?;
            child
                .validate_chain_binding(&issuer_root)
                .map_err(map_optional_feature_error)?;
        }
        if child.issued_at < parent.issued_at
            || child.expires_at > parent.expires_at
            || link.timestamp < parent.issued_at
            || link.timestamp >= parent.expires_at
            || child.issued_at < link.timestamp
            || child.budget_share_bps.unwrap_or(10_000) > parent.budget_share_bps.unwrap_or(10_000)
        {
            return Err(invalid(
                "delegated validity or budget share widens its signed parent",
            ));
        }
        validate_attenuation(&parent.scope, &child.scope).map_err(map_optional_feature_error)?;
        if child.scope.grants.iter().any(|grant| {
            !parent
                .scope
                .grants
                .iter()
                .any(|p| p.operations.contains(&Operation::Delegate) && grant.is_subset_of(p))
        }) || child.scope.resource_grants.iter().any(|grant| {
            !parent
                .scope
                .resource_grants
                .iter()
                .any(|p| p.operations.contains(&Operation::Delegate) && grant.is_subset_of(p))
        }) || child.scope.prompt_grants.iter().any(|grant| {
            !parent
                .scope
                .prompt_grants
                .iter()
                .any(|p| p.operations.contains(&Operation::Delegate) && grant.is_subset_of(p))
        }) {
            return Err(invalid(
                "signed parent does not grant delegation for the child scope",
            ));
        }
        let family_root = (index != 0).then_some(root);
        verify_negotiated_aggregate_budget(parent, trusted, aggregate, family_root)?;
        verify_negotiated_cumulative_approval(parent, trusted, cumulative, family_root)?;
    }
    Ok(())
}
