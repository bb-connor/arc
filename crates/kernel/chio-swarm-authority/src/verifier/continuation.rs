//! Continuation token validation against the verified swarm graph.

use super::*;

pub(super) struct ContinuationValidationContext<'a, 'b> {
    pub(super) bundle: &'a SwarmAuthorityBundle,
    pub(super) graph_sha256: &'a str,
    pub(super) task_by_id: &'a BTreeMap<&'b str, &'b SwarmGraphNode>,
    pub(super) edge_set: &'a BTreeSet<(&'b str, &'b str)>,
    pub(super) route_by_id: &'a BTreeMap<&'b str, &'b SwarmRoutePlanReceipt>,
    pub(super) join_by_id: &'a BTreeMap<&'b str, &'b SwarmJoinReceipt>,
    pub(super) allocation_by_id: &'a BTreeMap<&'b str, &'b SwarmBudgetAllocation>,
    pub(super) trusted_witness_issuer_keys: &'a [PublicKey],
}

pub(super) fn validate_continuation_tokens(
    context: &ContinuationValidationContext<'_, '_>,
) -> Result<(), SwarmAuthorityError> {
    let mut continuations = BTreeMap::new();
    let mut continuation_nonces = BTreeSet::new();
    for token in &context.bundle.continuation_tokens {
        validate_continuation_token(context, token)?;
        verify_continuation_token_signature(token, context.trusted_witness_issuer_keys)?;
        if !continuation_nonces.insert(token.nonce.as_str()) {
            return Err(rejected(format!(
                "swarm continuation nonce replay: {}",
                token.token_id
            )));
        }
        if continuations
            .insert(token.token_id.as_str(), token)
            .is_some()
        {
            return Err(rejected(format!(
                "duplicate swarm continuation token: {}",
                token.token_id
            )));
        }
    }
    for node in &context.bundle.task_graph.nodes {
        if node.parent_task_id.is_some() && node.continuation_token_ref.is_none() {
            return Err(rejected(format!(
                "swarm task continuation token ref missing: {}",
                node.task_id
            )));
        }
        if let Some(token_ref) = &node.continuation_token_ref {
            match continuations.get(token_ref.as_str()) {
                Some(token) if token.child_task_id == node.task_id => {}
                Some(_) => {
                    return Err(rejected(format!(
                        "swarm continuation token task mismatch: {token_ref}"
                    )));
                }
                None => {
                    return Err(rejected(format!(
                        "missing swarm continuation token: {token_ref}"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn validate_continuation_token(
    context: &ContinuationValidationContext<'_, '_>,
    token: &SwarmContinuationToken,
) -> Result<(), SwarmAuthorityError> {
    let bundle = context.bundle;
    if token.schema != CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA {
        return Err(util::unsupported_schema(format!(
            "unsupported swarm continuation token schema: {}",
            token.schema
        )));
    }
    require_non_empty(&token.token_id, "swarm continuation token id")?;
    require_same_graph(
        &token.graph_id,
        &bundle.task_graph.graph_id,
        "continuation token",
    )?;
    require_non_empty(&token.child_task_id, "swarm continuation child task id")?;
    require_non_empty(&token.issuer, "swarm continuation issuer")?;
    require_non_empty(&token.signature, "swarm continuation signature")?;
    let child_task = context
        .task_by_id
        .get(token.child_task_id.as_str())
        .copied()
        .ok_or_else(|| {
            rejected(format!(
                "swarm continuation child task is unknown: {}",
                token.child_task_id
            ))
        })?;
    if token.issued_at_unix_ms > bundle.now_unix_ms {
        return Err(rejected(format!(
            "swarm continuation token is from the future: {}",
            token.token_id
        )));
    }
    if token.expires_at_unix_ms <= bundle.now_unix_ms {
        return Err(rejected(format!(
            "swarm continuation token is stale: {}",
            token.token_id
        )));
    }
    if token.graph_sha256 != context.graph_sha256 {
        return Err(util::digest_mismatch(format!(
            "swarm continuation graph digest mismatch: {}",
            token.token_id
        )));
    }
    require_non_empty(
        &token.session_anchor_ref,
        "swarm continuation session anchor",
    )?;
    require_non_empty(&token.nonce, "swarm continuation nonce")?;
    require_unique_strings(
        &token.parent_receipt_ids,
        "swarm continuation parent receipt",
    )?;
    validate_continuation_parent(token, child_task, context.edge_set, context.join_by_id)?;
    validate_continuation_witness_chain(token, bundle)?;
    validate_continuation_route(token, child_task, context.route_by_id)?;
    validate_continuation_budget(token, child_task, context.allocation_by_id)?;
    if token.revocation_epoch_ref != bundle.revocation_epoch.epoch_id {
        return Err(rejected(format!(
            "swarm continuation revocation epoch mismatch: {}",
            token.token_id
        )));
    }
    require_sha256(
        &token.revocation_epoch_root_hash,
        "swarm continuation revocation epoch root",
    )?;
    if token.revocation_epoch_root_hash != bundle.revocation_epoch.root_hash {
        return Err(rejected(format!(
            "swarm continuation revocation epoch root mismatch: {}",
            token.token_id
        )));
    }
    Ok(())
}

fn validate_continuation_witness_chain(
    token: &SwarmContinuationToken,
    bundle: &SwarmAuthorityBundle,
) -> Result<(), SwarmAuthorityError> {
    let Some(parent_task_id) = token.parent_task_id.as_deref() else {
        if token.witness_chain_ref.is_some() || token.witness_chain_sha256.is_some() {
            return Err(rejected(format!(
                "swarm continuation witness chain binding without parent task: {}",
                token.token_id
            )));
        }
        return Ok(());
    };
    let witness_chain_ref = token.witness_chain_ref.as_deref().ok_or_else(|| {
        rejected(format!(
            "swarm continuation witness chain binding missing: {}",
            token.token_id
        ))
    })?;
    require_non_empty(witness_chain_ref, "swarm continuation witness chain ref")?;
    let witness_chain_sha256 = token.witness_chain_sha256.as_deref().ok_or_else(|| {
        rejected(format!(
            "swarm continuation witness chain digest missing: {}",
            token.token_id
        ))
    })?;
    require_sha256(
        witness_chain_sha256,
        "swarm continuation witness chain digest",
    )?;
    let chain = bundle
        .witness_chains
        .iter()
        .find(|chain| chain.chain_id == witness_chain_ref)
        .ok_or_else(|| {
            rejected(format!(
                "swarm continuation witness chain mismatch: {}",
                token.token_id
            ))
        })?;
    if chain.parent_task_id != parent_task_id || chain.child_task_id != token.child_task_id {
        return Err(rejected(format!(
            "swarm continuation witness chain mismatch: {}",
            token.token_id
        )));
    }
    let actual_sha256 = canonical_sha256(chain)?;
    if actual_sha256 != witness_chain_sha256 {
        return Err(util::digest_mismatch(format!(
            "swarm continuation witness chain digest mismatch: {}",
            token.token_id
        )));
    }
    Ok(())
}

fn verify_continuation_token_signature(
    token: &SwarmContinuationToken,
    trusted_witness_issuer_keys: &[PublicKey],
) -> Result<(), SwarmAuthorityError> {
    let public_key = witness_issuer_public_key(&token.issuer)?;
    ensure_continuation_issuer_is_pinned(token, &public_key, trusted_witness_issuer_keys)?;
    let signature = Signature::from_hex(&token.signature).map_err(|error| {
        util::signature_invalid(format!(
            "swarm continuation signature invalid: {}: {error}",
            token.token_id
        ))
    })?;
    let body = continuation_token_signature_body(token)?;
    let verified = verify_wrapped(
        &public_key,
        CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA,
        &body,
        &signature,
    )
    .is_ok();
    if verified {
        Ok(())
    } else {
        Err(util::signature_invalid(format!(
            "swarm continuation signature invalid: {}",
            token.token_id
        )))
    }
}

fn ensure_continuation_issuer_is_pinned(
    token: &SwarmContinuationToken,
    public_key: &PublicKey,
    trusted_witness_issuer_keys: &[PublicKey],
) -> Result<(), SwarmAuthorityError> {
    if trusted_witness_issuer_keys.is_empty() {
        return Err(util::unsupported(
            "trusted swarm witness keys missing: CHIO_SWARM_TRUSTED_WITNESS_KEYS must pin trusted swarm witness keys",
        ));
    }
    if trusted_witness_issuer_keys
        .iter()
        .any(|trusted_key| trusted_key == public_key)
    {
        Ok(())
    } else {
        Err(rejected(format!(
            "swarm continuation issuer is not trusted: {}",
            token.token_id
        )))
    }
}

fn validate_continuation_parent(
    token: &SwarmContinuationToken,
    child_task: &SwarmGraphNode,
    edge_set: &BTreeSet<(&str, &str)>,
    join_by_id: &BTreeMap<&str, &SwarmJoinReceipt>,
) -> Result<(), SwarmAuthorityError> {
    match (&token.parent_task_id, &token.join_receipt_id) {
        (Some(parent_task_id), None) => {
            if child_task.parent_task_id.as_deref() != Some(parent_task_id.as_str()) {
                return Err(rejected(format!(
                    "swarm continuation parent task mismatch: {}",
                    token.token_id
                )));
            }
            if token.parent_receipt_ids.is_empty() {
                return Err(rejected(format!(
                    "swarm continuation lacks parent receipt: {}",
                    token.token_id
                )));
            }
            if !edge_set.contains(&(parent_task_id.as_str(), token.child_task_id.as_str())) {
                return Err(rejected(format!(
                    "swarm continuation parent edge mismatch: {}",
                    token.token_id
                )));
            }
        }
        (None, Some(join_receipt_id)) => {
            let join = join_by_id.get(join_receipt_id.as_str()).ok_or_else(|| {
                rejected(format!(
                    "swarm continuation join receipt is unknown: {join_receipt_id}"
                ))
            })?;
            if join.next_task_id != token.child_task_id {
                return Err(rejected(format!(
                    "swarm continuation join target mismatch: {}",
                    token.token_id
                )));
            }
            if sorted_strings(&token.parent_receipt_ids)
                != sorted_strings(&join.actual_parent_receipt_ids)
            {
                return Err(rejected(format!(
                    "swarm continuation join parent receipts mismatch: {}",
                    token.token_id
                )));
            }
        }
        (Some(_), Some(_)) => {
            return Err(rejected(format!(
                "swarm continuation must choose parent task or join receipt: {}",
                token.token_id
            )));
        }
        (None, None) => {
            return Err(rejected(format!(
                "swarm continuation missing parent context: {}",
                token.token_id
            )));
        }
    }
    Ok(())
}

fn validate_continuation_route(
    token: &SwarmContinuationToken,
    child_task: &SwarmGraphNode,
    route_by_id: &BTreeMap<&str, &SwarmRoutePlanReceipt>,
) -> Result<(), SwarmAuthorityError> {
    match child_task.route_plan_ref.as_deref() {
        Some(route_plan_ref) if route_plan_ref == token.route_plan_receipt_id => {}
        Some(_) => {
            return Err(rejected(format!(
                "swarm continuation route-plan ref mismatch: {}",
                token.token_id
            )));
        }
        None => {
            return Err(rejected(format!(
                "swarm continuation route-plan ref missing: {}",
                token.token_id
            )));
        }
    }
    let route = route_by_id
        .get(token.route_plan_receipt_id.as_str())
        .ok_or_else(|| {
            rejected(format!(
                "swarm continuation route-plan receipt is unknown: {}",
                token.route_plan_receipt_id
            ))
        })?;
    if route.task_id != token.child_task_id {
        return Err(rejected(format!(
            "swarm continuation route-plan task mismatch: {}",
            token.token_id
        )));
    }
    Ok(())
}

fn validate_continuation_budget(
    token: &SwarmContinuationToken,
    child_task: &SwarmGraphNode,
    allocation_by_id: &BTreeMap<&str, &SwarmBudgetAllocation>,
) -> Result<(), SwarmAuthorityError> {
    match child_task.budget_allocation_ref.as_deref() {
        Some(allocation_ref) if allocation_ref == token.budget_allocation_id => {}
        Some(_) => {
            return Err(rejected(format!(
                "swarm continuation budget ref mismatch: {}",
                token.token_id
            )));
        }
        None => {
            return Err(rejected(format!(
                "swarm continuation budget ref missing: {}",
                token.token_id
            )));
        }
    }
    let allocation = allocation_by_id
        .get(token.budget_allocation_id.as_str())
        .ok_or_else(|| {
            rejected(format!(
                "swarm continuation budget allocation is unknown: {}",
                token.budget_allocation_id
            ))
        })?;
    if allocation.task_id != token.child_task_id {
        return Err(rejected(format!(
            "swarm continuation budget task mismatch: {}",
            token.token_id
        )));
    }
    if allocation.state != SwarmBudgetAllocationState::Active {
        return Err(rejected(format!(
            "swarm budget allocation is not active: {}",
            allocation.allocation_id
        )));
    }
    Ok(())
}
