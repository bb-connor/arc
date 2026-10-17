use chio_core_types::PublicKey;
use chio_swarm_authority::{
    verify_swarm_authority_for_admission, SwarmAuthorityBundle, SwarmContinuationMode,
    SwarmContinuationToken, SwarmDelegationWitnessChain, SwarmJoinReceipt, SwarmRoutePlanReceipt,
};
use serde::Serialize;

use super::swarm_ref::{SwarmAuthorityReference, SwarmEvidenceReference};
use super::swarm_request_binding::verify_swarm_request_binding;
use crate::*;

pub(super) fn verify_swarm_authority_reference_from_store<S>(
    store: &S,
    reference: &SwarmAuthorityReference,
    request: &chio_kernel::ToolCallRequest,
    trusted_witness_keys: &[PublicKey],
    route_metadata: Option<&serde_json::Value>,
    now_unix_ms: u64,
) -> Result<VerifiedSwarmAuthorityReference, ChioRuntimeError>
where
    S: RuntimeAdmissionStore,
{
    let Some(mut bundle) = store.swarm_authority_bundle_for_graph(
        &reference.task_graph.evidence_id,
        &reference.task_graph.artifact_sha256,
    )?
    else {
        return rejected(
            "missing_chio_swarm_authority_bundle",
            "swarm-bound request referenced authority evidence that is not in the verifier-owned store",
        );
    };
    bundle.now_unix_ms = now_unix_ms;
    verify_swarm_reference_hashes(&bundle, reference)?;
    let route_plan = find_route_plan(&bundle, &reference.route_plan_receipt.evidence_id)?;
    let route_metadata = verify_route_metadata_matches(route_metadata, route_plan)?;
    verify_swarm_authority_for_admission(&bundle, trusted_witness_keys).map_err(|error| {
        ChioRuntimeError::Rejected {
            code: "chio_swarm_authority_rejected",
            detail: error.runtime_detail(),
        }
    })?;
    let continuation = find_continuation(&bundle, &reference.continuation_token.evidence_id)?;
    if continuation.route_plan_receipt_id != reference.route_plan_receipt.evidence_id {
        return rejected(
            "chio_swarm_authority_ref_mismatch",
            "swarm continuation route plan does not match referenced route plan evidence",
        );
    }
    let request_binding = verify_swarm_request_binding(&bundle, continuation, reference, request)?;
    let continuation_artifact_digest = crate::hash::canonical_sha256(continuation)?;
    // Evaluation time is verifier-local, not an artifact. Bind all stored
    // evidence while allowing dispatch freshness to be checked at a later time.
    let mut evidence = serde_json::to_value(&bundle).map_err(ChioRuntimeError::Json)?;
    if let Some(object) = evidence.as_object_mut() {
        object.remove("nowUnixMs");
    }
    let evidence_digest = crate::hash::canonical_sha256(&(
        "chio.runtime-prepared-swarm.v1",
        evidence,
        trusted_witness_keys,
    ))?;
    Ok(VerifiedSwarmAuthorityReference {
        // The verifier validates the entire bundle, not just the selected
        // continuation. Preserve every temporal prerequisite of that decision.
        valid_until_unix_ms: bundle
            .continuation_tokens
            .iter()
            .map(|token| token.expires_at_unix_ms)
            .chain(
                bundle
                    .route_plan_receipts
                    .iter()
                    .map(|route| route.expires_at_unix_ms),
            )
            .chain(
                bundle
                    .witness_chains
                    .iter()
                    .flat_map(|chain| &chain.hops)
                    .map(|hop| hop.expires_at_unix_ms),
            )
            .chain([
                bundle.task_graph.expires_at_unix_ms,
                bundle.revocation_epoch.valid_until_unix_ms,
            ])
            .min()
            .ok_or_else(|| ChioRuntimeError::Rejected {
                code: "runtime_swarm_validity_missing",
                detail: "missing swarm validity".into(),
            })?,
        continuation_artifact_digest,
        evidence_digest,
        continuation_id_to_consume: match continuation.mode {
            SwarmContinuationMode::SingleUse => Some(continuation.token_id.clone()),
            SwarmContinuationMode::Resumable => None,
        },
        route_metadata,
        request_binding,
    })
}

pub(super) struct VerifiedSwarmAuthorityReference {
    pub(super) valid_until_unix_ms: u64,
    pub(super) continuation_artifact_digest: String,
    pub(super) evidence_digest: String,
    pub(super) continuation_id_to_consume: Option<String>,
    pub(super) route_metadata: serde_json::Value,
    pub(super) request_binding: serde_json::Value,
}

fn verify_swarm_reference_hashes(
    bundle: &SwarmAuthorityBundle,
    reference: &SwarmAuthorityReference,
) -> Result<(), ChioRuntimeError> {
    verify_ref_matches(
        &reference.task_graph,
        &bundle.task_graph.graph_id,
        &bundle.task_graph,
    )?;
    verify_ref_matches(
        &reference.continuation_token,
        &find_continuation(bundle, &reference.continuation_token.evidence_id)?.token_id,
        find_continuation(bundle, &reference.continuation_token.evidence_id)?,
    )?;
    verify_ref_matches(
        &reference.route_plan_receipt,
        &find_route_plan(bundle, &reference.route_plan_receipt.evidence_id)?.route_plan_id,
        find_route_plan(bundle, &reference.route_plan_receipt.evidence_id)?,
    )?;
    verify_ref_matches(
        &reference.delegation_witness,
        &find_witness_chain(bundle, &reference.delegation_witness.evidence_id)?.chain_id,
        find_witness_chain(bundle, &reference.delegation_witness.evidence_id)?,
    )?;
    if let Some(reference) = &reference.join_receipt {
        let join = find_join_receipt(bundle, &reference.evidence_id)?;
        verify_ref_matches(reference, &join.join_id, join)?;
    }
    verify_ref_matches(
        &reference.revocation_epoch,
        &bundle.revocation_epoch.epoch_id,
        &bundle.revocation_epoch,
    )?;
    verify_ref_matches(
        &reference.budget_pool,
        &bundle.budget_pool.pool_id,
        &bundle.budget_pool,
    )?;
    Ok(())
}

const SWARM_ROUTE_FIELDS: [&str; 3] = ["bridge", "protocolTarget", "selectedRoute"];

fn route_rejected(detail: String) -> ChioRuntimeError {
    ChioRuntimeError::Rejected {
        code: "chio_swarm_authority_rejected",
        detail,
    }
}

fn verify_route_metadata_matches(
    route_metadata: Option<&serde_json::Value>,
    route_plan: &SwarmRoutePlanReceipt,
) -> Result<serde_json::Value, ChioRuntimeError> {
    let Some(metadata) = route_metadata else {
        return Err(route_rejected(format!(
            "swarm route metadata missing for route plan {}",
            route_plan.route_plan_id
        )));
    };
    let Some(route) = metadata.get("route") else {
        if let Some(key) = ["route_selection", "routeSelection"]
            .into_iter()
            .find(|key| metadata.get(*key).is_some())
        {
            return Err(route_rejected(format!(
                "swarm route metadata {key} is not a swarm route; send route"
            )));
        }
        return Err(route_rejected(format!(
            "swarm route metadata missing routed entry for route plan {}",
            route_plan.route_plan_id
        )));
    };
    let Some(route) = route.as_object() else {
        return Err(route_rejected(
            "swarm route metadata route must be an object".to_string(),
        ));
    };
    if let Some(field) = route
        .keys()
        .find(|field| !SWARM_ROUTE_FIELDS.contains(&field.as_str()))
    {
        return Err(route_rejected(format!(
            "swarm route metadata field route.{field} is not accepted"
        )));
    }
    let field = |name: &str| route.get(name).and_then(serde_json::Value::as_str);
    let bridge = field("bridge").ok_or_else(|| {
        route_rejected(format!(
            "swarm route metadata missing bridge for route plan {}",
            route_plan.route_plan_id
        ))
    })?;
    if bridge != route_plan.bridge_id {
        return Err(route_rejected(format!(
            "swarm route metadata bridge mismatch: expected {}, got {}",
            route_plan.bridge_id, bridge
        )));
    }
    let protocol_target = field("protocolTarget").ok_or_else(|| {
        route_rejected(format!(
            "swarm route metadata missing protocol target for route plan {}",
            route_plan.route_plan_id
        ))
    })?;
    if protocol_target != route_plan.protocol_target {
        return Err(route_rejected(format!(
            "swarm route metadata target mismatch: expected {}, got {}",
            route_plan.protocol_target, protocol_target
        )));
    }
    let selected_route = field("selectedRoute").ok_or_else(|| {
        route_rejected(format!(
            "swarm route metadata missing selected route for route plan {}",
            route_plan.route_plan_id
        ))
    })?;
    if selected_route != route_plan.selected_route {
        return Err(route_rejected(format!(
            "swarm route metadata selected route mismatch: expected {}, got {}",
            route_plan.selected_route, selected_route
        )));
    }
    Ok(serde_json::json!({
        "route": {
            "bridge": bridge,
            "protocolTarget": protocol_target,
            "selectedRoute": selected_route
        }
    }))
}

fn verify_ref_matches<T>(
    reference: &SwarmEvidenceReference,
    stored_id: &str,
    stored_artifact: &T,
) -> Result<(), ChioRuntimeError>
where
    T: Serialize,
{
    if reference.evidence_id != stored_id
        || reference.artifact_sha256 != canonical_sha256(stored_artifact)?
    {
        return rejected(
            "chio_swarm_authority_ref_mismatch",
            "swarm-bound request evidence hash does not match verifier-owned authority evidence",
        );
    }
    Ok(())
}

fn find_continuation<'a>(
    bundle: &'a SwarmAuthorityBundle,
    token_id: &str,
) -> Result<&'a SwarmContinuationToken, ChioRuntimeError> {
    find_by_id(&bundle.continuation_tokens, token_id, |token| {
        &token.token_id
    })
}

fn find_route_plan<'a>(
    bundle: &'a SwarmAuthorityBundle,
    route_plan_id: &str,
) -> Result<&'a SwarmRoutePlanReceipt, ChioRuntimeError> {
    find_by_id(&bundle.route_plan_receipts, route_plan_id, |route| {
        &route.route_plan_id
    })
}

fn find_witness_chain<'a>(
    bundle: &'a SwarmAuthorityBundle,
    chain_id: &str,
) -> Result<&'a SwarmDelegationWitnessChain, ChioRuntimeError> {
    find_by_id(&bundle.witness_chains, chain_id, |chain| &chain.chain_id)
}

fn find_join_receipt<'a>(
    bundle: &'a SwarmAuthorityBundle,
    join_id: &str,
) -> Result<&'a SwarmJoinReceipt, ChioRuntimeError> {
    find_by_id(&bundle.join_receipts, join_id, |receipt| &receipt.join_id)
}

fn find_by_id<'a, T>(
    items: &'a [T],
    expected_id: &str,
    id: impl Fn(&'a T) -> &'a str,
) -> Result<&'a T, ChioRuntimeError> {
    items
        .iter()
        .find(|item| id(item) == expected_id)
        .ok_or_else(|| ChioRuntimeError::Rejected {
            code: "chio_swarm_authority_ref_mismatch",
            detail: "swarm-bound request referenced authority evidence that is absent from the stored bundle"
                .to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route_plan() -> SwarmRoutePlanReceipt {
        SwarmRoutePlanReceipt {
            schema: "chio.swarm.route-plan-receipt.v1".to_string(),
            route_plan_id: "route-plan-1".to_string(),
            graph_id: "graph-1".to_string(),
            task_id: "task-1".to_string(),
            selected_route: "mcp:task-child-a".to_string(),
            candidate_set_digest: "a".repeat(64),
            registry_snapshot_hash: "b".repeat(64),
            bridge_id: "mcp".to_string(),
            protocol_target: "mcp://provider-runtime".to_string(),
            egress_contract_id: "egress-1".to_string(),
            egress_constraints: Vec::new(),
            attenuation_decision: "attenuated".to_string(),
            policy_digest: "c".repeat(64),
            expires_at_unix_ms: 1,
            issuer: "issuer".to_string(),
            signature: "signature".to_string(),
        }
    }

    fn refusal(metadata: serde_json::Value) -> String {
        match verify_route_metadata_matches(Some(&metadata), &route_plan()) {
            Err(ChioRuntimeError::Rejected { code, detail }) => {
                assert_eq!(code, "chio_swarm_authority_rejected");
                detail
            }
            other => panic!("route metadata must be refused: {other:?}"),
        }
    }

    #[test]
    fn swarm_route_metadata_admits_the_route_object() {
        let metadata = serde_json::json!({"route": {
            "bridge": "mcp",
            "protocolTarget": "mcp://provider-runtime",
            "selectedRoute": "mcp:task-child-a"
        }});
        let verified = verify_route_metadata_matches(Some(&metadata), &route_plan())
            .unwrap_or_else(|error| panic!("route metadata must verify: {error}"));
        assert_eq!(verified, metadata);
    }

    #[test]
    fn swarm_route_metadata_refuses_route_selection_spellings() {
        for key in ["route_selection", "routeSelection"] {
            let metadata = serde_json::json!({key: {
                "bridge": "mcp",
                "protocolTarget": "mcp://provider-runtime",
                "selectedRoute": "mcp:task-child-a"
            }});
            assert_eq!(
                refusal(metadata),
                format!("swarm route metadata {key} is not a swarm route; send route")
            );
        }
    }

    #[test]
    fn swarm_route_metadata_refuses_alternate_field_names() {
        for (field, value) in [
            ("bridgeId", "mcp"),
            ("targetProtocol", "mcp"),
            ("selectedTargetProtocol", "mcp"),
            ("protocol_target", "mcp://provider-runtime"),
            ("selected_route", "mcp:task-child-a"),
            ("selectedRouteId", "mcp:task-child-a"),
            ("selected_route_id", "mcp:task-child-a"),
        ] {
            let mut route = serde_json::json!({
                "bridge": "mcp",
                "protocolTarget": "mcp://provider-runtime",
                "selectedRoute": "mcp:task-child-a"
            });
            route[field] = serde_json::json!(value);
            assert_eq!(
                refusal(serde_json::json!({"route": route})),
                format!("swarm route metadata field route.{field} is not accepted")
            );
        }
    }

    #[test]
    fn swarm_route_metadata_refuses_a_non_object_route() {
        assert_eq!(
            refusal(serde_json::json!({"route": "mcp:task-child-a"})),
            "swarm route metadata route must be an object"
        );
    }
}
