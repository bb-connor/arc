use chio_kernel::ToolCallRequest;
use chio_swarm_authority::{SwarmAuthorityBundle, SwarmContinuationToken};

use super::swarm_ref::SwarmAuthorityReference;
use crate::{canonical_sha256, rejected, ChioRuntimeError};

/// Bind already verified swarm evidence to the exact kernel request. Bundle
/// validity alone does not prove that this capability belongs to this task.
/// Capability signature, issuer trust, subject, revocation and tool scope remain
/// the kernel's responsibility; this is an additional, not alternate, authority.
pub(super) fn verify_swarm_request_binding(
    bundle: &SwarmAuthorityBundle,
    continuation: &SwarmContinuationToken,
    reference: &SwarmAuthorityReference,
    request: &ToolCallRequest,
) -> Result<serde_json::Value, ChioRuntimeError> {
    if continuation
        .witness_chain_ref
        .as_deref()
        .is_some_and(|chain_id| chain_id != reference.delegation_witness.evidence_id)
        || continuation
            .join_receipt_id
            .as_deref()
            .is_some_and(|join_id| join_id != reference.join_receipt.evidence_id)
    {
        return rejected(
            "chio_swarm_authority_ref_mismatch",
            "swarm request witness or join does not belong to the selected continuation",
        );
    }

    let task_id = &continuation.child_task_id;
    let task = bundle
        .task_graph
        .nodes
        .iter()
        .find(|node| &node.task_id == task_id)
        .ok_or_else(|| binding_error("selected swarm task is absent"))?;
    let scope_sha256 = canonical_sha256(&request.capability.scope)?;
    if scope_sha256 != task.scope_hash {
        return Err(binding_error(
            "request capability scope does not match the selected swarm task",
        ));
    }
    // Hash the complete signed token, including security bindings and signature.
    // Reissuing a token with the same ID or scope must not inherit task authority.
    let capability_sha256 = canonical_sha256(&request.capability)?;
    let mut referenced_witness_bound = false;
    for chain in &bundle.witness_chains {
        let endpoint = if &chain.child_task_id == task_id {
            chain
                .hops
                .last()
                .map(|hop| (&hop.child_capability_digest, &hop.child_scope_hash))
        } else if &chain.parent_task_id == task_id {
            chain
                .hops
                .first()
                .map(|hop| (&hop.parent_capability_digest, &hop.parent_scope_hash))
        } else {
            continue;
        };
        let (digest, scope) =
            endpoint.ok_or_else(|| binding_error("swarm task witness has no endpoint"))?;
        if digest != &capability_sha256 || scope != &scope_sha256 {
            return Err(binding_error(
                "request capability does not match the swarm task witness endpoint",
            ));
        }
        // Every incident edge must agree on a task's capability. This includes
        // fan-in continuations returning to a root that has only outgoing edges.
        referenced_witness_bound |= chain.chain_id == reference.delegation_witness.evidence_id;
    }
    if !referenced_witness_bound {
        return rejected(
            "chio_swarm_authority_ref_mismatch",
            "referenced swarm witness does not bind the selected task capability",
        );
    }
    Ok(serde_json::json!({
        "graph_id": bundle.task_graph.graph_id,
        "task_id": task_id,
        "capability_sha256": capability_sha256,
        "scope_sha256": scope_sha256,
        "evidence_refs_sha256": canonical_sha256(reference)?
    }))
}

fn binding_error(detail: &str) -> ChioRuntimeError {
    ChioRuntimeError::Rejected {
        code: "chio_swarm_authority_rejected",
        detail: detail.to_string(),
    }
}
