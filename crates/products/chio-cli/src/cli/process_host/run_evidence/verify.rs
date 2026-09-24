use std::collections::BTreeSet;

use chio_core::capability::aggregate_invocation::{
    verify_aggregate_invocation_budget, AggregateInvocationScope,
};
use chio_core::receipt::kinds::{
    BoundaryClass, ObservationOutcome, ReceiptKind, ToolOrigin, TrustLevel,
};
use chio_swarm_authority::verify_swarm_authority_bundle;

use super::*;

#[path = "verify_calls.rs"]
mod calls;

pub(super) fn verify(
    signed: &ChioReceipt,
    evidence: &Evidence,
    key: &PublicKey,
    runtime_id: &str,
    native_pins: &BTreeMap<String, PublicKey>,
) -> Result<(), CliError> {
    verified_receipt(signed, key)?;
    observation(signed, "attest_completed_fanout")?;
    require(
        !runtime_id.is_empty()
            && evidence.runtime_id == runtime_id
            && matches!(evidence.schema.as_str(), SCHEMA | LEGACY_SCHEMA),
        "run schema or pinned runtime differs",
    )?;
    require(
        signed.action.parameters == serde_json::to_value(evidence).map_err(error)?,
        "signed run payload differs",
    )?;
    verified_receipt(&evidence.bootstrap, key)?;
    require(
        evidence.bootstrap.action.parameters["record_sha256"] == hash(&evidence.host_record)?
            && evidence.host_record.runtime_policy_hash == evidence.bootstrap.policy_hash,
        "host record differs from original provisioning",
    )?;
    super::super::state::require_abi(&evidence.host_record.abi, "completed run")?;
    require(
        (evidence.schema == SCHEMA) == evidence.host_record.config.execution_nonces,
        "run nonce profile differs from original provisioning",
    )?;
    super::native::verify(evidence, native_pins)?;
    observation(&evidence.bootstrap, "provision_swarm")?;
    require(
        evidence.bootstrap.action.parameters["runtime_id"] == runtime_id,
        "bootstrap runtime differs",
    )?;
    let bundle = &evidence.authority;
    let graph = &bundle.task_graph;
    require(
        graph.root_transaction_ref == evidence.bootstrap.id,
        "graph is not rooted in provisioning",
    )?;
    require(
        signed.timestamp == bundle.now_unix_ms / 1000
            && evidence.bootstrap.timestamp <= signed.timestamp,
        "run observation time differs",
    )?;
    require(
        signed.policy_hash == evidence.bootstrap.policy_hash
            && signed.capability_id == evidence.bootstrap.capability_id,
        "run observation policy or capability differs",
    )?;
    verify_swarm_authority_bundle(bundle, std::slice::from_ref(key)).map_err(error)?;
    let caps = capabilities(evidence)?;
    let root = caps
        .get("root")
        .ok_or_else(|| error("missing issued root capability"))?;
    require(
        root.id == signed.capability_id && graph.planner_subject == root.subject.to_hex(),
        "root capability identity differs",
    )?;
    let family = verify_aggregate_invocation_budget(root, std::slice::from_ref(key), None)
        .map_err(error)?
        .ok_or_else(|| error("missing root aggregate budget"))?;
    require(
        family.scope == AggregateInvocationScope::DelegationFamily,
        "run requires a shared delegation-family budget",
    )?;
    let tasks: BTreeSet<_> = graph
        .nodes
        .iter()
        .map(|node| node.task_id.as_str())
        .collect();
    require(
        tasks.len() == graph.nodes.len() && tasks == caps.keys().map(String::as_str).collect(),
        "graph and issued capability set differ",
    )?;
    let workers: BTreeSet<_> = evidence.results.keys().map(String::as_str).collect();
    require(
        (2..=32).contains(&workers.len())
            && !workers.contains("root")
            && tasks
                == workers
                    .iter()
                    .copied()
                    .chain(std::iter::once("root"))
                    .collect(),
        "completed worker set differs from graph",
    )?;
    require(
        graph.max_depth == 1 && !graph.multi_hop_witness_chains && graph.joins.len() == 1,
        "only fixed direct fan-out is supported",
    )?;
    for node in &graph.nodes {
        let cap = &caps[&node.task_id];
        require(
            node.scope_hash == hash(&cap.scope)?
                && cap.issued_at <= evidence.bootstrap.timestamp
                && cap.expires_at > signed.timestamp,
            "issued capability scope or validity differs",
        )?;
        if node.task_id == "root" {
            require(
                node.parent_task_id.is_none() && node.depth == 0,
                "root graph parent differs",
            )?;
        } else {
            require(
                node.parent_task_id.as_deref() == Some("root") && node.depth == 1,
                "worker is not a direct child",
            )?;
            let child =
                verify_aggregate_invocation_budget(cap, std::slice::from_ref(key), Some(root))
                    .map_err(error)?
                    .ok_or_else(|| error("missing child aggregate budget"))?;
            require(
                child == family,
                "worker does not share the root aggregate family",
            )?;
        }
    }
    require(
        bundle.witness_chains.len() == workers.len(),
        "witness inventory differs",
    )?;
    for witness in &bundle.witness_chains {
        require(
            witness.parent_task_id == "root"
                && workers.contains(witness.child_task_id.as_str())
                && witness.hops.len() == 1,
            "unexpected delegation witness",
        )?;
        let child = &caps[&witness.child_task_id];
        let hop = &witness.hops[0];
        require(
            hop.parent_capability_digest == hash(root)?
                && hop.child_capability_digest == hash(child)?
                && hop.parent_scope_hash == hash(&root.scope)?
                && hop.child_scope_hash == hash(&child.scope)?,
            "witness does not bind actual issued capabilities",
        )?;
    }
    let aggregate = &evidence.aggregate;
    require(
        aggregate.profile
            == chio_kernel::budget_store::BudgetQuotaProfile::AggregateFamilyInvocation.as_str()
            && aggregate.owner_id == family.owner_id
            && aggregate.max_invocations == family.max_invocations
            && aggregate.reserved_invocations == 0
            && u64::from(aggregate.captured_invocations) >= workers.len() as u64
            && aggregate.captured_invocations <= family.max_invocations,
        "retained aggregate usage violates the issued budget",
    )?;
    require(
        bundle.budget_pool.total_units == u64::from(family.max_invocations),
        "allocation authority and aggregate limit differ",
    )?;
    let parents = calls::verify(evidence, &caps, key)?;
    terminal(evidence, &parents, &workers, &tasks)
}

fn observation(receipt: &ChioReceipt, tool: &str) -> Result<(), CliError> {
    require(
        receipt.receipt_kind == ReceiptKind::TraceObservation
            && receipt.boundary_class == BoundaryClass::DetectOnly
            && receipt.observation_outcome == Some(ObservationOutcome::Observed)
            && receipt.tool_origin == ToolOrigin::ChioInternal
            && receipt.trust_level == TrustLevel::Verified
            && receipt.decision.is_none()
            && receipt.tool_server == "chio-process-host"
            && receipt.tool_name == tool
            && receipt.content_hash == hash(&receipt.action.parameters)?,
        "invalid process observation role or content",
    )
}

fn terminal(
    evidence: &Evidence,
    parents: &BTreeMap<String, String>,
    workers: &BTreeSet<&str>,
    tasks: &BTreeSet<&str>,
) -> Result<(), CliError> {
    let bundle = &evidence.authority;
    require(
        bundle.join_receipts.len() == 1 && bundle.terminal_receipts.len() == 1,
        "expected one complete fan-out join and terminal receipt",
    )?;
    let join = &bundle.join_receipts[0];
    let terminal = &bundle.terminal_receipts[0];
    let joined: BTreeMap<_, _> = join
        .parent_task_receipts
        .iter()
        .map(|parent| (parent.task_id.clone(), parent.receipt_id.clone()))
        .collect();
    require(
        joined.len() == join.parent_task_receipts.len() && &joined == parents,
        "join parents are not the actual tool receipts",
    )?;
    require(
        bundle.task_graph.joins[0]
            .parent_task_ids
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == *workers
            && join.next_task_id == "root"
            && join.join_predicate == "all_success",
        "join task set or success predicate differs",
    )?;
    let digest = hash(&evidence.results)?;
    require(
        join.result_digest == digest
            && terminal.result_digest == digest
            && join.chain_id == evidence.runtime_id
            && terminal.chain_id == evidence.runtime_id,
        "terminal runtime or result digest differs",
    )?;
    require(
        terminal.terminal_task_ids == ["root"]
            && terminal
                .completed_task_ids
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == *tasks
            && terminal.completed_task_ids.len() == tasks.len(),
        "terminal task set differs",
    )?;
    require(
        terminal.completed_at_unix_ms == bundle.now_unix_ms
            && join.hlc_unix_ms == bundle.now_unix_ms,
        "terminal observation time differs",
    )
}
