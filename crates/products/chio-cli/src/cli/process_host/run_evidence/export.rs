use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::capability::aggregate_invocation::verify_aggregate_invocation_budget;
use chio_core::receipt::decision::ToolCallAction;
use chio_kernel::budget_store::{BudgetQuotaKey, BudgetQuotaProfile, BudgetStore};
use chio_swarm_authority::*;

use super::super::state::{read_json, write_secret, Host};
use super::*;

pub(crate) fn export(state: &Path, plan: &Path, output: &Path) -> Result<(), CliError> {
    let host = Host::open(state, false)?;
    if host.record.config.execution_nonces {
        host.checkpoint_receipts()?;
    }
    let directory = host.lease.directory.path();
    let runner = super::super::runner::completed_snapshot(&host, plan)?;
    require(
        !directory.join("swarm-bundles.json").try_exists()?,
        "completed-fanout export requires a single graph",
    )?;
    let bootstrap: ChioReceipt = read_json(&directory.join("swarm-bootstrap.json"))?;
    verified_receipt(&bootstrap, &host.kernel.public_key())?;
    let mut authority: SwarmAuthorityBundle = read_json(&directory.join("swarm-bundle.json"))?;
    require(
        authority.join_receipts.is_empty() && authority.terminal_receipts.is_empty(),
        "expected original live fan-out authority",
    )?;
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(error)?
            .as_millis(),
    )
    .map_err(error)?;
    authority.now_unix_ms = now;
    verify_swarm_authority_for_admission(&authority, &[host.kernel.public_key()]).map_err(error)?;
    let calls: Value = read_json(&directory.join("swarm-calls.json"))?;
    require(
        calls["runtime_id"] == host.runtime.runtime_id(),
        "planned calls belong to another runtime",
    )?;
    let mut results = BTreeMap::new();
    let mut parents = Vec::new();
    for call in calls["calls"]
        .as_array()
        .ok_or_else(|| error("missing planned calls"))?
    {
        let process = call["process"]
            .as_str()
            .ok_or_else(|| error("missing planned process"))?;
        let retained = host.runtime.process(process).map_err(error)?;
        require(
            bootstrap.action.parameters["capabilities"][process]
                == serde_json::to_value(&retained.capability).map_err(error)?,
            "issued capability differs from bootstrap",
        )?;
        let request = json!({
            "operation_key": call["operation_key"], "server_id": call["server_id"],
            "tool_name": call["tool_name"], "arguments": call["arguments"], "known_outcome_only": false,
        });
        let context = json!({"runtime_id": host.runtime.runtime_id(), "process_id": process, "capability_id": retained.capability.id});
        let response = retained.checkpoint.value["response"].clone();
        let receipt = crate::process_response_verify::verify_values(
            &request,
            &context,
            &response,
            &host.kernel.public_key(),
        )?;
        require(
            response["verdict"] == "allow",
            "every joined task must have an allowed result",
        )?;
        let custody = super::custody::export(&host, &receipt, now)?;
        let (nonce, receipt_log) = if host.record.config.execution_nonces {
            (
                super::super::nonce_evidence::export(&host, &receipt, None, now)?,
                Some(super::super::receipt_evidence::export(
                    &host, &receipt, now,
                )?),
            )
        } else {
            (None, None)
        };
        parents.push(SwarmJoinParentReceipt {
            task_id: process.into(),
            receipt_id: receipt.id,
        });
        require(
            results
                .insert(
                    process.into(),
                    CompletedCall {
                        request,
                        context,
                        response,
                        custody,
                        nonce,
                        receipt_log,
                    },
                )
                .is_none(),
            "duplicate planned worker",
        )?;
    }
    let root = host.runtime.process("root").map_err(error)?;
    require(
        bootstrap.action.parameters["capabilities"]["root"]
            == serde_json::to_value(&root.capability).map_err(error)?,
        "root capability differs from bootstrap",
    )?;
    let verified =
        verify_aggregate_invocation_budget(&root.capability, &[host.kernel.public_key()], None)
            .map_err(error)?
            .ok_or_else(|| error("missing aggregate root budget"))?;
    let quota_key = BudgetQuotaKey {
        profile: BudgetQuotaProfile::AggregateFamilyInvocation,
        owner_id: verified.owner_id,
        grant_index: None,
    };
    let usage = host
        .authority
        .local_budget_store()
        .ok_or_else(|| error("missing local budget authority"))?
        .get_invocation_quota_usage(&quota_key)
        .map_err(error)?
        .ok_or_else(|| error("aggregate budget has no retained usage"))?;
    let aggregate = AggregateUsage {
        profile: usage.quota.key.profile.as_str().into(),
        owner_id: usage.quota.key.owner_id,
        max_invocations: usage.quota.max_invocations,
        reserved_invocations: usage.reserved_invocations,
        captured_invocations: usage.captured_invocations,
    };
    let result_digest = hash(&results)?;
    let join = authority
        .task_graph
        .joins
        .first()
        .ok_or_else(|| error("missing root join"))?;
    let ids: Vec<_> = parents
        .iter()
        .map(|parent| parent.receipt_id.clone())
        .collect();
    let key = host.authority.kernel_keypair();
    authority.join_receipts.push(
        mint_swarm_join_receipt(
            SwarmJoinReceiptMintRequest {
                join_id: join.join_id.clone(),
                graph_id: authority.task_graph.graph_id.clone(),
                chain_id: host.runtime.runtime_id().into(),
                dag_ordinal: 1,
                hlc_unix_ms: now,
                parent_task_receipts: parents,
                expected_parent_receipt_ids: ids.clone(),
                actual_parent_receipt_ids: ids,
                join_predicate: "all_success".into(),
                result_digest: result_digest.clone(),
                next_task_id: "root".into(),
            },
            &key,
        )
        .map_err(error)?,
    );
    let mut terminal = SwarmTerminalGraphReceipt {
        schema: CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_SCHEMA.into(),
        receipt_id: format!("terminal-{}", host.runtime.runtime_id()),
        graph_id: authority.task_graph.graph_id.clone(),
        chain_id: host.runtime.runtime_id().into(),
        terminal_task_ids: vec!["root".into()],
        completed_task_ids: std::iter::once("root".into())
            .chain(results.keys().cloned())
            .collect(),
        join_receipt_ids: authority
            .join_receipts
            .iter()
            .map(|receipt| receipt.join_id.clone())
            .collect(),
        route_plan_receipt_ids: authority.task_graph.route_plan_refs.clone(),
        budget_pool_id: authority.budget_pool.pool_id.clone(),
        budget_rollups: allocation_rollups(&authority)?,
        revocation_epoch_ref: authority.revocation_epoch.epoch_id.clone(),
        result_digest,
        completed_at_unix_ms: now,
        issuer: authority.task_graph.issuer.clone(),
        signature: String::new(),
    };
    terminal.signature = sign_swarm_terminal_graph_receipt(&terminal, &key).map_err(error)?;
    authority.terminal_receipts.push(terminal);
    let native = super::native::export(&host.record.config, &results)?;
    let evidence = Evidence {
        schema: if host.record.config.execution_nonces {
            SCHEMA
        } else {
            LEGACY_SCHEMA
        }
        .into(),
        runtime_id: host.runtime.runtime_id().into(),
        bootstrap,
        host_record: host.record,
        authority,
        results,
        runner,
        aggregate,
        confinement: native.confinement,
    };
    let value = serde_json::to_value(&evidence).map_err(error)?;
    let mut body = evidence.bootstrap.body();
    body.id.clear();
    body.timestamp = now / 1000;
    body.tool_name = "attest_completed_fanout".into();
    body.action = ToolCallAction::from_parameters(value.clone()).map_err(error)?;
    body.content_hash = hash(&value)?;
    let signed = ChioReceipt::sign(body, &key).map_err(error)?;
    super::verification::verify(
        &signed,
        &evidence,
        &host.kernel.public_key(),
        host.runtime.runtime_id(),
        &native.pins,
    )?;
    let bytes = canonical_json_bytes(&signed).map_err(error)?;
    require(
        bytes.len() as u64 <= MAX_ARTIFACT_BYTES,
        "run artifact exceeds 64 MiB",
    )?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let destination = chio_control_plane::prepare_private_directory(parent)?;
    let name = output
        .file_name()
        .ok_or_else(|| error("artifact path has no file name"))?;
    write_secret(&destination, name, &bytes)?;
    println!(
        "{}",
        json!({"artifact": output, "receipt_id": signed.id, "runtime_id": evidence.runtime_id, "workers": evidence.results.len(), "m5_acceptance_complete": false})
    );
    Ok(())
}

// These rollups describe the original allocation authority snapshot. Captured
// dispatch accounting is read separately from the authoritative quota store.
fn allocation_rollups(
    authority: &SwarmAuthorityBundle,
) -> Result<Vec<SwarmTerminalBudgetRollup>, CliError> {
    let mut totals = BTreeMap::<String, [u64; 5]>::new();
    for allocation in &authority.budget_pool.allocations {
        let total = totals.entry(allocation.dimension_id.clone()).or_default();
        for (sum, value) in total.iter_mut().zip([
            allocation.reserved_units,
            allocation.active_units,
            allocation.consumed_units,
            allocation.released_units,
            allocation.reversed_units,
        ]) {
            *sum = sum
                .checked_add(value)
                .ok_or_else(|| error("allocation rollup overflow"))?;
        }
    }
    totals
        .into_iter()
        .map(|(dimension_id, units)| {
            Ok(SwarmTerminalBudgetRollup {
                dimension_id,
                reserved_units: units[0],
                active_units: units[1],
                consumed_units: units[2],
                released_units: units[3],
                reversed_units: units[4],
                total_units: units.into_iter().try_fold(0_u64, |sum, value| {
                    sum.checked_add(value)
                        .ok_or_else(|| error("allocation total overflow"))
                })?,
            })
        })
        .collect()
}
