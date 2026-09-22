use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::receipt::decision::ToolCallAction;
use chio_kernel::budget_store::{BudgetQuotaKey, BudgetQuotaProfile, BudgetStore};

use super::super::super::state::{read_json, write_secret, Host};
use super::*;

pub(crate) fn export(state: &Path, plan: &Path, output: &Path) -> Result<(), CliError> {
    let host = Host::open(state, false)?;
    if host.record.config.execution_nonces {
        host.checkpoint_receipts()?;
    }
    let directory = host.lease.directory.path();
    let runner = super::super::super::runner::completed_snapshot(&host, plan)?;
    let bootstrap: ChioReceipt = read_json(&directory.join("swarm-bootstrap.json"))?;
    let authorities = if directory.join("swarm-bundles.json").try_exists()? {
        require(
            !directory.join("swarm-bundle.json").try_exists()?,
            "ambiguous authority inventory",
        )?;
        let source: Value = read_json(&directory.join("swarm-bundles.json"))?;
        require(
            source["schema"] == "chio.process.swarm-authorities.v1"
                && source["runtime_id"] == host.runtime.runtime_id(),
            "authority inventory differs from runtime",
        )?;
        serde_json::from_value(source["graphs"].clone()).map_err(error)?
    } else {
        vec![read_json(&directory.join("swarm-bundle.json"))?]
    };
    let now = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(error)?
            .as_millis(),
    )
    .map_err(error)?;
    let planned: Value = read_json(&directory.join("swarm-calls.json"))?;
    require(
        planned["runtime_id"] == host.runtime.runtime_id(),
        "planned calls belong to another runtime",
    )?;
    let mut calls = BTreeMap::new();
    for call in planned["calls"]
        .as_array()
        .ok_or_else(|| error("missing planned calls"))?
    {
        let process = call["process"]
            .as_str()
            .ok_or_else(|| error("missing planned process"))?;
        let retained = host.runtime.process(process).map_err(error)?;
        let request = json!({
            "operation_key": call["operation_key"], "server_id": call["server_id"],
            "tool_name": call["tool_name"], "arguments": call["arguments"], "known_outcome_only": false,
        });
        let context = json!({"runtime_id": host.runtime.runtime_id(), "process_id": process, "capability_id": retained.capability.id});
        let observed = super::super::exporting::observe(
            &host,
            request,
            context,
            retained.checkpoint.value["response"].clone(),
            now,
        )?;
        require(
            calls.insert(process.to_owned(), observed).is_none(),
            "duplicate planned process",
        )?;
    }
    let root = host.runtime.process("root").map_err(error)?;
    let family =
        verify_aggregate_invocation_budget(&root.capability, &[host.kernel.public_key()], None)
            .map_err(error)?
            .ok_or_else(|| error("missing family budget"))?;
    let usage = host
        .authority
        .local_budget_store()
        .ok_or_else(|| error("missing local budget authority"))?
        .get_invocation_quota_usage(&BudgetQuotaKey {
            profile: BudgetQuotaProfile::AggregateFamilyInvocation,
            owner_id: family.owner_id,
            grant_index: None,
        })
        .map_err(error)?
        .ok_or_else(|| error("missing retained family usage"))?;
    let native = native::export(&host.record.config, &calls)?;
    let run = Outcomes {
        schema: if host.record.config.execution_nonces {
            OUTCOMES_SCHEMA
        } else {
            PREVIOUS_OUTCOMES_SCHEMA
        }
        .into(),
        runtime_id: host.runtime.runtime_id().into(),
        observed_at_unix_ms: now,
        bootstrap,
        host_record: host.record,
        authorities,
        runner,
        calls,
        confinement: native.confinement,
        aggregate: Usage {
            owner_id: usage.quota.key.owner_id,
            max_invocations: usage.quota.max_invocations,
            reserved_invocations: usage.reserved_invocations,
            captured_invocations: usage.captured_invocations,
        },
    };
    let parameters = serde_json::to_value(&run).map_err(error)?;
    let mut body = run.bootstrap.body();
    body.id.clear();
    body.timestamp = now / 1000;
    body.tool_name = "attest_worker_outcomes".into();
    body.action = ToolCallAction::from_parameters(parameters.clone()).map_err(error)?;
    body.content_hash = hash(&parameters)?;
    let signed = ChioReceipt::sign(body, &host.authority.kernel_keypair()).map_err(error)?;
    verify_outcomes(
        &signed,
        &run,
        &host.kernel.public_key(),
        host.runtime.runtime_id(),
        &native.pins,
    )?;
    let bytes = canonical_json_bytes(&signed).map_err(error)?;
    require(bytes.len() as u64 <= LIMIT, "worker outcomes exceed 32 MiB")?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let destination = chio_control_plane::prepare_private_directory(parent)?;
    write_secret(
        &destination,
        output
            .file_name()
            .ok_or_else(|| error("artifact needs a file name"))?,
        &bytes,
    )?;
    println!(
        "{}",
        json!({"artifact": output, "receipt_id": signed.id, "runtime_id": run.runtime_id, "workers": run.calls.len(), "m5_acceptance_complete": false})
    );
    Ok(())
}
