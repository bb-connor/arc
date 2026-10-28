use super::swarm_evolution::{graphs, issuer, treaty_versions};
use super::*;
use chio_swarm_authority::verify_swarm_authority_extension;
use std::sync::Arc;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const NOW: u64 = 1_800_000_001_000;

fn preparation_failure_code(
    graphs: Option<Arc<IssuedGraphs>>,
    swarm: &SwarmAuthorityBundle,
) -> TestResult<Option<serde_json::Value>> {
    let store = InMemoryRuntimeAdmissionStore::new();
    let mut admission = bundle();
    admission.destructive = false;
    admission.lease_id = None;
    admission.governance_receipt_id = None;
    let args = serde_json::json!({"record": "vendor-ledger-7", "value": "closed"});
    admission.binding.tool_args_sha256 = tool_args_sha256(&args)?;
    admission.binding.origin_kernel_id = None;
    let bundle_hash = runtime_admission_bundle_sha256(&admission)?;
    store.insert_bundle(admission)?;
    let request = chio_swarm_runtime_request(args, bundle_hash, swarm_runtime_context(swarm)?)?;
    let mut hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());
    if let Some(graphs) = graphs {
        hook = hook.with_swarm_graph_source(graphs);
    }
    let preparation = hook.prepare_request(&RuntimeAdmissionContext {
        request: &request,
        extra_metadata: Some(&swarm_route_metadata()),
        now_unix_secs: NOW / 1000,
        now_unix_ms: NOW,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })?;
    match preparation {
        super::super::preparation::HookAdmissionPreparation::Prepared(_) => Ok(None),
        super::super::preparation::HookAdmissionPreparation::Immediate(decision) => {
            assert!(!decision.allowed);
            let metadata = decision.metadata.ok_or("runtime metadata missing")?;
            Ok(Some(metadata["chio_runtime"]["failure_code"].clone()))
        }
    }
}

#[test]
fn preparation_resolves_the_archived_version_after_the_issuer_advances() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    let directory = tempfile::tempdir()?;
    let (prior, next) = treaty_versions()?;
    let authority = issuer(directory.path())?;
    issue_root(&authority, &prior)?;
    authority.work_graph_store().advance(
        &canonical_test_hash(&prior)?,
        next.clone(),
        &trusted_swarm_witness_keys(),
        &authority.mutation_fence(),
        NOW,
    )?;
    let code = preparation_failure_code(Some(graphs(&authority)), &prior)?;
    assert_eq!(code, None);
    let code = preparation_failure_code(Some(graphs(&authority)), &next)?;
    assert_eq!(code, None);
    Ok(())
}

#[test]
fn an_unissued_successor_is_refused_at_preparation() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    let directory = tempfile::tempdir()?;
    let (prior, next) = treaty_versions()?;
    verify_swarm_authority_extension(&prior, &next, &trusted_swarm_witness_keys(), NOW)?;
    let authority = issuer(directory.path())?;
    issue_root(&authority, &prior)?;
    let code = preparation_failure_code(Some(graphs(&authority)), &prior)?;
    assert_eq!(code, None);
    assert_eq!(
        preparation_failure_code(Some(graphs(&authority)), &next)?,
        Some(serde_json::json!("missing_chio_swarm_authority_bundle"))
    );
    Ok(())
}

#[test]
fn a_hook_without_the_issuer_refuses_swarm_requests() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    let (prior, _) = treaty_versions()?;
    assert_eq!(
        preparation_failure_code(None, &prior)?,
        Some(serde_json::json!("missing_chio_swarm_authority_bundle"))
    );
    Ok(())
}
