#[path = "../examples/dynamic_delegation_support/mod.rs"]
mod support;
use chio_kernel::*;
use chio_workflow::delegation::*;
use serde_json::json;
use std::sync::{atomic::Ordering, Arc};
use support::Result;

#[test]
fn receiver_executes_with_allocator_offline_and_rejects_another_receiver() -> Result {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("allocation.db");
    let store = Arc::new(DelegationStore::open(&path)?);
    store.create_root(slot("leaf", 2, 60, 2)?)?;
    let (kernel, calls) = open(dir.path(), 3, false)?;
    let mut call = request(&kernel, "leaf", 2, "offline-owner", 20)?;
    choose(&store, &call, 2, 3, 0, 20)?;
    seal(&store, &mut call, 20)?;
    drop(store);
    std::fs::rename(&path, dir.path().join("offline-owner.db"))?;
    assert!(!path.exists());
    let response = kernel.evaluate_tool_call_blocking(&call)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let (other, other_calls) = open(dir.path(), 4, false)?;
    let mut substitution = request(&other, "leaf", 2, "offline-owner", 20)?;
    substitution.arguments["allocation"] = call.arguments["allocation"].clone();
    let rejected = other.evaluate_tool_call_blocking(&substitution)?;
    assert_eq!(rejected.verdict, Verdict::Deny);
    assert!(format!("{:?}", rejected.reason).contains("delegated work"));
    assert_eq!(other_calls.load(Ordering::SeqCst), 0);
    Ok(())
}

struct ChangeOutput;
impl chio_kernel::post_invocation::PostInvocationHook for ChangeOutput {
    fn name(&self) -> &str {
        "change-output-for-contract-test"
    }
    fn inspect(
        &self,
        _: &chio_kernel::post_invocation::PostInvocationContext<'_>,
        _: &serde_json::Value,
    ) -> chio_kernel::post_invocation::PostInvocationVerdict {
        chio_kernel::post_invocation::PostInvocationVerdict::Redact(
            json!({"kind":"value", "value":{"count": 99}}),
        )
    }
    fn durable_identity(
        &self,
    ) -> std::result::Result<Option<chio_kernel::post_invocation::PostInvocationHookIdentity>, String>
    {
        chio_kernel::post_invocation::PostInvocationHookIdentity::from_canonical_config(
            "change-output-test",
            "1",
            "constant-output-99",
            &json!({"count":99}),
        )
        .map(Some)
    }
}

#[test]
fn output_transform_cannot_bypass_the_contract() -> Result {
    let dir = tempfile::tempdir()?;
    let store = DelegationStore::open(dir.path().join("allocation.db"))?;
    store.create_root(slot("leaf", 2, 60, 2)?)?;
    let (mut kernel, calls) = open(dir.path(), 3, false)?;
    kernel.add_post_invocation_hook(Box::new(ChangeOutput));
    let mut call = request(&kernel, "leaf", 2, "transform", 20)?;
    choose(&store, &call, 2, 3, 0, 20)?;
    seal(&store, &mut call, 20)?;
    let response = kernel.evaluate_tool_call_blocking(&call)?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    assert!(response.output.is_none());
    Ok(())
}
use support::*;

#[test]
fn dynamic_selection_recursion_and_native_replay() -> Result {
    let dir = tempfile::tempdir()?;
    let report = demonstration(dir.path())?;
    assert_eq!(report["native_dispatches_for_selected_work"], 1);
    assert_eq!(report["replay_dispatches"], 0);
    assert_eq!(report["replacement_after_dispatch_rejected"], true);
    assert_eq!(report["sibling_completed"], true);
    assert_eq!(report["balances"], json!([0, 950, 0, 30, 20, 0]));
    Ok(())
}

#[test]
fn changed_native_identity_payload_and_ceiling_never_dispatch() -> Result {
    for mutation in 0..5 {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(DelegationStore::open(dir.path().join("allocation.db"))?);
        store.create_root(slot("leaf", 2, 60, 2)?)?;
        let (kernel, calls) = open(dir.path(), 3, false)?;
        let mut call = request(
            &kernel,
            "leaf",
            2,
            "original",
            if mutation == 2 { 21 } else { 20 },
        )?;
        choose(&store, &call, 2, 3, 0, 20)?;
        seal(&store, &mut call, 20)?;
        match mutation {
            0 => call.request_id = "replacement".into(),
            1 => call.arguments["payload"] = json!(["changed"]),
            2 => (),
            3 => {
                let permit = call.arguments["allocation"].clone();
                call = request(&kernel, "leaf", 2, "original", 20)?;
                call.arguments["allocation"] = permit;
            }
            _ => call.arguments["allocation"]["body"]["slot"]["contract"]["max_units"] = json!(59),
        }
        let response = kernel.evaluate_tool_call_blocking(&call)?;
        assert_eq!(
            response.verdict,
            Verdict::Deny,
            "mutation {mutation}: {:?}",
            response.reason
        );
        assert!(
            format!("{:?}", response.reason).contains("delegated work"),
            "wrong rejection: {:?}",
            response.reason
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn output_must_satisfy_the_immutable_contract() -> Result {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(DelegationStore::open(dir.path().join("allocation.db"))?);
    store.create_root(slot("leaf", 2, 60, 2)?)?;
    let (kernel, calls) = open(dir.path(), 3, true)?;
    let mut call = request(&kernel, "leaf", 2, "bad-output", 20)?;
    choose(&store, &call, 2, 3, 0, 20)?;
    seal(&store, &mut call, 20)?;
    let response = kernel.evaluate_tool_call_blocking(&call)?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert!(response.receipt.verify_signature()?);
    let replay = kernel.evaluate_tool_call_blocking(&call)?;
    assert_eq!(
        serde_json::to_value(&replay.receipt)?,
        serde_json::to_value(&response.receipt)?
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let rail = rusqlite::Connection::open(dir.path().join("bank.db"))?;
    let balance: i64 = rail.query_row("SELECT balance FROM accounts WHERE id=1", [], |row| {
        row.get(0)
    })?;
    assert_eq!(balance, 1000, "rejected output must earn zero charge");
    Ok(())
}

#[test]
fn installation_requires_durable_native_custody() {
    let mut kernel = unconfigured(3);
    assert!(
        delegated_work::install_delegated_work(&mut kernel, vec![key(1).public_key()]).is_err()
    );
}

#[cfg(all(feature = "admission-test-support", unix))]
#[test]
fn dynamic_recovery_worker() -> Result {
    let Some(root) = std::env::var_os("CHIO_DYNAMIC_WORKER_ROOT") else {
        return Ok(());
    };
    let root = std::path::PathBuf::from(root);
    let (mut kernel, _) = open(&root, 3, false)?;
    let request: ToolCallRequest =
        serde_json::from_slice(&std::fs::read(root.join("original.json"))?)?;
    kernel.install_durable_finalization_cutpoint(Arc::new(|point| {
        if point == DurableFinalizationCutpoint::ToolReturnRecorded {
            let _ = std::process::Command::new("kill")
                .args(["-KILL", &std::process::id().to_string()])
                .status();
            std::process::exit(93);
        }
    }));
    kernel.evaluate_tool_call_blocking(&request)?;
    Err("worker did not hit the selected native fault cut".into())
}

#[cfg(all(feature = "admission-test-support", unix))]
#[test]
fn unknown_original_keeps_its_allocation_while_a_sibling_completes() -> Result {
    use std::os::unix::process::ExitStatusExt;
    let dir = tempfile::tempdir()?;
    let store = DelegationStore::open(dir.path().join("allocation.db"))?;
    store.create_root(slot("root", 1, 100, 3)?)?;
    split(&store, "root", 1, slot("uncertain", 2, 60, 2)?)?;
    split(&store, "root", 1, slot("sibling", 1, 40, 2)?)?;
    let (first, _) = open(dir.path(), 3, false)?;
    let mut original = request(&first, "uncertain", 2, "original-uncertain", 20)?;
    choose(&store, &original, 2, 3, 0, 20)?;
    seal(&store, &mut original, 20)?;
    std::fs::write(
        dir.path().join("original.json"),
        serde_json::to_vec(&original)?,
    )?;
    drop(first);
    let killed = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", "dynamic_recovery_worker", "--nocapture"])
        .env("CHIO_DYNAMIC_WORKER_ROOT", dir.path())
        .output()?;
    assert_eq!(
        killed.status.signal(),
        Some(9),
        "{}",
        String::from_utf8_lossy(&killed.stdout)
    );
    let (second, sibling_calls) = open(dir.path(), 4, false)?;
    let forbidden = request(&second, "uncertain", 2, "blind-replacement", 20)?;
    assert!(choose(&store, &forbidden, 2, 4, 1, 20).is_err());
    let mut sibling = request(&second, "sibling", 1, "independent-progress", 30)?;
    choose(&store, &sibling, 1, 4, 0, 30)?;
    seal(&store, &mut sibling, 30)?;
    let response = second.evaluate_tool_call_blocking(&sibling)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(sibling_calls.load(Ordering::SeqCst), 1);
    let (recovered, fresh_calls) = open(dir.path(), 3, false)?;
    let resumed = recovered.evaluate_tool_call_blocking(&original)?;
    assert_eq!(resumed.verdict, Verdict::Allow, "{:?}", resumed.reason);
    assert_eq!(fresh_calls.load(Ordering::SeqCst), 0);
    assert!(resumed.receipt.verify_signature()?);
    if let Some(path) = std::env::var_os("CHIO_DYNAMIC_RECOVERY_EVIDENCE") {
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&json!({
                "cut":"ToolReturnRecorded", "signal":9, "blind_replacement_rejected":true,
                "sibling_completed_before_recovery":true, "recovery_dispatches":0,
                "original_request":original.request_id, "recovered_receipt":resumed.receipt,
                "sibling_receipt":response.receipt
            }))?,
        )?;
    }
    Ok(())
}
