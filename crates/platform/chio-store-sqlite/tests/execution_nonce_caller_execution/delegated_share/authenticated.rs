use super::*;
use crate::authenticated::{fixture, start};
use chio_store_sqlite::caller_execution_ledger::SqliteCallerExecutionLedger;

#[test]
fn lost_authenticated_report_retains_sibling_share_until_original_settlement() -> TestResult {
    let (fixture, executor_key) = fixture()?;
    let ledger = SqliteCallerExecutionLedger::provision(
        &fixture.directory.path().join("delegated-executor.db"),
        fixture.caller_executor.clone().ok_or("executor")?,
        4,
    )?;
    let (siblings, first, authorization, report) = {
        let mut runtime = fixture.open()?;
        let siblings = Siblings::new(&fixture, &mut runtime)?;
        let first = reserve_child(
            &runtime,
            &request(&siblings.first, "authenticated-share-first")?,
        )?;
        let authorization = start(&runtime, &first)?;
        let report = ledger.execute_once(
            &authorization,
            &fixture.signer.public_key(),
            &authorization.authorization.invocation,
            &executor_key,
            || Ok(crate::report()),
        )?;
        let blocked = runtime.kernel.reserve_caller_execution_blocking(&request(
            &siblings.second,
            "authenticated-share-before-restart",
        )?)?;
        assert_eq!(blocked.verdict, Verdict::Deny);
        (siblings, first, authorization, report)
    };
    let expires = u64::try_from(first.execution_nonce.as_ref().ok_or("nonce")?.expires_at())?;
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(expires + 1, []);
    assert!(expires + 1 < first.capability.expires_at);
    let mut runtime = fixture.open()?;
    siblings.configure(&fixture, &mut runtime)?;
    assert_state(&fixture, &first, "awaiting_caller_report")?;
    let blocked = runtime.kernel.reserve_caller_execution_blocking(&request(
        &siblings.second,
        "authenticated-share-after-restart",
    )?)?;
    assert_eq!(blocked.verdict, Verdict::Deny, "{:?}", blocked.reason);
    let settled = runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
    assert_eq!(settled.verdict, Verdict::Allow, "{:?}", settled.reason);
    let replay = runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
    assert_eq!(canonical(&settled.receipt)?, canonical(&replay.receipt)?);
    let _second = reserve_child(
        &runtime,
        &request(&siblings.second, "authenticated-share-settled")?,
    )?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
