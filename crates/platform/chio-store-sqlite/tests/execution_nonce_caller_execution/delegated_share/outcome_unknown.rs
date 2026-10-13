//! An unknown caller outcome retains executor custody, quota and delegated share.

use super::*;
use crate::authenticated::{fixture, start};
use chio_kernel::KernelError;
use chio_store_sqlite::caller_execution_ledger::CallerExecutionLedgerError;
use std::fs::OpenOptions;
use std::io::Write;

#[test]
fn an_unknown_caller_outcome_retains_its_share_and_capture_after_restart_and_expiry() -> TestResult
{
    let (fixture, executor_key) = fixture()?;
    let ledger_path = fixture.directory.path().join("executor.db");
    let effect_path = fixture.directory.path().join("unknown-external-effect");
    let effects = std::sync::atomic::AtomicUsize::new(0);
    let (siblings, first, authorization) = {
        let ledger = crate::authenticated::ledger(&fixture)?;
        let mut runtime = fixture.open()?;
        let siblings = Siblings::new(&fixture, &mut runtime)?;
        let first = reserve_child(&runtime, &request(&siblings.first, "unknown-caller")?)?;
        let authorization = start(&runtime, &first)?;
        let result = ledger.execute_once(
            &authorization,
            &fixture.signer.public_key(),
            &authorization.authorization.invocation,
            &executor_key,
            || {
                effects.fetch_add(1, Ordering::SeqCst);
                let write_effect = || -> std::io::Result<()> {
                    let mut effect = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&effect_path)?;
                    effect.write_all(b"caller effect committed\n")?;
                    effect.sync_all()
                };
                write_effect().map_err(|error| KernelError::ToolServerError(error.to_string()))?;
                Err(KernelError::ToolServerError(
                    "caller result unavailable".into(),
                ))
            },
        );
        assert!(matches!(
            result,
            Err(CallerExecutionLedgerError::OutcomeUnknown)
        ));
        assert_eq!(std::fs::read(&effect_path)?, b"caller effect committed\n");
        assert_eq!(authorization, start(&runtime, &first)?);
        assert_state(&fixture, &first, "dispatch_committed")?;
        assert_eq!(grant_quota(&runtime, &first)?, (0, 1));
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        (siblings, first, authorization)
    };
    let expiry = u64::try_from(
        first
            .execution_nonce
            .as_ref()
            .ok_or("reserved nonce")?
            .expires_at(),
    )?;
    let after_expiry = expiry.checked_add(1).ok_or("expiry overflow")?;
    assert!(after_expiry < first.capability.expires_at);
    let _clock = chio_test_support::clock::scope_unix_secs(after_expiry);
    let mut runtime = fixture.open_with_reconcile(false)?;
    siblings.configure(&fixture, &mut runtime)?;
    runtime.kernel.reconcile_durable_admission_startup()?;
    assert_state(&fixture, &first, "awaiting_caller_report")?;
    assert_eq!(grant_quota(&runtime, &first)?, (0, 1));
    let parent = AdmissionIdentifier::try_new("parent_id", siblings.parent.id.clone())?;
    let shares = runtime
        .authority
        .admission_operation_store()
        .load_caller_budget_shares(
            &parent,
            1,
            &runtime.authority.mutation_fence(),
            after_expiry.checked_mul(1_000).ok_or("clock overflow")?,
        )?;
    assert_eq!(
        shares.len(),
        1,
        "unreported caller effects retain their delegated share"
    );
    assert_eq!(shares[0].child_id().as_str(), first.capability.id);
    assert!(shares[0].is_reserved_for_caller());
    let blocked = runtime.kernel.reserve_caller_execution_blocking(&request(
        &siblings.second,
        "sibling-after-unknown-caller",
    )?)?;
    assert_eq!(blocked.verdict, Verdict::Deny, "{:?}", blocked.reason);
    assert!(blocked
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("sibling-sum")));
    let ledger = crate::authenticated::ledger(&fixture)?;
    for _ in 0..2 {
        let replayed = start(&runtime, &first)?;
        assert_eq!(replayed, authorization);
        let result = ledger.execute_once(
            &replayed,
            &fixture.signer.public_key(),
            &authorization.authorization.invocation,
            &executor_key,
            || {
                effects.fetch_add(1, Ordering::SeqCst);
                Ok(report())
            },
        );
        assert!(matches!(
            result,
            Err(CallerExecutionLedgerError::OutcomeUnknown)
        ));
    }
    let connection = rusqlite::Connection::open(&ledger_path)?;
    let custody: (i64, i64) = connection.query_row(
        "SELECT (SELECT count(*) FROM caller_executor_claims),
                (SELECT count(*) FROM caller_executor_reports)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(custody, (1, 0));
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    assert_eq!(std::fs::read(&effect_path)?, b"caller effect committed\n");
    assert_state(&fixture, &first, "awaiting_caller_report")?;
    assert_eq!(grant_quota(&runtime, &first)?, (0, 1));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
