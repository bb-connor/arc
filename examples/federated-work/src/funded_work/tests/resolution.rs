use crate::{
    common::Result,
    funded_work::{
        capture_resolution, lifecycle,
        native::Native,
        observer::{FundingSource, Observation},
        settlement::Prepared,
        smoke::setup,
        Checkpoint,
    },
};
use serde_json::json;
use std::sync::{Arc, Mutex};

struct RefundSource(Mutex<Observation>);
impl FundingSource for RefundSource {
    fn observe(&self, _: &str) -> Result<Observation> {
        Err("refund-only fixture does not admit work".into())
    }
    fn observe_transaction(&self, _: &Prepared) -> Result<Observation> {
        Ok(self
            .0
            .lock()
            .map_err(|_| "refund fixture poisoned")?
            .clone())
    }
}

#[test]
#[ignore = "requires the owned Node chain; selected explicitly by successor qualification"]
fn refund_substitution_cannot_authorize_a_native_waiver() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let scenario = setup(directory.path())?;
    let checkpoint: Checkpoint = Arc::new(|_| Ok(()));
    scenario
        .native
        .execute(&scenario.agreement, &scenario.request)?;
    lifecycle::progress(
        directory.path(),
        &scenario.native,
        &scenario.request,
        "absent",
        &checkpoint,
        &|phase| {
            scenario.chain.request(json!({"method":"advance","allocation":scenario.funding["allocationId"],"phase":phase}))?;
            Ok(())
        },
    )?;
    let entry = scenario
        .native
        .journal
        .by_request(&scenario.request.request_id)?
        .ok_or("entry")?;
    let prepared: Prepared = scenario
        .native
        .journal
        .retained(&entry.allocation, "refund")?
        .ok_or("refund")?;
    let valid = scenario.chain.observe_transaction(&prepared)?;
    drop(scenario.native);
    let source = Arc::new(RefundSource(Mutex::new(valid.clone())));
    let native = Native::open_for_resolution(directory.path(), source.clone())?;
    let before =
        capture_resolution::original_sources(directory.path(), &native, &scenario.request)?;
    let connection = rusqlite::Connection::open_with_flags(
        directory.path().join("authority.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let counts = || -> Result<(i64, i64)> {
        Ok((
            connection.query_row("SELECT count(*) FROM capture_waiver_records", [], |r| {
                r.get(0)
            })?,
            connection.query_row("SELECT count(*) FROM authority_global_commits", [], |r| {
                r.get(0)
            })?,
        ))
    };
    let original_counts = counts()?;
    assert_eq!(original_counts.0, 0);
    for case in 0..5 {
        let mut changed = valid.clone();
        match case {
            0 => changed.receipt.transaction_hash = format!("0x{}", "f".repeat(64)),
            1 => changed.receipt.status = 0,
            2 => changed.receipt.logs.clear(),
            3 => {
                for log in &mut changed.receipt.logs {
                    if log.address == native.policy.domain.token {
                        log.data = format!("0x{:064x}", 99);
                    }
                }
            }
            _ => changed.work.block_hash = format!("0x{}", "f".repeat(64)),
        }
        *source.0.lock().map_err(|_| "refund fixture poisoned")? = changed;
        assert!(
            capture_resolution::resolve(directory.path(), &native, &scenario.request, &checkpoint)
                .is_err(),
            "accepted refund mutation {case}"
        );
        assert_eq!(
            counts()?,
            original_counts,
            "mutated authority for refund {case}"
        );
        assert_eq!(
            capture_resolution::original_sources(directory.path(), &native, &scenario.request)?,
            before
        );
    }
    *source.0.lock().map_err(|_| "refund fixture poisoned")? = valid;
    let observer_path = directory.path().join("verifier/key.seed");
    let original_key = std::fs::read(&observer_path)?;
    std::fs::write(
        &observer_path,
        chio_core_types::Keypair::generate().seed_hex(),
    )?;
    let error =
        capture_resolution::resolve(directory.path(), &native, &scenario.request, &checkpoint)
            .err()
            .ok_or("substituted observer authorized waiver")?;
    assert!(error
        .to_string()
        .contains("observation key differs from original policy"));
    assert_eq!(counts()?, original_counts);
    std::fs::write(observer_path, original_key)?;
    assert_eq!(
        capture_resolution::resolve(directory.path(), &native, &scenario.request, &checkpoint)?
            ["resolved"],
        true
    );
    assert_eq!(counts()?.0, 2);
    assert_eq!(
        capture_resolution::original_sources(directory.path(), &native, &scenario.request)?,
        before
    );
    assert_eq!(native.journal.execution_count()?, 1);
    Ok(())
}
