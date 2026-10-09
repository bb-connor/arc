//! V25-MEMORY: every variable-length field a walker or fetch copies is
//! measured before it is allocated. A row over the per-row limit is a typed
//! resource outcome, and a step never owns more than its byte budget except
//! for its first row.
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use rusqlite::params;

use super::super::walk::{
    authenticate, check_sources, copy_checkpoints, copy_claims, copy_lineage, WalkError, WalkLimits,
};
use super::support::{context, limits, Fixture, Spec};

const MIB: u64 = 1024 * 1024;

fn tight() -> WalkLimits {
    WalkLimits {
        max_receipt_bytes: MIB,
        step_bytes: MIB,
        ..limits()
    }
}

fn row_cap<T: std::fmt::Debug>(result: Result<T, WalkError>) {
    match result {
        Err(WalkError::RowCap { .. }) => {}
        other => panic!("expected a typed per-row resource outcome, got {other:?}"),
    }
}

fn tail_fixture() -> Fixture {
    let fixture = Fixture::new(0);
    fixture.append_varied(0..6);
    fixture
}

#[test]
fn an_oversized_claim_receipt_id_with_small_raw_json_is_refused_before_allocation() {
    let fixture = tail_fixture();
    fixture
        .tamper()
        .execute(
            "UPDATE claim_receipt_log_entries SET receipt_id = ?1 WHERE entry_seq = 3",
            ["x".repeat(2 * 1024 * 1024)],
        )
        .unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let ctx = context(&fixture.store, &cancel, tight());
    row_cap(copy_claims(&ctx, 3, 3));
}

#[test]
fn claim_metadata_counts_toward_the_step_byte_budget() {
    let fixture = tail_fixture();
    let tamper = fixture.tamper();
    for entry in 1..=3 {
        tamper
            .execute(
                "UPDATE claim_receipt_log_entries SET receipt_id = ?1 WHERE entry_seq = ?2",
                params![format!("{entry}-{}", "y".repeat(600 * 1024)), entry],
            )
            .unwrap();
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let ctx = context(&fixture.store, &cancel, tight());
    let rows = copy_claims(&ctx, 1, 3).unwrap();
    // Each row is about 600 KiB of metadata: only the first fits a 1 MiB step.
    assert_eq!(rows.len(), 1);
}

#[test]
fn an_oversized_checkpoint_row_is_refused_before_allocation() {
    let fixture = Fixture::new(2);
    fixture.append_varied(0..4);
    fixture
        .tamper()
        .execute(
            "UPDATE kernel_checkpoints SET signature = ?1 WHERE checkpoint_seq = 1",
            ["s".repeat(2 * 1024 * 1024)],
        )
        .unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let ctx = context(&fixture.store, &cancel, tight());
    row_cap(copy_checkpoints(&ctx, 1, 2));
}

#[test]
fn an_oversized_archived_checkpoint_row_is_refused_before_allocation() {
    let fixture = Fixture::new(2);
    fixture.append_varied(0..6);
    assert!(fixture.rotate(1_800_000_000) > 0);
    fixture
        .tamper_archive()
        .execute(
            "UPDATE kernel_checkpoints SET statement_json = ?1 WHERE checkpoint_seq = 1",
            ["j".repeat(2 * 1024 * 1024)],
        )
        .unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let ctx = context(&fixture.store, &cancel, tight());
    row_cap(copy_checkpoints(&ctx, 1, 2));
}

fn insert_lineage(fixture: &Fixture, capability: &str, subject: &str, grants: &str) {
    fixture
        .tamper()
        .execute(
            "INSERT INTO capability_lineage (capability_id, subject_key, issuer_key, issued_at,
                expires_at, grants_json, delegation_depth)
             VALUES (?1, ?2, 'issuer', 1, 2, ?3, 0)",
            params![capability, subject, grants],
        )
        .unwrap();
}

#[test]
fn an_oversized_lineage_row_is_refused_before_allocation_on_refresh() {
    let fixture = tail_fixture();
    insert_lineage(&fixture, "cap-1", &"z".repeat(2 * 1024 * 1024), "[]");
    let cancel = Arc::new(AtomicBool::new(false));
    let ctx = context(&fixture.store, &cancel, tight());
    row_cap(copy_lineage(&ctx, 0, i64::MAX, 256));
}

#[test]
fn an_oversized_lineage_row_is_refused_before_a_projection_allocates_it() {
    let fixture = Fixture::new(0);
    // No signed attribution: the subject falls back to capability lineage.
    fixture.append(&Spec::new("no-attribution", 1_700_000_000));
    fixture.flush();
    insert_lineage(&fixture, "cap-1", "subject", &"g".repeat(2 * 1024 * 1024));
    let cancel = Arc::new(AtomicBool::new(false));
    let ctx = context(&fixture.store, &cancel, tight());
    let rows = copy_claims(&ctx, 1, 1).unwrap();
    let entries = authenticate(&ctx, rows, None).unwrap();
    row_cap(check_sources(&ctx, &entries));
}

#[test]
fn legacy_lineage_subjects_are_charged_to_the_step_budget_and_the_build_completes() {
    let fixture = Fixture::new(0);
    let subject_bytes = 300 * 1024;
    for index in 0..5_u64 {
        let mut spec = Spec::new(format!("legacy-{index}"), 1_700_000_000 + index);
        spec.capability = format!("cap-legacy-{index}");
        fixture.append(&spec);
    }
    fixture.flush();
    for index in 0..5 {
        insert_lineage(
            &fixture,
            &format!("cap-legacy-{index}"),
            &format!("{index}{}", "s".repeat(subject_bytes)),
            "[]",
        );
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let mut wide = tight();
    wide.step_rows = 5;
    let ctx = context(&fixture.store, &cancel, wide);
    let rows = copy_claims(&ctx, 1, 5).unwrap();
    assert_eq!(
        rows.len(),
        5,
        "claim rows are small and all fit the copy budget"
    );
    let entries = authenticate(&ctx, rows, None).unwrap();
    let (tools, _) = check_sources(&ctx, &entries).unwrap();
    let retained: u64 = tools
        .iter()
        .map(|row| u64::try_from(row.subject.as_ref().map_or(0, String::len)).unwrap())
        .sum();
    assert!(!tools.is_empty());
    assert!(
        retained <= tight().step_bytes,
        "one step retained {retained} bytes of lineage subjects"
    );
    // Every subject is kept whole, and the build still completes.
    assert!(tools.iter().all(|row| row
        .subject
        .as_ref()
        .is_some_and(|s| s.len() == subject_bytes + 1)));
    let (db, _) = super::super::pass::build_snapshot(
        &ctx,
        super::support::target(&ctx),
        64 * 1024 * 1024,
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(db.tool_row_count().unwrap(), 5);
}
