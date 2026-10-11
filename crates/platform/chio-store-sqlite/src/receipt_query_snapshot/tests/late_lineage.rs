//! Capability lineage recorded after receipts of that capability without
//! signed attribution were archived. The archived history stays readable, and
//! per-call reads and refreshed, recertified and rebuilt snapshots attribute it
//! alike. An archive that records a different attribution, or loses a signed
//! one, is still refused.
use std::time::{Duration, Instant};

use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::crypto::Keypair;
use chio_kernel::receipt_query::{ReceiptQuery, ReceiptReadContext};
use chio_kernel::ReceiptStoreError;
use rusqlite::params;

use super::super::service::{
    ReceiptQuerySnapshotConfig, ReceiptQuerySnapshotState, ReceiptQuerySnapshots,
};
use super::service::{config, ready, wait_for};
use super::support::{keypair, Fixture, Spec};
use crate::receipt_store::retained_read::unrecorded_lineage_reads_for_test;

const CAPABILITY: &str = "cap-late";
const OTHER: &str = "cap-other";
const SIGNED_SUBJECT: &str = "subject-signed";

fn holder() -> Keypair {
    Keypair::from_seed(&[0x61; 32])
}

fn late_subject() -> String {
    holder().public_key().to_hex()
}

fn token() -> CapabilityToken {
    let issuer = keypair();
    let body = CapabilityTokenBody {
        id: CAPABILITY.to_string(),
        issuer: issuer.public_key(),
        subject: holder().public_key(),
        scope: ChioScope {
            grants: vec![ToolGrant {
                server_id: "shell".to_string(),
                tool_name: "bash".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: vec![],
            prompt_grants: vec![],
        },
        issued_at: 1_700_000_000,
        expires_at: 4_000_000_000,
        delegation_chain: vec![],
        aggregate_invocation_budget: None,
    };
    CapabilityToken::sign(body, &issuer).unwrap()
}

fn spec(index: u64, capability: &str, subject: Option<&str>) -> Spec {
    let mut spec = Spec::new(format!("late-lineage-{index}"), 1_700_000_000 + index);
    spec.capability = capability.into();
    spec.subject = subject.map(Into::into);
    spec.tenant = index.is_multiple_of(2).then(|| "tenant-a".to_string());
    spec
}

fn id(spec: &Spec) -> String {
    spec.sign(&keypair()).id
}

/// Receipts of `CAPABILITY` without signed attribution, one with a signed
/// subject and one of an unrelated capability are archived; one unattributed
/// receipt of `CAPABILITY` and one unrelated receipt stay live. No lineage
/// exists yet.
struct History {
    fixture: Fixture,
    archived_unattributed: String,
    archived_signed: String,
    live_unattributed: String,
    live_other: String,
}

fn history() -> History {
    let fixture = Fixture::new(4);
    let mut specs = Vec::new();
    for index in 0..8 {
        let spec = match index {
            5 => spec(index, CAPABILITY, Some(SIGNED_SUBJECT)),
            7 => spec(index, OTHER, None),
            _ => spec(index, CAPABILITY, None),
        };
        fixture.append(&spec);
        specs.push(spec);
    }
    archive_before(&fixture, 1_700_000_008, 8);
    let live = spec(20, CAPABILITY, None);
    let other = spec(21, OTHER, Some("subject-other"));
    fixture.append(&live);
    fixture.append(&other);
    fixture.flush();
    History {
        archived_unattributed: id(&specs[0]),
        archived_signed: id(&specs[5]),
        live_unattributed: id(&live),
        live_other: id(&other),
        fixture,
    }
}

/// Rotate until at least `expected` receipts older than `cutoff` are
/// archived; the background checkpoint may lag the appends.
fn archive_before(fixture: &Fixture, cutoff: u64, expected: u64) {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut archived = 0;
    while archived < expected {
        archived += fixture.rotate(cutoff);
        assert!(
            Instant::now() < deadline,
            "only {archived} receipts were archived"
        );
        if archived < expected {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

fn record_lineage(fixture: &Fixture) {
    fixture
        .store
        .record_capability_snapshot(&token(), None)
        .unwrap();
}

fn admin(limit: usize) -> ReceiptQuery {
    ReceiptQuery {
        limit,
        ..ReceiptQuery::default().local_operator_admin()
    }
}

/// Queries across every filter class whose answer the late lineage could
/// change: global, unrelated capability, the capability itself, its subjects
/// and a tenant scope.
fn queries() -> Vec<ReceiptQuery> {
    vec![
        admin(100),
        admin(3),
        ReceiptQuery {
            capability_id: Some(OTHER.into()),
            ..admin(100)
        },
        ReceiptQuery {
            capability_id: Some(CAPABILITY.into()),
            ..admin(100)
        },
        ReceiptQuery {
            agent_subject: Some(late_subject()),
            ..admin(100)
        },
        ReceiptQuery {
            agent_subject: Some(late_subject()),
            ..admin(2)
        },
        ReceiptQuery {
            agent_subject: Some(SIGNED_SUBJECT.into()),
            ..admin(100)
        },
        ReceiptQuery {
            agent_subject: Some(late_subject()),
            ..ReceiptQuery {
                limit: 100,
                ..ReceiptQuery::default().authenticated_tenant("tenant-a")
            }
        },
    ]
}

type Page = (Vec<u64>, u64, Option<u64>);

fn per_call(fixture: &Fixture, query: &ReceiptQuery) -> Result<Page, ReceiptStoreError> {
    let page = fixture.store.query_receipts(query)?;
    Ok((
        page.receipts.iter().map(|row| row.seq).collect(),
        page.total_count,
        page.next_cursor,
    ))
}

fn served(
    service: &ReceiptQuerySnapshots,
    query: &ReceiptQuery,
) -> Result<Page, ReceiptStoreError> {
    let page = service.query_receipts(query)?;
    Ok((
        page.receipts.iter().map(|row| row.seq).collect(),
        page.total_count,
        page.next_cursor,
    ))
}

fn receipt_ids(fixture: &Fixture, query: &ReceiptQuery) -> Vec<String> {
    let page = fixture.store.query_receipts(query).unwrap();
    page.receipts
        .into_iter()
        .map(|row| row.receipt.id)
        .collect()
}

/// Every per-call read of the history succeeds and attributes every
/// receipt of `CAPABILITY` without signed attribution, archived or live, to
/// the lineage subject, and the signed one to its own subject.
fn assert_per_call_reads(history: &History) {
    let fixture = &history.fixture;
    for query in queries() {
        if let Err(error) = per_call(fixture, &query) {
            panic!("a per-call read of intact archived history refused {query:?}: {error:?}");
        }
    }
    let late = receipt_ids(
        fixture,
        &ReceiptQuery {
            agent_subject: Some(late_subject()),
            ..admin(100)
        },
    );
    assert_eq!(late.len(), 7, "{late:?}");
    assert!(late.contains(&history.archived_unattributed));
    assert!(late.contains(&history.live_unattributed));
    assert!(!late.contains(&history.archived_signed));
    let signed = receipt_ids(
        fixture,
        &ReceiptQuery {
            agent_subject: Some(SIGNED_SUBJECT.into()),
            ..admin(100)
        },
    );
    assert_eq!(signed, vec![history.archived_signed.clone()]);
    let context = ReceiptReadContext::admin_service();
    for id in [&history.archived_unattributed, &history.live_other] {
        let found = fixture.store.load_chio_receipt_with_context(id, &context);
        assert!(
            matches!(&found, Ok(Some(receipt)) if &receipt.id == id),
            "point read of {id}: {found:?}"
        );
    }
}

/// The snapshot answers every query exactly as the per-call path does.
fn assert_snapshot_agrees(fixture: &Fixture, service: &ReceiptQuerySnapshots, what: &str) {
    for query in queries() {
        let expected = per_call(fixture, &query).unwrap();
        assert_eq!(
            served(service, &query).unwrap(),
            expected,
            "{what}: {query:?}"
        );
    }
}

fn snapshot_config() -> ReceiptQuerySnapshotConfig {
    ReceiptQuerySnapshotConfig {
        recertify_interval: Duration::from_millis(100),
        invalid_retry_backoff: Duration::from_secs(3),
        ..config()
    }
}

/// Wait for two full recertification passes to complete, so the second one
/// started after every change made before this call, failing if the snapshot
/// leaves Ready.
fn await_recertified(service: &ReceiptQuerySnapshots) {
    let recertified = || {
        let status = service.status();
        assert_eq!(
            status.state,
            ReceiptQuerySnapshotState::Ready,
            "during recertification"
        );
        status.watermark.map(|w| w.recertified_at_unix_ms)
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut last = recertified();
    let mut passes = 0;
    while passes < 2 {
        std::thread::sleep(Duration::from_millis(10));
        let now = recertified();
        if now != last {
            passes += 1;
            last = now;
        }
        assert!(
            Instant::now() < deadline,
            "recertification did not complete"
        );
    }
}

/// A snapshot built from scratch over the history.
fn rebuilt(fixture: &Fixture) -> ReceiptQuerySnapshots {
    let service = ReceiptQuerySnapshots::start(fixture.store.clone(), snapshot_config()).unwrap();
    let state = wait_for(&service, "a rebuilt snapshot", |state| {
        !matches!(
            state,
            ReceiptQuerySnapshotState::WaitingForWriterSeed
                | ReceiptQuerySnapshotState::Building { .. }
        )
    });
    assert_eq!(state, ReceiptQuerySnapshotState::Ready, "rebuild");
    service
}

#[test]
fn a_late_lineage_keeps_every_per_call_read_of_archived_history() {
    let history = history();
    assert_per_call_reads_before_lineage(&history);
    record_lineage(&history.fixture);
    assert_per_call_reads(&history);
}

fn assert_per_call_reads_before_lineage(history: &History) {
    for query in queries() {
        per_call(&history.fixture, &query).unwrap();
    }
}

#[test]
fn refreshed_recertified_and_rebuilt_snapshots_agree_on_a_late_lineage() {
    let history = history();
    let fixture = &history.fixture;
    let service = ready(fixture, snapshot_config());
    record_lineage(fixture);
    await_attributed(&service, &history.archived_unattributed);
    let refreshed: Vec<Page> = queries()
        .iter()
        .map(|query| served(&service, query).unwrap())
        .collect();
    let rebuilt = rebuilt(fixture);
    let answers: Vec<Page> = queries()
        .iter()
        .map(|query| served(&rebuilt, query).unwrap())
        .collect();
    assert_eq!(
        answers, refreshed,
        "rebuilt and refreshed snapshots disagree"
    );
    rebuilt.shutdown();
    await_recertified(&service);
    assert_snapshot_agrees(fixture, &service, "recertified");
    assert_per_call_reads(&history);
    service.shutdown();
}

/// Wait until extension has attributed `id` to the lineage subject, failing
/// if the snapshot leaves Ready.
fn await_attributed(service: &ReceiptQuerySnapshots, id: &str) {
    let query = ReceiptQuery {
        agent_subject: Some(late_subject()),
        ..admin(100)
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(page) = service.query_receipts(&query) {
            if page.receipts.iter().any(|row| row.receipt.id == id) {
                return;
            }
        }
        let state = service.status().state;
        assert_eq!(
            state,
            ReceiptQuerySnapshotState::Ready,
            "before the refresh"
        );
        assert!(Instant::now() < deadline, "the lineage was never refreshed");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_late_legacy_lineage_row_attributes_archived_history_alike() {
    let history = history();
    let fixture = &history.fixture;
    let token = token();
    fixture
        .tamper()
        .execute(
            "INSERT INTO capability_lineage (capability_id, subject_key, issuer_key, issued_at,
                expires_at, grants_json, delegation_depth, provenance)
             VALUES (?1, ?2, ?3, 1700000000, 4000000000, ?4, 0, 'legacy_projection')",
            params![
                CAPABILITY,
                late_subject(),
                token.issuer.to_hex(),
                serde_json::to_string(&token.scope).unwrap()
            ],
        )
        .unwrap();
    assert_per_call_reads(&history);
    let service = rebuilt(fixture);
    assert_snapshot_agrees(fixture, &service, "rebuilt");
    service.shutdown();
}

#[test]
fn a_later_rotation_keeps_a_late_lineage_consistent() {
    let history = history();
    let fixture = &history.fixture;
    let service = ready(fixture, snapshot_config());
    record_lineage(fixture);
    await_attributed(&service, &history.archived_unattributed);
    // Complete the open checkpoint batch and archive everything, so the
    // rotation also copies the late lineage row into the archive.
    fixture.append(&spec(22, CAPABILITY, None));
    fixture.append(&spec(23, OTHER, None));
    fixture.flush();
    archive_before(fixture, 1_800_000_000, 4);
    let late = receipt_ids(
        fixture,
        &ReceiptQuery {
            agent_subject: Some(late_subject()),
            ..admin(100)
        },
    );
    assert_eq!(late.len(), 8, "{late:?}");
    await_recertified(&service);
    assert_snapshot_agrees(fixture, &service, "after the rotation");
    service.shutdown();
    let service = rebuilt(fixture);
    assert_snapshot_agrees(fixture, &service, "rebuilt after the rotation");
    service.shutdown();
}

#[test]
fn stripping_an_unsigned_attribution_from_the_archive_changes_no_answer() {
    let history = history();
    let fixture = &history.fixture;
    record_lineage(fixture);
    fixture.append(&spec(22, CAPABILITY, None));
    fixture.append(&spec(23, OTHER, None));
    fixture.flush();
    archive_before(fixture, 1_800_000_000, 4);
    let before: Vec<Page> = queries()
        .iter()
        .map(|query| per_call(fixture, query).unwrap())
        .collect();
    // The rotation recorded the lineage in the archive; remove it and the
    // receipts' own unsigned subject columns there.
    let archive = fixture.tamper_archive();
    let removed = archive
        .execute(
            "DELETE FROM capability_lineage WHERE capability_id = ?1",
            [CAPABILITY],
        )
        .unwrap();
    assert_eq!(removed, 1);
    archive
        .execute(
            "UPDATE chio_tool_receipts SET subject_key = NULL, issuer_key = NULL
             WHERE capability_id = ?1 AND receipt_id != ?2",
            params![CAPABILITY, history.archived_signed],
        )
        .unwrap();
    let after: Vec<Page> = queries()
        .iter()
        .map(|query| per_call(fixture, query).unwrap())
        .collect();
    assert_eq!(after, before);
    let service = rebuilt(fixture);
    assert_snapshot_agrees(fixture, &service, "rebuilt over a stripped archive");
    service.shutdown();
}

/// After the late lineage, `tamper` edits the archive. Every per-call read
/// and a snapshot build refuse the archive.
fn archive_tamper_is_refused(tamper: impl FnOnce(&History)) {
    let history = history();
    let fixture = &history.fixture;
    record_lineage(fixture);
    tamper(&history);
    for query in [admin(100), queries()[2].clone()] {
        let read = per_call(fixture, &query);
        assert!(read.is_err(), "a tampered archive was read: {read:?}");
    }
    let service = ReceiptQuerySnapshots::start(fixture.store.clone(), snapshot_config()).unwrap();
    let state = wait_for(&service, "a refused build", |state| {
        matches!(state, ReceiptQuerySnapshotState::Invalid { .. })
            || *state == ReceiptQuerySnapshotState::Ready
    });
    assert!(
        matches!(state, ReceiptQuerySnapshotState::Invalid { .. }),
        "a snapshot was built over a tampered archive: {state:?}"
    );
    service.shutdown();
}

#[test]
fn an_archived_unsigned_subject_edited_to_another_value_is_refused() {
    archive_tamper_is_refused(|history| {
        let changed = history
            .fixture
            .tamper_archive()
            .execute(
                "UPDATE chio_tool_receipts SET subject_key = 'forged-subject' WHERE receipt_id = ?1",
                [&history.archived_unattributed],
            )
            .unwrap();
        assert_eq!(changed, 1);
    });
}

#[test]
fn a_forged_archive_lineage_row_is_refused() {
    archive_tamper_is_refused(|history| {
        let token = token();
        history
            .fixture
            .tamper_archive()
            .execute(
                "INSERT INTO capability_lineage (capability_id, subject_key, issuer_key, issued_at,
                    expires_at, grants_json, delegation_depth, provenance)
                 VALUES (?1, 'forged-subject', ?2, 1700000000, 4000000000, ?3, 0, 'legacy_projection')",
                params![
                    CAPABILITY,
                    token.issuer.to_hex(),
                    serde_json::to_string(&token.scope).unwrap()
                ],
            )
            .unwrap();
    });
}

#[test]
fn a_signed_subject_stripped_from_the_archive_is_refused() {
    archive_tamper_is_refused(|history| {
        let changed = history
            .fixture
            .tamper_archive()
            .execute(
                "UPDATE chio_tool_receipts SET subject_key = NULL WHERE receipt_id = ?1",
                [&history.archived_signed],
            )
            .unwrap();
        assert_eq!(changed, 1);
    });
}

#[test]
fn an_archived_claim_edit_is_refused() {
    archive_tamper_is_refused(|history| {
        let mut forged = spec(0, CAPABILITY, None);
        forged.tool_name = "forged".into();
        let raw = serde_json::to_string(&forged.sign(&keypair())).unwrap();
        let changed = history
            .fixture
            .tamper_archive()
            .execute(
                "UPDATE claim_receipt_log_entries SET raw_json = ?1 WHERE receipt_id = ?2",
                params![raw, history.archived_unattributed],
            )
            .unwrap();
        assert_eq!(changed, 1);
    });
}

/// More late capabilities with archived history for one subject than the
/// per-call attribution binds in one chunk.
const LATE_CAPABILITIES: u64 = 300;

fn insert_legacy_lineage(fixture: &Fixture, capability: &str, subject: &str) {
    let token = token();
    fixture
        .tamper()
        .execute(
            "INSERT INTO capability_lineage (capability_id, subject_key, issuer_key, issued_at,
                expires_at, grants_json, delegation_depth, provenance)
             VALUES (?1, ?2, ?3, 1700000000, 4000000000, ?4, 0, 'legacy_projection')",
            params![
                capability,
                subject,
                token.issuer.to_hex(),
                serde_json::to_string(&token.scope).unwrap()
            ],
        )
        .unwrap();
}

/// Every page of `query` by cursor, with the total each page reported.
fn pages(read: impl Fn(&ReceiptQuery) -> Page, query: &ReceiptQuery) -> Vec<Page> {
    let mut query = query.clone();
    let mut pages = Vec::new();
    loop {
        let page = read(&query);
        let next = page.2;
        pages.push(page);
        match next {
            Some(cursor) => query.cursor = Some(cursor),
            None => return pages,
        }
    }
}

#[test]
fn a_subject_with_many_late_capabilities_pages_and_counts_alike() {
    let fixture = Fixture::new(4);
    let subject = late_subject();
    let mut index = 100;
    let mut expected: Vec<(u64, Option<String>)> = Vec::new();
    let mut append = |capability: &str, signed: Option<&str>, attributed: bool| {
        let spec = spec(index, capability, signed);
        index += 1;
        let seq = fixture.append(&spec);
        if attributed {
            expected.push((seq, spec.tenant.clone()));
        }
        seq
    };
    // Lineage that existed before its receipts were written.
    for current in 0..3 {
        insert_legacy_lineage(&fixture, &format!("cap-current-{current}"), &subject);
    }
    // Capabilities whose lineage arrives only after archival.
    for late in 0..LATE_CAPABILITIES {
        append(&format!("cap-late-{late}"), None, true);
    }
    for current in 0..3 {
        for _ in 0..2 {
            append(&format!("cap-current-{current}"), None, true);
        }
    }
    for _ in 0..3 {
        append("cap-signed", Some(&subject), true);
    }
    // A signed subject wins over the late lineage of its capability.
    let precedence: Vec<u64> = (0..2)
        .map(|_| append("cap-late-150", Some("subject-precedence"), false))
        .collect();
    for _ in 0..3 {
        append(OTHER, Some("subject-other"), false);
    }
    for _ in 0..2 {
        append("cap-late-unrelated", None, false);
    }
    fixture.flush();
    archive_before(&fixture, 1_800_000_000, 316);
    for late in 0..LATE_CAPABILITIES {
        insert_legacy_lineage(&fixture, &format!("cap-late-{late}"), &subject);
        if late == 200 {
            // A row the canonical reader refuses and a very large row, both
            // carrying the subject, for capabilities with no receipts: neither
            // attributes anything, and the attribution never reads them.
            let tamper = fixture.tamper();
            tamper
                .execute(
                    "INSERT INTO capability_lineage (capability_id, subject_key, issuer_key,
                        issued_at, expires_at, grants_json, delegation_depth, provenance)
                     VALUES ('cap-malformed', ?1, 'issuer', 1700000000, 4000000000, '{}', 0,
                        'signed_token')",
                    [&subject],
                )
                .unwrap();
            tamper
                .execute(
                    "INSERT INTO capability_lineage (capability_id, subject_key, issuer_key,
                        issued_at, expires_at, grants_json, delegation_depth, provenance)
                     VALUES ('cap-large', ?1, 'issuer', 1700000000, 4000000000, ?2, 0,
                        'legacy_projection')",
                    params![subject, "g".repeat(8 * 1024 * 1024)],
                )
                .unwrap();
        }
    }
    insert_legacy_lineage(&fixture, "cap-late-unrelated", "subject-unrelated");
    // Receipts written after the late lineage stay live.
    append("cap-late-1", None, true);
    append("cap-late-299", None, true);
    append("cap-late-unrelated", None, false);
    fixture.flush();

    let scopes = [
        (
            None,
            ReceiptQuery {
                agent_subject: Some(subject.clone()),
                ..admin(97)
            },
        ),
        (
            Some("tenant-a"),
            ReceiptQuery {
                agent_subject: Some(subject.clone()),
                limit: 47,
                ..ReceiptQuery::default().authenticated_tenant("tenant-a")
            },
        ),
    ];
    // The attribution reads current lineage only for the capabilities of
    // archived rows that recorded none: the late ones and the unrelated one.
    let reads = unrecorded_lineage_reads_for_test();
    per_call(&fixture, &scopes[0].1).unwrap();
    assert_eq!(
        unrecorded_lineage_reads_for_test() - reads,
        LATE_CAPABILITIES + 1
    );
    let service = rebuilt(&fixture);
    for (scope, query) in &scopes {
        let scoped: Vec<u64> = expected
            .iter()
            .filter(|(_, tenant)| scope.is_none() || tenant.as_deref() == *scope)
            .map(|(seq, _)| *seq)
            .collect();
        let read = pages(|query| per_call(&fixture, query).unwrap(), query);
        assert!(read.len() > 2, "{} pages", read.len());
        let seqs: Vec<u64> = read.iter().flat_map(|page| page.0.clone()).collect();
        assert_eq!(seqs, scoped, "per-call pages of {query:?}");
        let total = u64::try_from(scoped.len()).unwrap();
        assert!(read.iter().all(|page| page.1 == total), "{read:?}");
        let served_pages = pages(|query| served(&service, query).unwrap(), query);
        assert_eq!(served_pages, read, "snapshot pages of {query:?}");
        let beyond = ReceiptQuery {
            cursor: Some(u64::MAX),
            ..query.clone()
        };
        assert_eq!(
            per_call(&fixture, &beyond).unwrap(),
            (Vec::new(), total, None)
        );
        assert_eq!(
            served(&service, &beyond).unwrap(),
            (Vec::new(), total, None)
        );
    }
    let signed = ReceiptQuery {
        agent_subject: Some("subject-precedence".into()),
        ..admin(100)
    };
    assert_eq!(
        per_call(&fixture, &signed).unwrap(),
        (precedence.clone(), 2, None)
    );
    assert_eq!(served(&service, &signed).unwrap(), (precedence, 2, None));
    service.shutdown();
}

#[test]
fn a_late_lineage_row_the_canonical_reader_refuses_is_refused_for_archived_history() {
    let history = history();
    let fixture = &history.fixture;
    fixture
        .tamper()
        .execute(
            "INSERT INTO capability_lineage (capability_id, subject_key, issuer_key, issued_at,
                expires_at, grants_json, delegation_depth, provenance)
             VALUES (?1, ?2, 'issuer', 1700000000, 4000000000, '{}', 0, 'signed_token')",
            params![CAPABILITY, late_subject()],
        )
        .unwrap();
    assert!(fixture.store.get_lineage(CAPABILITY).is_err());
    let read = per_call(fixture, &admin(100));
    assert!(
        read.is_err(),
        "archived history was read through a refused lineage row: {read:?}"
    );
    let service = ReceiptQuerySnapshots::start(fixture.store.clone(), snapshot_config()).unwrap();
    let state = wait_for(&service, "a refused build", |state| {
        matches!(state, ReceiptQuerySnapshotState::Invalid { .. })
            || *state == ReceiptQuerySnapshotState::Ready
    });
    assert!(
        matches!(state, ReceiptQuerySnapshotState::Invalid { .. }),
        "a snapshot attributed archived history through a refused lineage row: {state:?}"
    );
    service.shutdown();
}
