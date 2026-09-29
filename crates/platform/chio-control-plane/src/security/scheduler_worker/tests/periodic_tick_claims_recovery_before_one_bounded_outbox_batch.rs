use super::*;


#[test]
fn periodic_tick_claims_recovery_before_one_bounded_outbox_batch() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let store = Arc::new(
        SqliteSecurityStateStore::open(directory.path().join("bounded-outbox-tick.sqlite"))
            .unwrap_or_else(|error| panic!("security store: {error}")),
    );
    let events = Arc::new(Mutex::new(Vec::new()));
    let scripted = Arc::new(
        ScriptedDeclassificationOutboxPort::new(
            0,
            0,
            Vec::new(),
            vec![Ok(DeclassificationReceiptDrainReport {
                appended: MAX_DECLASSIFICATION_EVIDENCE_BATCH,
                acknowledged: MAX_DECLASSIFICATION_EVIDENCE_BATCH,
                deferred: 0,
                remaining: 7,
            })],
        )
        .with_compactions(vec![Ok(DeclassificationCompactionReport {
            compacted: 1,
            last_tenant_id: Some(tenant()),
            last_grant_id: Some(
                GrantId::new("grant-bounded-outbox")
                    .unwrap_or_else(|error| panic!("compaction grant: {error}")),
            ),
        })])
        .with_events(Arc::clone(&events)),
    );
    let outbox_port: Arc<dyn DeclassificationReceiptOutboxPort> = scripted.clone();
    let outbox = ProductionDeclassificationReceiptOutbox::new_for_test(outbox_port);
    let ports = Arc::new(SqliteTestPorts);
    let clock: Arc<dyn Clock> = Arc::new(OrderingClock {
        now_unix_ms: current_unix_ms(),
        events: Arc::clone(&events),
    });
    let worker = SqliteResponseWorkerPort::new_with_declassification_outbox(
        store,
        outbox,
        Arc::clone(&ports) as Arc<dyn EffectPort>,
        Arc::clone(&ports) as Arc<dyn SecurityReceiptSink>,
        Arc::clone(&ports) as Arc<dyn SecurityAlertPort>,
        ports as Arc<dyn SchedulerHealthPort>,
        clock,
        ProductionResponseSchedulerConfig {
            tenant_id: tenant(),
            lease_owner_id: LeaseOwnerId::new("worker-bounded-outbox")
                .unwrap_or_else(|error| panic!("lease owner id: {error}")),
            scheduler_policy: SchedulerPolicy {
                lease_duration_ms: 5_000,
                base_backoff_ms: 10,
                max_backoff_ms: 20,
                operator_page_threshold_ms: 100,
                max_claims: 8,
            },
            renewal_margin_ms: 5,
        },
    )
    .unwrap_or_else(|error| panic!("worker port: {error}"));
    scripted.set_pending(u64::from(MAX_DECLASSIFICATION_EVIDENCE_BATCH).saturating_add(7));
    events
        .lock()
        .unwrap_or_else(|_| panic!("event lock"))
        .clear();

    let report = worker
        .tick(0, false)
        .unwrap_or_else(|error| panic!("worker tick: {error}"));

    assert_eq!(
        report.declassification_receipts_acknowledged,
        MAX_DECLASSIFICATION_EVIDENCE_BATCH
    );
    assert_eq!(report.declassification_receipts_pending, 7);
    assert_eq!(report.declassification_receipts_compacted, 1);
    assert_eq!(report.claimed, 0);
    // Authorized recovery precedes outbox maintenance so an outbox outage
    // cannot strand rollback. Maintenance still performs one bounded batch.
    assert_eq!(scripted.events(), vec!["claim", "drain", "compact"]);
    assert_eq!(
        scripted.requested_batches(),
        vec![MAX_DECLASSIFICATION_EVIDENCE_BATCH]
    );
    assert_eq!(
        scripted.requested_compactions(),
        vec![(None, None, MAX_DECLASSIFICATION_EVIDENCE_BATCH)]
    );
    assert_eq!(
        worker.declassification_outbox_status(),
        (true, Some(7), None)
    );
}
