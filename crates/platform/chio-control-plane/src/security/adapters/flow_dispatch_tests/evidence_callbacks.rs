use super::*;
use chio_security_types::ports::*;

/// Only the read callback advances time. All persistence remains real SQLite.
struct DelayedEvidence {
    store: Arc<SqliteSecurityStateStore>,
    clock: Arc<ControlledClock>,
}

impl DeclassificationEvidenceCommitStore for DelayedEvidence {
    fn ensure_declassification_evidence_ready(&self) -> PortResult<()> {
        self.store.ensure_declassification_evidence_ready()
    }

    fn declassification_evidence_readiness_cursor(&self) -> PortResult<RecordId> {
        self.store.declassification_evidence_readiness_cursor()
    }

    fn begin_declassification_reconciliation(&self) -> PortResult<()> {
        self.store.begin_declassification_reconciliation()
    }

    fn end_declassification_reconciliation(&self) -> PortResult<()> {
        self.store.end_declassification_reconciliation()
    }

    fn seal_declassification_live_dispatch(&self) -> PortResult<()> {
        self.store.seal_declassification_live_dispatch()
    }

    fn commit_declassification_consumption_evidence(
        &self,
        request: &DeclassificationConsumptionEvidenceCommit,
    ) -> PortResult<DeclassificationConsume> {
        self.store
            .commit_declassification_consumption_evidence(request)
    }

    fn commit_declassification_outcome_evidence(
        &self,
        request: &DeclassificationOutcomeEvidenceCommit,
    ) -> PortResult<()> {
        self.store.commit_declassification_outcome_evidence(request)
    }

    fn load_declassification_use(
        &self,
        query: &DeclassificationUseQuery,
    ) -> PortResult<Option<DeclassificationUseRecord>> {
        self.store.load_declassification_use(query)
    }

    fn load_declassification_evidence(
        &self,
        query: &DeclassificationEvidenceQuery,
    ) -> PortResult<Option<DeclassificationEvidenceRecord>> {
        let result = self.store.load_declassification_evidence(query);
        self.clock.0.store(200_000, Ordering::SeqCst);
        result
    }

    fn load_pending_declassification_evidence(
        &self,
        query: &DeclassificationEvidencePendingQuery,
    ) -> PortResult<Vec<DeclassificationEvidenceRecord>> {
        self.store.load_pending_declassification_evidence(query)
    }

    fn load_pending_declassification_evidence_batch(
        &self,
        now_unix_ms: u64,
        max_records: u32,
    ) -> PortResult<Vec<DeclassificationEvidenceRecord>> {
        self.store
            .load_pending_declassification_evidence_batch(now_unix_ms, max_records)
    }

    fn load_stranded_declassification_consumptions_batch(
        &self,
        max_records: u32,
    ) -> PortResult<Vec<DeclassificationEvidenceRecord>> {
        self.store
            .load_stranded_declassification_consumptions_batch(max_records)
    }

    fn acknowledge_declassification_evidence(
        &self,
        request: &DeclassificationEvidenceAckRequest,
    ) -> PortResult<()> {
        self.store.acknowledge_declassification_evidence(request)
    }

    fn record_declassification_evidence_retry(
        &self,
        request: &DeclassificationEvidenceRetryRequest,
    ) -> PortResult<DeclassificationEvidenceRecord> {
        self.store.record_declassification_evidence_retry(request)
    }

    fn count_pending_declassification_evidence(&self) -> PortResult<u64> {
        self.store.count_pending_declassification_evidence()
    }

    fn count_stranded_declassification_consumptions(&self) -> PortResult<u64> {
        self.store.count_stranded_declassification_consumptions()
    }

    fn load_declassification_compaction_candidates(
        &self,
        query: &DeclassificationCompactionQuery,
    ) -> PortResult<Vec<DeclassificationCompactionCandidate>> {
        self.store
            .load_declassification_compaction_candidates(query)
    }

    fn compact_declassification_evidence(
        &self,
        request: &DeclassificationCompactionRequest,
    ) -> PortResult<DeclassificationEvidenceTombstone> {
        self.store.compact_declassification_evidence(request)
    }
}

#[test]
fn expiry_during_evidence_lookup_rejects_before_consumption() {
    let mut fixture = Fixture::new(true);
    fixture
        .resolver
        .config
        .declassification_evidence
        .as_mut()
        .unwrap_or_else(|| panic!("evidence configuration missing"))
        .store = Arc::new(DelayedEvidence {
        store: fixture.state.clone(),
        clock: fixture.clock.clone(),
    });
    let snapshot = fixture.snapshot();
    let inventory = fixture.inventory();
    let prepared = fixture.prepare();
    let result = prepared.commit();
    fixture.assert_unused(&snapshot, &inventory);
    assert!(matches!(
        result,
        Err(chio_flow::FlowDenial::DeclassificationExpired)
    ));
}
