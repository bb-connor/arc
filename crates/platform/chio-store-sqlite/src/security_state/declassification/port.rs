//! Legacy public ports retain retirement checks and own their outer commit.

use super::*;

impl SqliteSecurityStateStore {
    pub(super) fn declassification_read<T>(
        &self,
        read: impl FnOnce(&Transaction<'_>) -> PortResult<T>,
    ) -> PortResult<T> {
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        participant_source::ensure_legacy_writable(&tx)?;
        let value = read(&tx)?;
        tx.commit().map_err(sqlite_error)?;
        Ok(value)
    }

    fn declassification_write<T>(
        &self,
        mutate: impl FnOnce(&ScopedMutation<'_>) -> PortResult<T>,
    ) -> PortResult<T> {
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let owner = SecurityStateWriteTransaction::new(tx)?;
        let value = mutate(&ScopedMutation::legacy(owner.transaction()))?;
        owner.into_transaction().commit().map_err(sqlite_error)?;
        Ok(value)
    }
}

impl DeclassificationEvidenceCommitStore for SqliteSecurityStateStore {
    fn ensure_declassification_evidence_ready(&self) -> PortResult<()> {
        self.declassification_read(|tx| {
            validate_declassification_evidence_schema(tx)?;
            integrity::verify(ScopedReader::legacy(tx))
        })
    }

    fn declassification_evidence_readiness_cursor(&self) -> PortResult<RecordId> {
        self.ensure_declassification_evidence_ready()?;
        RecordId::new(DECLASSIFICATION_READINESS_CURSOR).map_err(PortError::from)
    }

    fn begin_declassification_reconciliation(&self) -> PortResult<()> {
        self.declassification_write(|state| state.begin_declassification_reconciliation())
    }

    fn end_declassification_reconciliation(&self) -> PortResult<()> {
        self.declassification_write(|state| state.end_declassification_reconciliation())
    }

    fn seal_declassification_live_dispatch(&self) -> PortResult<()> {
        self.declassification_write(|state| state.seal_declassification_live_dispatch())
    }

    fn commit_declassification_consumption_evidence(
        &self,
        request: &DeclassificationConsumptionEvidenceCommit,
    ) -> PortResult<DeclassificationConsume> {
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let (owner, consumed) = SecurityStateWriteTransaction::new(tx)?
            .commit_declassification_consumption_evidence(request, self.clock.as_ref())?;
        owner.into_transaction().commit().map_err(sqlite_error)?;
        Ok(consumed)
    }

    fn commit_declassification_outcome_evidence(
        &self,
        request: &DeclassificationOutcomeEvidenceCommit,
    ) -> PortResult<()> {
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let owner = SecurityStateWriteTransaction::new(tx)?
            .commit_declassification_outcome_evidence(request)?;
        owner.into_transaction().commit().map_err(sqlite_error)
    }

    fn load_declassification_use(
        &self,
        query: &DeclassificationUseQuery,
    ) -> PortResult<Option<DeclassificationUseRecord>> {
        self.declassification_read(|tx| records::load_use(ScopedReader::legacy(tx), query))
    }

    fn load_declassification_evidence(
        &self,
        query: &DeclassificationEvidenceQuery,
    ) -> PortResult<Option<DeclassificationEvidenceRecord>> {
        self.declassification_read(|tx| records::load_evidence(ScopedReader::legacy(tx), query))
    }

    fn load_pending_declassification_evidence(
        &self,
        query: &DeclassificationEvidencePendingQuery,
    ) -> PortResult<Vec<DeclassificationEvidenceRecord>> {
        self.declassification_read(|tx| {
            records::pending(
                ScopedReader::legacy(tx),
                Some(&query.tenant_id),
                Some(&query.grant_id),
                query.now_unix_ms,
                query.max_records,
            )
        })
    }

    fn load_pending_declassification_evidence_batch(
        &self,
        now_unix_ms: u64,
        max_records: u32,
    ) -> PortResult<Vec<DeclassificationEvidenceRecord>> {
        self.declassification_read(|tx| {
            records::pending(
                ScopedReader::legacy(tx),
                None,
                None,
                now_unix_ms,
                max_records,
            )
        })
    }

    fn load_stranded_declassification_consumptions_batch(
        &self,
        max_records: u32,
    ) -> PortResult<Vec<DeclassificationEvidenceRecord>> {
        self.declassification_read(|tx| outbox::stranded(ScopedReader::legacy(tx), max_records))
    }

    fn acknowledge_declassification_evidence(
        &self,
        request: &DeclassificationEvidenceAckRequest,
    ) -> PortResult<()> {
        self.declassification_write(|state| state.acknowledge_declassification_evidence(request))
    }

    fn record_declassification_evidence_retry(
        &self,
        request: &DeclassificationEvidenceRetryRequest,
    ) -> PortResult<DeclassificationEvidenceRecord> {
        self.declassification_write(|state| state.record_declassification_evidence_retry(request))
    }

    fn load_declassification_compaction_candidates(
        &self,
        query: &DeclassificationCompactionQuery,
    ) -> PortResult<Vec<DeclassificationCompactionCandidate>> {
        self.declassification_read(|tx| {
            validate_declassification_evidence_schema(tx)?;
            compaction::candidates(ScopedReader::legacy(tx), query)
        })
    }

    fn compact_declassification_evidence(
        &self,
        request: &DeclassificationCompactionRequest,
    ) -> PortResult<DeclassificationEvidenceTombstone> {
        self.declassification_write(|state| state.compact_declassification_evidence(request))
    }

    fn count_pending_declassification_evidence(&self) -> PortResult<u64> {
        self.declassification_read(|tx| outbox::count_pending(ScopedReader::legacy(tx)))
    }

    fn count_stranded_declassification_consumptions(&self) -> PortResult<u64> {
        self.declassification_read(|tx| outbox::count_stranded(ScopedReader::legacy(tx)))
    }
}
