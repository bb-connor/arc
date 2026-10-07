//! Cold activation records exact writer intervals, never unverified zero custody.
use super::*;
use crate::admission_operation_store::knowledge::references::PreparedNewArtifactReferenceBaseline;

#[derive(Serialize)]
enum ColdReceiptIdentity {
    KnowledgeReferenceBaseline,
}

struct ColdWriterReceipt<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    account: ReferenceAccount,
    before: GlobalHead,
    last: GlobalHead,
    commitment: String,
    mutations: u64,
    encoded_bytes: u64,
}

pub(in crate::admission_operation_store) struct VerifiedKnowledgeReferenceColdProgress<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    account: ReferenceAccount,
    before: GlobalHead,
    after: GlobalHead,
    commitment: String,
    mutations: u64,
    encoded_bytes: u64,
}

fn initial_commitment(
    account: &ReferenceAccount,
    before: &GlobalHead,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(sha256_hex(&encode(&(
        chio_core_types::recovery::RecoveryDigestDomain::ParticipantOwner.name(),
        ColdReceiptIdentity::KnowledgeReferenceBaseline,
        account,
        before.sequence,
        before.digest,
    ))?))
}

fn extend_commitment(
    previous: &str,
    source: &ProtectedSourceReference,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(sha256_hex(&encode(&(
        chio_core_types::recovery::RecoveryDigestDomain::ParticipantOwner.name(),
        ColdReceiptIdentity::KnowledgeReferenceBaseline,
        previous,
        source.record_key(),
        source.scope_key(),
        source.kind(),
        source.version(),
        source.digest(),
        source.event_sequence(),
        source.global_commit_sequence(),
    ))?))
}

impl<'tx, 'conn> ColdWriterReceipt<'tx, 'conn> {
    fn begin(
        tx: &'tx Transaction<'conn>,
        scope: &RecoveryScopeV1,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let before = global_head(tx)?;
        let account = ReferenceAccount::from_scope(scope);
        let commitment = initial_commitment(&account, &before)?;
        Ok(Self {
            transaction: tx,
            account,
            last: before.clone(),
            before,
            commitment,
            mutations: 0,
            encoded_bytes: 0,
        })
    }

    fn observe(
        &mut self,
        source: &ProtectedSourceReference,
        payload_bytes: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        verify_source_reference(self.transaction, source)?;
        let after = global_head(self.transaction)?;
        if self.last.sequence.checked_add(1) != Some(after.sequence)
            || source.global_commit_sequence() != after.sequence
        {
            return Err(invariant(
                "cold reference writer acquired unaccounted global work",
            ));
        }
        self.commitment = extend_commitment(&self.commitment, source)?;
        self.mutations = self
            .mutations
            .checked_add(1)
            .ok_or_else(|| invariant("cold reference mutation count overflow"))?;
        self.encoded_bytes = self
            .encoded_bytes
            .checked_add(payload_bytes)
            .ok_or_else(|| invariant("cold reference byte count overflow"))?;
        self.last = after;
        Ok(())
    }

    fn finish(
        self,
    ) -> Result<
        (
            VerifiedKnowledgeReferenceColdProgress<'tx, 'conn>,
            ProtectedMutationDelta,
        ),
        AdmissionOperationStoreError,
    > {
        if global_head(self.transaction)? != self.last {
            return Err(invariant(
                "cold reference writer changed before its receipt",
            ));
        }
        let delta = ProtectedMutationDelta {
            mutations: self.mutations,
            encoded_bytes: self.encoded_bytes,
        };
        let receipt = VerifiedKnowledgeReferenceColdProgress {
            transaction: self.transaction,
            account: self.account,
            before: self.before,
            after: self.last,
            commitment: self.commitment,
            mutations: self.mutations,
            encoded_bytes: self.encoded_bytes,
        };
        receipt.verify(receipt.transaction)?;
        Ok((receipt, delta))
    }
}

impl<'conn> VerifiedKnowledgeReferenceColdProgress<'_, 'conn> {
    pub(in crate::admission_operation_store) fn account_domain(&self) -> &AuthorityDomainId {
        &self.account.authority_domain
    }
    pub(in crate::admission_operation_store) fn account_tenant(&self) -> &RecoveryTenantId {
        &self.account.tenant_id
    }
    pub(in crate::admission_operation_store) fn before_sequence(&self) -> u64 {
        self.before.sequence
    }
    pub(in crate::admission_operation_store) fn before_chain_digest(&self) -> &[u8; 32] {
        &self.before.digest
    }
    pub(in crate::admission_operation_store) fn after_sequence(&self) -> u64 {
        self.after.sequence
    }
    pub(in crate::admission_operation_store) fn after_chain_digest(&self) -> &[u8; 32] {
        &self.after.digest
    }

    /// Every retained global entry must match a row actually written by this
    /// closed writer. The chain endpoints alone cannot establish that fact.
    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        same_writer(self.transaction, tx)?;
        if global_head(tx)? != self.after
            || self.before.sequence.checked_add(self.mutations) != Some(self.after.sequence)
        {
            return Err(invariant(
                "cold reference receipt no longer owns the exact head",
            ));
        }
        let before_digest: String = tx
            .query_row(
                "SELECT chain_digest FROM authority_global_commits WHERE commit_sequence=?1",
                [i64::try_from(self.before.sequence)
                    .map_err(|_| invariant("cold reference ordinal exhausted"))?],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if before_digest != hex::encode(self.before.digest) {
            return Err(invariant(
                "cold reference receipt lost its starting custody",
            ));
        }
        let mut commitment = initial_commitment(&self.account, &self.before)?;
        let mut mutations = 0_u64;
        let mut bytes = 0_u64;
        let mut statement = tx.prepare(
            "SELECT commit_sequence,projection_kind,projection_key,projection_sequence
             FROM authority_global_commits WHERE commit_sequence>?1 AND commit_sequence<=?2 ORDER BY commit_sequence",
        ).map_err(sqlite_error)?;
        let mut rows = statement
            .query(params![
                i64::try_from(self.before.sequence)
                    .map_err(|_| invariant("cold reference ordinal exhausted"))?,
                i64::try_from(self.after.sequence)
                    .map_err(|_| invariant("cold reference ordinal exhausted"))?,
            ])
            .map_err(sqlite_error)?;
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            let ordinal = stored_u64(
                row.get(0).map_err(sqlite_error)?,
                "cold reference global ordinal",
            )?;
            let kind: String = row.get(1).map_err(sqlite_error)?;
            let key: String = row.get(2).map_err(sqlite_error)?;
            let version = stored_u64(
                row.get(3).map_err(sqlite_error)?,
                "cold reference global version",
            )?;
            mutations = mutations
                .checked_add(1)
                .ok_or_else(|| invariant("cold reference count overflow"))?;
            if kind != "recovery" || self.before.sequence.checked_add(mutations) != Some(ordinal) {
                return Err(invariant(
                    "cold reference receipt contains foreign global work",
                ));
            }
            let source = source_reference(tx, &key)?;
            if source.version() != version || source.global_commit_sequence() != ordinal {
                return Err(invariant(
                    "cold reference receipt changed an exact written source",
                ));
            }
            let payload = raw_checked(tx, &key)?
                .ok_or_else(|| invariant("cold reference receipt row disappeared"))?;
            bytes = bytes
                .checked_add(
                    u64::try_from(payload.payload.len())
                        .map_err(|_| invariant("cold reference bytes overflow"))?,
                )
                .ok_or_else(|| invariant("cold reference bytes overflow"))?;
            commitment = extend_commitment(&commitment, &source)?;
        }
        if mutations != self.mutations
            || bytes != self.encoded_bytes
            || commitment != self.commitment
        {
            return Err(invariant(
                "cold reference receipt changed its verified footprint",
            ));
        }
        Ok(())
    }
}

pub(in crate::admission_operation_store) fn initialize_knowledge_reference_account<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    owner: &SqliteServingOwner,
    proof: VerifiedKnowledgeReferenceAccountBaseline<'tx, 'conn>,
) -> Result<
    (
        VerifiedKnowledgeReferenceAccountBaseline<'tx, 'conn>,
        VerifiedKnowledgeReferenceColdProgress<'tx, 'conn>,
        ProtectedMutationDelta,
    ),
    AdmissionOperationStoreError,
> {
    require_reference_format(tx)?;
    same_writer(proof.transaction(), tx)?;
    crate::admission_operation_store::schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
    proof.verify(tx)?;
    let head = global_head(tx)?;
    if proof.scope().authority_domain.as_str() != owner.fence.store_uuid
        || head.sequence != proof.global_cutoff().sequence()
        || &head.digest != proof.global_cutoff().chain_digest()
        || raw_checked(
            tx,
            &ReferenceAccount::from_scope(proof.scope()).ready_key()?,
        )?
        .is_some()
    {
        return Err(invariant(
            "reference account preflight changed before its first write",
        ));
    }
    crate::admission_operation_store::recovery::resources::check_intake_committing(tx)?;
    let account = ReferenceCapacity::from_baseline(&proof);
    let mut receipt = ColdWriterReceipt::begin(tx, proof.scope())?;
    let (source, bytes) = save_capacity(tx, owner, proof.scope(), &account, None)?;
    receipt.observe(&source, bytes)?;
    let (receipt, delta) = receipt.finish()?;
    Ok((proof, receipt, delta))
}

pub(in crate::admission_operation_store) fn persist_knowledge_reference_cold_baseline<
    'tx,
    'conn,
>(
    tx: &'tx Transaction<'conn>,
    owner: &SqliteServingOwner,
    plan: PreparedColdReferenceBaseline<'tx, 'conn>,
) -> Result<
    (
        VerifiedKnowledgeReferenceColdProgress<'tx, 'conn>,
        ProtectedMutationDelta,
    ),
    AdmissionOperationStoreError,
> {
    require_reference_format(tx)?;
    same_writer(plan.transaction(), tx)?;
    crate::admission_operation_store::schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
    plan.verify_current(tx)?;
    let scope = &plan.reference().scope;
    let (account, _) = load_capacity(tx, scope)?;
    if account.cutoff() != plan.global_cutoff()
        || account.cohort_digest() != &plan.cohort_digest()
        || raw_checked(tx, &ReferenceAccount::from_scope(scope).ready_key()?)?.is_some()
    {
        return Err(invariant("cold reference plan changed its pending account"));
    }
    let footprint = plan.write_footprint();
    if footprint.record_count() != footprint.event_count() {
        return Err(invariant("cold reference plan changed its event footprint"));
    }
    crate::admission_operation_store::recovery::resources::check_intake_committing(tx)?;
    let mut receipt = ColdWriterReceipt::begin(tx, scope)?;
    plan.visit_staged_updates(tx, |write| {
        if write.expected_version().is_some()
            || write.version() != 1
            || write.scope() != scope_key(scope)?
        {
            return Err(invariant(
                "cold reference plan changed an immutable initial row",
            ));
        }
        let source = persist_update(tx, owner, write, MAX_RECOVERY_RECORD_BYTES)?;
        receipt.observe(
            &source,
            u64::try_from(write.payload().len())
                .map_err(|_| invariant("cold reference byte count overflow"))?,
        )
    })?;
    let (receipt, delta) = receipt.finish()?;
    if delta.mutations != footprint.record_count()
        || delta.encoded_bytes != footprint.encoded_bytes()
    {
        return Err(invariant(
            "cold reference writer changed its complete staged inventory",
        ));
    }
    Ok((receipt, delta))
}

pub(in crate::admission_operation_store) fn persist_knowledge_reference_ready<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    owner: &SqliteServingOwner,
    proof: VerifiedKnowledgeReferenceReady<'tx, 'conn>,
) -> Result<(ProtectedSourceReference, ProtectedMutationDelta), AdmissionOperationStoreError> {
    require_reference_format(tx)?;
    same_writer(proof.transaction(), tx)?;
    proof.verify(tx, owner)?;
    let record = proof.record();
    let (account, _) = load_capacity_account(tx, &record.account)?;
    if !account.matches_ready_record(record) {
        return Err(invariant(
            "reference readiness changed its authenticated account baseline",
        ));
    }
    let scope = record.account.scope_key()?;
    let key = record.account.ready_key()?;
    let bytes = encode(record)?;
    if bytes.len() > ACCOUNT_RECORD_BYTES || raw_checked(tx, &key)?.is_some() {
        return Err(invariant(
            "reference ready marker is not a bounded fresh identity",
        ));
    }
    crate::admission_operation_store::recovery::resources::check_intake_committing(tx)?;
    let before = global_head(tx)?;
    persist_record(tx, owner, &key, &scope, "command", &bytes, None)?;
    let source = source_reference(tx, &key)?;
    let after = global_head(tx)?;
    if source.version() != 1
        || source.global_commit_sequence() != after.sequence
        || before.sequence.checked_add(1) != Some(after.sequence)
    {
        return Err(invariant(
            "reference readiness writer changed its exact footprint",
        ));
    }
    Ok((
        source,
        ProtectedMutationDelta {
            mutations: 1,
            encoded_bytes: u64::try_from(bytes.len())
                .map_err(|_| invariant("reference ready byte count overflow"))?,
        },
    ))
}

/// The authenticated MetadataCommitted phase is still reversible. This fresh
/// logical initialization must finish before the publication becomes Available.
pub(in crate::admission_operation_store) fn persist_knowledge_new_artifact_reference_baseline<
    'tx,
    'conn,
>(
    tx: &'tx Transaction<'conn>,
    owner: &SqliteServingOwner,
    plan: PreparedNewArtifactReferenceBaseline<'tx, 'conn>,
) -> Result<(ProtectedSourceReference, ProtectedMutationDelta), AdmissionOperationStoreError> {
    require_reference_format(tx)?;
    same_writer(plan.transaction(), tx)?;
    crate::admission_operation_store::schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
    plan.verify_current(tx)?;
    require_ready_capacity(tx, &plan.reference().scope)?;
    let write = plan.staged_update();
    if write.key() != aggregate_key(reference_identity(plan.reference())?)
        || write.scope() != scope_key(&plan.reference().scope)?
        || write.expected_version().is_some()
        || write.version() != 1
    {
        return Err(invariant(
            "new artifact baseline changed its exact zero initializer",
        ));
    }
    crate::admission_operation_store::recovery::resources::check_intake_committing(tx)?;
    let before = global_head(tx)?;
    let source = persist_update(tx, owner, write, ORDINARY_REFERENCE_BYTES)?;
    let after = global_head(tx)?;
    if before.sequence.checked_add(1) != Some(after.sequence)
        || source.global_commit_sequence() != after.sequence
    {
        return Err(invariant(
            "new artifact baseline changed its exact write footprint",
        ));
    }
    Ok((
        source,
        ProtectedMutationDelta {
            mutations: 1,
            encoded_bytes: u64::try_from(write.payload().len())
                .map_err(|_| invariant("reference baseline byte count overflow"))?,
        },
    ))
}
