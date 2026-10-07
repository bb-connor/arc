//! Exact Unknown+Incident provenance is data, not effect or delivery authority.
use super::*;
use chio_kernel::admission_operation::{
    NativeSecurityAuthorityBindingV1, RetainedToolAdmissionRequestV1,
};
use chio_security_types::ports::FlowStateKey;

/// Minted only by a fenced native-store transaction after authenticating actual
/// physical capture and terminal Incident custody. This never attests returned
/// tool bytes, certain finality, retry permission or current disclosure.
pub(in crate::admission_operation_store) struct AuthenticatedNativeStatusSource<'tx, 'conn> {
    tx: &'tx Transaction<'conn>,
    store: &'tx SqliteAdmissionOperationStore,
    trusted_now_unix_ms: u64,
    origin: crate::serving_owner::NativeSourceTransactionOrigin<'tx>,
    identity: StatusIdentity,
}

struct StatusIdentity {
    operation: AdmissionOperationV1,
    original: RetainedToolAdmissionRequestV1,
    binding: NativeSecurityAuthorityBindingV1,
    key: FlowStateKey,
    incident_id: AdmissionIdentifier,
    projection_digest: AdmissionDigest,
    global_commit_sequence: u64,
    capture_global_commit_sequence: u64,
    terminal_committed_at_unix_ms: u64,
}

impl<'tx, 'conn> AuthenticatedNativeStatusSource<'tx, 'conn> {
    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        // Transaction wrappers may move. The underlying live Connection is the
        // physical identity, and the borrow prevents this source outliving it.
        if !std::ptr::eq(&**self.tx, &**tx) {
            return Err(invariant("native status source changed its transaction"));
        }
        self.origin.verify(tx).map_err(map_owner_error)?;
        if !self.origin.matches_owner(&self.store.serving_owner) {
            return Err(invariant(
                "native status changed its transaction source owner",
            ));
        }
        let current = load_status_identity(
            tx,
            self.store,
            self.operation().binding().operation_id(),
            self.trusted_now_unix_ms,
        )?;
        if current.operation.to_persisted() != self.identity.operation.to_persisted()
            || current.original.canonical_bytes() != self.identity.original.canonical_bytes()
            || current.binding != self.identity.binding
            || current.key != self.identity.key
            || current.incident_id != self.identity.incident_id
            || current.projection_digest != self.identity.projection_digest
            || current.global_commit_sequence != self.identity.global_commit_sequence
            || current.capture_global_commit_sequence
                != self.identity.capture_global_commit_sequence
            || current.terminal_committed_at_unix_ms != self.identity.terminal_committed_at_unix_ms
        {
            return Err(invariant(
                "native status source changed its immutable custody",
            ));
        }
        Ok(())
    }
    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.tx
    }
    pub(in crate::admission_operation_store) fn operation(&self) -> &AdmissionOperationV1 {
        &self.identity.operation
    }
    pub(in crate::admission_operation_store) fn original(&self) -> &RetainedToolAdmissionRequestV1 {
        &self.identity.original
    }
    pub(in crate::admission_operation_store) fn native_binding(
        &self,
    ) -> &NativeSecurityAuthorityBindingV1 {
        &self.identity.binding
    }
    pub(in crate::admission_operation_store) fn key(&self) -> &FlowStateKey {
        &self.identity.key
    }
    pub(in crate::admission_operation_store) fn authority(&self) -> &str {
        self.identity.binding.security_authority_id().as_str()
    }
    pub(in crate::admission_operation_store) fn serving_domain(&self) -> &str {
        self.identity.binding.store_uuid().as_str()
    }
    pub(in crate::admission_operation_store) fn terminal_version(&self) -> u64 {
        self.identity.operation.version()
    }
    pub(in crate::admission_operation_store) fn incident_id(&self) -> &AdmissionIdentifier {
        &self.identity.incident_id
    }
    pub(in crate::admission_operation_store) fn projection_digest(&self) -> &AdmissionDigest {
        &self.identity.projection_digest
    }
    pub(in crate::admission_operation_store) fn global_commit_sequence(&self) -> u64 {
        self.identity.global_commit_sequence
    }
    pub(in crate::admission_operation_store) fn capture_global_commit_sequence(&self) -> u64 {
        self.identity.capture_global_commit_sequence
    }
    pub(in crate::admission_operation_store) fn terminal_committed_at_unix_ms(&self) -> u64 {
        self.identity.terminal_committed_at_unix_ms
    }
}

/// The operation selector locates data only. No caller can construct the affine
/// result, select a protected mutation purpose, or spend a finishing allowance.
pub(in crate::admission_operation_store) fn authenticate_historical_native_status_source<
    'tx,
    'conn,
>(
    tx: &'tx Transaction<'conn>,
    store: &'tx SqliteAdmissionOperationStore,
    origin: &crate::serving_owner::NativeSourceTransactionOrigin<'tx>,
    operation_id: &AdmissionOperationId,
    trusted_now_unix_ms: u64,
) -> Result<AuthenticatedNativeStatusSource<'tx, 'conn>, AdmissionOperationStoreError> {
    origin.verify(tx).map_err(map_owner_error)?;
    if !origin.matches_owner(&store.serving_owner) {
        return Err(invariant(
            "native status source owner differs from anchored transaction",
        ));
    }
    let identity = load_status_identity(tx, store, operation_id, trusted_now_unix_ms)?;
    Ok(AuthenticatedNativeStatusSource {
        tx,
        store,
        trusted_now_unix_ms,
        origin: origin.fork_for_source(),
        identity,
    })
}

fn load_status_identity(
    tx: &Transaction<'_>,
    store: &SqliteAdmissionOperationStore,
    operation_id: &AdmissionOperationId,
    now: u64,
) -> Result<StatusIdentity, AdmissionOperationStoreError> {
    verify_active_owner(tx, &store.serving_owner, Some(&store.serving_owner.fence))?;
    super::super::schema::authority_validation_time(tx, now)?;
    let stored = load_by_operation_id_tx(tx, operation_id)?
        .ok_or_else(|| invariant("native status operation absent"))?;
    stored.verify_decision_time(now)?;
    let operation = stored.operation;
    if operation.state() != AdmissionOperationState::OutcomeUnknownAfterDispatch
        || operation.dispatch_commit().is_none()
        || operation.native_dispatch_ledger_digest().is_none()
    {
        return Err(invariant("native status requires captured unknown custody"));
    }
    let Some(AdmissionTerminalReplay::Incident {
        incident_id,
        projection_digest,
    }) = operation.terminal_replay()
    else {
        return Err(invariant(
            "native status requires terminal Incident custody",
        ));
    };
    let incident_id = incident_id.clone();
    let projection_digest = projection_digest.clone();
    let original = retained_request::load_retained_request_tx(tx, &operation)?
        .ok_or_else(|| invariant("native status original request absent"))?;
    let binding = original
        .native_security_authority_binding()
        .ok_or_else(|| invariant("native status original authority absent"))?
        .clone();
    if binding.store_uuid().as_str() != store.serving_owner.fence.store_uuid {
        return Err(invariant("native status changed its serving domain"));
    }
    let key = super::super::security_participant_state::dispatch_ledger::authenticated_status_key(
        tx, &operation, &original, &binding,
    )?;
    let physical = store
        .native_capture_tx(tx, operation_id, now)?
        .ok_or_else(|| invariant("native status physical capture absent"))?;
    let chio_kernel::budget_store::BudgetInvocationCaptureDecision::Captured(decision) =
        &physical.decision
    else {
        return Err(invariant(
            "native status lost its captured budget participant",
        ));
    };
    if physical.operation.to_persisted() != operation.to_persisted() {
        return Err(invariant(
            "native status capture changed its exact operation",
        ));
    }
    // load_by_operation_id_tx already verified the full canonical terminal
    // manifest, all bounded records, lease/participant/obligation/credit joins.
    let projection = load_terminal_projection_tx(tx, operation_id)?
        .ok_or_else(|| invariant("native status terminal projection absent"))?;
    let body: StoredTerminalProjectionBody = serde_json::from_slice(&projection.projection_json)
        .map_err(|_| invariant("native status terminal context invalid"))?;
    let context = body.context;
    if context.operation_id != *operation_id
        || context.request_id != *operation.binding().request_id()
        || context.coordinator_lease_epoch != operation.coordinator_lease_epoch()
        || context.store_fence.store_uuid != binding.store_uuid().as_str()
        || context.store_fence.store_uuid != projection.store_uuid
        || context.trusted_time_unix_ms > stored.updated_at_unix_ms
        || stored_u64(projection.committed_at_unix_ms, "native_status_apply_time")?
            != stored.updated_at_unix_ms
        || stored_u64(
            projection.terminal_operation_version,
            "native_status_version",
        )? != operation.version()
        || context.expected_operation_version.checked_add(1) != Some(operation.version())
    {
        return Err(invariant("native status terminal identity differs"));
    }
    let terminal_committed_at_unix_ms = stored.updated_at_unix_ms;
    let apply_fence = StoreMutationFence {
        store_uuid: projection.store_uuid.clone(),
        lease_id: projection.store_lease_id.clone(),
        owner_epoch: stored_u64(projection.store_owner_epoch, "native_status_owner_epoch")?,
    };
    let global_commit_sequence = exact_admission_global_reference(
        tx,
        &operation,
        operation.version(),
        &apply_fence,
        terminal_committed_at_unix_ms,
    )?;
    let capture_global_commit_sequence = exact_capture_global_reference(tx, &operation, decision)?;
    if capture_global_commit_sequence >= global_commit_sequence {
        return Err(invariant(
            "native status precedes its original physical capture",
        ));
    }
    Ok(StatusIdentity {
        operation,
        original,
        binding,
        key,
        incident_id,
        projection_digest,
        global_commit_sequence,
        capture_global_commit_sequence,
        terminal_committed_at_unix_ms,
    })
}

fn exact_admission_global_reference(
    tx: &Connection,
    operation: &AdmissionOperationV1,
    version: u64,
    fence: &StoreMutationFence,
    committed_at: u64,
) -> Result<u64, AdmissionOperationStoreError> {
    let mut statement = tx.prepare("SELECT global.commit_sequence FROM admission_operation_commits AS admission
        JOIN authority_global_commits AS global ON global.projection_kind='admission'
         AND global.projection_key=admission.operation_id AND global.projection_sequence=admission.commit_sequence
         AND global.projection_reference_digest=admission.chain_digest AND global.mutation_kind=admission.mutation_kind
         AND global.store_uuid=admission.store_uuid AND global.store_lease_id=admission.store_lease_id
         AND global.store_owner_epoch=admission.store_owner_epoch
        WHERE admission.operation_id=?1 AND admission.operation_version=?2 AND admission.mutation_kind='compare_and_swap'
          AND admission.operation_digest=?3 AND admission.store_uuid=?4 AND admission.store_lease_id=?5
          AND admission.store_owner_epoch=?6 AND admission.recorded_at_unix_ms=?7 LIMIT 2").map_err(sqlite_error)?;
    let mut rows = statement
        .query(params![
            operation.binding().operation_id().as_str(),
            sqlite_i64(version, "status_version")?,
            sha256_hex(&encode_operation(operation)?),
            &fence.store_uuid,
            &fence.lease_id,
            sqlite_i64(fence.owner_epoch, "status_owner_epoch")?,
            sqlite_i64(committed_at, "status_time")?
        ])
        .map_err(sqlite_error)?;
    unique_positive_global_sequence(&mut rows)
}

fn exact_capture_global_reference(
    tx: &Connection,
    operation: &AdmissionOperationV1,
    decision: &chio_kernel::budget_store::BudgetHoldMutationDecision,
) -> Result<u64, AdmissionOperationStoreError> {
    let dispatch = operation
        .dispatch_commit()
        .ok_or_else(|| invariant("native status dispatch absent"))?;
    let mut statement = tx.prepare("SELECT authority.commit_sequence FROM admission_operation_commits AS admission
        JOIN authority_global_commits AS budget ON budget.projection_kind='budget'
         AND budget.projection_reference_digest=admission.participant_digest AND budget.mutation_kind='capture_invocation'
         AND budget.store_uuid=admission.store_uuid AND budget.store_lease_id=admission.store_lease_id
         AND budget.store_owner_epoch=admission.store_owner_epoch
        JOIN authority_global_commits AS authority ON authority.projection_kind='admission'
         AND authority.projection_key=admission.operation_id AND authority.projection_sequence=admission.commit_sequence
         AND authority.projection_reference_digest=admission.chain_digest AND authority.mutation_kind=admission.mutation_kind
         AND authority.store_uuid=admission.store_uuid AND authority.store_lease_id=admission.store_lease_id
         AND authority.store_owner_epoch=admission.store_owner_epoch
        WHERE admission.operation_id=?1 AND admission.operation_version=?2 AND admission.mutation_kind='compare_and_swap'
          AND budget.projection_key=?3 AND budget.projection_sequence=?4
          AND admission.store_uuid=?5 AND admission.store_lease_id=?6 AND admission.store_owner_epoch=?7
          AND authority.commit_sequence>budget.commit_sequence LIMIT 2").map_err(sqlite_error)?;
    let mut rows = statement
        .query(params![
            operation.binding().operation_id().as_str(),
            sqlite_i64(dispatch.committed_version, "status_capture_version")?,
            decision.metadata.event_id.as_deref(),
            decision
                .metadata
                .budget_commit_index
                .map(|v| sqlite_i64(v, "status_capture_sequence"))
                .transpose()?,
            &dispatch.store_fence.store_uuid,
            &dispatch.store_fence.lease_id,
            sqlite_i64(dispatch.store_fence.owner_epoch, "status_capture_epoch")?
        ])
        .map_err(sqlite_error)?;
    unique_positive_global_sequence(&mut rows)
}

fn unique_positive_global_sequence(
    rows: &mut rusqlite::Rows<'_>,
) -> Result<u64, AdmissionOperationStoreError> {
    let row = rows
        .next()
        .map_err(sqlite_error)?
        .ok_or_else(|| invariant("native status global reference absent"))?;
    let sequence: i64 = row.get(0).map_err(sqlite_error)?;
    let sequence = stored_u64(sequence, "native_status_global_sequence")?;
    if sequence == 0
        || sequence > 9_007_199_254_740_991
        || rows.next().map_err(sqlite_error)?.is_some()
    {
        return Err(invariant(
            "native status global reference ambiguous or invalid",
        ));
    }
    Ok(sequence)
}

/// Fresh owning terminal append plus authenticated classification data. No
/// finishing allowance, effect certainty or native output closure is implied.
pub(in crate::admission_operation_store) struct AuthenticatedNativeStatusAppend<'tx, 'conn> {
    source: AuthenticatedNativeStatusSource<'tx, 'conn>,
    append: super::super::commit_chain::AdmissionCommitAppendReceipt,
}
impl<'tx, 'conn> AuthenticatedNativeStatusAppend<'tx, 'conn> {
    pub(in crate::admission_operation_store) fn source(
        &self,
    ) -> &AuthenticatedNativeStatusSource<'tx, 'conn> {
        &self.source
    }
    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.source.verify(tx)?;
        self.append.verify(tx, &self.source.store.serving_owner)?;
        if self.append.operation().to_persisted() != self.source.operation().to_persisted()
            || self.append.global_sequence() != self.source.global_commit_sequence()
            || self.append.recorded_at_unix_ms() != self.source.terminal_committed_at_unix_ms()
            || self.append.global_sequence() <= self.source.origin.prepared_global_sequence()
        {
            return Err(invariant(
                "native status append changed its exact fresh source",
            ));
        }
        Ok(())
    }
}

/// Called only with the private receipt returned by the actual fresh terminal
/// writer. Exact terminal replay and historical loading cannot mint it.
pub(in crate::admission_operation_store) fn authenticate_native_status_append<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    store: &'tx SqliteAdmissionOperationStore,
    origin: &crate::serving_owner::NativeSourceTransactionOrigin<'tx>,
    append: super::super::commit_chain::AdmissionCommitAppendReceipt,
) -> Result<AuthenticatedNativeStatusAppend<'tx, 'conn>, AdmissionOperationStoreError> {
    origin.verify(tx).map_err(map_owner_error)?;
    append.verify(tx, &store.serving_owner)?;
    let operation_id = append.operation().binding().operation_id().clone();
    let source = authenticate_historical_native_status_source(
        tx,
        store,
        origin,
        &operation_id,
        append.recorded_at_unix_ms(),
    )?;
    let result = AuthenticatedNativeStatusAppend { source, append };
    result.verify(tx)?;
    Ok(result)
}

/// Actual terminal writers authenticate an Unknown native append before their
/// commit. Classification remains separate data and is never a current
/// audience/annotation prerequisite for already owed terminal fate.
pub(in crate::admission_operation_store) fn verify_native_status_terminal_append(
    tx: &Transaction<'_>,
    store: &SqliteAdmissionOperationStore,
    origin: &crate::serving_owner::NativeSourceTransactionOrigin<'_>,
    append: super::super::commit_chain::AdmissionCommitAppendReceipt,
) -> Result<(), AdmissionOperationStoreError> {
    if append.operation().state() != AdmissionOperationState::OutcomeUnknownAfterDispatch
        || append.operation().native_dispatch_ledger_digest().is_none()
    {
        return Ok(());
    }
    let status = authenticate_native_status_append(tx, store, origin, append)?;
    status.verify(tx)?;
    status.source().verify(tx)
}
