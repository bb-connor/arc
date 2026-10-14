//! The actual admission lease owns a monotone native flow mutation.
use super::*;
use chio_kernel::SecurityInvocationContext;
use chio_security_types::ports::{BoundedVec, FlowJoinRequest, FlowStateSnapshot};

#[path = "mutations/command.rs"]
mod command;
use command::Command;

/// Default-off lost-acknowledgement fixture for exactly one classified Input
/// join of one store. The first real write commits durably and its
/// acknowledgement is discarded; the same legitimate classification then
/// retries the real writer before the kernel consumes any result. No
/// production path can select this and request bytes cannot arm it.
#[cfg(feature = "admission-test-support")]
mod lost_ack_classified_retry {
    use super::*;
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex, OnceLock},
    };

    /// The recorded outcomes of one armed lost-acknowledgement retry.
    #[derive(Clone, Default)]
    pub(super) struct LostAckRecord {
        pub(super) consumed: bool,
        pub(super) first_refused: bool,
        pub(super) replay_refused: bool,
        pub(super) first_fate: Option<chio_kernel::admission_operation::NativeSecurityInputFateV1>,
        pub(super) replay_fate: Option<chio_kernel::admission_operation::NativeSecurityInputFateV1>,
        pub(super) first: Option<LostAckObservation>,
        pub(super) replay: Option<LostAckObservation>,
    }

    /// Test-only observation of one committed classified join: the exact
    /// retained native record bytes and the global journal commit count.
    #[derive(Clone)]
    pub(super) struct LostAckObservation {
        pub(super) record_bytes: Vec<u8>,
        pub(super) global_commits: i64,
    }

    type Shared = Arc<Mutex<LostAckRecord>>;

    fn armed() -> &'static Mutex<BTreeMap<String, Shared>> {
        static ARMED: OnceLock<Mutex<BTreeMap<String, Shared>>> = OnceLock::new();
        ARMED.get_or_init(|| Mutex::new(BTreeMap::new()))
    }

    pub(super) fn arm(store_uuid: &str) -> Result<(), AdmissionOperationStoreError> {
        let mut armed = armed()
            .lock()
            .map_err(|_| invalid("lost-ack retry fixture registry unavailable"))?;
        if armed.contains_key(store_uuid) {
            return Err(invalid("lost-ack retry fixture already armed"));
        }
        armed.insert(
            store_uuid.to_owned(),
            Arc::new(Mutex::new(LostAckRecord::default())),
        );
        Ok(())
    }

    /// Consumes the one armed retry, if any. The consumed flag keeps the
    /// retry's own second call on the ordinary single-call path.
    pub(super) fn take(store_uuid: &str) -> Option<Shared> {
        let shared = armed().lock().ok()?.get(store_uuid)?.clone();
        {
            let mut record = shared.lock().ok()?;
            if record.consumed {
                return None;
            }
            record.consumed = true;
        }
        Some(shared)
    }

    /// Records the discarded first acknowledgement of the armed retry, with
    /// the retained native record bytes and global journal state captured
    /// immediately after its real committed join.
    pub(super) fn record_first(
        shared: &Shared,
        refused: bool,
        fate: chio_kernel::admission_operation::NativeSecurityInputFateV1,
        observed: LostAckObservation,
    ) {
        if let Ok(mut record) = shared.lock() {
            record.first_refused = refused;
            record.first_fate = Some(fate);
            record.first = Some(observed);
        }
    }

    /// Records the retried classification the kernel will consume, with the
    /// same observation captured immediately after the replay.
    pub(super) fn record_replay(
        shared: &Shared,
        refused: bool,
        fate: chio_kernel::admission_operation::NativeSecurityInputFateV1,
        observed: LostAckObservation,
    ) {
        if let Ok(mut record) = shared.lock() {
            record.replay_refused = refused;
            record.replay_fate = Some(fate);
            record.replay = Some(observed);
        }
    }

    /// The committed native record bytes for this operation plus the number
    /// of global journal commits, read immediately after a committed join.
    /// Observation only: it grants no custody and writes nothing.
    pub(super) fn observe(
        store: &SqliteAdmissionOperationStore,
        operation: &str,
    ) -> Result<LostAckObservation, AdmissionOperationStoreError> {
        let connection = store.connection()?;
        let record_bytes: Vec<u8> = connection
            .query_row(
                "SELECT canonical_record FROM security_participant_state_mutations
                 WHERE operation_id = ?1",
                params![operation],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        let global_commits: i64 = connection
            .query_row("SELECT COUNT(*) FROM authority_global_commits", [], |row| {
                row.get(0)
            })
            .map_err(sqlite_error)?;
        Ok(LostAckObservation {
            record_bytes,
            global_commits,
        })
    }

    pub(super) fn read(store_uuid: &str) -> Option<LostAckRecord> {
        let shared = armed().lock().ok()?.get(store_uuid)?.clone();
        Some(
            shared
                .lock()
                .ok()
                .map(|record| record.clone())
                .unwrap_or_default(),
        )
    }
}

#[cfg(feature = "admission-test-support")]
pub use record_clock_inversion::RecordClockInversionObservation;

/// Default-off, one-shot fixture for exactly one refused classified Input
/// join of one store. It places the record's observation before the origin's
/// own observation, the relation a clock step backwards between the two real
/// observations produces, and records what the writer's post-append full
/// validation then decided for that same write. Everything else is the real
/// writer; no production path can select it and request bytes cannot arm it.
#[cfg(feature = "admission-test-support")]
mod record_clock_inversion {
    use super::*;
    use std::{
        collections::BTreeMap,
        sync::{Mutex, OnceLock},
    };

    /// What the post-append validation decided for the inverted write.
    /// `structure_valid` is the structural and lease phase alone; a write
    /// whose full validation refused while its structure held was refused by
    /// the cold origin phase and by nothing earlier.
    #[derive(Clone, Copy, Debug)]
    pub struct RecordClockInversionObservation {
        pub origin_observed_at: u64,
        pub record_observed_at: u64,
        pub structure_valid: bool,
        pub retained_valid: bool,
    }

    #[derive(Clone, Copy)]
    struct Inversion {
        origin_observed_at: u64,
        record_observed_at: u64,
        validation: Option<(bool, bool)>,
    }

    /// `None` while armed and waiting, `Some` once a refused write used it.
    fn stores() -> &'static Mutex<BTreeMap<String, Option<Inversion>>> {
        static STORES: OnceLock<Mutex<BTreeMap<String, Option<Inversion>>>> = OnceLock::new();
        STORES.get_or_init(|| Mutex::new(BTreeMap::new()))
    }

    pub(super) fn arm(store_uuid: &str) -> Result<(), AdmissionOperationStoreError> {
        let mut stores = stores()
            .lock()
            .map_err(|_| invalid("record clock inversion registry unavailable"))?;
        if stores.contains_key(store_uuid) {
            return Err(invalid("record clock inversion already armed"));
        }
        stores.insert(store_uuid.to_owned(), None);
        Ok(())
    }

    /// The record observation for a refused write: one millisecond before the
    /// origin observation, once. `None` leaves the real observation unchanged.
    pub(super) fn take(store_uuid: &str, origin_observed_at: u64) -> Option<u64> {
        let mut stores = stores().lock().ok()?;
        let slot = stores.get_mut(store_uuid)?;
        if slot.is_some() {
            return None;
        }
        let record_observed_at = origin_observed_at.checked_sub(1)?;
        *slot = Some(Inversion {
            origin_observed_at,
            record_observed_at,
            validation: None,
        });
        Some(record_observed_at)
    }

    /// Records the decision of the post-append validation for the inverted
    /// write only, identified by its record observation. `full_valid` is the
    /// unconditional production call's result; the structure phase is
    /// evaluated again here, for observation only.
    pub(super) fn observe_validation(
        store_uuid: &str,
        record: &history::Record,
        tx: &rusqlite::Transaction<'_>,
        full_valid: bool,
    ) {
        let awaiting = |stores: &BTreeMap<String, Option<Inversion>>| {
            stores
                .get(store_uuid)
                .copied()
                .flatten()
                .is_some_and(|inversion| {
                    inversion.validation.is_none()
                        && inversion.record_observed_at == record.observed_at
                })
        };
        if !stores().lock().is_ok_and(|stores| awaiting(&stores)) {
            return;
        }
        let structure_valid = record.validate_structure(tx).is_ok();
        if let Ok(mut stores) = stores().lock() {
            if awaiting(&stores) {
                if let Some(Some(inversion)) = stores.get_mut(store_uuid) {
                    inversion.validation = Some((structure_valid, full_valid));
                }
            }
        }
    }

    pub(super) fn observed(store_uuid: &str) -> Option<RecordClockInversionObservation> {
        let stores = stores().lock().ok()?;
        let inversion = (*stores.get(store_uuid)?)?;
        let (structure_valid, retained_valid) = inversion.validation?;
        Some(RecordClockInversionObservation {
            origin_observed_at: inversion.origin_observed_at,
            record_observed_at: inversion.record_observed_at,
            structure_valid,
            retained_valid,
        })
    }

    pub(super) fn applied(store_uuid: &str) -> bool {
        stores()
            .lock()
            .ok()
            .and_then(|stores| stores.get(store_uuid).copied())
            .is_some_and(|slot| slot.is_some())
    }
}

/// Borrowed original admission context shared by raw and classified flow joins.
struct NativeFlowJoinContext<'a> {
    operation: &'a AdmissionOperationV1,
    lease: &'a AdmissionRecoveryLease,
    initialized: &'a SecurityParticipantStateInitialization,
    context: &'a SecurityInvocationContext,
    trusted_now_unix_ms: u64,
}

struct JoinedNativeCommand {
    record: history::Record,
    refused: bool,
}

/// Affine, crate-private authority created only inside the verified admission
/// transaction. Inspection, serialized history and raw SQL handles cannot mint
/// it. It authorizes this monotone join, never external execution.
pub(crate) struct NativeFlowJoinAuthority {
    authority: AdmissionIdentifier,
    request: FlowJoinRequest,
}

impl NativeFlowJoinAuthority {
    pub(crate) fn authority(&self) -> &str {
        self.authority.as_str()
    }
    pub(crate) fn request(&self) -> &FlowJoinRequest {
        &self.request
    }
}

pub(super) fn require_request(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    context: &SecurityInvocationContext,
    key: &chio_security_types::ports::FlowStateKey,
) -> Result<
    chio_kernel::admission_operation::RetainedToolAdmissionRequestV1,
    AdmissionOperationStoreError,
> {
    operation.validate()?;
    if operation.state() != AdmissionOperationState::BrokerAttemptRegistered
        || operation.dispatch_commit().is_some()
    {
        return Err(invalid(
            "native flow join requires original pre-budget dispatch preparation",
        ));
    }
    let original = super::super::retained_request::load_retained_request_tx(connection, operation)?
        .ok_or_else(|| invalid("native mutation requires the original retained request"))?;
    original.validate_native_security_context(context)?;
    let context = context.as_v1();
    if &key.tenant_id != context.tenant_id()
        || &key.principal_id != context.principal_id()
        || &key.session_id != context.session_id()
        || &key.lineage_id != context.lineage_root_id()
        || &key.isolation_epoch_id != context.isolation_epoch_id()
    {
        return Err(invalid(
            "native flow key differs from the original security identity",
        ));
    }
    Ok(original)
}

impl SqliteAdmissionOperationStore {
    /// Join native labels under the actual current operation/recovery lease.
    /// The trusted host must select the initialized authority independently of
    /// agent metadata, and bind it at original admission before the first join.
    /// This does not activate dispatch, acquire an egress fence,
    /// consume declassification, or release any imported historical obligation.
    /// One immutable join is allowed per operation. Retries return the recorded
    /// result, not a fresh flow observation or an execution permit.
    pub fn join_security_participant_flow(
        &self,
        operation: &AdmissionOperationV1,
        lease: &AdmissionRecoveryLease,
        initialized: &SecurityParticipantStateInitialization,
        context: &SecurityInvocationContext,
        request: &FlowJoinRequest,
        trusted_now_unix_ms: u64,
    ) -> Result<FlowStateSnapshot, AdmissionOperationStoreError> {
        self.join_native_command(
            NativeFlowJoinContext {
                operation,
                lease,
                initialized,
                context,
                trusted_now_unix_ms,
            },
            Command::Raw(request),
            None,
        )
        .map(|joined| joined.record.result)
    }

    pub(in crate::admission_operation_store) fn join_security_participant_input(
        &self,
        operation: &AdmissionOperationV1,
        lease: &AdmissionRecoveryLease,
        initialized: &SecurityParticipantStateInitialization,
        context: &SecurityInvocationContext,
        input: &chio_kernel::admission_operation::NativeSecurityInputJoinRequestV1,
        trusted_now_unix_ms: u64,
    ) -> Result<
        chio_kernel::admission_operation::NativeSecurityInputJoinRecordV1,
        AdmissionOperationStoreError,
    > {
        self.join_native_command(
            NativeFlowJoinContext {
                operation,
                lease,
                initialized,
                context,
                trusted_now_unix_ms,
            },
            Command::Input(input),
            None,
        )?
        .record
        .input_record(initialized)
    }

    pub(in crate::admission_operation_store) fn join_security_participant_input_classified<
        'call,
    >(
        &self,
        initialized: &SecurityParticipantStateInitialization,
        classification: &'call chio_kernel::admission_operation::NativeSecurityInputClassificationAuthority<'call>,
    ) -> Result<
        chio_kernel::admission_operation::NativeSecurityInputJoinOutcome<'call>,
        AdmissionOperationStoreError,
    > {
        #[cfg(feature = "admission-test-support")]
        {
            if let Some(shared) =
                lost_ack_classified_retry::take(self.serving_owner.fence.store_uuid.as_str())
            {
                // One genuine lost acknowledgement: the real writer commits
                // the Input durably and that first acknowledgement is never
                // minted, so the kernel's single-use classification stays
                // unconsumed. The same legitimate classification then retries
                // the real writer, which must read the retained fate, never
                // re-assess and never write again. Only that retry's result
                // is acknowledged to the kernel.
                let first = self.join_classified_record(initialized, classification)?;
                let first_record = first.record.input_record(initialized)?;
                let first_observed = lost_ack_classified_retry::observe(
                    self,
                    classification.operation().binding().operation_id().as_str(),
                )?;
                lost_ack_classified_retry::record_first(
                    &shared,
                    first.refused,
                    first_record.fate,
                    first_observed,
                );
                let replay = self.join_classified_record(initialized, classification)?;
                let replay_record = replay.record.input_record(initialized)?;
                let replay_observed = lost_ack_classified_retry::observe(
                    self,
                    classification.operation().binding().operation_id().as_str(),
                )?;
                lost_ack_classified_retry::record_replay(
                    &shared,
                    replay.refused,
                    replay_record.fate,
                    replay_observed,
                );
                return Self::acknowledge_classified(classification, replay_record, replay.refused);
            }
        }
        let joined = self.join_classified_record(initialized, classification)?;
        let record = joined.record.input_record(initialized)?;
        Self::acknowledge_classified(classification, record, joined.refused)
    }

    fn join_classified_record(
        &self,
        initialized: &SecurityParticipantStateInitialization,
        classification: &chio_kernel::admission_operation::NativeSecurityInputClassificationAuthority<'_>,
    ) -> Result<JoinedNativeCommand, AdmissionOperationStoreError> {
        self.join_native_command(
            NativeFlowJoinContext {
                operation: classification.operation(),
                lease: classification.lease(),
                initialized,
                context: classification.context(),
                trusted_now_unix_ms: classification.trusted_now_unix_ms(),
            },
            Command::Input(classification.input()),
            Some(classification),
        )
    }

    /// Mints the one acknowledgment the Kernel's classification permits.
    fn acknowledge_classified<'call>(
        classification: &'call chio_kernel::admission_operation::NativeSecurityInputClassificationAuthority<'call>,
        record: chio_kernel::admission_operation::NativeSecurityInputJoinRecordV1,
        refused: bool,
    ) -> Result<
        chio_kernel::admission_operation::NativeSecurityInputJoinOutcome<'call>,
        AdmissionOperationStoreError,
    > {
        if refused {
            classification.refused(record)
        } else {
            classification.eligible(record)
        }
    }

    fn join_native_command(
        &self,
        original_context: NativeFlowJoinContext<'_>,
        command: Command<'_>,
        classification: Option<
            &chio_kernel::admission_operation::NativeSecurityInputClassificationAuthority<'_>,
        >,
    ) -> Result<JoinedNativeCommand, AdmissionOperationStoreError> {
        let NativeFlowJoinContext {
            operation,
            lease,
            initialized,
            context,
            trusted_now_unix_ms,
        } = original_context;
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(lease.store_fence()))?;
        observed_time(&tx, trusted_now_unix_ms)?;
        verify_participant_recovery_tx(
            &tx,
            &self.serving_owner,
            operation,
            lease,
            trusted_now_unix_ms,
        )?;
        ensure_no_reserved_terminal_stage(&tx, operation.binding().operation_id())?;
        let original = require_request(&tx, operation, context, command.key())?;
        // Only the Kernel's private original callback supplies a full live
        // request. A legacy direct Input has no such authority and cannot
        // reconstruct credentials from the deliberately sanitized original.
        if let Some(classification) = classification {
            if classification.operation() != operation
                || classification.context() != context
                || command.input() != Some(classification.input())
                || !std::ptr::eq(classification.lease(), lease)
                || classification.trusted_now_unix_ms() != trusted_now_unix_ms
            {
                return Err(invalid(
                    "native Input classification changed its original callback",
                ));
            }
            original.validate_request_material(classification.request())?;
        }
        command.validate(operation.binding().operation_id())?;
        // The serving owner verified current rows at open, rejects external
        // connection writes and pins its anchored head here. Every native
        // change is captured below; do not replay history on each command.
        let actual = records::load_metadata(&tx, initialized.authority.as_str())?
            .ok_or_else(|| invalid("native initialization is absent"))?;
        if &actual != initialized || actual.fence.store_uuid != lease.store_fence().store_uuid {
            return Err(invalid(
                "native initialization differs from selected destination history",
            ));
        }
        if let Some(classification) = classification {
            if classification.binding() != &actual.admission_binding()? {
                return Err(invalid(
                    "native Input classification changed its initialized authority",
                ));
            }
        }
        if let Some(record) = history::load_for_operation(&tx, operation.binding().operation_id())?
        {
            // Flow generation may advance after the original join. Stable
            // context is rechecked above against the retained request.
            if record.authority != actual.authority || !command.matches(&record) {
                return Err(invalid(
                    "native operation cannot replace its authority or command",
                ));
            }
            // The retained fate decides, never a literal. An Input written
            // before fates were retained is Unproved and stays refused.
            let refused = record.input_fate() != history::HistoricalInputFate::Eligible;
            return Ok(JoinedNativeCommand { record, refused });
        }
        // Existing context-only journals remain historical data. They cannot
        // acquire a first native mutation without an original authority binding.
        original.validate_native_security_authority(&actual.admission_binding()?)?;
        if original.authority_profile().is_none() {
            return Err(invalid(
                "first native mutation requires an original authority profile",
            ));
        }
        let occupied: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM security_participant_state_transitions
             WHERE security_authority_id = ?1 AND tenant_id = ?2 AND transition_id = ?3)",
                params![
                    actual.authority.as_str(),
                    command.key().tenant_id.as_str(),
                    command.transition_id().as_str()
                ],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if occupied {
            return Err(invalid(
                "native transition belongs to another operation or imported history",
            ));
        }
        let generation: Option<i64> = tx.query_row(
            "SELECT generation FROM security_participant_state_flow_contexts WHERE security_authority_id = ?1
             AND tenant_id = ?2 AND principal_id = ?3 AND lineage_id = ?4 AND session_id = ?5 AND isolation_epoch_id = ?6",
            params![actual.authority.as_str(), command.key().tenant_id.as_str(), command.key().principal_id.as_str(),
                command.key().lineage_id.as_str(), command.key().session_id.as_str(), command.key().isolation_epoch_id.as_str()],
            |row| row.get(0),
        ).optional().map_err(sqlite_error)?;
        if generation.map(u64::try_from).transpose().map_err(invalid)?
            != context.as_v1().flow_state_generation()
        {
            return Err(invalid("native flow observation is stale or absent"));
        }
        let mut segment = history::segments::SegmentSnapshot::capture(&tx, &actual)?;
        let head = segment.head(&tx, history::segments::Family::Mutations)?;
        let previous = if head == 1 {
            actual.digest.clone()
        } else {
            history::load(&tx, actual.authority.as_str(), head)?
                .ok_or_else(|| invalid("native mutation head absent"))?
                .digest()?
        };
        let (mut current_rows, mut current_bytes) = history::ordered::latest_totals(&tx, &segment)?;
        // Resolve every inherited label in this same write transaction, before
        // minting the affine mutation owner. No partial snapshot or raw writer
        // escapes. The common mutator still validates epoch and membership.
        let mut request = command.resolve(&tx, actual.authority.as_str())?;
        let mut refused = false;
        let mut actual_assessment_for_join_validation = None;
        #[cfg(feature = "admission-test-support")]
        let mut refused_origin_observed_at = None;
        if let Some(input) = command.input() {
            let binding = actual.admission_binding()?;
            let (before, _) = crate::security_state::observe_native_flow_state(
                &tx,
                actual.authority.as_str(),
                input.key(),
            )
            .map_err(invalid)?;
            let witnessed_at = observed_time(&tx, trusted_now_unix_ms)?;
            let assessment = super::super::semantic::verify_input_tx(
                &tx,
                super::super::semantic::SemanticInputObservation {
                    operation,
                    original: &original,
                    classification,
                    binding: &binding,
                    context,
                    input,
                    before: before.as_ref(),
                    resolved: &request,
                    now: witnessed_at,
                },
            )?;
            if let Some(witness) = &assessment {
                refused = witness.is_refused();
                #[cfg(feature = "admission-test-support")]
                {
                    if refused {
                        refused_origin_observed_at = Some(witnessed_at);
                    }
                }
                let mut floor = witness.restriction_floor().clone();
                if let Some(status) = witness.withheld_status_audience() {
                    floor = floor.join_restrictions(status).map_err(invalid)?;
                }
                request.principal_join = request
                    .principal_join
                    .join_restrictions(&floor)
                    .map_err(invalid)?;
                request.lineage_join = request
                    .lineage_join
                    .join_restrictions(&floor)
                    .map_err(invalid)?;
                request.session_join = request
                    .session_join
                    .join_restrictions(&floor)
                    .map_err(invalid)?;
            }
            actual_assessment_for_join_validation = assessment;
        }
        // Source/history verification can take time. Recheck the actual lease
        // immediately before enabling writes, using the later trusted time for
        // expiry but retaining the independent observation as historical data.
        let now = observed_time(&tx, trusted_now_unix_ms)?;
        #[cfg(feature = "admission-test-support")]
        let now = refused_origin_observed_at
            .and_then(|origin| {
                record_clock_inversion::take(self.serving_owner.fence.store_uuid.as_str(), origin)
            })
            .unwrap_or(now);
        verify_participant_recovery_tx(
            &tx,
            &self.serving_owner,
            operation,
            lease,
            trusted_now_unix_ms,
        )?;
        let authorization = NativeFlowJoinAuthority {
            authority: actual.authority.clone(),
            request: request.clone(),
        };
        let (tx, result, changes) =
            crate::security_state::join_native_flow(tx, authorization).map_err(invalid)?;
        // The retained fate comes from this transaction's own verified
        // assessment. A refused origin must agree with the actual native
        // source, resolution and complete joined floor before it is retained.
        let input_fate = match command.input() {
            None => None,
            Some(input) => Some(
                match actual_assessment_for_join_validation
                    .as_ref()
                    .and_then(|assessment| assessment.refused_origin())
                {
                    Some(origin) => {
                        origin.validate_source(
                            &actual.admission_binding()?,
                            input.key(),
                            operation.binding().operation_id(),
                            input,
                        )?;
                        input.validate_resolution(
                            operation.binding().operation_id(),
                            &request,
                            &result,
                        )?;
                        origin.validate_joined_request(&request, &result)?;
                        // Cold open reconstructs the before-state from these
                        // before-images. A record it could not reproduce is
                        // refused now rather than committed unreadable.
                        if crate::security_state::NativeRowChange::
                            predecessor_snapshot_for_native_flow_join(
                                &request, &result, &changes,
                            )
                            .map_err(invalid)?
                            != *origin.before_state()
                        {
                            return Err(invalid(
                                "Refused Input before-state is not reconstructible from its join",
                            ));
                        }
                        history::NativeInputFateV1::Refused {
                            origin: origin.canonical_body_json()?,
                        }
                    }
                    None if refused => {
                        return Err(invalid("Refused Input assessment lost its origin"));
                    }
                    None => history::NativeInputFateV1::Eligible,
                },
            ),
        };
        verify_participant_recovery_tx(
            &tx,
            &self.serving_owner,
            operation,
            lease,
            trusted_now_unix_ms,
        )?;
        cutpoint(7)?;
        for change in &changes {
            if let Some(before) = &change.before {
                current_rows = current_rows
                    .checked_sub(1)
                    .ok_or_else(|| invalid("native row count underflow"))?;
                current_bytes = current_bytes
                    .checked_sub(u64::try_from(before.len()).map_err(invalid)?)
                    .ok_or_else(|| invalid("native byte count underflow"))?;
            }
            if let Some(after) = &change.after {
                current_rows = current_rows
                    .checked_add(1)
                    .ok_or_else(|| invalid("native row count overflow"))?;
                current_bytes = current_bytes
                    .checked_add(u64::try_from(after.len()).map_err(invalid)?)
                    .ok_or_else(|| invalid("native byte count overflow"))?;
            }
        }
        let record = history::Record {
            schema: history::format(
                command.input().is_some(),
                self.serving_owner.fence.store_uuid.as_str(),
            ),
            authority: actual.authority.clone(),
            sequence: head
                .checked_add(1)
                .ok_or_else(|| invalid("native mutation sequence overflow"))?,
            initialization: actual.digest.clone(),
            previous,
            operation: operation.to_persisted(),
            lease: history::LeaseHistory::new(lease),
            context: context.clone(),
            input: command.input().cloned(),
            input_fate: history::retained_input_fate(
                self.serving_owner.fence.store_uuid.as_str(),
                input_fate,
            ),
            request: request.clone(),
            result: result.clone(),
            observed_at: now,
            decision_at: trusted_now_unix_ms,
            changes: BoundedVec::new(changes).map_err(invalid)?,
            current_rows,
            current_bytes,
        };
        record.validate_structure(&tx)?;
        storage::require_tenant_live(
            &tx,
            actual.authority.as_str(),
            record.request.key.tenant_id.as_str(),
        )?;
        crate::admission_operation_store::recovery::resources::check_intake_committing(&tx)?;
        let append = history::segments::Append::mutation(&record)?;
        segment.prepare_pre_effect_append(&tx, &self.serving_owner, &append)?;
        record.insert(&tx)?;
        segment.appended(&tx, append.entry())?;
        cutpoint(8)?;
        self.serving_owner
            .append_global_commit(
                &tx,
                history::MUTATION,
                PROJECTION_KIND,
                actual.authority.as_str(),
                record.sequence,
            )
            .map_err(map_owner_error)?;
        segment.committed(&tx, append.entry())?;
        // The record now has its real retained global commit. Apply the same
        // full validation every later load applies, so a cold predicate this
        // writer could violate (origin time against record time, origin
        // binding, reconstructed before-state) rolls back the whole write,
        // labels, journal, segment and accounting included, instead of
        // committing history no open could read.
        let validated = record.validate(&tx);
        #[cfg(feature = "admission-test-support")]
        record_clock_inversion::observe_validation(
            self.serving_owner.fence.store_uuid.as_str(),
            &record,
            &tx,
            validated.is_ok(),
        );
        validated?;
        cutpoint(9)?;
        self.commit_write(tx)?;
        if let Err(error) = cutpoint(10) {
            return Err(map_owner_error(
                self.serving_owner.outcome_unknown(error.to_string()),
            ));
        }
        self.sync_after_write(&connection)?;
        cutpoint(11)?;
        Ok(JoinedNativeCommand { record, refused })
    }
}

#[cfg(feature = "admission-test-support")]
impl SqliteAdmissionOperationStore {
    /// Arms exactly one lost-acknowledgement retry for this store's next
    /// classified Input join: the real writer commits, that first
    /// acknowledgement is discarded, and the same legitimate classification
    /// retries the real writer before the kernel consumes the result.
    pub fn arm_lost_ack_classified_input_retry_for_test(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        lost_ack_classified_retry::arm(self.serving_owner.fence.store_uuid.as_str())
    }

    /// Arms exactly one clock inversion for this store's next refused
    /// classified Input join: the record observation precedes the origin
    /// observation, which the writer must refuse and roll back completely.
    pub fn arm_record_clock_inversion_for_test(&self) -> Result<(), AdmissionOperationStoreError> {
        record_clock_inversion::arm(self.serving_owner.fence.store_uuid.as_str())
    }

    /// What the post-append full validation decided for the inverted write,
    /// once it has run: its structure phase alone, and the full retained
    /// validation the writer applies unconditionally.
    pub fn record_clock_inversion_validation_for_test(
        &self,
    ) -> Option<RecordClockInversionObservation> {
        record_clock_inversion::observed(self.serving_owner.fence.store_uuid.as_str())
    }

    /// Whether a refused write consumed the armed clock inversion.
    pub fn record_clock_inversion_applied_for_test(&self) -> bool {
        record_clock_inversion::applied(self.serving_owner.fence.store_uuid.as_str())
    }

    /// Whether the armed retry consumed a classified Input join.
    pub fn lost_ack_classified_input_retry_consumed_for_test(&self) -> bool {
        lost_ack_classified_retry::read(self.serving_owner.fence.store_uuid.as_str())
            .is_some_and(|record| record.consumed)
    }

    /// Whether the discarded first acknowledgement classified Refused.
    pub fn lost_ack_classified_input_retry_first_refused_for_test(&self) -> bool {
        lost_ack_classified_retry::read(self.serving_owner.fence.store_uuid.as_str())
            .is_some_and(|record| record.first_refused)
    }

    /// Whether the retried classification, read from the retained fate,
    /// still classified Refused.
    pub fn lost_ack_classified_input_retry_replay_refused_for_test(&self) -> bool {
        lost_ack_classified_retry::read(self.serving_owner.fence.store_uuid.as_str())
            .is_some_and(|record| record.replay_refused)
    }

    /// The retained fates the discarded first join and the retry's join
    /// derived from their retained bytes.
    pub fn lost_ack_classified_input_retry_fates_for_test(
        &self,
    ) -> Option<(
        chio_kernel::admission_operation::NativeSecurityInputFateV1,
        chio_kernel::admission_operation::NativeSecurityInputFateV1,
    )> {
        lost_ack_classified_retry::read(self.serving_owner.fence.store_uuid.as_str())
            .and_then(|record| record.first_fate.zip(record.replay_fate))
    }

    /// The retained native record bytes and global journal commit count
    /// captured immediately after the discarded first acknowledgement's
    /// real committed join.
    pub fn lost_ack_classified_input_retry_first_join_for_test(&self) -> Option<(Vec<u8>, i64)> {
        lost_ack_classified_retry::read(self.serving_owner.fence.store_uuid.as_str()).and_then(
            |record| {
                record
                    .first
                    .map(|observed| (observed.record_bytes, observed.global_commits))
            },
        )
    }

    /// The same observation captured immediately after the immediate
    /// same-classification replay.
    pub fn lost_ack_classified_input_retry_replay_join_for_test(&self) -> Option<(Vec<u8>, i64)> {
        lost_ack_classified_retry::read(self.serving_owner.fence.store_uuid.as_str()).and_then(
            |record| {
                record
                    .replay
                    .map(|observed| (observed.record_bytes, observed.global_commits))
            },
        )
    }
}
