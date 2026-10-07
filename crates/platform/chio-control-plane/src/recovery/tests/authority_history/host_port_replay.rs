//! Retained host replies remain data under current read authority.
use super::*;
use rusqlite::{types::ValueRef, Connection, OpenFlags};
use sha2::{Digest, Sha256};
use std::{cell::Cell, marker::PhantomData, rc::Rc};

const MAX_SIGNING_EVENTS: u16 = 16;

#[derive(Clone, Copy, Default)]
struct SigningCount {
    count: u16,
    overflow: bool,
}

thread_local! {
    static SIGNING_COUNT: Cell<Option<SigningCount>> = const { Cell::new(None) };
}

/// Observes only the existing synchronous recovery grant-signing cutpoint.
/// Default-off and thread-local; no worker-thread or other signer claim.
pub(in crate::recovery::tests) fn record_signed_cutpoint(stage: &str) {
    if stage != "signed" {
        return;
    }
    SIGNING_COUNT.with(|cell| {
        if let Some(mut observed) = cell.get() {
            if observed.count == MAX_SIGNING_EVENTS {
                observed.overflow = true;
            } else {
                observed.count += 1;
            }
            cell.set(Some(observed));
        }
    });
}

struct ObserveSigning {
    prior: Option<SigningCount>,
    _same_thread: PhantomData<Rc<()>>,
}
impl ObserveSigning {
    fn new() -> Self {
        Self {
            prior: SIGNING_COUNT.with(|cell| cell.replace(Some(SigningCount::default()))),
            _same_thread: PhantomData,
        }
    }

    fn count(&self) -> TestResult<u16> {
        let observed = SIGNING_COUNT
            .with(Cell::get)
            .ok_or("signing observer is inactive")?;
        if observed.overflow {
            return Err("signing observer exceeded its bounded event count".into());
        }
        Ok(observed.count)
    }
}
impl Drop for ObserveSigning {
    fn drop(&mut self) {
        SIGNING_COUNT.with(|cell| cell.set(self.prior));
    }
}

#[test]
fn synchronous_signing_observer_is_default_off_and_restores_nested_scopes() -> TestResult {
    assert!(SIGNING_COUNT.with(Cell::get).is_none());
    record_signed_cutpoint("signed");
    assert!(SIGNING_COUNT.with(Cell::get).is_none());
    {
        let outer = ObserveSigning::new();
        record_signed_cutpoint("signed");
        assert_eq!(outer.count()?, 1);
        {
            let inner = ObserveSigning::new();
            record_signed_cutpoint("issuance");
            assert_eq!(inner.count()?, 0);
            record_signed_cutpoint("signed");
            assert_eq!(inner.count()?, 1);
        }
        assert_eq!(outer.count()?, 1);
    }
    assert!(SIGNING_COUNT.with(Cell::get).is_none());
    Ok(())
}

#[test]
fn synchronous_signing_observer_refuses_a_count_beyond_its_bound() -> TestResult {
    let observer = ObserveSigning::new();
    for _ in 0..MAX_SIGNING_EVENTS {
        record_signed_cutpoint("signed");
    }
    assert_eq!(observer.count()?, MAX_SIGNING_EVENTS);
    record_signed_cutpoint("signed");
    assert!(observer.count().is_err());
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum HostPort {
    Review,
    Reservation,
    Materialization,
    Issuance,
    Signature,
    Envelope,
}
impl HostPort {
    const ALL: [Self; 6] = [
        Self::Review,
        Self::Reservation,
        Self::Materialization,
        Self::Issuance,
        Self::Signature,
        Self::Envelope,
    ];

    fn permission(self) -> RecoveryPermission {
        match self {
            Self::Review => RecoveryPermission::Approve,
            Self::Reservation
            | Self::Materialization
            | Self::Issuance
            | Self::Signature
            | Self::Envelope => RecoveryPermission::Resume,
        }
    }

    fn expected(self, retained: &RetainedHostInput) -> TestResult<Vec<u8>> {
        Ok(match self {
            Self::Review => chio_core::canonical_json_bytes(
                retained.workflow.review.as_ref().ok_or("retained review")?,
            )?,
            Self::Issuance => chio_core::canonical_json_bytes(
                retained
                    .workflow
                    .issuance
                    .as_ref()
                    .ok_or("retained issuance")?,
            )?,
            // Materialization returns a current workflow, not a frozen reply.
            // Its exact retained action is the immutable value being replayed.
            Self::Materialization => chio_core::canonical_json_bytes(
                retained.workflow.action.as_ref().ok_or("retained action")?,
            )?,
            Self::Reservation | Self::Signature | Self::Envelope => {
                chio_core::canonical_json_bytes(&())?
            }
        })
    }

    fn replay(
        self,
        fixture: &RecoveryFixture,
        actor: &AuthenticatedRecoveryActor,
        retained: &RetainedHostInput,
    ) -> Result<Vec<u8>, KernelError> {
        let kernel = &fixture.kernel;
        let workflow = &retained.workflow.workflow_id;
        let missing = || KernelError::Internal("host replay fixture omitted retained input".into());
        match self {
            Self::Review => reply_bytes(&kernel.reserve_recovery_review(
                actor,
                workflow,
                retained.workflow.review.as_ref().ok_or_else(missing)?,
            )?),
            Self::Reservation => {
                kernel.acknowledge_recovery_reservation(
                    actor,
                    workflow,
                    &retained.reservation,
                    &fixture.process,
                )?;
                reply_bytes(&())
            }
            Self::Materialization => {
                let response = kernel.materialize_recovery_action(
                    actor,
                    workflow,
                    retained.workflow.action.as_ref().ok_or_else(missing)?,
                )?;
                reply_bytes(response.action.as_ref().ok_or_else(missing)?)
            }
            Self::Issuance => reply_bytes(&kernel.reserve_recovery_issuance(
                actor,
                workflow,
                retained.workflow.issuance.as_ref().ok_or_else(missing)?,
            )?),
            Self::Signature => {
                kernel.attach_recovery_signature(
                    actor,
                    workflow,
                    retained
                        .workflow
                        .signed_grant
                        .as_ref()
                        .ok_or_else(missing)?,
                )?;
                reply_bytes(&())
            }
            Self::Envelope => {
                kernel.finalize_recovery_envelope(
                    actor,
                    workflow,
                    retained.workflow.envelope.as_ref().ok_or_else(missing)?,
                    &retained.identity,
                )?;
                reply_bytes(&())
            }
        }
    }
}

fn reply_bytes<T: serde::Serialize>(reply: &T) -> Result<Vec<u8>, KernelError> {
    chio_core::canonical_json_bytes(reply)
        .map_err(|_| KernelError::Internal("host replay reply encoding failed".into()))
}

struct RetainedHostInput {
    workflow: Box<RecoveryWorkflowRecordV1>,
    reservation: RecoveryProcessReservationV1,
    identity: RecoveryNativeIdentity,
    first_resume: Box<RecoveryCommandV1>,
}

fn accept_fixture_execution_request(
    fixture: &RecoveryFixture,
    workflow: &WorkflowId,
) -> TestResult<Box<RecoveryCommandV1>> {
    let current = Box::new(fixture.record(workflow)?);
    assert!(current.admission.is_none());
    assert!(!current.captured);
    assert!(!current.admission_closed);
    let command = Box::new(fixture.command(
        "host-replay-first-resume",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: workflow.clone(),
            expected_revision: current.revision,
        },
    )?);
    let actor = authenticated_actor(fixture, RecoveryPermission::Resume)?;
    let outcome = fixture
        .kernel
        .execute_recovery_command_outcome_with_origin(&actor, &command, &fixture.process)?;
    assert_eq!(
        outcome.selection().mode(),
        RecoveryCommandContinuationMode::SameCurrentGeneration
    );
    let selected = fixture
        .kernel
        .read_recovery_command_selection(&actor, outcome.selection())?;
    assert_eq!(
        selected.mode(),
        RecoveryCommandContinuationMode::SameCurrentGeneration
    );
    assert_eq!(selected.record().effect, EffectObservationV1::NeverAdmitted);
    assert!(selected.record().admission.is_none());
    assert!(!selected.record().captured);
    assert_eq!(external_count(&fixture.path)?, 0);
    assert_eq!(fixture.process.process("root")?.tree_calls, 2);
    eprintln!(
        "host closure stage=0 selection={} effect={} captured={} closed={} durable_effects={} process_calls={}",
        continuation_mode_code(selected.mode()),
        effect_code(&selected.record().effect),
        u8::from(selected.record().captured),
        u8::from(selected.record().admission_closed),
        external_count(&fixture.path)?,
        fixture.process.process("root")?.tree_calls,
    );
    // The actual owning command source, not a descriptive fixture row, retains
    // this execution request. The later driver reuses this exact identity.
    Ok(command)
}

async fn prepared_fixture(
    directory: &Path,
) -> TestResult<(Box<RecoveryFixture>, Box<RetainedHostInput>)> {
    let fixture = Box::new(RecoveryFixture::open(directory.to_path_buf(), None, false)?);
    let workflow = Box::pin(fixture.ready()).await?;
    assert!(fixture.record(&workflow)?.signed_grant.is_none());
    assert_eq!(external_count(&fixture.path)?, 0);
    // Real Runtime ordering accepts the first execution request before grant
    // preparation. A new command after admission would be a read-only alias.
    let first_resume = accept_fixture_execution_request(&fixture, &workflow)?;
    let signing = ObserveSigning::new();
    let custody =
        crate::recovery::freeze_original_for_test(&fixture.runtime, &fixture.control, &workflow)?;
    assert_eq!(
        signing.count()?,
        1,
        "real synchronous preparation must sign once"
    );
    drop(signing);
    let record = Box::new(fixture.record(&workflow)?);
    assert_eq!(record.control, WorkflowControlV1::Active);
    assert!(!record.admission_closed);
    assert!(!record.captured);
    assert!(record.historical_hold.is_none());
    assert!(record.review.is_some());
    assert!(record.approval.is_some());
    assert!(record.issuance.is_some());
    assert!(record
        .signed_grant
        .as_ref()
        .ok_or("retained grant")?
        .verify_signature()?);
    let envelope = record.envelope.as_ref().ok_or("retained envelope")?;
    let request: ToolCallRequest = serde_json::from_str(envelope.request.as_str())?;
    assert!(
        chio_core::canonical_json_bytes(&request)?
            == chio_core::canonical_json_bytes(custody.request())?,
        "native custody changed the retained finalized request"
    );
    let profile = fixture
        .kernel
        .recovery_deployment(fixture.runtime.scope())?;
    let identity = fixture
        .kernel
        .recovery_native_identity(&request, &profile.security_context)?;
    let admission = record
        .admission
        .as_ref()
        .ok_or("retained native preparation")?;
    assert!(
        identity.binding().to_persisted() == admission.native_binding,
        "retained admission omitted the genuine native binding"
    );
    let reservation: RecoveryProcessReservationV1 = serde_json::from_str(
        record
            .process_reservation
            .as_ref()
            .ok_or("retained process reservation")?
            .as_str(),
    )?;
    RecoveryProcessReservationPort::verify_reservation(&fixture.process, &reservation)?;
    assert_eq!(external_count(&fixture.path)?, 0);
    assert_eq!(fixture.process.process("root")?.tree_calls, 2);
    Ok((
        fixture,
        Box::new(RetainedHostInput {
            workflow: record,
            reservation,
            identity,
            first_resume,
        }),
    ))
}

/// Hash every actual logical table in a coherent read-only snapshot. Fixture
/// bounds reject excess input; values are streamed without copying raw blobs.
#[derive(Debug, Eq, PartialEq)]
struct DatabaseSnapshot {
    rows: u64,
    bytes: u64,
    digest: [u8; 32],
}

fn quoted_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn hash_frame(hasher: &mut Sha256, total: &mut u64, tag: u8, bytes: &[u8]) -> TestResult {
    const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;
    let length = u64::try_from(bytes.len())?;
    *total = total
        .checked_add(length)
        .ok_or("snapshot byte count overflow")?;
    if *total > MAX_SNAPSHOT_BYTES {
        return Err("host replay fixture exceeds snapshot byte bound".into());
    }
    hasher.update([tag]);
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

fn database_snapshot(path: &Path) -> TestResult<DatabaseSnapshot> {
    const MAX_TABLES: usize = 512;
    const MAX_COLUMNS: usize = 128;
    const MAX_ROWS: u64 = 100_000;
    let mut connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let tx = connection.transaction()?;
    let mut hash = Sha256::new();
    let mut bytes = 0;
    let mut row_count = 0;
    let mut catalog = tx.prepare(
        "SELECT type,name,tbl_name,coalesce(sql,'') FROM sqlite_schema ORDER BY type,name",
    )?;
    let mut catalog_rows = catalog.query([])?;
    let mut catalog_count = 0;
    while let Some(row) = catalog_rows.next()? {
        catalog_count += 1;
        if catalog_count > 4096 {
            return Err("host replay fixture exceeds schema bound".into());
        }
        for index in 0..4 {
            hash_frame(
                &mut hash,
                &mut bytes,
                0,
                row.get_ref(index)?.as_str()?.as_bytes(),
            )?;
        }
    }
    drop(catalog_rows);
    drop(catalog);
    let mut tables_query =
        tx.prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")?;
    let mut table_rows = tables_query.query([])?;
    let mut tables = Vec::new();
    while let Some(row) = table_rows.next()? {
        if tables.len() == MAX_TABLES {
            return Err("host replay fixture exceeds table bound".into());
        }
        tables.push(row.get::<_, String>(0)?);
    }
    drop(table_rows);
    drop(tables_query);
    for table in tables {
        let quoted = quoted_identifier(&table);
        hash_frame(&mut hash, &mut bytes, 1, table.as_bytes())?;
        let mut columns_query = tx.prepare(&format!("PRAGMA table_info({quoted})"))?;
        let mut column_rows = columns_query.query([])?;
        let mut columns = Vec::new();
        while let Some(row) = column_rows.next()? {
            if columns.len() == MAX_COLUMNS {
                return Err("host replay fixture exceeds column bound".into());
            }
            columns.push(quoted_identifier(&row.get::<_, String>(1)?));
        }
        drop(column_rows);
        drop(columns_query);
        if columns.is_empty() {
            return Err("host replay snapshot encountered an empty table declaration".into());
        }
        let columns = columns.join(",");
        let mut query = tx.prepare(&format!(
            "SELECT {columns} FROM {quoted} ORDER BY {columns}"
        ))?;
        let column_count = query.column_count();
        let mut rows = query.query([])?;
        while let Some(row) = rows.next()? {
            row_count += 1;
            if row_count > MAX_ROWS {
                return Err("host replay fixture exceeds row bound".into());
            }
            hash_frame(&mut hash, &mut bytes, 2, &[])?;
            for index in 0..column_count {
                match row.get_ref(index)? {
                    ValueRef::Null => hash_frame(&mut hash, &mut bytes, 3, &[])?,
                    ValueRef::Integer(value) => {
                        hash_frame(&mut hash, &mut bytes, 4, &value.to_be_bytes())?
                    }
                    ValueRef::Real(value) => {
                        hash_frame(&mut hash, &mut bytes, 5, &value.to_bits().to_be_bytes())?
                    }
                    ValueRef::Text(value) => hash_frame(&mut hash, &mut bytes, 6, value)?,
                    ValueRef::Blob(value) => hash_frame(&mut hash, &mut bytes, 7, value)?,
                }
            }
        }
    }
    Ok(DatabaseSnapshot {
        rows: row_count,
        bytes,
        digest: hash.finalize().into(),
    })
}

#[derive(Debug, Eq, PartialEq)]
struct HostSnapshot {
    authority: DatabaseSnapshot,
    process: DatabaseSnapshot,
    effects: usize,
    memory_effects: usize,
}
fn host_snapshot(fixture: &RecoveryFixture) -> TestResult<HostSnapshot> {
    Ok(HostSnapshot {
        authority: database_snapshot(&fixture.path.join("admission.db"))?,
        process: database_snapshot(&fixture.path.join("process.db"))?,
        effects: external_count(&fixture.path)?,
        memory_effects: fixture.effects.load(Ordering::SeqCst),
    })
}

fn authenticated_host_actor(
    fixture: &RecoveryFixture,
    port: HostPort,
) -> TestResult<AuthenticatedRecoveryActor> {
    authenticated_actor(fixture, port.permission())
}

fn authenticated_actor(
    fixture: &RecoveryFixture,
    permission: RecoveryPermission,
) -> TestResult<AuthenticatedRecoveryActor> {
    if fixture.control.expires_at <= now_ms()? / 1000 {
        return Err("host replay fixture lost its live control capability".into());
    }
    Ok(fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        permission,
    )?)
}

fn assert_retained_replay(
    fixture: &RecoveryFixture,
    retained: &RetainedHostInput,
    port: HostPort,
    phase: &str,
) -> TestResult {
    let actor = authenticated_host_actor(fixture, port)?;
    let expected = port.expected(retained)?;
    let before = host_snapshot(fixture)?;
    let signing = ObserveSigning::new();
    eprintln!("host replay port={port:?} phase={phase} retained=true fresh_actor=true");
    let response = port.replay(fixture, &actor, retained);
    let signed = signing.count()?;
    drop(signing);
    assert_eq!(
        host_snapshot(fixture)?,
        before,
        "{port:?} {phase}: changed durable facts or effects"
    );
    assert_eq!(signed, 0, "{port:?} {phase}: signed another recovery grant");
    // Diagnostics name the owning phase without printing protected inputs or a
    // dynamic error containing caller-controlled content.
    let response = response
        .map_err(|_| format!("retained host reply refused: port={port:?} phase={phase}"))?;
    assert!(
        response == expected,
        "{port:?} {phase}: replaced retained value"
    );
    Ok(())
}

fn assert_refused_without_progress(
    fixture: &RecoveryFixture,
    actor: &AuthenticatedRecoveryActor,
    retained: &RetainedHostInput,
    port: HostPort,
    control: &str,
) -> TestResult {
    let before = host_snapshot(fixture)?;
    let signing = ObserveSigning::new();
    let response = port.replay(fixture, actor, retained);
    let signed = signing.count()?;
    drop(signing);
    assert_eq!(
        host_snapshot(fixture)?,
        before,
        "{port:?} {control}: changed durable facts or effects"
    );
    assert_eq!(signed, 0, "{port:?} {control}: signed another grant");
    assert!(
        response.is_err(),
        "{port:?} {control}: retained reply crossed current authority boundary"
    );
    Ok(())
}

fn assert_changed_retained_input_refused(
    fixture: &RecoveryFixture,
    retained: &RetainedHostInput,
    port: HostPort,
    phase: &str,
) -> TestResult {
    // reserve_review takes a draft and returns the already retained review. It
    // has no separate record_review or incoming retained-identity conflict API.
    if matches!(port, HostPort::Review) {
        return Ok(());
    }
    let actor = authenticated_host_actor(fixture, port)?;
    let workflow = &retained.workflow.workflow_id;
    let changed_digest = *chio_core::sha256(b"different-retained-host-input").as_bytes();
    let mut reservation = retained.reservation.clone();
    reservation.capability_digest = chio_core::sha256_hex(b"different-reservation-capability");
    assert!(reservation != retained.reservation);
    let mut action = retained
        .workflow
        .action
        .as_ref()
        .ok_or("retained action")?
        .clone();
    action.source_generation = SafeInteger::new(
        action
            .source_generation
            .get()
            .checked_add(1)
            .ok_or("fixture generation overflow")?,
    )?;
    let mut body = retained
        .workflow
        .issuance
        .as_ref()
        .ok_or("retained issuance")?
        .clone();
    body.recovery.action_intent = IntentDigest::from_bytes(changed_digest);
    assert!(
        body != *retained
            .workflow
            .issuance
            .as_ref()
            .ok_or("retained issuance")?
    );
    let signature = if matches!(port, HostPort::Signature) {
        // Deliberate negative input signed by the actual current fixture key.
        // Construction precedes the replay observation, never inside the port.
        Some(chio_core_types::recovery::SignedRecoveryGrantV2::sign(
            body.clone(),
            &fixture_aggregate_key(&fixture.path),
        )?)
    } else {
        None
    };
    let mut envelope = retained
        .workflow
        .envelope
        .as_ref()
        .ok_or("retained envelope")?
        .clone();
    envelope.action_intent = IntentDigest::from_bytes(changed_digest);
    let before = host_snapshot(fixture)?;
    let signing = ObserveSigning::new();
    let response = match port {
        HostPort::Reservation => fixture.kernel.acknowledge_recovery_reservation(
            &actor,
            workflow,
            &reservation,
            &fixture.process,
        ),
        HostPort::Materialization => fixture
            .kernel
            .materialize_recovery_action(&actor, workflow, &action)
            .map(|_| ()),
        HostPort::Issuance => fixture
            .kernel
            .reserve_recovery_issuance(&actor, workflow, &body)
            .map(|_| ()),
        HostPort::Signature => fixture.kernel.attach_recovery_signature(
            &actor,
            workflow,
            signature.as_ref().ok_or("negative signed input")?,
        ),
        HostPort::Envelope => fixture.kernel.finalize_recovery_envelope(
            &actor,
            workflow,
            &envelope,
            &retained.identity,
        ),
        HostPort::Review => return Err("review conflict API is not available".into()),
    };
    let signed = signing.count()?;
    drop(signing);
    assert_eq!(
        host_snapshot(fixture)?,
        before,
        "{port:?} {phase}: conflicting input changed facts"
    );
    assert_eq!(
        signed, 0,
        "{port:?} {phase}: conflicting input signed authority"
    );
    assert!(
        response.is_err(),
        "{port:?} {phase}: conflicting input replaced retained identity"
    );
    Ok(())
}

fn continuation_mode_code(mode: RecoveryCommandContinuationMode) -> u8 {
    match mode {
        RecoveryCommandContinuationMode::SameCurrentGeneration => 0,
        RecoveryCommandContinuationMode::HistoricalGenerationReadOnly => 1,
        RecoveryCommandContinuationMode::ControlOnly => 2,
    }
}

fn effect_code(effect: &EffectObservationV1) -> u8 {
    match effect {
        EffectObservationV1::NeverAdmitted => 0,
        EffectObservationV1::AdmissionUnresolved { .. } => 1,
        EffectObservationV1::ClosedBeforeEffect { .. } => 2,
        EffectObservationV1::AwaitingApproval { .. } => 3,
        EffectObservationV1::InFlight { .. } => 4,
        EffectObservationV1::AwaitingCallerReport { .. } => 5,
        EffectObservationV1::Unknown { .. } => 6,
        EffectObservationV1::Complete { .. } => 7,
        EffectObservationV1::Partial { .. } => 8,
        EffectObservationV1::FailedAfterEffect { .. } => 9,
    }
}

fn control_code(control: WorkflowControlV1) -> u8 {
    match control {
        WorkflowControlV1::Active => 0,
        WorkflowControlV1::CancelRequested => 1,
        WorkflowControlV1::Cancelled => 2,
        WorkflowControlV1::Quarantined => 3,
    }
}

fn release_code(release: &ReleaseDispositionV1) -> u8 {
    match release {
        ReleaseDispositionV1::NotAvailable => 0,
        ReleaseDispositionV1::Pending { .. } => 1,
        ReleaseDispositionV1::Withheld { .. } => 2,
        ReleaseDispositionV1::Released { .. } => 3,
        ReleaseDispositionV1::Denied { .. } => 4,
    }
}

fn native_state_code(state: AdmissionOperationState) -> u8 {
    match state {
        AdmissionOperationState::Prepared => 1,
        AdmissionOperationState::BrokerAttemptRegistered => 2,
        AdmissionOperationState::ApprovalRequired => 3,
        AdmissionOperationState::BudgetAuthorized => 4,
        AdmissionOperationState::ApprovalReserved => 5,
        AdmissionOperationState::ReadyToDispatch => 6,
        AdmissionOperationState::CapturePending => 7,
        AdmissionOperationState::DispatchCommitted => 8,
        AdmissionOperationState::AwaitingCallerReport => 9,
        AdmissionOperationState::Finalizing => 10,
        AdmissionOperationState::Completed => 11,
        AdmissionOperationState::CompensatedBeforeDispatch => 12,
        AdmissionOperationState::NotAcceptedAfterDispatchCommit => 13,
        AdmissionOperationState::OutcomeUnknownAfterDispatch => 14,
        AdmissionOperationState::DeniedAfterDelivery => 15,
        AdmissionOperationState::MutationReady => 16,
        AdmissionOperationState::MutationSubmitted => 17,
        AdmissionOperationState::EconomicMutationApplied => 18,
        AdmissionOperationState::EconomicMutationNotApplied => 19,
    }
}

#[derive(serde::Serialize)]
struct ClosureSample {
    stage: u8,
    selection_mode: u8,
    control: u8,
    effect: u8,
    release: u8,
    captured: u8,
    admission_closed: u8,
    workflow_revision: u64,
    response_effect: Option<u8>,
    response_has_original: u8,
    native_state: u8,
    native_dispatch_committed: u8,
    native_terminal_replay: u8,
    quota_version: u64,
    planning_used: u64,
    control_used: u64,
    native_used: u64,
    resume_purpose_used: u64,
    process_calls: u64,
    durable_effects: u64,
    memory_effects: u64,
    now_unix_ms: u64,
    control_expires_unix_s: u64,
    seed_expires_unix_s: u64,
    grant_expires_unix_s: u64,
}

fn observe_closure_sample(
    fixture: &RecoveryFixture,
    retained: &RetainedHostInput,
    stage: u8,
    selection: RecoveryCommandContinuationMode,
    response: Option<&RecoveryCommandResultV1>,
) -> TestResult {
    let current = Box::new(fixture.record(&retained.workflow.workflow_id)?);
    let admission = retained
        .workflow
        .admission
        .as_ref()
        .ok_or("native intent")?;
    let operation = fixture
        .authority
        .admission_operation_store()
        .load_by_operation_id(
            &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                admission.native_operation_id.as_str(),
            )?,
        )?;
    let (native_state, native_dispatch_committed, native_terminal_replay) = match operation {
        Some(operation) => (
            native_state_code(operation.state()),
            u8::from(operation.dispatch_commit().is_some()),
            u8::from(operation.terminal_replay().is_some()),
        ),
        None => (0, 0, 0),
    };
    let (quota_version, quota_bytes) =
        retained_workflow_quota_bytes(&fixture.path, &retained.workflow)?;
    let quota: Value = serde_json::from_slice(&quota_bytes)?;
    let count = |field: &str| {
        quota
            .get(field)
            .and_then(Value::as_u64)
            .ok_or("closure sample lost actual quota counter")
    };
    let resume_purpose_used = quota
        .get("commands")
        .and_then(Value::as_array)
        .and_then(|commands| commands.get(3))
        .and_then(Value::as_u64)
        .ok_or("closure sample lost actual Resume purpose")?;
    let sample = ClosureSample {
        stage,
        selection_mode: continuation_mode_code(selection),
        control: control_code(current.control),
        effect: effect_code(&current.effect),
        release: release_code(&current.release),
        captured: u8::from(current.captured),
        admission_closed: u8::from(current.admission_closed),
        workflow_revision: current.revision.get(),
        response_effect: response.map(|reply| effect_code(&reply.status.effect)),
        response_has_original: u8::from(
            response.is_some_and(|reply| reply.original_response.is_some()),
        ),
        native_state,
        native_dispatch_committed,
        native_terminal_replay,
        quota_version,
        planning_used: count("planning")?,
        control_used: count("control")?,
        native_used: count("native")?,
        resume_purpose_used,
        process_calls: u64::from(fixture.process.process("root")?.tree_calls),
        durable_effects: u64::try_from(external_count(&fixture.path)?)?,
        memory_effects: u64::try_from(fixture.effects.load(Ordering::SeqCst))?,
        now_unix_ms: now_ms()?,
        control_expires_unix_s: fixture.control.expires_at,
        seed_expires_unix_s: retained.workflow.seed.capability.expires_at,
        grant_expires_unix_s: retained
            .workflow
            .issuance
            .as_ref()
            .ok_or("retained issuance")?
            .claims
            .expires_at_unix_seconds(),
    };
    let encoded = chio_core::canonical_json_bytes(&sample)?;
    if encoded.len() > 4096 {
        return Err("closure sample exceeded its diagnostic bound".into());
    }
    eprintln!("host closure numeric={}", std::str::from_utf8(&encoded)?);
    Ok(())
}

fn retained_execution_mode(
    fixture: &RecoveryFixture,
    retained: &RetainedHostInput,
) -> TestResult<RecoveryCommandContinuationMode> {
    // Keep authenticated selection/custody decoding outside the async driver
    // frame. This owning replay must not charge another request or native slot.
    let actor = authenticated_actor(fixture, RecoveryPermission::Resume)?;
    let before = host_snapshot(fixture)?;
    let outcome = fixture
        .kernel
        .execute_recovery_command_outcome_with_origin(
            &actor,
            &retained.first_resume,
            &fixture.process,
        )?;
    let selected = fixture
        .kernel
        .read_recovery_command_selection(&actor, outcome.selection())?;
    let mode = selected.mode();
    assert_eq!(mode, RecoveryCommandContinuationMode::SameCurrentGeneration);
    assert_eq!(
        host_snapshot(fixture)?,
        before,
        "retained driver selection changed facts before dispatch"
    );
    Ok(mode)
}

#[derive(Clone, Copy)]
enum ClosedFate {
    Completed,
    Cancelled,
    RotatedCompleted,
    RotatedCancelled,
}

async fn close_naturally(
    fixture: &RecoveryFixture,
    retained: &RetainedHostInput,
    fate: ClosedFate,
) -> TestResult {
    let workflow = &retained.workflow.workflow_id;
    let current = fixture.record(workflow)?;
    match fate {
        ClosedFate::Completed | ClosedFate::RotatedCompleted => {
            let mode = retained_execution_mode(fixture, retained)?;
            observe_closure_sample(fixture, retained, 1, mode, None)?;
            // The original execution request may drive its fixed continuation.
            // A fresh alias identity must never be used as a completion driver.
            let response = Box::pin(
                fixture
                    .runtime
                    .execute_command(&fixture.control, &retained.first_resume),
            )
            .await?;
            observe_closure_sample(fixture, retained, 2, mode, Some(&response))?;
            assert!(matches!(
                response.status.effect,
                EffectObservationV1::Complete { .. }
            ));
            assert!(response
                .original_response
                .as_ref()
                .ok_or("real native response")?
                .receipt
                .verify_signature()?);
            let terminal = fixture.record(workflow)?;
            assert!(terminal.admission_closed);
            assert!(matches!(
                terminal.effect,
                EffectObservationV1::Complete { .. }
            ));
            assert!(matches!(
                terminal.release,
                ReleaseDispositionV1::Released { .. }
            ));
            assert_eq!(external_count(&fixture.path)?, 1);
            require_original_terminal_receipt(fixture, &retained.workflow)?;
            let admission = retained
                .workflow
                .admission
                .as_ref()
                .ok_or("native intent")?;
            let operation = fixture
                .authority
                .admission_operation_store()
                .load_by_operation_id(
                    &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                        admission.native_operation_id.as_str(),
                    )?,
                )?
                .ok_or("real completed native operation")?;
            assert_eq!(operation.state(), AdmissionOperationState::Completed);
        }
        ClosedFate::Cancelled | ClosedFate::RotatedCancelled => {
            Box::pin(fixture.execute(
                "host-replay-cancel",
                RecoveryCommandBodyV1::CancelWorkflow {
                    workflow_id: workflow.clone(),
                    expected_revision: current.revision,
                },
            ))
            .await?;
            fixture.runtime.settle(&fixture.control, workflow)?;
            let terminal = fixture.record(workflow)?;
            assert_eq!(terminal.control, WorkflowControlV1::Cancelled);
            assert!(terminal.admission_closed);
            assert_eq!(terminal.effect, EffectObservationV1::NeverAdmitted);
            assert!(!terminal.captured);
            assert_eq!(external_count(&fixture.path)?, 0);
            let admission = retained
                .workflow
                .admission
                .as_ref()
                .ok_or("native intent")?;
            assert!(fixture
                .authority
                .admission_operation_store()
                .load_by_operation_id(
                    &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                        admission.native_operation_id.as_str()
                    )?,
                )?
                .is_none());
        }
    }
    assert_eq!(fixture.process.process("root")?.tree_calls, 2);
    Ok(())
}

async fn replay_after_closure(port: HostPort, fate: ClosedFate) -> TestResult {
    let directory = tempfile::tempdir()?;
    let (fixture, retained) = Box::pin(prepared_fixture(directory.path())).await?;
    assert_retained_replay(&fixture, &retained, port, "prepared-positive")?;
    Box::pin(close_naturally(&fixture, &retained, fate)).await?;
    let expected_effects = external_count(&fixture.path)?;
    let fixture = if matches!(
        fate,
        ClosedFate::RotatedCancelled | ClosedFate::RotatedCompleted
    ) {
        let old_control = fixture.control.clone();
        let old_profile = fixture
            .kernel
            .recovery_deployment(fixture.runtime.scope())?;
        drop(fixture);
        for rotation in [
            DeploymentRotation::Actor,
            DeploymentRotation::Aggregate,
            DeploymentRotation::Coverage,
        ] {
            rotate_deployment(directory.path(), &retained.workflow.scope, rotation)?;
        }
        let mut reopened = Box::new(RecoveryFixture::open(
            directory.path().to_path_buf(),
            None,
            false,
        )?);
        reopened.control = current_control(&reopened)?;
        let current = reopened
            .kernel
            .recovery_deployment(reopened.runtime.scope())?;
        assert_ne!(current.aggregate_issuer, old_profile.aggregate_issuer);
        assert_ne!(
            current.coverage.as_slice()[0].key,
            old_profile.coverage.as_slice()[0].key
        );
        assert_ne!(reopened.control.subject, old_control.subject);
        let before = host_snapshot(&reopened)?;
        assert!(reopened
            .kernel
            .authenticate_recovery_actor(reopened.runtime.scope(), &old_control, port.permission())
            .is_err());
        assert_eq!(
            host_snapshot(&reopened)?,
            before,
            "old actor authentication changed facts"
        );
        let terminal = reopened.record(&retained.workflow.workflow_id)?;
        assert!(terminal.admission_closed);
        match fate {
            ClosedFate::RotatedCompleted => {
                assert!(matches!(
                    terminal.effect,
                    EffectObservationV1::Complete { .. }
                ));
                assert!(matches!(
                    terminal.release,
                    ReleaseDispositionV1::Released { .. }
                ));
                require_original_terminal_receipt(&reopened, &retained.workflow)?;
            }
            ClosedFate::RotatedCancelled => {
                assert_eq!(terminal.control, WorkflowControlV1::Cancelled);
                assert_eq!(terminal.effect, EffectObservationV1::NeverAdmitted);
            }
            ClosedFate::Completed | ClosedFate::Cancelled => {
                return Err("rotation fixture selected an unrotated fate".into())
            }
        }
        reopened
    } else {
        fixture
    };
    let phase = match fate {
        ClosedFate::Completed => "native-completed",
        ClosedFate::Cancelled => "naturally-cancelled",
        ClosedFate::RotatedCompleted => "native-completed-current-actor-issuer-coverage",
        ClosedFate::RotatedCancelled => "cancelled-current-actor-issuer-coverage",
    };
    // Repeat the actual owning port, not a generic control-command replay.
    assert_retained_replay(&fixture, &retained, port, phase)?;
    assert_retained_replay(&fixture, &retained, port, phase)?;
    assert_changed_retained_input_refused(&fixture, &retained, port, phase)?;
    assert_eq!(external_count(&fixture.path)?, expected_effects);
    assert_eq!(fixture.process.process("root")?.tree_calls, 2);
    Ok(())
}

macro_rules! retained_host_test {
    ($name:ident, $port:ident, $fate:ident) => {
        #[tokio::test]
        async fn $name() -> TestResult {
            Box::pin(replay_after_closure(HostPort::$port, ClosedFate::$fate)).await
        }
    };
}
retained_host_test!(
    retained_review_survives_native_completion,
    Review,
    Completed
);
retained_host_test!(
    retained_reservation_survives_native_completion,
    Reservation,
    Completed
);
retained_host_test!(
    retained_action_survives_native_completion,
    Materialization,
    Completed
);
retained_host_test!(
    retained_issuance_survives_native_completion,
    Issuance,
    Completed
);
retained_host_test!(
    retained_signature_survives_native_completion,
    Signature,
    Completed
);
retained_host_test!(
    retained_envelope_survives_native_completion,
    Envelope,
    Completed
);
retained_host_test!(retained_review_survives_control_closure, Review, Cancelled);
retained_host_test!(
    retained_reservation_survives_control_closure,
    Reservation,
    Cancelled
);
retained_host_test!(
    retained_action_survives_control_closure,
    Materialization,
    Cancelled
);
retained_host_test!(
    retained_issuance_survives_control_closure,
    Issuance,
    Cancelled
);
retained_host_test!(
    retained_signature_survives_control_closure,
    Signature,
    Cancelled
);
retained_host_test!(
    retained_envelope_survives_control_closure,
    Envelope,
    Cancelled
);
retained_host_test!(
    retained_review_survives_current_profile_rotation,
    Review,
    RotatedCancelled
);
retained_host_test!(
    retained_reservation_survives_current_profile_rotation,
    Reservation,
    RotatedCancelled
);
retained_host_test!(
    retained_action_survives_current_profile_rotation,
    Materialization,
    RotatedCancelled
);
retained_host_test!(
    retained_issuance_survives_current_profile_rotation,
    Issuance,
    RotatedCancelled
);
retained_host_test!(
    retained_signature_survives_current_profile_rotation,
    Signature,
    RotatedCancelled
);
retained_host_test!(
    retained_envelope_survives_current_profile_rotation,
    Envelope,
    RotatedCancelled
);

retained_host_test!(
    retained_review_survives_native_completion_with_current_profile,
    Review,
    RotatedCompleted
);
retained_host_test!(
    retained_reservation_survives_native_completion_with_current_profile,
    Reservation,
    RotatedCompleted
);
retained_host_test!(
    retained_action_survives_native_completion_with_current_profile,
    Materialization,
    RotatedCompleted
);
retained_host_test!(
    retained_issuance_survives_native_completion_with_current_profile,
    Issuance,
    RotatedCompleted
);
retained_host_test!(
    retained_signature_survives_native_completion_with_current_profile,
    Signature,
    RotatedCompleted
);
retained_host_test!(
    retained_envelope_survives_native_completion_with_current_profile,
    Envelope,
    RotatedCompleted
);

#[tokio::test]
async fn retained_host_ports_refuse_wrong_permission_without_progress() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (fixture, retained) = Box::pin(prepared_fixture(directory.path())).await?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Inspect,
    )?;
    for port in HostPort::ALL {
        assert_retained_replay(&fixture, &retained, port, "prepared-positive")?;
        assert_refused_without_progress(&fixture, &actor, &retained, port, "wrong-permission")?;
    }
    Ok(())
}

#[tokio::test]
async fn retained_host_ports_refuse_foreign_actor_without_progress() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (fixture, retained) = Box::pin(prepared_fixture(directory.path())).await?;
    let foreign = Box::new(RecoveryFixture::new(false)?);
    assert_ne!(
        foreign.runtime.scope().authority_domain,
        fixture.runtime.scope().authority_domain
    );
    for port in HostPort::ALL {
        assert_retained_replay(&fixture, &retained, port, "prepared-positive")?;
        let actor = authenticated_host_actor(&foreign, port)?;
        let foreign_before = host_snapshot(&foreign)?;
        assert_refused_without_progress(&fixture, &actor, &retained, port, "foreign-authority")?;
        assert_eq!(host_snapshot(&foreign)?, foreign_before);
    }
    Ok(())
}

async fn refuse_after_audience_loss(port: HostPort) -> TestResult {
    // Active retained state isolates audience refusal from terminal gates.
    let directory = tempfile::tempdir()?;
    let (fixture, retained) = Box::pin(prepared_fixture(directory.path())).await?;
    assert_retained_replay(&fixture, &retained, port, "prepared-positive")?;
    let mut profile = fixture
        .kernel
        .recovery_deployment(fixture.runtime.scope())?;
    let mut actors = profile.actors.as_slice().to_vec();
    let controller = actors
        .iter_mut()
        .find(|assignment| assignment.subject == fixture.control.subject)
        .ok_or("current controller")?;
    controller.preview_clearance = InformationLabel::bottom();
    profile.actors = NonEmptyBoundedList::new(actors)?;
    profile.authority_scope = recovery_authority_scope_digest(&profile)?;
    fixture
        .authority
        .admission_operation_store()
        .configure_recovery_deployment(&profile)?;
    let actor = authenticated_host_actor(&fixture, port)?;
    assert!(fixture
        .kernel
        .read_recovery_workflow(&actor, &retained.workflow.workflow_id)
        .is_err());
    assert_refused_without_progress(&fixture, &actor, &retained, port, "current-audience-loss")?;
    Ok(())
}

macro_rules! audience_host_test {
    ($name:ident, $port:ident) => {
        #[tokio::test]
        async fn $name() -> TestResult {
            Box::pin(refuse_after_audience_loss(HostPort::$port)).await
        }
    };
}
audience_host_test!(retained_review_rechecks_current_audience, Review);
audience_host_test!(retained_reservation_rechecks_current_audience, Reservation);
audience_host_test!(retained_action_rechecks_current_audience, Materialization);
audience_host_test!(retained_issuance_rechecks_current_audience, Issuance);
audience_host_test!(retained_signature_rechecks_current_audience, Signature);
audience_host_test!(retained_envelope_rechecks_current_audience, Envelope);

#[tokio::test]
async fn retained_host_ports_recheck_revoked_actor_without_progress() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (fixture, retained) = Box::pin(prepared_fixture(directory.path())).await?;
    let actors = HostPort::ALL
        .into_iter()
        .map(|port| authenticated_host_actor(&fixture, port))
        .collect::<TestResult<Vec<_>>>()?;
    for port in HostPort::ALL {
        assert_retained_replay(&fixture, &retained, port, "prepared-positive")?;
    }
    fixture.kernel.revoke_capability(&fixture.control.id)?;
    for (port, actor) in HostPort::ALL.into_iter().zip(actors) {
        assert_refused_without_progress(&fixture, &actor, &retained, port, "revoked-actor")?;
    }
    Ok(())
}

#[tokio::test]
async fn retained_host_ports_refuse_damaged_physical_history_without_progress() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (fixture, retained) = Box::pin(prepared_fixture(directory.path())).await?;
    let actors = HostPort::ALL
        .into_iter()
        .map(|port| authenticated_host_actor(&fixture, port))
        .collect::<TestResult<Vec<_>>>()?;
    for port in HostPort::ALL {
        assert_retained_replay(&fixture, &retained, port, "prepared-positive")?;
    }
    let mut connection = Connection::open(fixture.path.join("admission.db"))?;
    let tx = connection.transaction()?;
    tx.execute_batch("DROP TRIGGER admission_operation_recovery_event_no_update")?;
    let changed = tx.execute(
        "UPDATE admission_operation_recovery_events SET event_digest=printf('%064d',0) WHERE sequence=1",
        [],
    )?;
    assert_eq!(
        changed, 1,
        "negative fixture must damage an actual existing history row"
    );
    tx.commit()?;
    drop(connection);
    // This deliberately invalidates real protected history and its schema.
    // It supplies no positive projection, owner, authority or fabricated row.
    for (port, actor) in HostPort::ALL.into_iter().zip(actors) {
        assert_refused_without_progress(
            &fixture,
            &actor,
            &retained,
            port,
            "damaged-current-history",
        )?;
    }
    Ok(())
}

/// Observe the actual physical source already authenticated by preparation.
/// This helper reads one bounded existing row and never fabricates custody.
fn retained_host_source_digest(
    fixture: &RecoveryFixture,
    retained: &RetainedHostInput,
) -> TestResult<[u8; 32]> {
    let max_source_bytes = i64::try_from(chio_kernel::recovery::MAX_RECOVERY_RECORD_BYTES)?;
    let scope = chio_core::sha256_hex(&chio_core::canonical_json_bytes(&retained.workflow.scope)?);
    let key = format!(
        "workflow:{scope}:{}",
        retained.workflow.workflow_id.as_str()
    );
    let expected = chio_core::canonical_json_bytes(&retained.workflow)?;
    let connection = Connection::open_with_flags(
        fixture.path.join("admission.db"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let (version, digest, same): (i64, [u8; 32], bool) = connection.query_row(
        "SELECT version,length(payload),payload FROM admission_operation_recovery_records
         WHERE record_key=?1 AND scope_key=?2 AND kind='workflow'",
        rusqlite::params![key, scope],
        |row| {
            let length: i64 = row.get(1)?;
            if length <= 0 || length > max_source_bytes {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let payload = row.get_ref(2)?;
            let payload = match payload {
                ValueRef::Text(bytes) | ValueRef::Blob(bytes) => bytes,
                _ => return Err(rusqlite::Error::InvalidQuery),
            };
            Ok((
                row.get(0)?,
                *chio_core::sha256(payload).as_bytes(),
                payload == expected.as_slice(),
            ))
        },
    )?;
    assert!(version == i64::try_from(retained.workflow.revision.get())?);
    assert!(
        same,
        "genuine later work changed the original physical workflow"
    );
    Ok(digest)
}

struct InheritedSourceExecution {
    command: Box<RecoveryCommandV1>,
    prepared: Box<RecoveryWorkflowRecordV1>,
}

fn prepare_inherited_source_execution(
    fixture: &RecoveryFixture,
    workflow: &WorkflowId,
) -> TestResult<InheritedSourceExecution> {
    let current = Box::new(fixture.record(workflow)?);
    assert!(current.admission.is_none());
    assert!(!current.captured);
    assert!(!current.admission_closed);
    let command = Box::new(fixture.command(
        "host-inherited-first-resume",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: workflow.clone(),
            expected_revision: current.revision,
        },
    )?);
    let actor = authenticated_actor(fixture, RecoveryPermission::Resume)?;
    let outcome = fixture
        .kernel
        .execute_recovery_command_outcome_with_origin(&actor, &command, &fixture.process)?;
    assert_eq!(
        outcome.selection().mode(),
        RecoveryCommandContinuationMode::SameCurrentGeneration
    );
    let selected = fixture
        .kernel
        .read_recovery_command_selection(&actor, outcome.selection())?;
    assert_eq!(
        selected.mode(),
        RecoveryCommandContinuationMode::SameCurrentGeneration
    );
    assert_eq!(selected.record().effect, EffectObservationV1::NeverAdmitted);
    assert!(selected.record().admission.is_none());
    assert!(!selected.record().captured);
    assert_eq!(external_count(&fixture.path)?, 0);
    assert_eq!(fixture.process.process("root")?.tree_calls, 4);
    let signing = ObserveSigning::new();
    let custody =
        crate::recovery::freeze_original_for_test(&fixture.runtime, &fixture.control, workflow)?;
    assert_eq!(
        signing.count()?,
        1,
        "real later native preparation must sign once"
    );
    drop(signing);
    let prepared = Box::new(fixture.record(workflow)?);
    let profile = fixture
        .kernel
        .recovery_deployment(fixture.runtime.scope())?;
    let identity = fixture
        .kernel
        .recovery_native_identity(custody.request(), &profile.security_context)?;
    assert!(
        prepared
            .admission
            .as_ref()
            .ok_or("later native intent")?
            .native_binding
            == identity.binding().to_persisted(),
        "later native preparation lost its actual custody binding"
    );
    Ok(InheritedSourceExecution { command, prepared })
}

async fn refuse_after_current_inherited_restriction(port: HostPort) -> TestResult {
    let directory = tempfile::tempdir()?;
    let (fixture, retained) = Box::pin(prepared_fixture(directory.path())).await?;
    assert_retained_replay(&fixture, &retained, port, "before-later-native-source")?;
    let source_before = retained_host_source_digest(&fixture, &retained)?;
    let profile_before = Box::new(
        fixture
            .kernel
            .recovery_deployment(fixture.runtime.scope())?,
    );
    let actor_before = authenticated_host_actor(&fixture, port)?;
    let clearance = profile_before
        .actors
        .as_slice()
        .iter()
        .find(|assignment| assignment.principal == *actor_before.principal())
        .ok_or("original current clearance")?
        .preview_clearance
        .clone();
    let old_source = retained
        .workflow
        .action
        .as_ref()
        .ok_or("original retained Action")?
        .authorization_requirements
        .source_label
        .clone();
    assert!(old_source.flows_to(&clearance));
    drop(fixture);

    // Change only the genuine output classifier for another actual effect.
    // Its native completion, not a SQL label edit, creates inherited taint.
    set_output_floor(directory.path(), &output_only_label()?)?;
    let fixture = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    let later =
        Box::pin(fixture.ready_named("host-inherited-native-source", "host-inherited")).await?;
    let execution = Box::new(prepare_inherited_source_execution(&fixture, &later)?);
    let result = Box::pin(
        fixture
            .runtime
            .execute_command(&fixture.control, &execution.command),
    )
    .await;
    assert!(
        matches!(result, Err(RecoveryRuntimeError::AuthorityDenied)),
        "later native output must reach current audience refusal"
    );
    let native = execution
        .prepared
        .admission
        .as_ref()
        .ok_or("later retained native intent")?;
    let operation = fixture
        .authority
        .admission_operation_store()
        .load_by_operation_id(
            &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                native.native_operation_id.as_str(),
            )?,
        )?
        .ok_or("later genuine completed native operation")?;
    assert_eq!(operation.state(), AdmissionOperationState::Completed);
    assert!(operation.dispatch_commit().is_some());
    assert!(operation.terminal_replay().is_some());
    require_original_terminal_receipt(&fixture, &execution.prepared)?;
    assert_eq!(external_count(&fixture.path)?, 1);
    assert_eq!(fixture.effects.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.process.process("root")?.tree_calls, 4);
    assert!(retained_host_source_digest(&fixture, &retained)? == source_before);
    drop(fixture);

    // Restore the classifier to public. Persisted inherited restrictions alone
    // must refuse the old reply under an unchanged freshly authenticated actor.
    set_output_floor(directory.path(), &InformationLabel::bottom())?;
    let fixture = Box::new(RecoveryFixture::open(
        directory.path().to_path_buf(),
        None,
        false,
    )?);
    let profile = fixture
        .kernel
        .recovery_deployment(fixture.runtime.scope())?;
    assert!(
        chio_core::canonical_json_bytes(&profile)?
            == chio_core::canonical_json_bytes(&profile_before)?,
        "the current actor or deployment changed instead of inherited taint"
    );
    let actor = authenticated_host_actor(&fixture, port)?;
    let assignment = profile
        .actors
        .as_slice()
        .iter()
        .find(|assignment| assignment.principal == *actor.principal())
        .ok_or("unchanged current actor clearance")?;
    assert!(assignment.preview_clearance == clearance);
    assert!(old_source.flows_to(&assignment.preview_clearance));
    let observation = fixture
        .kernel
        .observe_recovery_source(fixture.runtime.scope())?;
    let inherited = observation
        .snapshot()
        .ok_or("actual current inherited flow")?;
    let inherited = inherited
        .principal_label
        .join_restrictions(&inherited.lineage_label)?
        .join_restrictions(&inherited.session_label)?;
    assert!(
        !inherited.flows_to(&assignment.preview_clearance),
        "the genuine later effect did not raise current inherited restrictions"
    );
    assert!(retained_host_source_digest(&fixture, &retained)? == source_before);
    assert!(matches!(
        fixture
            .kernel
            .read_recovery_workflow(&actor, &retained.workflow.workflow_id),
        Err(KernelError::RecoveryAuthorityDenied)
    ));
    assert_refused_without_progress(
        &fixture,
        &actor,
        &retained,
        port,
        "current-inherited-restriction",
    )?;
    assert_eq!(external_count(&fixture.path)?, 1);
    assert_eq!(fixture.process.process("root")?.tree_calls, 4);
    Ok(())
}

macro_rules! inherited_audience_host_test {
    ($name:ident, $port:ident) => {
        #[tokio::test]
        async fn $name() -> TestResult {
            Box::pin(refuse_after_current_inherited_restriction(HostPort::$port)).await
        }
    };
}
inherited_audience_host_test!(
    retained_review_rechecks_current_inherited_restrictions,
    Review
);
inherited_audience_host_test!(
    retained_reservation_rechecks_current_inherited_restrictions,
    Reservation
);
inherited_audience_host_test!(
    retained_action_rechecks_current_inherited_restrictions,
    Materialization
);
inherited_audience_host_test!(
    retained_issuance_rechecks_current_inherited_restrictions,
    Issuance
);
inherited_audience_host_test!(
    retained_signature_rechecks_current_inherited_restrictions,
    Signature
);
inherited_audience_host_test!(
    retained_envelope_rechecks_current_inherited_restrictions,
    Envelope
);

fn retained_store_refusal_class<T>(
    result: &Result<T, chio_kernel::admission_operation::AdmissionOperationStoreError>,
) -> u8 {
    use chio_kernel::admission_operation::AdmissionOperationStoreError;
    match result {
        Ok(_) => 0,
        Err(AdmissionOperationStoreError::RecoveryAuthorityDenied) => 1,
        Err(AdmissionOperationStoreError::NotFound) => 2,
        Err(AdmissionOperationStoreError::Invariant(_)) => 3,
        Err(_) => 4,
    }
}

// Closed diagnostic codes carry no workflow, authority or dynamic error data.
// The guard tag identifies only two exact serving-owner refusal messages.
fn retained_store_failure_diagnostic<T>(
    result: &Result<T, chio_kernel::admission_operation::AdmissionOperationStoreError>,
) -> (u8, u8) {
    use chio_kernel::admission_operation::AdmissionOperationStoreError;
    match result {
        Ok(_) => (0, 0),
        Err(AdmissionOperationStoreError::RecoveryAuthorityDenied) => (1, 0),
        Err(AdmissionOperationStoreError::NotFound) => (2, 0),
        Err(AdmissionOperationStoreError::Invariant(_)) => (3, 0),
        Err(AdmissionOperationStoreError::Unavailable(_)) => (4, 0),
        Err(AdmissionOperationStoreError::Fenced) => (5, 0),
        Err(AdmissionOperationStoreError::OutcomeUnknown(reason)) => {
            let guard = match reason.as_str() {
                "authority database changed outside its serving-owner connection" => 1,
                "sqlite authority owner is poisoned after an outcome-unknown anchor sync" => 2,
                _ => 0,
            };
            (6, guard)
        }
        Err(AdmissionOperationStoreError::RecoveryMediationRequired) => (7, 0),
        Err(AdmissionOperationStoreError::Operation(_)) => (8, 0),
    }
}

#[derive(Clone, Copy)]
enum RetainedSourceDamage {
    EventDigest,
    WorkflowProjection,
}

fn exact_review_workflow_key(
    retained: &RetainedHostInput,
    workflow: &WorkflowId,
) -> TestResult<String> {
    let scope = chio_core::sha256_hex(&chio_core::canonical_json_bytes(&retained.workflow.scope)?);
    Ok(format!("workflow:{scope}:{}", workflow.as_str()))
}

fn require_genuinely_absent_review_workflow(
    fixture: &RecoveryFixture,
    retained: &RetainedHostInput,
    absent: &WorkflowId,
) -> TestResult {
    let key = exact_review_workflow_key(retained, absent)?;
    let connection = Connection::open_with_flags(
        fixture.path.join("admission.db"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let (physical, history): (bool, bool) = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records WHERE record_key=?1),
                EXISTS(SELECT 1 FROM admission_operation_recovery_events WHERE record_key=?1)",
        [key],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert!(
        !physical && !history,
        "absent control has actual retained ownership"
    );
    Ok(())
}

/// Damage only genuine existing custody in a disposable negative fixture.
/// Restore the exact trigger so the owning data check, not missing DDL, refuses.
fn damage_retained_review_source(
    fixture: &RecoveryFixture,
    retained: &RetainedHostInput,
    damage: RetainedSourceDamage,
) -> TestResult {
    let key = exact_review_workflow_key(retained, &retained.workflow.workflow_id)?;
    let mut connection = Connection::open(fixture.path.join("admission.db"))?;
    // This negative mutation leaves immutable references behind deliberately.
    // It never creates positive ownership or supplies production write authority.
    connection.pragma_update(None, "foreign_keys", false)?;
    let tx = connection.transaction()?;
    let trigger = match damage {
        RetainedSourceDamage::EventDigest => "admission_operation_recovery_event_no_update",
        RetainedSourceDamage::WorkflowProjection => "admission_operation_recovery_no_delete",
    };
    let actual_sql: String = tx.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?1",
        [trigger],
        |row| row.get(0),
    )?;
    if actual_sql.is_empty() || actual_sql.len() > 16 * 1024 {
        return Err("negative review fixture has an unbounded trigger".into());
    }
    let changed = match damage {
        RetainedSourceDamage::EventDigest => {
            tx.execute_batch("DROP TRIGGER admission_operation_recovery_event_no_update")?;
            tx.execute(
                "UPDATE admission_operation_recovery_events SET record_digest=printf('%064d',0)
                 WHERE sequence=(SELECT max(sequence) FROM admission_operation_recovery_events
                                 WHERE record_key=?1)",
                [&key],
            )?
        }
        RetainedSourceDamage::WorkflowProjection => {
            tx.execute_batch("DROP TRIGGER admission_operation_recovery_no_delete")?;
            tx.execute(
                "DELETE FROM admission_operation_recovery_records
                 WHERE record_key=?1 AND kind='workflow'",
                [&key],
            )?
        }
    };
    assert_eq!(changed, 1, "negative control must damage one real source");
    tx.execute_batch(&actual_sql)?;
    let restored: String = tx.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?1",
        [trigger],
        |row| row.get(0),
    )?;
    assert!(
        restored == actual_sql,
        "negative control changed the canonical trigger"
    );
    let retained_events: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_events WHERE record_key=?1)",
        [&key],
        |row| row.get(0),
    )?;
    assert!(
        retained_events,
        "damaged source lost its actual immutable ownership"
    );
    tx.commit()?;
    Ok(())
}

#[tokio::test]
async fn retained_review_coarsens_genuine_absence_and_hidden_workflow() -> TestResult {
    use chio_kernel::admission_operation::AdmissionOperationStoreError;
    use chio_kernel::recovery::RecoveryAuthorityPort;
    for damage in [
        RetainedSourceDamage::EventDigest,
        RetainedSourceDamage::WorkflowProjection,
    ] {
        let directory = tempfile::tempdir()?;
        let (fixture, retained) = Box::pin(prepared_fixture(directory.path())).await?;
        assert_retained_replay(
            &fixture,
            &retained,
            HostPort::Review,
            "visible-review-positive",
        )?;
        let original_source = retained_host_source_digest(&fixture, &retained)?;
        let absent = WorkflowId::new("workflow:absent-retained-review-control")?;
        assert!(absent != retained.workflow.workflow_id);
        require_genuinely_absent_review_workflow(&fixture, &retained, &absent)?;

        let mut profile = fixture
            .kernel
            .recovery_deployment(fixture.runtime.scope())?;
        let mut actors = profile.actors.as_slice().to_vec();
        let controller = actors
            .iter_mut()
            .find(|assignment| assignment.subject == fixture.control.subject)
            .ok_or("current review controller")?;
        controller.preview_clearance = InformationLabel::bottom();
        profile.actors = NonEmptyBoundedList::new(actors)?;
        profile.authority_scope = recovery_authority_scope_digest(&profile)?;
        fixture
            .authority
            .admission_operation_store()
            .configure_recovery_deployment(&profile)?;
        let actor = authenticated_actor(&fixture, RecoveryPermission::Approve)?;
        let old_source = &retained
            .workflow
            .action
            .as_ref()
            .ok_or("real review Action")?
            .authorization_requirements
            .source_label;
        assert!(!old_source.flows_to(&InformationLabel::bottom()));
        assert!(retained_host_source_digest(&fixture, &retained)? == original_source);

        let store = fixture.authority.admission_operation_store();
        let fence = fixture.authority.mutation_fence();
        let review = retained
            .workflow
            .review
            .as_ref()
            .ok_or("real retained review")?;
        let before = host_snapshot(&fixture)?;
        let signing = ObserveSigning::new();
        let hidden_reader = Box::new(store.load_workflow(
            &actor,
            &retained.workflow.workflow_id,
            &fence,
            now_ms()?,
        ));
        let absent_reader = Box::new(store.load_workflow(&actor, &absent, &fence, now_ms()?));
        let hidden = Box::new(store.reserve_review(
            &actor,
            &retained.workflow.workflow_id,
            review,
            &fence,
            now_ms()?,
        ));
        let absent_result =
            Box::new(store.reserve_review(&actor, &absent, review, &fence, now_ms()?));
        let signed = signing.count()?;
        drop(signing);
        assert_eq!(host_snapshot(&fixture)?, before);
        assert_eq!(signed, 0);
        eprintln!(
            "retained review visibility hidden={} absent={} reader_hidden={} reader_absent={}",
            retained_store_refusal_class(&hidden),
            retained_store_refusal_class(&absent_result),
            retained_store_refusal_class(&hidden_reader),
            retained_store_refusal_class(&absent_reader),
        );
        assert!(matches!(
            *hidden_reader,
            Err(AdmissionOperationStoreError::RecoveryAuthorityDenied)
        ));
        assert!(matches!(
            *absent_reader,
            Err(AdmissionOperationStoreError::RecoveryAuthorityDenied)
        ));
        assert!(matches!(
            *hidden,
            Err(AdmissionOperationStoreError::RecoveryAuthorityDenied)
        ));
        assert!(
            matches!(
                *absent_result,
                Err(AdmissionOperationStoreError::RecoveryAuthorityDenied)
            ),
            "retained review exposes genuine absence versus a hidden workflow"
        );

        // Neither damaged history nor a missing owned projection is pristine.
        // Keep the same actual actor and retained inputs; only this real source
        // is damaged, and the source's canonical protection is restored.
        damage_retained_review_source(&fixture, &retained, damage)?;
        let damaged_before = host_snapshot(&fixture)?;
        let signing = ObserveSigning::new();
        let corrupt_reader = Box::new(store.load_workflow(
            &actor,
            &retained.workflow.workflow_id,
            &fence,
            now_ms()?,
        ));
        let corrupt_reply = Box::new(store.reserve_review(
            &actor,
            &retained.workflow.workflow_id,
            review,
            &fence,
            now_ms()?,
        ));
        let signed = signing.count()?;
        drop(signing);
        assert_eq!(host_snapshot(&fixture)?, damaged_before);
        assert_eq!(signed, 0);
        let (reader_class, reader_guard) = retained_store_failure_diagnostic(&corrupt_reader);
        let (reply_class, reply_guard) = retained_store_failure_diagnostic(&corrupt_reply);
        let damage_code = match damage {
            RetainedSourceDamage::EventDigest => 0,
            RetainedSourceDamage::WorkflowProjection => 1,
        };
        eprintln!(
            "retained review damaged source kind={} reader_class={} reader_guard={} reply_class={} reply_guard={}",
            damage_code, reader_class, reader_guard, reply_class, reply_guard,
        );
        assert!(
            matches!(
                *corrupt_reader,
                Err(AdmissionOperationStoreError::Invariant(_))
            ),
            "canonical reader coarsened actual damaged custody"
        );
        assert!(
            matches!(
                *corrupt_reply,
                Err(AdmissionOperationStoreError::Invariant(_))
            ),
            "retained review coarsened actual damaged custody into hidden or pristine absence"
        );
        assert_eq!(external_count(&fixture.path)?, 0);
        assert_eq!(fixture.process.process("root")?.tree_calls, 2);
    }
    Ok(())
}
