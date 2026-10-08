//! Valid originals are controls. External corruption poisons the serving owner.
//! Those refusals occur before selection; private store controls pin its branches.
use super::*;
use crate::authority_ipc::BrokerAdmissionAuthority;
use crate::kernel_admission::BrokerKernelAdmissionAuthority;
use chio_kernel::supplemental_admission::SupplementalAdmissionAuthorityBindingV1;
use chio_kernel::supplemental_quota::supplemental_authorization_artifact_digest;

pub(super) struct LiveControls {
    wrong_native: BrokerKernelAdmissionAuthority,
    wrong_participant: BrokerKernelAdmissionAuthority,
}

pub(super) struct LiveReport {
    wrong_native: crate::Result<crate::service::TrustedExecutionContext>,
    wrong_participant: crate::Result<crate::service::TrustedExecutionContext>,
}

impl LiveControls {
    pub(super) fn new(
        authority: &SqliteAuthorityStore,
        native: &NativeSecurityAuthorityBindingV1,
        participant: &Arc<BrokerAdmissionParticipant>,
        verifier: &BrokerQuotaVerifier,
        directory: &Path,
    ) -> TestResult<Self> {
        let other_native = NativeSecurityAuthorityBindingV1::new(
            native.store_uuid().clone(),
            AdmissionIdentifier::try_new("authority", "other-selector-authority")?,
            native.initialization_digest().clone(),
        );
        let wrong_native = BrokerKernelAdmissionAuthority::new(
            BrokerNativeCaptureReader::new(authority, other_native, participant.binding().clone())?,
            participant.clone(),
        )?;
        let other_participant = Arc::new(BrokerAdmissionParticipant::new(
            BrokerIpcClientConfig {
                socket_path: directory.join("other-broker.sock"),
                tenant_scope: "other-broker-original-selection".into(),
                timeout_ms: 1000,
                expected_peer: BrokerPeerIdentity {
                    process_id: 100,
                    user_id: 1000,
                    group_id: 1000,
                },
                trusted_receipt_signer: Keypair::from_seed(&[35; 32]).public_key(),
            },
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[34; 32]))),
            "broker-revocation-domain".into(),
            verifier,
        )?);
        assert_ne!(participant.binding(), other_participant.binding());
        let wrong_participant = BrokerKernelAdmissionAuthority::new(
            BrokerNativeCaptureReader::new(
                authority,
                native.clone(),
                other_participant.binding().clone(),
            )?,
            other_participant,
        )?;
        Ok(Self {
            wrong_native,
            wrong_participant,
        })
    }

    pub(super) fn observe(&self, request: &BrokerExecuteRequest) -> LiveReport {
        LiveReport {
            wrong_native: self.wrong_native.prepare_execution(request),
            wrong_participant: self.wrong_participant.prepare_execution(request),
        }
    }
}

#[test]
fn wrong_installed_native_and_participant_refuse_the_live_captured_original() -> TestResult {
    let store = DurableStore::provision()?;
    let broker = store.native_broker_with_selector_probe(REQUEST_ID, true)?;
    let response = broker.evaluate(&broker.execute)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    let dispatch = broker.only_dispatch()?;
    let (registration, _) = dispatch
        .registration
        .as_ref()
        .ok_or("original registration")?;
    assert_prepared(&dispatch.prepared, registration, &broker.execute)?;
    assert!(matches!(
        &dispatch.hold,
        Some(Ok(AuthorityResult::Hold(ExecutionHoldState::Captured(_))))
    ));
    let original = dispatch
        .stored
        .iter()
        .find(|operation| operation.binding().operation_id().as_str() == dispatch.operation_id)
        .ok_or("captured original")?;
    assert_eq!(original.state(), AdmissionOperationState::DispatchCommitted);
    let report = dispatch.selector_report.ok_or("selector control report")?;
    for (label, result) in [
        ("native", report.wrong_native),
        ("participant", report.wrong_participant),
    ] {
        assert!(
            matches!(result, Err(BrokerError::AuthorizationDenied(ref message)) if message == INSTALLED_AUTHORITY_REFUSAL),
            "{label}: {result:?}"
        );
    }
    assert_eq!(
        request_operations(&store.database, REQUEST_ID)?,
        vec![dispatch.operation_id]
    );
    assert_eq!(broker.pending_dispatches()?, 0);
    Ok(())
}

struct CompletedOriginal {
    store: DurableStore,
    broker: NativeBroker,
    operation: AdmissionOperationId,
    native: NativeSecurityAuthorityBindingV1,
    participant: SupplementalAdmissionAuthorityBindingV1,
    digest: String,
}

impl CompletedOriginal {
    fn new() -> TestResult<Self> {
        let store = DurableStore::provision()?;
        let broker = store.native_broker(REQUEST_ID)?;
        let response = broker.evaluate(&broker.execute)?;
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        let dispatch = broker.only_dispatch()?;
        let (registration, _) = dispatch
            .registration
            .as_ref()
            .ok_or("original registration")?;
        assert_prepared(&dispatch.prepared, registration, &broker.execute)?;
        let operation = AdmissionOperationId::from_persisted(dispatch.operation_id)?;
        let reader = broker._authority.admission_operation_store();
        let now = reader.observed_authority_time()?.get();
        let original = reader
            .load_retained_tool_admission_custody(
                &operation,
                &broker._authority.mutation_fence(),
                now,
            )?
            .ok_or("completed original custody")?;
        let native = original
            .request
            .native_security_authority_binding()
            .cloned()
            .ok_or("original native binding")?;
        let participant = original
            .request
            .authority_profile()
            .supplemental_participant()
            .cloned()
            .ok_or("original participant")?;
        let digest =
            supplemental_authorization_artifact_digest(&canonical_json_bytes(&broker.execute)?);
        let fixture = Self {
            store,
            broker,
            operation,
            native,
            participant,
            digest,
        };
        assert_eq!(
            fixture
                .select(&fixture.digest)?
                .ok_or("exact selected original")?
                .operation
                .binding()
                .operation_id(),
            &fixture.operation
        );
        Ok(fixture)
    }

    fn select(
        &self,
        digest: &str,
    ) -> std::result::Result<
        Option<chio_store_sqlite::admission_operation_store::RetainedToolAdmissionCustodySnapshot>,
        chio_kernel::admission_operation::AdmissionOperationStoreError,
    > {
        let reader = self.broker._authority.admission_operation_store();
        let now = reader.observed_authority_time()?.get();
        reader.load_retained_tool_admission_custody_by_supplemental_artifact(
            digest,
            &self.native,
            &self.participant,
            &self.broker._authority.mutation_fence(),
            now,
        )
    }
}

#[test]
fn malformed_selector_is_integrity_and_external_index_tamper_poisoned() -> TestResult {
    let fixture = CompletedOriginal::new()?;
    assert!(matches!(
        fixture.select(&"a".repeat(63)),
        Err(chio_kernel::admission_operation::AdmissionOperationStoreError::Invariant(_))
    ));
    assert!(matches!(
        fixture.select(&"A".repeat(64)),
        Err(chio_kernel::admission_operation::AdmissionOperationStoreError::Invariant(_))
    ));
    // Corruption injection: replace the named index with a different column
    // order. No admission or production writer creates this catalog state.
    let connection = rusqlite::Connection::open(&fixture.store.database)?;
    connection.execute_batch(
        "DROP INDEX idx_budget_holds_supplemental_artifact;
         CREATE INDEX idx_budget_holds_supplemental_artifact ON budget_authorization_holds(operation_id, supplemental_artifact_digest) WHERE supplemental_artifact_digest IS NOT NULL;",
    )?;
    assert!(matches!(
        fixture.select(&fixture.digest),
        Err(chio_kernel::admission_operation::AdmissionOperationStoreError::OutcomeUnknown(_))
    ));
    assert_eq!(fixture.broker.pending_dispatches()?, 0);
    assert_eq!(
        request_operations(&fixture.store.database, REQUEST_ID)?,
        vec![fixture.operation.as_str().to_owned()]
    );
    Ok(())
}

fn duplicate_hold_index(fixture: &CompletedOriginal) -> TestResult {
    let connection = rusqlite::Connection::open(&fixture.store.database)?;
    // Corruption injection: copy a physical hold under an operation that was
    // never admitted. This is not a claimed reachable duplicate artifact.
    let mut info = connection.prepare("PRAGMA table_info(budget_authorization_holds)")?;
    let columns = info
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    drop(info);
    let select = columns
        .iter()
        .map(|name| match name.as_str() {
            "operation_id" => "'zz-corrupt-selector-operation'".to_owned(),
            "hold_id" => "'corrupt-selector-hold'".to_owned(),
            _ => format!("\"{name}\""),
        })
        .collect::<Vec<_>>()
        .join(", ");
    connection.execute(
        &format!("INSERT INTO budget_authorization_holds SELECT {select} FROM budget_authorization_holds WHERE operation_id = ?1"),
        [fixture.operation.as_str()],
    )?;
    let ids = connection.prepare("SELECT operation_id FROM budget_authorization_holds WHERE supplemental_artifact_digest = ?1 ORDER BY operation_id LIMIT 2")?
        .query_map([&fixture.digest], |row| row.get::<_, String>(0))?.collect::<std::result::Result<Vec<_>, _>>()?;
    assert_eq!(
        ids,
        vec![
            fixture.operation.as_str().to_owned(),
            "zz-corrupt-selector-operation".to_owned()
        ]
    );
    Ok(())
}

#[test]
fn external_corrupt_duplicate_hold_index_poisoning_returns_no_original() -> TestResult {
    let fixture = CompletedOriginal::new()?;
    duplicate_hold_index(&fixture)?;
    assert!(matches!(
        fixture.select(&fixture.digest),
        Err(chio_kernel::admission_operation::AdmissionOperationStoreError::OutcomeUnknown(_))
    ));
    assert_eq!(fixture.broker.pending_dispatches()?, 0);
    assert_eq!(
        request_operations(&fixture.store.database, REQUEST_ID)?,
        vec![fixture.operation.as_str().to_owned()]
    );
    Ok(())
}

#[test]
fn external_oversized_hold_operation_index_poisoning_returns_no_original() -> TestResult {
    let fixture = CompletedOriginal::new()?;
    // Corruption injection: a physical selector ID exceeds the 512-byte
    // bound. The separately retained original request is unchanged.
    let connection = rusqlite::Connection::open(&fixture.store.database)?;
    assert_eq!(
        connection.execute(
            "UPDATE budget_authorization_holds SET operation_id = ?1 WHERE operation_id = ?2",
            rusqlite::params!["x".repeat(513), fixture.operation.as_str()],
        )?,
        1
    );
    assert!(matches!(
        fixture.select(&fixture.digest),
        Err(chio_kernel::admission_operation::AdmissionOperationStoreError::OutcomeUnknown(_))
    ));
    assert_eq!(fixture.broker.pending_dispatches()?, 0);
    assert_eq!(
        request_operations(&fixture.store.database, REQUEST_ID)?,
        vec![fixture.operation.as_str().to_owned()]
    );
    Ok(())
}
