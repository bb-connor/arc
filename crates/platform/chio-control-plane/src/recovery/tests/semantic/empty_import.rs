//! Clean native origins begin with a sealed empty import and an owned input.
use super::*;
use chio_kernel::tool_outcome::ToolOutcomeStore;
use chio_store_sqlite::security_state::SecurityParticipantSourceSnapshot;

const IMPORT_TABLES: [&str; 14] = [
    "security_declassification_evidence_identity",
    "security_declassification_lifecycle",
    "security_declassification_receipt_outbox",
    "security_declassification_tombstones",
    "security_declassification_uses",
    "security_egress_fences",
    "security_flow_contexts",
    "security_flow_sequences",
    "security_isolation_epochs",
    "security_lineage_flow_state",
    "security_principal_flow_state",
    "security_session_flow_state",
    "security_session_memberships",
    "security_transitions",
];

pub(in crate::recovery::tests) async fn native_fixture_from_empty_import(
    kind: &str,
) -> TestResult<RecoveryFixture> {
    native_fixture_from_empty_import_with_optional_payment(kind, None).await
}

pub(in crate::recovery::tests) async fn native_fixture_from_empty_import_with_payment(
    kind: &str,
    adapter: Box<dyn chio_kernel::PaymentAdapter>,
) -> TestResult<RecoveryFixture> {
    native_fixture_from_empty_import_with_optional_payment(kind, Some(adapter)).await
}

async fn native_fixture_from_empty_import_with_optional_payment(
    kind: &str,
    payment_adapter: Option<Box<dyn chio_kernel::PaymentAdapter>>,
) -> TestResult<RecoveryFixture> {
    native_fixture_from_empty_import_with_optional_retention(kind, payment_adapter, None).await
}

pub(in crate::recovery::tests) async fn native_fixture_from_empty_import_with_retention(
    kind: &str,
    profile: &chio_kernel::admission_operation::NativeOutputRetentionProfileV1,
) -> TestResult<RecoveryFixture> {
    native_fixture_from_empty_import_with_optional_retention(kind, None, Some(profile)).await
}

async fn native_fixture_from_empty_import_with_optional_retention(
    kind: &str,
    payment_adapter: Option<Box<dyn chio_kernel::PaymentAdapter>>,
    retention: Option<&chio_kernel::admission_operation::NativeOutputRetentionProfileV1>,
) -> TestResult<RecoveryFixture> {
    if matches!(
        kind,
        "read-weak-manifest" | "read-missing-status" | "annotated-read-weak-manifest"
    ) {
        return Err("public-floor empty genesis requires an independent downstream refusal".into());
    }
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join("semantic-kind"), kind)?;
    std::fs::write(directory.path().join("empty-native-import"), "selected")?;
    if let Some(profile) = retention {
        std::fs::write(
            directory.path().join("output-retention-profile.json"),
            chio_core::canonical_json_bytes(profile)?,
        )?;
    }
    let fixture = match payment_adapter {
        Some(adapter) => RecoveryFixture::open_with_payment_adapter(
            directory.path().to_path_buf(),
            Some(directory),
            false,
            adapter,
        )?,
        None => RecoveryFixture::open(directory.path().to_path_buf(), Some(directory), false)?,
    };
    assert_lifecycle_only_import(&fixture)?;
    let deployment = fixture
        .kernel
        .recovery_deployment(fixture.runtime.scope())?;
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let observed = store.observe_security_participant_flow(
        &deployment.native_authority,
        &recovery_flow_key(&deployment.security_context),
        &fence,
        now_ms()?,
    )?;
    assert!(observed.snapshot().is_none());
    assert_eq!(observed.stored_context_generation(), None);
    let request = fixture.process.tool_request(
        "root",
        "native-input-genesis",
        &fixture.seed.server_id,
        &fixture.seed.tool_name,
        fixture.seed.arguments.clone(),
    )?;
    assert!(request.declassification_grant.is_none());
    assert!(request.execution_nonce.is_none());
    // The real Restricted input joins before the ordinary native flow policy
    // refuses its public destination. An Input guard would deny before the join.
    let denied = Box::pin(fixture.process.invoke_known_only(
        "root",
        "native-input-genesis",
        &request,
    ))
    .await?;
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(denied.receipt.verify_signature()?);
    let (operation, original) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("genuine native genesis original absent")?;
    original.validate_request_material(&request)?;
    original.validate_native_security_authority(&deployment.native_authority)?;
    original.validate_native_security_context(&deployment.security_context)?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    assert!(operation.native_dispatch_ledger_digest().is_none());
    assert!(
        fixture
            .authority
            .tool_outcome_store()
            .load_raw_invocation_by_operation(operation.binding().operation_id())?
            .is_none()
    );
    let input = store
        .load_security_participant_flow_join(operation.binding().operation_id(), &fence, now_ms()?)?
        .ok_or("genuine native first-input journal absent")?;
    assert_eq!(input.operation_id(), operation.binding().operation_id());
    let key = recovery_flow_key(&deployment.security_context);
    assert_eq!(input.historical_snapshot().key, key);
    let observed = store.observe_security_participant_flow(
        &deployment.native_authority,
        &key,
        &fence,
        now_ms()?,
    )?;
    let current = observed
        .snapshot()
        .ok_or("genuine native first input did not create its source")?;
    assert_eq!(current, input.historical_snapshot());
    assert_eq!(
        observed.stored_context_generation(),
        Some(current.context_generation)
    );
    let expected = restricted_label();
    assert_eq!(current.principal_label, expected);
    assert_eq!(current.lineage_label, expected);
    assert_eq!(current.session_label, expected);
    assert_eq!(fixture.effects.load(Ordering::SeqCst), 0);
    assert_eq!(external_count(&fixture.path)?, 0);
    assert_lifecycle_only_import(&fixture)?;
    Ok(fixture)
}

fn retained_import_inventory(fixture: &RecoveryFixture) -> TestResult<Vec<(String, u64)>> {
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let deployment = fixture
        .kernel
        .recovery_deployment(fixture.runtime.scope())?;
    let initialized = store
        .load_security_participant_state(
            deployment.native_authority.security_authority_id(),
            &fence,
            now_ms()?,
        )?
        .ok_or("actual native initialization absent")?;
    assert_eq!(
        initialized.admission_binding()?,
        deployment.native_authority
    );
    let database = rusqlite::Connection::open_with_flags(
        fixture.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let (canonical, digest, expectation): (Vec<u8>, String, String) = database.query_row(
        "SELECT canonical_source, fingerprint_digest, expectation_id
         FROM security_participant_migration_expectations
         WHERE security_authority_id=?1 AND length(canonical_source) BETWEEN 1 AND 65536",
        [deployment.native_authority.security_authority_id().as_str()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let imported = SecurityParticipantSourceSnapshot::from_canonical_bytes(&canonical)?;
    assert_eq!(imported.canonical_bytes()?, canonical);
    assert_eq!(imported.digest()?, digest);
    assert_eq!(expectation, initialized.expectation_id().as_str());
    assert_eq!(
        imported.binding().security_authority_id().as_str(),
        deployment.native_authority.security_authority_id().as_str()
    );
    assert_eq!(
        imported.binding().destination_store_uuid().as_str(),
        fence.store_uuid
    );
    let source = SqliteSecurityParticipantSource::open(fixture.path.join("source.db"))?;
    let seal = source
        .load_seal()?
        .ok_or("actual imported physical source seal absent")?;
    assert_eq!(seal.snapshot(), &imported);
    source.verify_seal(&imported)?;
    let data: serde_json::Value = serde_json::from_slice(&canonical)?;
    let tables = data["tables"]
        .as_array()
        .ok_or("retained canonical inventory tables absent")?;
    assert_eq!(tables.len(), IMPORT_TABLES.len());
    tables
        .iter()
        .zip(IMPORT_TABLES)
        .map(|(table, expected)| {
            let name = table["table"]
                .as_str()
                .ok_or("retained canonical inventory table name absent")?;
            assert_eq!(name, expected);
            let count = table["row_count"]
                .as_u64()
                .ok_or("retained canonical inventory row count absent")?;
            Ok((name.to_owned(), count))
        })
        .collect()
}

fn assert_lifecycle_only_import(fixture: &RecoveryFixture) -> TestResult {
    for (table, rows) in retained_import_inventory(fixture)? {
        if table == "security_declassification_lifecycle" {
            assert!(rows <= 1);
        } else {
            assert_eq!(rows, 0, "clean imported table contains retained history");
        }
    }
    Ok(())
}

#[tokio::test]
async fn native_empty_import_bootstraps_only_through_its_first_owned_input() -> TestResult {
    let fixture = native_fixture_from_empty_import("trusted-history").await?;
    let observed = fixture
        .authority
        .admission_operation_store()
        .observe_knowledge_influence(
            fixture.runtime.scope(),
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?;
    assert!(observed.is_none());
    assert_eq!(fixture.effects.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn native_nonempty_import_holds_fresh_influence_reads_without_rewriting_history() -> TestResult
{
    let fixture = native_fixture("trusted-history")?;
    let inventory = retained_import_inventory(&fixture)?;
    assert!(
        inventory
            .iter()
            .any(|(table, rows)| table != "security_declassification_lifecycle" && *rows != 0)
    );
    let before = fixture
        .kernel
        .observe_recovery_source(fixture.runtime.scope())?;
    let refusal = fixture
        .authority
        .admission_operation_store()
        .observe_knowledge_influence(
            fixture.runtime.scope(),
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )
        .err()
        .ok_or("nonempty imported history produced a usable influence observation")?;
    assert!(
        refusal
            .to_string()
            .contains("native imported influence history remains held"),
        "import hold failed in a different prerequisite: {refusal}"
    );
    let after = fixture
        .kernel
        .observe_recovery_source(fixture.runtime.scope())?;
    assert_eq!(before.snapshot(), after.snapshot());
    assert_eq!(inventory, retained_import_inventory(&fixture)?);
    assert_eq!(fixture.effects.load(Ordering::SeqCst), 0);
    assert_eq!(external_count(&fixture.path)?, 0);
    Ok(())
}
