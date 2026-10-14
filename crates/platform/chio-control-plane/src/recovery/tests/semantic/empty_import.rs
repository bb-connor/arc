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

pub(super) async fn initialize_public_native_source(path: &std::path::Path) -> TestResult {
    use chio_kernel::admission_operation::{
        NativeOutputEnvelopeBoundsV1, NativeOutputRetentionProfileV1,
    };
    assert!(!path.join("fixture.json").exists());
    assert!(!path.join("output-retention-profile.json").exists());
    assert!(path.join("public-original-profile").exists());
    std::fs::write(path.join("empty-native-import"), "selected")?;
    std::fs::write(path.join("no-output-retention-profile"), "absent")?;
    let fixture = RecoveryFixture::open(path.to_path_buf(), None, false)?;
    // The public input is retained by the real native writer. Its original
    // deliberately has no output-retention selection, so capture must refuse
    // after the input join and before any provider effect.
    initialize_native_source_input(
        &fixture,
        InformationLabel::bottom(),
        true,
        "native-input-genesis",
    )
    .await?;
    let selected = chio_core::canonical_json_bytes(
        &fixture
            .authority
            .admission_operation_store()
            .read_semantic_installation(
                fixture.runtime.scope(),
                &fixture.authority.mutation_fence(),
                now_ms()?,
            )?,
    )?;
    let source = fixture
        .kernel
        .observe_recovery_source(fixture.runtime.scope())?;
    drop(fixture);
    let profile = NativeOutputRetentionProfileV1::new(NativeOutputEnvelopeBoundsV1::new(
        1024 * 1024,
        1024 * 1024,
        1024 * 1024,
        1024 * 1024,
        1,
    )?);
    std::fs::write(
        path.join("output-retention-profile.json"),
        chio_core::canonical_json_bytes(&profile)?,
    )?;
    // A normal serving reopen must authenticate the retained producer history
    // and preserve the semantic selection before the owning test continues.
    let reopened = RecoveryFixture::open(path.to_path_buf(), None, false)?;
    assert_lifecycle_only_import(&reopened)?;
    let store = reopened.authority.admission_operation_store();
    assert_eq!(
        chio_core::canonical_json_bytes(&store.read_semantic_installation(
            reopened.runtime.scope(),
            &reopened.authority.mutation_fence(),
            now_ms()?,
        )?)?,
        selected,
    );
    assert_eq!(
        reopened
            .kernel
            .observe_recovery_source(reopened.runtime.scope())?
            .snapshot(),
        source.snapshot(),
    );
    assert!(store
        .observe_knowledge_influence(
            reopened.runtime.scope(),
            &reopened.authority.mutation_fence(),
            now_ms()?,
        )?
        .is_none());
    assert_eq!(reopened.effects.load(Ordering::SeqCst), 0);
    assert_eq!(external_count(path)?, 0);
    Ok(())
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
    // The owned source Input is admitted before any profile is selected.
    std::fs::write(directory.path().join("no-output-retention-profile"), "absent")?;
    let Some(profile) = retention else {
        let fixture = match payment_adapter {
            Some(adapter) => RecoveryFixture::open_with_payment_adapter(
                directory.path().to_path_buf(),
                Some(directory),
                false,
                adapter,
            )?,
            None => RecoveryFixture::open(directory.path().to_path_buf(), Some(directory), false)?,
        };
        initialize_native_source_input(&fixture, restricted_label(), false, "native-input-genesis")
            .await?;
        return Ok(fixture);
    };
    if payment_adapter.is_some() {
        return Err("a selected retention fixture has no payment participant".into());
    }
    // The first owned Input must be admitted before any profile is selected:
    // a selected original needs its finishing preparation before the Input
    // join, so no profile can precede the source bootstrap. The profile is
    // selected by a normal reopen that authenticates the retained history.
    let bootstrap = RecoveryFixture::open(directory.path().to_path_buf(), Some(directory), false)?;
    initialize_native_source_input(
        &bootstrap,
        restricted_label(),
        true,
        "native-source-bootstrap",
    )
    .await?;
    let selected = chio_core::canonical_json_bytes(
        &bootstrap
            .authority
            .admission_operation_store()
            .read_semantic_installation(
                bootstrap.runtime.scope(),
                &bootstrap.authority.mutation_fence(),
                now_ms()?,
            )?,
    )?;
    let source = bootstrap
        .kernel
        .observe_recovery_source(bootstrap.runtime.scope())?;
    let (path, directory) = release_serving_owner(bootstrap);
    std::fs::write(
        path.join("output-retention-profile.json"),
        chio_core::canonical_json_bytes(profile)?,
    )?;
    let fixture = RecoveryFixture::open(path, directory, false)?;
    assert_lifecycle_only_import(&fixture)?;
    assert_eq!(
        chio_core::canonical_json_bytes(
            &fixture
                .authority
                .admission_operation_store()
                .read_semantic_installation(
                    fixture.runtime.scope(),
                    &fixture.authority.mutation_fence(),
                    now_ms()?,
                )?
        )?,
        selected,
    );
    assert_eq!(
        fixture
            .kernel
            .observe_recovery_source(fixture.runtime.scope())?
            .snapshot(),
        source.snapshot(),
    );
    refuse_selected_genesis(&fixture, profile).await?;
    Ok(fixture)
}

/// Drops every owner of the fixture's serving files. The temporary directory
/// keeps the real files; no source role or mutation authority survives.
fn release_serving_owner(f: RecoveryFixture) -> (std::path::PathBuf, Option<tempfile::TempDir>) {
    let path = f.path.clone();
    let directory = f._directory;
    drop(f.runtime);
    drop(f.kernel);
    drop(f.process);
    drop(f.authority);
    (path, directory)
}

/// A selected original is refused by its finishing preparation before any
/// Input join, dispatch, capture or provider effect.
async fn refuse_selected_genesis(
    fixture: &RecoveryFixture,
    profile: &chio_kernel::admission_operation::NativeOutputRetentionProfileV1,
) -> TestResult {
    let deployment = fixture
        .kernel
        .recovery_deployment(fixture.runtime.scope())?;
    let request = fixture.process.tool_request(
        "root",
        "native-input-genesis",
        &fixture.seed.server_id,
        &fixture.seed.tool_name,
        fixture.seed.arguments.clone(),
    )?;
    let denied = Box::pin(fixture.process.invoke_known_only(
        "root",
        "native-input-genesis",
        &request,
    ))
    .await?;
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(denied.receipt.verify_signature()?);
    assert!(denied.output.is_none());
    let (operation, original) = fixture
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("selected native genesis original absent")?;
    original.validate_request_material(&request)?;
    original.validate_native_security_authority(&deployment.native_authority)?;
    original.validate_native_security_context(&deployment.security_context)?;
    assert_eq!(original.native_output_retention(), Some(profile));
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    assert!(operation.native_dispatch_ledger_digest().is_none());
    assert_eq!(fixture.effects.load(Ordering::SeqCst), 0);
    assert_eq!(external_count(&fixture.path)?, 0);
    Ok(())
}

async fn initialize_native_source_input(
    fixture: &RecoveryFixture,
    expected: InformationLabel,
    require_unselected_retention: bool,
    label: &str,
) -> TestResult {
    assert_lifecycle_only_import(fixture)?;
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
        label,
        &fixture.seed.server_id,
        &fixture.seed.tool_name,
        fixture.seed.arguments.clone(),
    )?;
    assert!(request.declassification_grant.is_none());
    assert!(request.execution_nonce.is_none());
    // Admission joins the actual classified input before the later refusal.
    // An Input guard would deny before this producer transaction.
    let denied = Box::pin(fixture.process.invoke_known_only("root", label, &request)).await?;
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(denied.receipt.verify_signature()?);
    assert!(denied.output.is_none());
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
    if require_unselected_retention {
        assert!(original.native_output_retention().is_none());
    }
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    assert!(operation.native_dispatch_ledger_digest().is_none());
    assert!(fixture
        .authority
        .tool_outcome_store()
        .load_raw_invocation_by_operation(operation.binding().operation_id())?
        .is_none());
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
    assert_eq!(current.principal_label, expected);
    assert_eq!(current.lineage_label, expected);
    assert_eq!(current.session_label, expected);
    assert_eq!(fixture.effects.load(Ordering::SeqCst), 0);
    assert_eq!(external_count(&fixture.path)?, 0);
    assert_lifecycle_only_import(fixture)?;
    Ok(())
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
async fn native_imported_history_conservatively_contributes_unknown_influence_without_rewrite(
) -> TestResult {
    let mut fixture = native_fixture("trusted-history")?;
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let scope = fixture.runtime.scope();
    let inventory = retained_import_inventory(&fixture)?;
    assert!(inventory
        .iter()
        .any(|(table, rows)| table != "security_declassification_lifecycle" && *rows != 0));
    let sealed_source = fixture.kernel.observe_recovery_source(scope)?;
    let sealed = sealed_source.snapshot();
    let before = fixture.effects.load(Ordering::SeqCst);
    let observed = store
        .observe_knowledge_influence(scope, &fence, now_ms()?)?
        .ok_or("matching imported history contributed no influence")?;
    // Genuine predecessor history conservatively contributes unknown origin
    // classifications. It never grants a trusted external classification.
    assert!(observed.unknown);
    assert!(!observed.externally_influenced);
    let commitment = observed.commitment;
    // A permitted read rewrites nothing: the sealed source snapshot, the
    // imported inventory and the effect side all stay byte-identical.
    assert_eq!(
        fixture.kernel.observe_recovery_source(scope)?.snapshot(),
        sealed
    );
    assert_eq!(inventory, retained_import_inventory(&fixture)?);
    assert_eq!(fixture.effects.load(Ordering::SeqCst), before);
    assert_eq!(external_count(&fixture.path)?, 0);
    // The exact commitment is stable across a genuine serving restart.
    let path = fixture.path.clone();
    let directory = fixture._directory.take();
    drop(store);
    drop(sealed_source);
    drop(fixture);
    let reopened = RecoveryFixture::open(path, directory, false)?;
    let reopened_scope = reopened.runtime.scope();
    let reopened_store = reopened.authority.admission_operation_store();
    let reopened_fence = reopened.authority.mutation_fence();
    let replayed = reopened_store
        .observe_knowledge_influence(reopened_scope, &reopened_fence, now_ms()?)?
        .ok_or("imported influence disappeared across restart")?;
    assert!(replayed.unknown);
    assert!(!replayed.externally_influenced);
    assert_eq!(replayed.commitment, commitment);
    assert_eq!(external_count(&reopened.path)?, 0);
    Ok(())
}

#[tokio::test]
async fn native_foreign_tenant_import_never_contaminates_another_flow() -> TestResult {
    // Seed the sealed source with flow history of one foreign tenant only.
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join("semantic-kind"), "trusted-history")?;
    // The marker skips the default fixture-context join below; only the
    // foreign rows seeded here are imported.
    std::fs::write(
        directory.path().join("empty-native-import"),
        "foreign-source",
    )?;
    let source = SqliteSecurityStateStore::open(directory.path().join("source.db"))?;
    source.seal_declassification_live_dispatch()?;
    let [principal_join, lineage_join, session_join] =
        command_quotas::fixture_source_labels(directory.path(), restricted_label())?;
    let foreign =
        chio_kernel::SecurityInvocationContext::V1(chio_kernel::SecurityInvocationContextV1::new(
            chio_security_types::ports::TenantId::new("foreign-import-tenant")?,
            chio_security_types::ports::SessionId::new("foreign-import-session")?,
            chio_security_types::PrincipalId::new("foreign-import-principal")?,
            chio_security_types::ports::IsolationEpochId::new("foreign-import-epoch")?,
            chio_security_types::ports::LineageId::new("foreign-import-lineage")?,
            0,
        ));
    source.join(&FlowJoinRequest {
        key: chio_kernel::recovery::recovery_flow_key(&foreign),
        principal_join,
        lineage_join,
        session_join,
        transition_id: RecordId::new("foreign-import-source")?,
    })?;
    drop(source);
    let fixture = RecoveryFixture::open(directory.path().to_path_buf(), Some(directory), false)?;
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let scope = fixture.runtime.scope();
    let inventory = retained_import_inventory(&fixture)?;
    assert!(inventory
        .iter()
        .any(|(table, rows)| table != "security_declassification_lifecycle" && *rows != 0));
    let before = fixture.effects.load(Ordering::SeqCst);
    // A foreign tenant's retained history never becomes this flow's influence.
    assert!(store
        .observe_knowledge_influence(scope, &fence, now_ms()?)?
        .is_none());
    assert_eq!(inventory, retained_import_inventory(&fixture)?);
    assert_eq!(fixture.effects.load(Ordering::SeqCst), before);
    assert_eq!(external_count(&fixture.path)?, 0);
    Ok(())
}

/// Drops every guard trigger of one table, applies the damage, and restores
/// each guard from its own captured definition before any later read.
fn with_dropped_guards(path: &std::path::Path, table: &str, damage: &str) -> TestResult<usize> {
    let connection = rusqlite::Connection::open(path.join("admission.db"))?;
    let guards: Vec<(String, String)> = {
        let mut statement = connection.prepare(
            "SELECT name, sql FROM sqlite_schema WHERE type='trigger' AND tbl_name=?1 ORDER BY name",
        )?;
        let rows = statement.query_map([table], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect::<rusqlite::Result<_>>()?
    };
    connection.pragma_update(None, "foreign_keys", false)?;
    for (name, _) in &guards {
        connection.execute_batch(&format!("DROP TRIGGER \"{name}\""))?;
    }
    let changed = connection.execute(damage, [])?;
    for (_, sql) in &guards {
        connection.execute_batch(sql)?;
    }
    Ok(changed)
}

#[tokio::test]
async fn native_imported_influence_read_ignores_large_foreign_tenant_history() -> TestResult {
    // The default fixture join seeds this flow's own genuine history; a large
    // foreign history is retained beside it in the same sealed source. The read
    // stays inside its fixed work budget only if it never prices that history.
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join("semantic-kind"), "trusted-history")?;
    let source = SqliteSecurityStateStore::open(directory.path().join("source.db"))?;
    source.seal_declassification_live_dispatch()?;
    let [principal_join, lineage_join, session_join] =
        command_quotas::fixture_source_labels(directory.path(), restricted_label())?;
    for index in 0..700 {
        let foreign = chio_kernel::SecurityInvocationContext::V1(
            chio_kernel::SecurityInvocationContextV1::new(
                chio_security_types::ports::TenantId::new(format!(
                    "foreign-import-tenant-{index:04}"
                ))?,
                chio_security_types::ports::SessionId::new(format!(
                    "foreign-import-session-{index:04}"
                ))?,
                chio_security_types::PrincipalId::new(format!(
                    "foreign-import-principal-{index:04}"
                ))?,
                chio_security_types::ports::IsolationEpochId::new(format!(
                    "foreign-import-epoch-{index:04}"
                ))?,
                chio_security_types::ports::LineageId::new(format!(
                    "foreign-import-lineage-{index:04}"
                ))?,
                0,
            ),
        );
        source.join(&FlowJoinRequest {
            key: chio_kernel::recovery::recovery_flow_key(&foreign),
            principal_join: principal_join.clone(),
            lineage_join: lineage_join.clone(),
            session_join: session_join.clone(),
            transition_id: RecordId::new(format!("foreign-import-source-{index:04}"))?,
        })?;
    }
    drop(source);
    let mut fixture =
        RecoveryFixture::open(directory.path().to_path_buf(), Some(directory), false)?;
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let scope = fixture.runtime.scope();
    let observed = store
        .observe_knowledge_influence(scope, &fence, now_ms()?)?
        .ok_or("own imported history contributed no influence beside foreign history")?;
    assert!(observed.unknown);
    assert!(!observed.externally_influenced);
    let replayed = store
        .observe_knowledge_influence(scope, &fence, now_ms()?)?
        .ok_or("own imported influence disappeared beside foreign history")?;
    assert_eq!(replayed.commitment, observed.commitment);
    // An out-of-band write invalidates the serving owner's database view,
    // even when it damages a foreign tenant. The public reader must refuse;
    // the cold reopen must independently reject the corrupted sealed source.
    let changed = with_dropped_guards(
        &fixture.path,
        "security_participant_migration_rows",
        "UPDATE security_participant_migration_rows SET canonical_row = X'007b7d'
         WHERE table_name = 'security_transitions'
           AND CAST(canonical_row AS TEXT) LIKE '%foreign-import-tenant-0000%'",
    )?;
    assert!(changed >= 1, "no foreign transition row to damage");
    assert!(store
        .observe_knowledge_influence(scope, &fence, now_ms()?)
        .is_err());
    let path = fixture.path.clone();
    let directory = fixture._directory.take();
    drop(store);
    drop(fixture);
    assert!(RecoveryFixture::open(path, directory, false).is_err());
    Ok(())
}

#[tokio::test]
async fn tampered_imported_scope_index_refuses_influence_reads_fail_closed() -> TestResult {
    let mut fixture = native_fixture("trusted-history")?;
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let scope = fixture.runtime.scope();
    assert!(store
        .observe_knowledge_influence(scope, &fence, now_ms()?)?
        .is_some());
    // Removing every index leaf would read as a genuine absence unless the
    // protected root still commits those leaves.
    let removed = with_dropped_guards(
        &fixture.path,
        "security_participant_state_imported_scope_index",
        "DELETE FROM security_participant_state_imported_scope_index",
    )?;
    assert!(removed >= 1, "no scope index leaf to remove");
    assert!(store
        .observe_knowledge_influence(scope, &fence, now_ms()?)
        .is_err());
    let path = fixture.path.clone();
    let directory = fixture._directory.take();
    drop(store);
    drop(fixture);
    assert!(RecoveryFixture::open(path, directory, false).is_err());
    Ok(())
}

#[tokio::test]
async fn tampered_imported_history_refuses_influence_reads_fail_closed() -> TestResult {
    let mut fixture = native_fixture("trusted-history")?;
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let scope = fixture.runtime.scope();
    assert!(store
        .observe_knowledge_influence(scope, &fence, now_ms()?)?
        .is_some());
    // The migration history triggers refuse every UPDATE and DELETE on the
    // serving tables, so a direct tamper cannot reach the reader. Use the
    // established authorized fixture pattern instead: capture the trigger
    // definitions, drop exactly those guards inside this test connection,
    // corrupt one retained transition row, and restore the triggers from
    // their own captured SQL before any subsequent read.
    let connection = rusqlite::Connection::open(fixture.path.join("admission.db"))?;
    let rows_guard: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='trigger'
         AND name='security_participant_migration_rows_immutable'",
        [],
        |row| row.get(0),
    )?;
    connection.pragma_update(None, "foreign_keys", false)?;
    connection.execute_batch("DROP TRIGGER security_participant_migration_rows_immutable")?;
    let changed = connection.execute(
        "UPDATE security_participant_migration_rows
         SET canonical_row = X'007b7d'
         WHERE table_name = 'security_transitions'",
        [],
    )?;
    assert!(changed >= 1, "no retained transition row to tamper");
    connection.execute_batch(&rows_guard)?;
    drop(connection);
    // A damaged imported row fails closed at the owner's sealed-source and
    // row verification checks; it never reinitializes, silently contributes
    // zero, or downgrades the refusal into a fresh observation. This is the
    // owner external-tamper refusal, not a claim about deep row acceptance.
    assert!(store
        .observe_knowledge_influence(scope, &fence, now_ms()?)
        .is_err());
    let path = fixture.path.clone();
    let directory = fixture._directory.take();
    drop(store);
    drop(fixture);
    assert!(RecoveryFixture::open(path, directory, false).is_err());
    Ok(())
}
