use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn authority_fixture() -> TestResult<(tempfile::TempDir, crate::SqliteAuthorityStore)> {
    let directory = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let database = directory.path().join("authority.db");
    let locks = directory.path().join("locks");
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&locks)?;
    crate::SqliteAuthorityStore::provision(&database, &locks)?;
    let authority = crate::SqliteAuthorityStore::open_serving(&database, &locks)?;
    Ok((directory, authority))
}

fn selection() -> TestResult<Selection> {
    let scope = RecoveryScopeV1 {
        authority_domain: AuthorityDomainId::new("legacy-setup-authority")?,
        tenant_id: RecoveryTenantId::new("legacy-setup-tenant")?,
        process_id: ProcessId::new("legacy-setup-process")?,
    };
    let workflow = WorkflowId::new("legacy-setup-workflow")?;
    Ok(Selection {
        probe: RecoverySetupProbeV1 {
            domain_version: VersionV1,
            scope,
            probe_id: ChallengeId::new("legacy-setup-probe")?,
            native_authority: SourceDigest::from_bytes([1; 32]),
            deployment: DeploymentDigest::from_bytes([2; 32]),
            source_profile: SourceDigest::from_bytes([3; 32]),
            required_coverage: CoverageDigest::from_bytes([4; 32]),
            benign_workflow: workflow.clone(),
            denied_command: CommandId::new("legacy-setup-denied")?,
            issued_at_unix_ms: SafeInteger::new(1_000)?,
            expires_at_unix_ms: SafeInteger::new(901_000)?,
        },
        creation: CanonicalPayloadDigest::from_bytes([5; 32]),
        command: RecoveryCommandV1 {
            schema: RecoveryCommandSchema::V1,
            version: VersionV1,
            command_id: CommandId::new("legacy-setup-benign")?,
            command: RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: workflow,
                expected_revision: SafeInteger::new(2)?,
            },
        },
        command_bound: true,
        operator: chio_core::Keypair::from_seed(&[6; 32]).public_key(),
        receipt_key: chio_core::Keypair::from_seed(&[7; 32]).public_key(),
        previous_fence: SourceDigest::from_bytes([8; 32]),
        evidence: None,
        report: None,
    })
}

fn store_legacy_selection(
    store: &SqliteAdmissionOperationStore,
    value: &Selection,
    legacy: &serde_json::Value,
) -> TestResult {
    store_selection_at_key(store, value, legacy, &legacy_key(&value.probe.scope)?)
}

fn store_selection_at_key(
    store: &SqliteAdmissionOperationStore,
    value: &Selection,
    payload: &serde_json::Value,
    record_key: &str,
) -> TestResult {
    let mut connection = store.connection()?;
    let tx = store.begin_write(&mut connection, None)?;
    protected::save(
        &tx,
        &store.serving_owner,
        record_key,
        &protected::scope_key(&value.probe.scope)?,
        "command",
        &chio_core::canonical_json_bytes(payload)?,
        None,
    )?;
    store.commit_write(tx)?;
    store.sync_after_write(&connection)?;
    Ok(())
}

#[test]
fn setup_legacy_selection_is_authenticated_before_explicit_canonical_decode() -> TestResult {
    let (_directory, authority) = authority_fixture()?;
    let store: SqliteAdmissionOperationStore = authority.admission_operation_store();
    let value = selection()?;
    let mut legacy = serde_json::to_value(&value)?;
    legacy
        .as_object_mut()
        .ok_or("legacy selection object")?
        .remove("command_bound");
    store_legacy_selection(&store, &value, &legacy)?;
    let connection = store.connection()?;
    let decoded = load(&connection, &value.probe.scope)?.ok_or("authenticated legacy selection")?;
    assert!(decoded.command_bound);
    assert_eq!(decoded.command, value.command);
    assert_eq!(decoded.probe, value.probe);
    Ok(())
}

#[test]
fn setup_legacy_selection_rejects_unknown_members_without_repairing_them() -> TestResult {
    let (_directory, authority) = authority_fixture()?;
    let store: SqliteAdmissionOperationStore = authority.admission_operation_store();
    let value = selection()?;
    let mut legacy = serde_json::to_value(&value)?;
    let object = legacy.as_object_mut().ok_or("legacy selection object")?;
    object.remove("command_bound");
    object.insert("unrecognized_authority".into(), serde_json::json!(true));
    store_legacy_selection(&store, &value, &legacy)?;
    let connection = store.connection()?;
    assert!(load(&connection, &value.probe.scope).is_err());
    Ok(())
}

#[test]
fn setup_independent_process_selections_preserve_their_own_native_custody() -> TestResult {
    let (_directory, authority) = authority_fixture()?;
    let store: SqliteAdmissionOperationStore = authority.admission_operation_store();
    let first = selection()?;
    let mut second = first.clone();
    second.probe.scope.process_id = ProcessId::new("second-setup-process")?;
    second.probe.benign_workflow = WorkflowId::new("second-setup-workflow")?;
    second.command.command = RecoveryCommandBodyV1::ResumeWorkflow {
        workflow_id: second.probe.benign_workflow.clone(),
        expected_revision: SafeInteger::new(2)?,
    };
    store_selection_at_key(
        &store,
        &first,
        &serde_json::to_value(&first)?,
        &key(&first.probe.scope)?,
    )?;
    {
        let connection = store.connection()?;
        let retained = protected::raw(&connection, &key(&first.probe.scope)?)?
            .ok_or("the first authenticated native setup selection")?;
        assert_eq!(retained.scope, protected::scope_key(&first.probe.scope)?);
        assert_eq!(retained.version, 1);
        assert_eq!(
            selection_codec::decode(&retained.payload)?.probe,
            first.probe
        );
    }
    assert_ne!(
        key(&first.probe.scope)?,
        key(&second.probe.scope)?,
        "independent process selections must own distinct native record identities"
    );
    store_selection_at_key(
        &store,
        &second,
        &serde_json::to_value(&second)?,
        &key(&second.probe.scope)?,
    )?;
    let connection = store.connection()?;
    let retained_first = load(&connection, &first.probe.scope)?.ok_or("first setup custody")?;
    let retained_second = load(&connection, &second.probe.scope)?.ok_or("second setup custody")?;
    assert_eq!(retained_first.probe.scope, first.probe.scope);
    assert_eq!(retained_first.command, first.command);
    assert_eq!(retained_second.probe.scope, second.probe.scope);
    assert_eq!(retained_second.command, second.command);
    Ok(())
}

#[test]
fn setup_legacy_cross_scope_overwrite_cannot_pass_native_event_authentication() -> TestResult {
    let (_directory, authority) = authority_fixture()?;
    let store = authority.admission_operation_store();
    let first = selection()?;
    let mut second = first.clone();
    second.probe.scope.process_id = ProcessId::new("collision-second-process")?;
    let legacy_key = format!(
        "protected-setup:{}",
        sha256_hex(&protected::encode(&(
            &first.probe.scope.authority_domain,
            &first.probe.scope.tenant_id,
        ))?)
    );
    store_selection_at_key(&store, &first, &serde_json::to_value(&first)?, &legacy_key)?;
    store_selection_at_key(
        &store,
        &second,
        &serde_json::to_value(&second)?,
        &legacy_key,
    )?;
    let connection = store.connection()?;
    let (scope_key, version, payload): (String, i64, Vec<u8>) = connection.query_row(
        "SELECT scope_key,version,payload FROM admission_operation_recovery_records WHERE record_key=?1",
        [&legacy_key],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(scope_key, protected::scope_key(&first.probe.scope)?);
    assert_eq!(version, 2);
    assert_eq!(
        selection_codec::decode(&payload)?.probe.scope,
        second.probe.scope
    );
    let events: i64 = connection.query_row(
        "SELECT count(*) FROM admission_operation_recovery_events WHERE record_key=?1",
        [&legacy_key],
        |row| row.get(0),
    )?;
    let references: i64 = connection.query_row(
        "SELECT count(*) FROM authority_global_commits WHERE projection_kind='recovery' AND projection_key=?1",
        [&legacy_key],
        |row| row.get(0),
    )?;
    assert_eq!((events, references), (2, 2));
    assert!(matches!(
        protected::raw(&connection, &legacy_key),
        Err(AdmissionOperationStoreError::Invariant(ref message))
            if message == "recovery projection lost its event"
    ));
    Ok(())
}
