//! The kernel's deployment read against an actual installed deployment.

use chio_kernel::admission_operation::AdmissionOperationStoreError;
use chio_kernel::recovery::RecoveryDeploymentPort;

use super::*;

/// Every global commit of the authority, so a read is shown to append none.
fn global_commits(database: &std::path::Path) -> TestResult<i64> {
    let raw = Connection::open(database)?;
    Ok(
        raw.query_row("SELECT count(*) FROM authority_global_commits", [], |row| {
            row.get(0)
        })?,
    )
}

fn installed() -> TestResult<(Authority, RecoveryDeploymentV1)> {
    let fixture = authority()?;
    let binding = fixture.initialized_binding("native-primary")?;
    let profile = deployment(&fixture.fence, &binding, "process:primary")?;
    fixture.store.configure_recovery_deployment(&profile)?;
    Ok((fixture, profile))
}

type Read = Result<RecoveryDeploymentV1, AdmissionOperationStoreError>;

fn read(fixture: &Authority, scope: &RecoveryScopeV1) -> TestResult<Read> {
    Ok(fixture.store.deployment(scope, &fixture.fence, now_ms()?))
}

/// Rewrite the current deployment projection through the serving owner as an
/// authenticated new version carrying `payload`.
fn rewrite_current(
    fixture: &Authority,
    profile: &RecoveryDeploymentV1,
    payload: &[u8],
) -> TestResult {
    let mut connection = fixture.store.connection()?;
    let tx = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    persist_protected_record(
        &tx,
        &fixture.store.serving_owner,
        &ProtectedWrite {
            key: &current_record_key(profile)?,
            scope: &protected_scope_key(&profile.scope)?,
            kind: ProtectedRecordKind::Deployment,
            payload,
        },
    )?;
    fixture.store.commit_write(tx)?;
    fixture.store.sync_after_write(&connection)?;
    Ok(())
}

#[test]
fn installed_deployment_reads_exactly_without_any_write() -> TestResult {
    let (fixture, profile) = installed()?;
    let before = (fixture.counts()?, global_commits(&fixture.database)?);
    let read_back = read(&fixture, &profile.scope)??;
    assert_eq!(encode_protected(&read_back)?, encode_protected(&profile)?);
    let read_again = read(&fixture, &profile.scope)??;
    assert_eq!(encode_protected(&read_again)?, encode_protected(&profile)?);
    assert_eq!(
        (fixture.counts()?, global_commits(&fixture.database)?),
        before
    );
    let reopened = verify_reopened(fixture)?;
    let after_restart = read(&reopened, &profile.scope)??;
    assert_eq!(
        encode_protected(&after_restart)?,
        encode_protected(&profile)?
    );
    assert_eq!(
        (reopened.counts()?, global_commits(&reopened.database)?),
        before
    );
    Ok(())
}

#[test]
fn absent_scope_is_an_unsupported_profile() -> TestResult {
    let (fixture, profile) = installed()?;
    let mut absent = profile.scope.clone();
    absent.process_id = ProcessId::new("process:absent")?;
    let before = fixture.counts()?;
    assert_eq!(
        read(&fixture, &absent)?.err(),
        Some(invariant("recovery profile is unsupported"))
    );
    assert_eq!(fixture.counts()?, before);
    Ok(())
}

#[test]
fn stale_fence_is_fenced_before_any_record_is_read() -> TestResult {
    let (fixture, profile) = installed()?;
    let mut stale = fixture.fence.clone();
    stale.owner_epoch += 1;
    assert_eq!(
        fixture
            .store
            .deployment(&profile.scope, &stale, now_ms()?)
            .err(),
        Some(AdmissionOperationStoreError::Fenced)
    );
    Ok(())
}

#[test]
fn authority_time_outside_the_skew_bound_is_refused() -> TestResult {
    let (fixture, profile) = installed()?;
    let regressed = now_ms()? - crate::admission_operation_store::MAX_TRUSTED_CLOCK_SKEW_MS - 1_000;
    assert_eq!(
        fixture
            .store
            .deployment(&profile.scope, &fixture.fence, regressed)
            .err(),
        Some(invariant(
            "trusted_now_unix_ms exceeds the permitted system-clock skew"
        ))
    );
    Ok(())
}

#[test]
fn missing_current_projection_with_retained_history_is_refused() -> TestResult {
    let (fixture, profile) = installed()?;
    delete_projection_through_owner(
        &fixture.store,
        &fixture.fence,
        &current_record_key(&profile)?,
    )?;
    let before = fixture.counts()?;
    assert_eq!(
        read(&fixture, &profile.scope)?.err(),
        Some(invariant(
            "recovery record disappeared with retained history"
        ))
    );
    assert_eq!(fixture.counts()?, before);
    Ok(())
}

/// A commit outside the serving owner poisons it; reads refuse from then on.
#[test]
fn external_commit_refuses_and_poisons_the_read() -> TestResult {
    let (fixture, profile) = installed()?;
    let quota = single_key(&fixture.database, "recovery-planning-quota:*:global")?;
    let raw = Connection::open(&fixture.database)?;
    raw.execute_batch("PRAGMA foreign_keys = OFF;")?;
    let guard: String = raw.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'trigger'
         AND name = 'admission_operation_recovery_records_no_delete'",
        [],
        |row| row.get(0),
    )?;
    raw.execute_batch("DROP TRIGGER admission_operation_recovery_records_no_delete;")?;
    assert_eq!(
        raw.execute(
            "DELETE FROM admission_operation_recovery_records WHERE record_key = ?1",
            [&quota],
        )?,
        1
    );
    raw.execute_batch(&guard)?;
    drop(raw);
    assert_eq!(
        read(&fixture, &profile.scope)?.err(),
        Some(AdmissionOperationStoreError::OutcomeUnknown(
            "authority database changed outside its serving-owner connection".into(),
        ))
    );
    assert_eq!(
        read(&fixture, &profile.scope)?.err(),
        Some(AdmissionOperationStoreError::OutcomeUnknown(
            "sqlite authority owner is poisoned after an outcome-unknown anchor sync".into(),
        ))
    );
    Ok(())
}

#[test]
fn authenticated_projection_for_another_scope_is_refused() -> TestResult {
    let (fixture, profile) = installed()?;
    let mut other = profile.clone();
    other.scope.process_id = ProcessId::new("process:other")?;
    rewrite_current(&fixture, &profile, &encode_protected(&sealed(other)?)?)?;
    let before = fixture.counts()?;
    assert_eq!(
        read(&fixture, &profile.scope)?.err(),
        Some(invariant("recovery scope changed"))
    );
    assert_eq!(fixture.counts()?, before);
    Ok(())
}

#[test]
fn authenticated_projection_with_stale_digests_is_refused() -> TestResult {
    let (fixture, profile) = installed()?;
    let mut unsealed = profile.clone();
    unsealed.effect_contract.resource = ProtectedText::new("https://support.example/v2")?;
    rewrite_current(&fixture, &profile, &encode_protected(&unsealed)?)?;
    assert_eq!(
        read(&fixture, &profile.scope)?.err(),
        Some(invariant("recovery deployment refused"))
    );
    Ok(())
}

#[test]
fn authenticated_projection_without_its_native_initialization_is_refused() -> TestResult {
    let (fixture, profile) = installed()?;
    let mut uninitialized = profile.clone();
    uninitialized.native_authority = NativeSecurityAuthorityBindingV1::new(
        AdmissionIdentifier::try_new("native_store_uuid", fixture.fence.store_uuid.clone())?,
        AdmissionIdentifier::try_new("security_authority_id", "native-absent")?,
        AdmissionDigest::try_new("native_initialization_digest", "a".repeat(64))?,
    );
    rewrite_current(
        &fixture,
        &profile,
        &encode_protected(&sealed(uninitialized)?)?,
    )?;
    assert_eq!(
        read(&fixture, &profile.scope)?.err(),
        Some(invariant(
            "native security state: recovery native initialization is absent"
        ))
    );
    Ok(())
}

#[test]
fn authenticated_projection_that_is_not_a_deployment_is_refused() -> TestResult {
    let (fixture, profile) = installed()?;
    rewrite_current(
        &fixture,
        &profile,
        &encode_protected(&serde_json::json!({ "kind": "not-a-deployment" }))?,
    )?;
    assert_eq!(
        read(&fixture, &profile.scope)?.err(),
        Some(invariant("recovery record payload does not decode"))
    );
    Ok(())
}

/// Run `tamper` in one serving-owner write transaction with each named guard
/// trigger dropped, then restore every guard from its exact stored SQL.
pub(super) fn tamper_through_owner(
    fixture: &Authority,
    guards: &[&str],
    tamper: impl FnOnce(&rusqlite::Transaction<'_>) -> TestResult,
) -> TestResult {
    let mut connection = fixture.store.connection()?;
    connection.execute_batch("PRAGMA foreign_keys = OFF;")?;
    let tx = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    let mut restore = Vec::with_capacity(guards.len());
    for guard in guards {
        let sql: String = tx.query_row(
            "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
            [*guard],
            |row| row.get(0),
        )?;
        tx.execute_batch(&format!("DROP TRIGGER {guard};"))?;
        restore.push(sql);
    }
    tamper(&tx)?;
    for sql in &restore {
        tx.execute_batch(sql)?;
    }
    fixture.store.commit_write(tx)?;
    fixture.store.sync_after_write(&connection)?;
    connection.execute_batch("PRAGMA foreign_keys = ON;")?;
    Ok(())
}

/// Install a deployment of another process with its own native context, so
/// every later global commit follows the primary scope's commits.
pub(super) fn install_second_scope(
    fixture: &Authority,
    profile: &RecoveryDeploymentV1,
) -> TestResult {
    let mut second = profile.clone();
    second.scope.process_id = ProcessId::new("process:secondary")?;
    second.security_context = SecurityInvocationContext::V1(SecurityInvocationContextV1::new(
        TenantId::new("tenant")?,
        SessionId::new("secondary-session")?,
        PrincipalId::new("principal")?,
        IsolationEpochId::new("new-epoch")?,
        LineageId::new("lineage")?,
        1,
    ));
    fixture
        .store
        .configure_recovery_deployment(&sealed(second)?)?;
    Ok(())
}

/// Delete, through the serving owner, the global commit that owns the current
/// deployment version. It must not be the global head, which the serving
/// owner validates on every transaction.
pub(super) fn drop_current_global_reference(
    fixture: &Authority,
    profile: &RecoveryDeploymentV1,
) -> TestResult {
    let key = current_record_key(profile)?;
    let (version, _) = record_bytes(&fixture.database, &key)?;
    tamper_through_owner(fixture, &["authority_global_commits_no_delete"], |tx| {
        let (commit, head): (i64, i64) = tx.query_row(
            "SELECT commit_sequence,
                    (SELECT head_sequence FROM authority_global_commit_meta WHERE singleton = 1)
             FROM authority_global_commits
             WHERE projection_kind = 'recovery' AND projection_key = ?1
               AND projection_sequence = ?2",
            rusqlite::params![key, version],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert!(
            commit < head,
            "the removed reference must not be the global head"
        );
        assert_eq!(
            tx.execute(
                "DELETE FROM authority_global_commits WHERE commit_sequence = ?1",
                [commit],
            )?,
            1
        );
        Ok(())
    })
}

/// The current projection and its local history are rewound to version 1
/// while the global chain still records version 2 as the latest head.
#[test]
fn current_projection_behind_its_latest_global_head_is_refused() -> TestResult {
    let (fixture, profile) = installed()?;
    let key = current_record_key(&profile)?;
    let (_, installed_payload) = record_bytes(&fixture.database, &key)?;
    let mut rotated = profile.clone();
    rotated.aggregate_issuer = key_pair(12).public_key();
    let rotated = sealed(rotated)?;
    fixture.store.configure_recovery_deployment(&rotated)?;
    assert_eq!(
        encode_protected(&read(&fixture, &profile.scope)??)?,
        encode_protected(&rotated)?
    );
    tamper_through_owner(
        &fixture,
        &[
            "admission_operation_recovery_identity",
            "admission_operation_recovery_event_no_delete",
        ],
        |tx| {
            assert_eq!(
                tx.execute(
                    "UPDATE admission_operation_recovery_records
                     SET version = 1, payload = ?2 WHERE record_key = ?1",
                    rusqlite::params![key, installed_payload],
                )?,
                1
            );
            assert_eq!(
                tx.execute(
                    "DELETE FROM admission_operation_recovery_events
                     WHERE record_key = ?1 AND record_version = 2",
                    [&key],
                )?,
                1
            );
            Ok(())
        },
    )?;
    let before = (fixture.counts()?, global_commits(&fixture.database)?);
    assert_eq!(
        read(&fixture, &profile.scope)?.err(),
        Some(invariant(
            "protected source projection is not its latest head"
        ))
    );
    assert_eq!(
        (fixture.counts()?, global_commits(&fixture.database)?),
        before
    );
    Ok(())
}

/// The current projection and its latest local event are intact, but the
/// global commit that owns that version is gone.
#[test]
fn current_projection_without_its_global_reference_is_refused() -> TestResult {
    let (fixture, profile) = installed()?;
    install_second_scope(&fixture, &profile)?;
    assert_eq!(
        encode_protected(&read(&fixture, &profile.scope)??)?,
        encode_protected(&profile)?
    );
    drop_current_global_reference(&fixture, &profile)?;
    let before = (fixture.counts()?, global_commits(&fixture.database)?);
    assert_eq!(
        read(&fixture, &profile.scope)?.err(),
        Some(invariant("historical deployment lost its global reference"))
    );
    assert_eq!(
        (fixture.counts()?, global_commits(&fixture.database)?),
        before
    );
    Ok(())
}
