//! Operator deployment installation against an actual provisioned authority
//! store with a really hydrated native security initialization.

use std::path::PathBuf;
use std::sync::Arc;

use chio_core::{Keypair, StoreMutationFence};
use chio_kernel::admission_operation::{
    AdmissionDigest, AdmissionIdentifier, NativeSecurityAuthorityBindingV1,
};
use chio_kernel::recovery::{
    NativeSetupPolicyV1, RecoveryActorAssignment, RecoveryCoverageAssignment, RecoveryDeploymentV1,
    RecoveryEffectContractSchema, RecoveryEffectContractV1, RecoveryPermission,
};
use chio_kernel::{SecurityInvocationContext, SecurityInvocationContextV1};
use chio_security_types::flow::{DeclassificationPurpose, InformationLabel, PrincipalId};
use chio_security_types::ports::{
    DestinationId, IsolationEpochId, LineageId, RecordId, SessionId, TenantId,
};
use chio_security_types::recovery::{
    AuthorityDomainId, AuthorityObligationV1, BoundedList, IssuerId, NonEmptyBoundedList,
    PolicyDigest, ProcessId, ProtectedText, RecoveryAttachmentProfile, RecoveryEffectAccountId,
    RecoveryEffectProviderId, RecoveryTenantId, SafeInteger,
};
use rusqlite::Connection;
use tempfile::TempDir;

use crate::SqliteAuthorityStore;

use super::super::recovery_records::{
    persist_protected_record, verify_global_coverage, verify_local_history, ProtectedRecordKind,
    ProtectedWrite,
};
use super::*;

mod actor_authentication;
mod authenticated_read;
mod semantic_installation;

pub(super) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// One provisioned serving authority with a fixed trusted clock.
pub(super) struct Authority {
    temp: TempDir,
    pub(super) database: PathBuf,
    lock_root: PathBuf,
    pub(super) authority: SqliteAuthorityStore,
    pub(super) store: SqliteAdmissionOperationStore,
    pub(super) fence: StoreMutationFence,
    _clock: chio_test_support::clock::ClockScope,
}

pub(super) fn authority() -> TestResult<Authority> {
    let clock = chio_test_support::clock::scope_unix_secs(chio_test_support::clock::unix_seconds());
    let temp = tempfile::tempdir()?;
    crate::test_authority::secure_directory(temp.path());
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let authority = crate::test_authority::open_serving(&database, &lock_root)?;
    let store = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    Ok(Authority {
        temp,
        database,
        lock_root,
        authority,
        store,
        fence,
        _clock: clock,
    })
}

fn now_ms() -> TestResult<u64> {
    chio_test_support::clock::scoped_unix_secs()
        .and_then(|seconds| seconds.checked_mul(1_000))
        .ok_or_else(|| "fixed test clock is unavailable".into())
}

impl Authority {
    /// Import and hydrate a real native security participant named `name`
    /// and return its admission binding.
    pub(super) fn initialized_binding(
        &self,
        name: &str,
    ) -> TestResult<NativeSecurityAuthorityBindingV1> {
        let path = self.temp.path().join(format!("{name}.db"));
        drop(crate::security_state::seeded_security_history(&path)?);
        seed_isolation_history(&path)?;
        let source = crate::security_state::SqliteSecurityParticipantSource::open(&path)?;
        let authority = AdmissionIdentifier::try_new("security_authority_id", name)?;
        let expected = self.store.expect_security_participant_source(
            &AdmissionIdentifier::try_new("source_id", name)?,
            &authority,
            &source,
            &self.fence,
            now_ms()?,
        )?;
        let imported = self.store.import_security_participant_source(
            &authority,
            expected.expectation_id(),
            &source,
            &self.fence,
            now_ms()?,
        )?;
        let initialized = self.store.hydrate_security_participant_state(
            &authority,
            imported.expectation_id(),
            &self.fence,
            now_ms()?,
        )?;
        Ok(initialized.admission_binding()?)
    }

    pub(super) fn counts(&self) -> TestResult<Counts> {
        counts(&self.database)
    }

    /// Close this serving owner and reopen the file through full startup
    /// verification.
    pub(super) fn reopened(self) -> TestResult<Authority> {
        let Authority {
            temp,
            database,
            lock_root,
            authority,
            store,
            fence: _,
            _clock,
        } = self;
        drop(store);
        drop(authority);
        let authority = crate::test_authority::open_serving(&database, &lock_root)?;
        let store = authority.admission_operation_store();
        let fence = authority.mutation_fence();
        Ok(Authority {
            temp,
            database,
            lock_root,
            authority,
            store,
            fence,
            _clock,
        })
    }
}

fn seed_isolation_history(path: &std::path::Path) -> TestResult {
    use chio_security_types::ports::{
        FlowStateStore, IsolationEpochEvidenceVerifierPort, IsolationEpochTransition,
        IsolationVerificationRecord, PortResult,
    };
    struct Verifier;
    impl IsolationEpochEvidenceVerifierPort for Verifier {
        fn verify(&self, _: &IsolationEpochTransition) -> PortResult<IsolationVerificationRecord> {
            Ok(IsolationVerificationRecord {
                verifier_id: RecordId::new("native-fixture-verifier")?,
                receipt_ref: chio_security_types::ports::OpaqueReceiptRef::new(
                    "native-fixture-receipt",
                )?,
            })
        }
    }
    let store = crate::SqliteSecurityStateStore::open_with_isolation_epoch_verifier(
        path,
        Arc::new(Verifier),
    )?;
    store.open_isolation_epoch(&IsolationEpochTransition {
        tenant_id: TenantId::new("tenant")?,
        principal_id: PrincipalId::new("principal")?,
        lineage_id: LineageId::new("lineage")?,
        previous_isolation_epoch_id: IsolationEpochId::new("epoch")?,
        new_isolation_epoch_id: IsolationEpochId::new("new-epoch")?,
        new_session_id: SessionId::new("new-session")?,
        verification_evidence_hash: chio_security_types::ports::Digest32::new([7; 32]),
        transition_id: RecordId::new("isolation-transition")?,
        effective_at_unix_ms: 1_000,
    })?;
    Ok(())
}

/// Records, events and global recovery commits, in that order.
pub(super) type Counts = (i64, i64, i64);

fn counts(database: &std::path::Path) -> TestResult<Counts> {
    let raw = Connection::open(database)?;
    Ok(raw.query_row(
        "SELECT (SELECT count(*) FROM admission_operation_recovery_records),
                (SELECT count(*) FROM admission_operation_recovery_events),
                (SELECT count(*) FROM authority_global_commits WHERE projection_kind = 'recovery')",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?)
}

fn key_pair(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

/// A deployment of the process `process` whose two derived digests match
/// every other field.
pub(super) fn deployment(
    fence: &StoreMutationFence,
    binding: &NativeSecurityAuthorityBindingV1,
    process: &str,
) -> TestResult<RecoveryDeploymentV1> {
    let profile = RecoveryDeploymentV1 {
        scope: RecoveryScopeV1 {
            authority_domain: AuthorityDomainId::new(&fence.store_uuid)?,
            tenant_id: RecoveryTenantId::new("tenant")?,
            process_id: ProcessId::new(process)?,
        },
        native_authority: binding.clone(),
        security_context: SecurityInvocationContext::V1(SecurityInvocationContextV1::new(
            TenantId::new("tenant")?,
            SessionId::new("new-session")?,
            PrincipalId::new("principal")?,
            IsolationEpochId::new("new-epoch")?,
            LineageId::new("lineage")?,
            1,
        )),
        server_id: RecordId::new("support-server")?,
        tool_name: RecordId::new("create-issue")?,
        recipient: DestinationId::new("support-server")?,
        purpose: DeclassificationPurpose::new("support-disclosure")?,
        target_label: InformationLabel::bottom(),
        policy_digest: PolicyDigest::from_bytes([1; 32]),
        contract_digest: ContractDigest::from_bytes([0; 32]),
        authority_scope: chio_security_types::recovery::AuthorityScopeDigest::from_bytes([0; 32]),
        attachment_profile: RecoveryAttachmentProfile::Ordinary,
        aggregate_issuer: key_pair(2).public_key(),
        aggregate_issuer_id: RecordId::new("aggregate-issuer")?,
        actors: NonEmptyBoundedList::new(vec![RecoveryActorAssignment {
            subject: key_pair(3).public_key(),
            principal: PrincipalId::new("operator")?,
            permissions: BoundedList::new(vec![
                RecoveryPermission::Create,
                RecoveryPermission::Inspect,
            ])?,
            preview_clearance: InformationLabel::bottom(),
        }])?,
        coverage: NonEmptyBoundedList::new(vec![RecoveryCoverageAssignment {
            issuer_id: IssuerId::new("issuer")?,
            principal: PrincipalId::new("owner")?,
            key: key_pair(4).public_key(),
            obligations: NonEmptyBoundedList::new(vec![AuthorityObligationV1::OwnerRelease {
                owner: PrincipalId::new("owner")?,
            }])?,
        }])?,
        effect_cardinality: SafeInteger::new(1)?,
        effect_contract: RecoveryEffectContractV1 {
            schema: RecoveryEffectContractSchema::V1,
            provider: RecoveryEffectProviderId::new("support-provider")?,
            account: RecoveryEffectAccountId::new("support-account")?,
            resource: ProtectedText::new("https://support.example/issues")?,
            observation_key: key_pair(5).public_key(),
            max_response_bytes: SafeInteger::new(4096)?,
        },
        setup_policy: None,
    };
    sealed(profile)
}

/// Recompute the contract and authority scope digests after a field change.
pub(super) fn sealed(mut profile: RecoveryDeploymentV1) -> TestResult<RecoveryDeploymentV1> {
    profile.contract_digest = ContractDigest::from_bytes(digest(
        RecoveryDigestDomain::EffectContract,
        &profile.effect_contract,
    )?);
    profile.authority_scope = recovery_authority_scope_digest(&profile)?;
    Ok(profile)
}

fn record_bytes(database: &std::path::Path, key: &str) -> TestResult<(i64, Vec<u8>)> {
    let raw = Connection::open(database)?;
    Ok(raw.query_row(
        "SELECT version, payload FROM admission_operation_recovery_records WHERE record_key = ?1",
        [key],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?)
}

fn current_record_key(profile: &RecoveryDeploymentV1) -> TestResult<String> {
    Ok(current_key(&protected_scope_key(&profile.scope)?))
}

fn history_record_key(profile: &RecoveryDeploymentV1) -> TestResult<String> {
    Ok(format!(
        "{HISTORY_PREFIX}{}:{}",
        protected_scope_key(&profile.scope)?,
        digest_hex(deployment_digest(profile)?.as_bytes())
    ))
}

fn verify_reopened(fixture: Authority) -> TestResult<Authority> {
    let fixture = fixture.reopened()?;
    let raw = Connection::open(&fixture.database)?;
    verify_local_history(&raw)?;
    verify_global_coverage(&raw)?;
    verify_planning_allocations(&raw)?;
    Ok(fixture)
}

/// Fresh install without a setup policy writes the context record, the new
/// history root and the current deployment once each, and each planned
/// deployment write advances both planning allocations: 5 records, 7 events
/// and 7 global recovery commits.
#[test]
fn fresh_install_retains_current_history_context_and_allocations() -> TestResult {
    let fixture = authority()?;
    let binding = fixture.initialized_binding("native-primary")?;
    let profile = deployment(&fixture.fence, &binding, "process:primary")?;
    fixture.store.configure_recovery_deployment(&profile)?;
    assert_eq!(fixture.counts()?, (5, 7, 7));
    let encoded = encode_protected(&profile)?;
    assert_eq!(
        record_bytes(&fixture.database, &current_record_key(&profile)?)?,
        (1, encoded.clone())
    );
    assert_eq!(
        record_bytes(&fixture.database, &history_record_key(&profile)?)?,
        (1, encoded)
    );
    let fixture = verify_reopened(fixture)?;
    assert_eq!(fixture.counts()?, (5, 7, 7));
    Ok(())
}

#[test]
fn replaying_the_same_profile_changes_no_row_event_or_commit() -> TestResult {
    let fixture = authority()?;
    let binding = fixture.initialized_binding("native-primary")?;
    let profile = deployment(&fixture.fence, &binding, "process:primary")?;
    fixture.store.configure_recovery_deployment(&profile)?;
    let before = fixture.counts()?;
    let bytes = record_bytes(&fixture.database, &current_record_key(&profile)?)?;
    fixture.store.configure_recovery_deployment(&profile)?;
    assert_eq!(fixture.counts()?, before);
    assert_eq!(
        record_bytes(&fixture.database, &current_record_key(&profile)?)?,
        bytes
    );
    verify_reopened(fixture)?;
    Ok(())
}

/// Each rotation axis retains the new root (one write) and rewrites the
/// current deployment (one write); each planned write advances both
/// allocations. The prior root stays byte-identical.
#[test]
fn every_rotation_axis_retains_both_roots_and_updates_current() -> TestResult {
    type Rotation = fn(&mut RecoveryDeploymentV1) -> TestResult;
    let rotations: [(&str, Rotation); 6] = [
        ("coverage", |profile| {
            profile.coverage = NonEmptyBoundedList::new(vec![RecoveryCoverageAssignment {
                issuer_id: IssuerId::new("issuer")?,
                principal: PrincipalId::new("owner")?,
                key: key_pair(14).public_key(),
                obligations: NonEmptyBoundedList::new(vec![AuthorityObligationV1::OwnerRelease {
                    owner: PrincipalId::new("owner")?,
                }])?,
            }])?;
            Ok(())
        }),
        ("actor", |profile| {
            profile.actors = NonEmptyBoundedList::new(vec![RecoveryActorAssignment {
                subject: key_pair(13).public_key(),
                principal: PrincipalId::new("operator")?,
                permissions: BoundedList::new(vec![RecoveryPermission::Create])?,
                preview_clearance: InformationLabel::bottom(),
            }])?;
            Ok(())
        }),
        ("aggregate", |profile| {
            profile.aggregate_issuer = key_pair(12).public_key();
            Ok(())
        }),
        ("policy", |profile| {
            profile.policy_digest = PolicyDigest::from_bytes([11; 32]);
            Ok(())
        }),
        ("effect contract", |profile| {
            profile.effect_contract.resource = ProtectedText::new("https://support.example/v2")?;
            Ok(())
        }),
        ("observation key", |profile| {
            profile.effect_contract.observation_key = key_pair(15).public_key();
            Ok(())
        }),
    ];
    for (axis, rotate) in rotations {
        let fixture = authority()?;
        let binding = fixture.initialized_binding("native-primary")?;
        let original = deployment(&fixture.fence, &binding, "process:primary")?;
        fixture.store.configure_recovery_deployment(&original)?;
        let prior = record_bytes(&fixture.database, &history_record_key(&original)?)?;
        let mut rotated = original.clone();
        rotate(&mut rotated)?;
        let rotated = sealed(rotated)?;
        fixture.store.configure_recovery_deployment(&rotated)?;
        assert_eq!(fixture.counts()?, (6, 13, 13), "{axis}");
        assert_eq!(
            record_bytes(&fixture.database, &history_record_key(&original)?)?,
            prior,
            "{axis}"
        );
        assert_eq!(
            record_bytes(&fixture.database, &history_record_key(&rotated)?)?,
            (1, encode_protected(&rotated)?),
            "{axis}"
        );
        assert_eq!(
            record_bytes(&fixture.database, &current_record_key(&rotated)?)?,
            (2, encode_protected(&rotated)?),
            "{axis}"
        );
        verify_reopened(fixture)?;
    }
    Ok(())
}

/// A native authority rotation additionally registers the new native context.
#[test]
fn native_authority_rotation_requires_its_own_initialization() -> TestResult {
    let fixture = authority()?;
    let primary = fixture.initialized_binding("native-primary")?;
    let original = deployment(&fixture.fence, &primary, "process:primary")?;
    fixture.store.configure_recovery_deployment(&original)?;
    let uninitialized = NativeSecurityAuthorityBindingV1::new(
        AdmissionIdentifier::try_new("native_store_uuid", fixture.fence.store_uuid.clone())?,
        AdmissionIdentifier::try_new("security_authority_id", "native-absent")?,
        AdmissionDigest::try_new("native_initialization_digest", "a".repeat(64))?,
    );
    let mut absent = original.clone();
    absent.native_authority = uninitialized;
    let absent = sealed(absent)?;
    let before = fixture.counts()?;
    assert_eq!(
        fixture.store.configure_recovery_deployment(&absent),
        Err(invariant(
            "native security state: recovery native initialization is absent"
        ))
    );
    assert_eq!(fixture.counts()?, before);
    let secondary = fixture.initialized_binding("native-secondary")?;
    let mut rotated = original.clone();
    rotated.native_authority = secondary;
    let rotated = sealed(rotated)?;
    fixture.store.configure_recovery_deployment(&rotated)?;
    assert_eq!(fixture.counts()?, (7, 14, 14));
    verify_reopened(fixture)?;
    Ok(())
}

#[test]
fn failed_initialization_leaves_no_record_event_commit_or_allocation() -> TestResult {
    let fixture = authority()?;
    let binding = fixture.initialized_binding("native-primary")?;
    let differs = NativeSecurityAuthorityBindingV1::new(
        binding.store_uuid().clone(),
        binding.security_authority_id().clone(),
        AdmissionDigest::try_new("native_initialization_digest", "b".repeat(64))?,
    );
    let absent = NativeSecurityAuthorityBindingV1::new(
        binding.store_uuid().clone(),
        AdmissionIdentifier::try_new("security_authority_id", "native-absent")?,
        AdmissionDigest::try_new("native_initialization_digest", "c".repeat(64))?,
    );
    for (native, expected) in [
        (
            differs,
            "native security state: recovery native initialization differs",
        ),
        (
            absent,
            "native security state: recovery native initialization is absent",
        ),
    ] {
        let profile = deployment(&fixture.fence, &native, "process:primary")?;
        assert_eq!(
            fixture.store.configure_recovery_deployment(&profile),
            Err(invariant(expected))
        );
        assert_eq!(fixture.counts()?, (0, 0, 0));
    }
    verify_reopened(fixture)?;
    Ok(())
}

#[test]
fn invalid_installations_refuse_with_their_exact_reason() -> TestResult {
    let fixture = authority()?;
    let binding = fixture.initialized_binding("native-primary")?;
    let valid = deployment(&fixture.fence, &binding, "process:primary")?;
    type Mutation = fn(&mut RecoveryDeploymentV1) -> TestResult;
    let cases: [(Mutation, &str); 9] = [
        (
            |profile| {
                profile.scope.authority_domain = AuthorityDomainId::new("foreign-authority")?;
                Ok(())
            },
            "recovery deployment refused",
        ),
        (
            |profile| {
                profile.effect_contract.resource = ProtectedText::new("http://support.example")?;
                Ok(())
            },
            "recovery deployment refused",
        ),
        (
            |profile| {
                profile.effect_contract.max_response_bytes = SafeInteger::new(65537)?;
                Ok(())
            },
            "recovery deployment refused",
        ),
        (
            |profile| {
                profile.actors = NonEmptyBoundedList::new(vec![RecoveryActorAssignment {
                    subject: key_pair(3).public_key(),
                    principal: PrincipalId::new("operator")?,
                    permissions: BoundedList::new(vec![
                        RecoveryPermission::Inspect,
                        RecoveryPermission::Create,
                    ])?,
                    preview_clearance: InformationLabel::bottom(),
                }])?;
                Ok(())
            },
            "recovery actor assignment refused",
        ),
        (
            |profile| {
                let mut actor = profile
                    .actors
                    .as_slice()
                    .first()
                    .cloned()
                    .ok_or("fixture actor absent")?;
                actor.permissions = BoundedList::new(Vec::new())?;
                profile.actors = NonEmptyBoundedList::new(vec![actor])?;
                Ok(())
            },
            "recovery actor assignment refused",
        ),
        (
            |profile| {
                let mut actor = profile
                    .actors
                    .as_slice()
                    .first()
                    .cloned()
                    .ok_or("fixture actor absent")?;
                actor.permissions =
                    BoundedList::new(vec![RecoveryPermission::Create, RecoveryPermission::Create])?;
                profile.actors = NonEmptyBoundedList::new(vec![actor])?;
                Ok(())
            },
            "recovery actor assignment refused",
        ),
        (
            |profile| {
                profile.coverage = NonEmptyBoundedList::new(vec![RecoveryCoverageAssignment {
                    issuer_id: IssuerId::new("issuer")?,
                    principal: PrincipalId::new("owner")?,
                    key: key_pair(4).public_key(),
                    obligations: NonEmptyBoundedList::new(vec![
                        AuthorityObligationV1::IntegrityEndorsement {
                            principal: PrincipalId::new("owner")?,
                        },
                    ])?,
                }])?;
                Ok(())
            },
            "recovery coverage assignment refused",
        ),
        (
            |profile| {
                profile.actors = NonEmptyBoundedList::new(vec![RecoveryActorAssignment {
                    subject: key_pair(3).public_key(),
                    principal: PrincipalId::new("operator")?,
                    permissions: BoundedList::new(vec![RecoveryPermission::Create])?,
                    preview_clearance: InformationLabel::Top,
                }])?;
                Ok(())
            },
            "recovery preview clearance refused",
        ),
        (
            |profile| {
                profile.effect_cardinality = SafeInteger::new(2)?;
                Ok(())
            },
            "recovery deployment refused",
        ),
    ];
    for (mutate, expected) in cases {
        let mut profile = valid.clone();
        mutate(&mut profile)?;
        let profile = sealed(profile)?;
        assert_eq!(
            fixture.store.configure_recovery_deployment(&profile),
            Err(invariant(expected))
        );
        assert_eq!(fixture.counts()?, (0, 0, 0));
    }
    let mut unsealed = valid.clone();
    unsealed.policy_digest = PolicyDigest::from_bytes([9; 32]);
    assert_eq!(
        fixture.store.configure_recovery_deployment(&unsealed),
        Err(invariant("recovery deployment refused"))
    );
    assert_eq!(fixture.counts()?, (0, 0, 0));
    Ok(())
}

#[test]
fn equal_native_context_for_another_scope_is_refused() -> TestResult {
    let fixture = authority()?;
    let binding = fixture.initialized_binding("native-primary")?;
    fixture.store.configure_recovery_deployment(&deployment(
        &fixture.fence,
        &binding,
        "process:primary",
    )?)?;
    let before = fixture.counts()?;
    assert_eq!(
        fixture.store.configure_recovery_deployment(&deployment(
            &fixture.fence,
            &binding,
            "process:secondary"
        )?),
        Err(invariant("protected recovery setup refused"))
    );
    assert_eq!(fixture.counts()?, before);
    Ok(())
}

#[test]
fn tenant_setup_requirement_is_written_once_and_never_changes() -> TestResult {
    let fixture = authority()?;
    let binding = fixture.initialized_binding("native-primary")?;
    let mut profile = deployment(&fixture.fence, &binding, "process:primary")?;
    profile.setup_policy = Some(NativeSetupPolicyV1 {
        operator_root: key_pair(20).public_key(),
    });
    let profile = sealed(profile)?;
    fixture.store.configure_recovery_deployment(&profile)?;
    assert_eq!(fixture.counts()?, (6, 8, 8));
    fixture.store.configure_recovery_deployment(&profile)?;
    assert_eq!(fixture.counts()?, (6, 8, 8));
    let marker = format!(
        "protected-setup-tenant:{}",
        chio_core::sha256_hex(&encode_protected(&(
            &profile.scope.authority_domain,
            &profile.scope.tenant_id
        ))?)
    );
    let raw = Connection::open(&fixture.database)?;
    let (version, scope): (i64, String) = raw.query_row(
        "SELECT version, scope_key FROM admission_operation_recovery_records
         WHERE record_key = ?1",
        [&marker],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(version, 1);
    assert_eq!(scope.len(), 64);
    drop(raw);
    let fixture = verify_reopened(fixture)?;
    assert_eq!(fixture.counts()?, (6, 8, 8));

    let changed = authority()?;
    let changed_binding = changed.initialized_binding("native-primary")?;
    let mut changed_profile = deployment(&changed.fence, &changed_binding, "process:primary")?;
    changed_profile.setup_policy = profile.setup_policy.clone();
    let changed_profile = sealed(changed_profile)?;
    let marker = format!(
        "protected-setup-tenant:{}",
        chio_core::sha256_hex(&encode_protected(&(
            &changed_profile.scope.authority_domain,
            &changed_profile.scope.tenant_id
        ))?)
    );
    let marker_scope = chio_core::sha256_hex(&encode_protected(&(
        &changed_profile.scope.authority_domain,
        &changed_profile.scope.tenant_id,
    ))?);
    let mut connection = changed.store.connection()?;
    let tx = changed
        .store
        .begin_write(&mut connection, Some(&changed.fence))?;
    persist_protected_record(
        &tx,
        &changed.store.serving_owner,
        &ProtectedWrite {
            key: &marker,
            scope: &marker_scope,
            kind: ProtectedRecordKind::Command,
            payload: b"{\"changed\":true}",
        },
    )?;
    changed.store.commit_write(tx)?;
    changed.store.sync_after_write(&connection)?;
    drop(connection);
    let before = changed.counts()?;
    assert_eq!(
        changed
            .store
            .configure_recovery_deployment(&changed_profile),
        Err(invariant("protected recovery setup refused"))
    );
    assert_eq!(changed.counts()?, before);
    Ok(())
}

#[test]
fn retained_deployment_history_is_immutable() -> TestResult {
    let fixture = authority()?;
    let binding = fixture.initialized_binding("native-primary")?;
    let profile = deployment(&fixture.fence, &binding, "process:primary")?;
    fixture.store.configure_recovery_deployment(&profile)?;
    let raw = Connection::open(&fixture.database)?;
    let updated = raw.execute(
        "UPDATE admission_operation_recovery_records SET version = version + 1
         WHERE record_key = ?1",
        [history_record_key(&profile)?],
    );
    assert!(matches!(
        updated,
        Err(rusqlite::Error::SqliteFailure(_, Some(message)))
            if message == "historical deployment is immutable"
    ));
    let inserted = raw.execute(
        "INSERT INTO admission_operation_recovery_records
         (record_key, scope_key, kind, version, payload)
         VALUES ('deployment-history:forged', ?1, 'command', 1, X'7B7D')",
        [protected_scope_key(&profile.scope)?],
    );
    assert!(matches!(
        inserted,
        Err(rusqlite::Error::SqliteFailure(_, Some(message)))
            if message == "historical deployment identity is invalid"
    ));
    drop(raw);

    let changed = authority()?;
    let changed_binding = changed.initialized_binding("native-primary")?;
    let changed_profile = deployment(&changed.fence, &changed_binding, "process:primary")?;
    let mut connection = changed.store.connection()?;
    let tx = changed
        .store
        .begin_write(&mut connection, Some(&changed.fence))?;
    persist_protected_record(
        &tx,
        &changed.store.serving_owner,
        &ProtectedWrite {
            key: &history_record_key(&changed_profile)?,
            scope: &protected_scope_key(&changed_profile.scope)?,
            kind: ProtectedRecordKind::Deployment,
            payload: b"{\"changed\":true}",
        },
    )?;
    changed.store.commit_write(tx)?;
    changed.store.sync_after_write(&connection)?;
    drop(connection);
    let before = changed.counts()?;
    assert_eq!(
        changed
            .store
            .configure_recovery_deployment(&changed_profile),
        Err(invariant("recovery immutable deployment custody changed"))
    );
    assert_eq!(changed.counts()?, before);
    Ok(())
}

#[test]
fn oversized_deployments_refuse_before_any_write() -> TestResult {
    let fixture = authority()?;
    let binding = fixture.initialized_binding("native-primary")?;
    let mut profile = deployment(&fixture.fence, &binding, "process:primary")?;
    let coverage = (0..64)
        .map(|issuer| {
            let principal = format!("owner-{issuer:02}-{}", "p".repeat(96));
            let obligations = (0..64)
                .map(|owner| {
                    Ok(AuthorityObligationV1::OwnerRelease {
                        owner: PrincipalId::new(format!("owner-{owner:02}-{}", "o".repeat(96)))?,
                    })
                })
                .collect::<TestResult<Vec<_>>>()?;
            let issuer_seed = u8::try_from(30 + issuer)?;
            Ok(RecoveryCoverageAssignment {
                issuer_id: IssuerId::new(&format!("issuer-{issuer:02}"))?,
                principal: PrincipalId::new(principal)?,
                key: key_pair(issuer_seed).public_key(),
                obligations: NonEmptyBoundedList::new(obligations)?,
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    profile.coverage = NonEmptyBoundedList::new(coverage)?;
    let profile = sealed(profile)?;
    assert!(chio_core::canonical::canonical_json_bytes(&profile)?.len() > 262_144);
    assert_eq!(
        fixture.store.configure_recovery_deployment(&profile),
        Err(invariant("recovery resource exhausted"))
    );
    assert_eq!(fixture.counts()?, (0, 0, 0));
    let raw = Connection::open(&fixture.database)?;
    let inserted = raw.execute(
        "INSERT INTO admission_operation_recovery_records
         (record_key, scope_key, kind, version, payload)
         VALUES ('command:oversized', ?1, 'command', 1, zeroblob(262145))",
        [protected_scope_key(&profile.scope)?],
    );
    assert!(matches!(
        inserted,
        Err(rusqlite::Error::SqliteFailure(_, Some(message)))
            if message == "CHECK constraint failed: length(payload) BETWEEN 1 AND 262144"
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
fn pinned_reader_backlog_refuses_installation_before_any_write() -> TestResult {
    let fixture = authority()?;
    let binding = fixture.initialized_binding("native-primary")?;
    let profile = deployment(&fixture.fence, &binding, "process:primary")?;
    let writer = Connection::open(&fixture.database)?;
    writer.execute_batch(
        "PRAGMA wal_autocheckpoint=0;
         CREATE TABLE pressure_fixture(payload BLOB NOT NULL);",
    )?;
    let reader = Connection::open(&fixture.database)?;
    reader.execute_batch("BEGIN;")?;
    let _: i64 = reader.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records",
        [],
        |row| row.get(0),
    )?;
    for _ in 0..17 {
        writer.execute(
            "INSERT INTO pressure_fixture(payload) VALUES(zeroblob(4194304))",
            [],
        )?;
    }
    assert_eq!(
        fixture.store.configure_recovery_deployment(&profile),
        Err(invariant("recovery disk headroom exhausted"))
    );
    reader.execute_batch("ROLLBACK;")?;
    assert_eq!(fixture.counts()?, (0, 0, 0));
    Ok(())
}

#[test]
fn raw_replacement_is_refused_while_rotation_succeeds() -> TestResult {
    let fixture = authority()?;
    let binding = fixture.initialized_binding("native-primary")?;
    let original = deployment(&fixture.fence, &binding, "process:primary")?;
    fixture.store.configure_recovery_deployment(&original)?;
    let raw = Connection::open(&fixture.database)?;
    let replaced = raw.execute(
        "INSERT INTO admission_operation_recovery_records
         (record_key, scope_key, kind, version, payload)
         VALUES (?1, ?2, 'deployment', 2, X'7B7D')",
        [
            current_record_key(&original)?,
            protected_scope_key(&original.scope)?,
        ],
    );
    assert!(matches!(
        replaced,
        Err(rusqlite::Error::SqliteFailure(_, Some(message)))
            if message == "recovery ownership cannot be replaced"
    ));
    drop(raw);
    let mut rotated = original.clone();
    rotated.policy_digest = PolicyDigest::from_bytes([21; 32]);
    let rotated = sealed(rotated)?;
    fixture.store.configure_recovery_deployment(&rotated)?;
    assert_eq!(
        record_bytes(&fixture.database, &current_record_key(&rotated)?)?.0,
        2
    );
    verify_reopened(fixture)?;
    Ok(())
}

#[test]
fn planned_records_without_allocations_refuse_at_verification() -> TestResult {
    let fixture = authority()?;
    let binding = fixture.initialized_binding("native-primary")?;
    let profile = deployment(&fixture.fence, &binding, "process:primary")?;
    let payload = encode_protected(&profile)?;
    let mut connection = fixture.store.connection()?;
    let tx = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    persist_protected_record(
        &tx,
        &fixture.store.serving_owner,
        &ProtectedWrite {
            key: &current_record_key(&profile)?,
            scope: &protected_scope_key(&profile.scope)?,
            kind: ProtectedRecordKind::Deployment,
            payload: &payload,
        },
    )?;
    assert_eq!(
        verify_planning_allocations(&tx),
        Err(invariant("recovery planning global allocation disappeared"))
    );
    tx.rollback()?;
    Ok(())
}

fn tenant_marker_key(profile: &RecoveryDeploymentV1) -> TestResult<String> {
    Ok(format!(
        "protected-setup-tenant:{}",
        chio_core::sha256_hex(&encode_protected(&(
            &profile.scope.authority_domain,
            &profile.scope.tenant_id
        ))?)
    ))
}

fn single_key(database: &std::path::Path, pattern: &str) -> TestResult<String> {
    let raw = Connection::open(database)?;
    Ok(raw.query_row(
        "SELECT record_key FROM admission_operation_recovery_records WHERE record_key GLOB ?1",
        [pattern],
        |row| row.get(0),
    )?)
}

/// Rotating a protected tenant's deployment to one without a setup policy
/// retains the tenant marker: protection is never removed.
#[test]
fn tenant_marker_survives_rotation_to_no_setup_policy() -> TestResult {
    let fixture = authority()?;
    let binding = fixture.initialized_binding("native-primary")?;
    let mut protected = deployment(&fixture.fence, &binding, "process:primary")?;
    protected.setup_policy = Some(NativeSetupPolicyV1 {
        operator_root: key_pair(20).public_key(),
    });
    let protected = sealed(protected)?;
    fixture.store.configure_recovery_deployment(&protected)?;
    assert_eq!(fixture.counts()?, (6, 8, 8));
    let marker = tenant_marker_key(&protected)?;
    let retained = record_bytes(&fixture.database, &marker)?;
    let mut unprotected = protected.clone();
    unprotected.setup_policy = None;
    let unprotected = sealed(unprotected)?;
    fixture.store.configure_recovery_deployment(&unprotected)?;
    assert_eq!(fixture.counts()?, (7, 14, 14));
    assert_eq!(record_bytes(&fixture.database, &marker)?, retained);
    assert_eq!(retained.0, 1);
    let fixture = verify_reopened(fixture)?;
    assert_eq!(record_bytes(&fixture.database, &marker)?, retained);
    assert_eq!(fixture.counts()?, (7, 14, 14));
    Ok(())
}

/// A planning allocation whose projection is gone while its local events and
/// global commits remain refuses the next planned write and startup planning
/// verification; the cold open refuses at local history.
#[test]
fn missing_quota_projection_with_retained_history_refuses_save_and_startup() -> TestResult {
    let fixture = authority()?;
    let binding = fixture.initialized_binding("native-primary")?;
    let original = deployment(&fixture.fence, &binding, "process:primary")?;
    fixture.store.configure_recovery_deployment(&original)?;
    let quota = single_key(&fixture.database, "recovery-planning-quota:*:global")?;
    delete_projection_through_owner(&fixture.store, &fixture.fence, &quota)?;
    assert_eq!(fixture.counts()?, (4, 7, 7));
    let mut rotated = original.clone();
    rotated.policy_digest = PolicyDigest::from_bytes([31; 32]);
    let rotated = sealed(rotated)?;
    let disappeared = || {
        Err(invariant(
            "recovery record disappeared with retained history",
        ))
    };
    assert_eq!(
        fixture.store.configure_recovery_deployment(&rotated),
        disappeared()
    );
    assert_eq!(fixture.counts()?, (4, 7, 7));
    let raw = Connection::open(&fixture.database)?;
    assert_eq!(verify_planning_allocations(&raw), disappeared());
    drop(raw);
    let Authority {
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);
    match crate::test_authority::open_serving(&database, &lock_root) {
        Err(crate::SqliteServingOwnerError::BudgetSchema(
            chio_kernel::BudgetStoreError::Invariant(message),
        )) => assert_eq!(
            message,
            "sqlite foreign key violation in `admission_operation_recovery_events` row 3"
        ),
        Err(other) => return Err(format!("unexpected cold open refusal: {other:?}").into()),
        Ok(_) => return Err("cold open accepted a missing quota projection".into()),
    }
    Ok(())
}

/// A native context record rewritten through the private writer keeps a valid
/// chain but is no longer its version 1 routing identity, so installation
/// refuses it.
#[test]
fn rewritten_native_context_record_is_refused_by_installation() -> TestResult {
    let fixture = authority()?;
    let binding = fixture.initialized_binding("native-primary")?;
    let profile = deployment(&fixture.fence, &binding, "process:primary")?;
    fixture.store.configure_recovery_deployment(&profile)?;
    let context = single_key(&fixture.database, "protected-setup-context:*")?;
    let (_, payload) = record_bytes(&fixture.database, &context)?;
    let mut rewritten: serde_json::Value = serde_json::from_slice(&payload)?;
    rewritten["scope"]["process_id"] = serde_json::json!("process:other");
    let rewritten = encode_protected(&rewritten)?;
    let mut connection = fixture.store.connection()?;
    let tx = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    persist_protected_record(
        &tx,
        &fixture.store.serving_owner,
        &ProtectedWrite {
            key: &context,
            scope: &protected_scope_key(&profile.scope)?,
            kind: ProtectedRecordKind::Command,
            payload: &rewritten,
        },
    )?;
    fixture.store.commit_write(tx)?;
    fixture.store.sync_after_write(&connection)?;
    drop(connection);
    assert_eq!(fixture.counts()?, (5, 8, 8));
    assert_eq!(
        fixture.store.configure_recovery_deployment(&profile),
        Err(invariant("protected recovery setup refused"))
    );
    assert_eq!(fixture.counts()?, (5, 8, 8));
    Ok(())
}

/// Corrupt one projection while retaining owner custody and the exact catalog.
fn delete_projection_through_owner(
    store: &SqliteAdmissionOperationStore,
    fence: &StoreMutationFence,
    key: &str,
) -> TestResult {
    let mut connection = store.connection()?;
    connection.execute_batch("PRAGMA foreign_keys = OFF;")?;
    let tx = store.begin_write(&mut connection, Some(fence))?;
    let guard: String = tx.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'trigger'
         AND name = 'admission_operation_recovery_records_no_delete'",
        [],
        |row| row.get(0),
    )?;
    tx.execute_batch("DROP TRIGGER admission_operation_recovery_records_no_delete;")?;
    tx.execute(
        "DELETE FROM main.admission_operation_recovery_records WHERE record_key = ?1",
        [key],
    )?;
    tx.execute_batch(&guard)?;
    store.commit_write(tx)?;
    store.sync_after_write(&connection)?;
    connection.execute_batch("PRAGMA foreign_keys = ON;")?;
    assert_eq!(
        connection.query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))?,
        1
    );
    Ok(())
}

#[test]
fn external_projection_deletion_fences_deployment_installation() -> TestResult {
    let fixture = authority()?;
    let binding = fixture.initialized_binding("native-primary")?;
    let profile = deployment(&fixture.fence, &binding, "process:primary")?;
    fixture.store.configure_recovery_deployment(&profile)?;
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
    assert_eq!(fixture.counts()?, (4, 7, 7));
    assert_eq!(
        fixture.store.configure_recovery_deployment(&profile),
        Err(
            chio_kernel::admission_operation::AdmissionOperationStoreError::OutcomeUnknown(
                "authority database changed outside its serving-owner connection".into(),
            )
        )
    );
    assert_eq!(fixture.counts()?, (4, 7, 7));
    Ok(())
}

#[test]
fn full_permission_assignment_installs_replays_and_survives_reopen() -> TestResult {
    let fixture = authority()?;
    let binding = fixture.initialized_binding("native-primary")?;
    let mut profile = deployment(&fixture.fence, &binding, "process:primary")?;
    let permissions = vec![
        RecoveryPermission::Create,
        RecoveryPermission::Inspect,
        RecoveryPermission::Select,
        RecoveryPermission::Approve,
        RecoveryPermission::Resume,
        RecoveryPermission::Cancel,
        RecoveryPermission::Report,
        RecoveryPermission::Settle,
        RecoveryPermission::KnowledgeRead,
        RecoveryPermission::KnowledgeWrite,
        RecoveryPermission::KnowledgeAdopt,
        RecoveryPermission::KnowledgeAdmin,
        RecoveryPermission::ConfinedLaunch,
        RecoveryPermission::ConfinedReturn,
        RecoveryPermission::ConfinedCancel,
        RecoveryPermission::Maintain,
        RecoveryPermission::InspectExplanationGraph,
    ];
    let mut actor = profile
        .actors
        .as_slice()
        .first()
        .cloned()
        .ok_or("fixture actor absent")?;
    actor.permissions = BoundedList::new(permissions.clone())?;
    profile.actors = NonEmptyBoundedList::new(vec![actor])?;
    let profile = sealed(profile)?;
    fixture.store.configure_recovery_deployment(&profile)?;
    assert_eq!(fixture.counts()?, (5, 7, 7));
    fixture.store.configure_recovery_deployment(&profile)?;
    assert_eq!(fixture.counts()?, (5, 7, 7));
    let reopened = verify_reopened(fixture)?;
    assert_eq!(reopened.counts()?, (5, 7, 7));
    let (_, payload) = record_bytes(&reopened.database, &current_record_key(&profile)?)?;
    let retained: RecoveryDeploymentV1 = serde_json::from_slice(&payload)?;
    assert_eq!(
        retained
            .actors
            .as_slice()
            .first()
            .ok_or("retained actor absent")?
            .permissions
            .as_slice(),
        permissions.as_slice()
    );
    Ok(())
}
