use super::*;
use crate::treaty_epoch::{
    sign_treaty_epoch_record, TreatyEpochParticipantV1, TreatyEpochRecordV1, TreatyEpochStatusV1,
    CHIO_TREATY_EPOCH_SCHEMA,
};
use crate::{
    RuntimeAdmissionAuthorityCommit, RuntimeTreatyAuthorizationBinding,
    RuntimeTreatyAuthorizationRequest, RuntimeTrustFloorEntry, RuntimeTrustFloorUpdate,
    TreatyScope,
};
use chio_core_types::crypto::{Ed25519Backend, Keypair, SigningBackend};
use chio_kernel::admission_operation::runtime_participant::{
    RuntimeParticipantClaimIntentInput, RuntimeParticipantClaimIntentV1,
    RuntimeParticipantClaimReferenceV1, RuntimeParticipantPhase,
};
use chio_kernel::admission_operation::{AdmissionOperationId, RuntimeSourcePort};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn id(value: &str) -> TestResult<AdmissionIdentifier> {
    Ok(AdmissionIdentifier::try_new("fixture", value)?)
}
fn digest(value: char) -> TestResult<AdmissionDigest> {
    Ok(AdmissionDigest::try_new(
        "fixture",
        value.to_string().repeat(64),
    )?)
}

struct Fixture {
    _directory: tempfile::TempDir,
    store: SqliteRuntimeOrchestrationStore,
    backend: Ed25519Backend,
    update: VerifiedTreatyEpochUpdate,
    request: RuntimeAdmissionAuthorityCommit,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let store = SqliteRuntimeOrchestrationStore::open_with_clock(
            directory.path().join("source.sqlite3"),
            chio_test_support::clock::clock(),
        )?;
        let qualification = store.qualify(&id("source")?, &id("runtime")?, &id("destination")?)?;
        let backend = Ed25519Backend::generate();
        let body = TreatyEpochRecordV1 {
            schema: CHIO_TREATY_EPOCH_SCHEMA.into(),
            verifier_id: id("verifier")?,
            treaty_id: id("treaty")?,
            sequence: 1,
            previous_record_sha256: None,
            status: TreatyEpochStatusV1::Active,
            participants: vec![
                TreatyEpochParticipantV1 {
                    kernel_id: id("buyer")?,
                    public_key: Keypair::generate().public_key(),
                    ladder_manifest_sha256: digest('a')?,
                },
                TreatyEpochParticipantV1 {
                    kernel_id: id("vendor")?,
                    public_key: Keypair::generate().public_key(),
                    ladder_manifest_sha256: digest('b')?,
                },
            ],
            trust_bundle_sha256: digest('c')?,
            issued_at_unix_ms: 900_000,
            expires_at_unix_ms: 1_100_000,
        };
        let update = sign_treaty_epoch_record(body.clone(), &backend, &backend.public_key()?)?;
        let scope = TreatyScope {
            schema: crate::CHIO_TREATY_SCOPE_SCHEMA.into(),
            treaty_id: "treaty".into(),
            participant_kernel_ids: body
                .participants
                .iter()
                .map(|p| p.kernel_id.as_str().into())
                .collect(),
            participant_public_keys: body
                .participants
                .iter()
                .map(|p| p.public_key.clone())
                .collect(),
            ladder_manifest_sha256s: body
                .participants
                .iter()
                .map(|p| p.ladder_manifest_sha256.as_str().into())
                .collect(),
            allowed_action_classes: vec!["invoke".into()],
            issued_at_unix_ms: 900_000,
            expires_at_unix_ms: 1_100_000,
            revocation_epoch_sha256: update.body_digest().as_str().into(),
            trust_bundle_sha256: body.trust_bundle_sha256.as_str().into(),
        };
        let reference = RuntimeParticipantClaimReferenceV1::new(
            AdmissionOperationId::from_persisted("d".repeat(64))?,
            id("episode")?,
            digest('e')?,
        );
        let intent = RuntimeParticipantClaimIntentV1::new(RuntimeParticipantClaimIntentInput {
            episode_id: id("episode")?,
            runtime_authority_id: id("runtime")?,
            qualification_id: id(qualification.qualification_sha256())?,
            request_binding_hash: digest('f')?,
            grant_index: 0,
            phase: RuntimeParticipantPhase::Dispatch,
            plan_digest: digest('a')?,
            resources: vec![],
        })?;
        let request = RuntimeAdmissionAuthorityCommit {
            treaty: Some(RuntimeTreatyAuthorizationRequest {
                binding: RuntimeTreatyAuthorizationBinding {
                    verifier_id: id("verifier")?,
                    scope,
                    reference,
                    intent,
                },
                now_unix_ms: 1_000_000,
                source_qualification: qualification,
            }),
            trust_floor: None,
        };
        Ok(Self {
            _directory: directory,
            store,
            backend,
            update,
            request,
        })
    }
    fn install(&self) -> TestResult {
        self.store.provision_treaty_epoch_authority(
            id("verifier")?,
            id("treaty")?,
            self.backend.public_key()?,
        )?;
        self.store.apply_treaty_epoch_update(None, &self.update)?;
        Ok(())
    }
}

#[test]
fn no_floor_commit_requires_current_authority_and_retains_exact_authorization() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(1000);
    let fixture = Fixture::new()?;
    assert_eq!(
        fixture
            .store
            .commit_runtime_authority(&fixture.request)
            .err()
            .ok_or("missing authority accepted")?
            .code(),
        "treaty_epoch_unavailable"
    );
    fixture.store.provision_treaty_epoch_authority(
        id("verifier")?,
        id("treaty")?,
        fixture.backend.public_key()?,
    )?;
    assert_eq!(
        fixture
            .store
            .commit_runtime_authority(&fixture.request)
            .err()
            .ok_or("missing epoch accepted")?
            .code(),
        "treaty_epoch_missing"
    );
    fixture
        .store
        .apply_treaty_epoch_update(None, &fixture.update)?;
    fixture.store.commit_runtime_authority(&fixture.request)?;
    fixture.store.commit_runtime_authority(&fixture.request)?;
    let binding = fixture.request.treaty().ok_or("treaty request")?.binding();
    fixture
        .store
        .verify_retained_treaty_authorization(binding)?;
    let mut changed = binding.clone();
    changed.scope.allowed_action_classes.push("other".into());
    assert_eq!(
        fixture
            .store
            .verify_retained_treaty_authorization(&changed)
            .err()
            .ok_or("changed claim accepted")?
            .code(),
        "treaty_epoch_authorization_mismatch"
    );
    let count: i64 = fixture.store.lock_connection()?.query_row(
        "SELECT COUNT(*) FROM runtime_treaty_authorizations",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(count, 1);
    Ok(())
}

#[test]
fn revoked_epoch_refuses_new_commit_but_retained_authorization_stays_historical() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(1000);
    let fixture = Fixture::new()?;
    fixture.install()?;
    fixture.store.commit_runtime_authority(&fixture.request)?;
    let mut revoked = fixture.update.body().clone();
    revoked.sequence = 2;
    revoked.previous_record_sha256 = Some(fixture.update.body_digest().clone());
    revoked.status = TreatyEpochStatusV1::Revoked;
    let revoked =
        sign_treaty_epoch_record(revoked, &fixture.backend, &fixture.backend.public_key()?)?;
    fixture
        .store
        .apply_treaty_epoch_update(Some(fixture.update.body_digest()), &revoked)?;
    assert_eq!(
        fixture
            .store
            .commit_runtime_authority(&fixture.request)
            .err()
            .ok_or("revoked epoch accepted")?
            .code(),
        "treaty_revoked"
    );
    fixture.store.verify_retained_treaty_authorization(
        fixture.request.treaty().ok_or("treaty request")?.binding(),
    )?;
    Ok(())
}

#[test]
fn floor_cas_failure_rolls_back_treaty_authorization() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(1000);
    let mut fixture = Fixture::new()?;
    fixture.install()?;
    fixture
        .store
        .store_runtime_trust_floor(RuntimeTrustFloorEntry {
            verifier_id: "verifier".into(),
            key_id: "key".into(),
            highest_version: 1,
            latest_bundle_sha256: "a".repeat(64),
            latest_revocation_checkpoint_sha256: "c".repeat(64),
        })?;
    fixture.request.trust_floor = Some(RuntimeTrustFloorUpdate {
        entry: RuntimeTrustFloorEntry {
            verifier_id: "verifier".into(),
            key_id: "key".into(),
            highest_version: 2,
            latest_bundle_sha256: "b".repeat(64),
            latest_revocation_checkpoint_sha256: "c".repeat(64),
        },
        previous_hash_sha256: Some("d".repeat(64)),
    });
    assert_eq!(
        fixture
            .store
            .commit_runtime_authority(&fixture.request)
            .err()
            .ok_or("floor CAS accepted wrong predecessor")?
            .code(),
        "runtime_trust_previous_hash_mismatch"
    );
    let count: i64 = fixture.store.lock_connection()?.query_row(
        "SELECT COUNT(*) FROM runtime_treaty_authorizations",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn authority_table_limits_refuse_before_unrelated_rows_are_decoded() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(1000);
    for (table, limit, insert) in [
        ("runtime_treaty_epoch_pins", MAX_PINS, "INSERT INTO runtime_treaty_epoch_pins SELECT printf('other-%d', n), x'00' FROM counts"),
        ("runtime_treaty_epoch_heads", MAX_PINS, "INSERT INTO runtime_treaty_epoch_heads SELECT printf('other-%d', n), 'invalid-unselected-digest' FROM counts"),
        ("runtime_treaty_epoch_records", MAX_RECORDS, "INSERT INTO runtime_treaty_epoch_records SELECT printf('other-%d', n), printf('%064x', n), 1, x'00' FROM counts"),
        ("runtime_treaty_authorizations", MAX_AUTHORIZATIONS, "INSERT INTO runtime_treaty_authorizations SELECT printf('other-%d', n), x'00' FROM counts"),
    ] {
        let fixture = Fixture::new()?;
        fixture.install()?;
        fixture.store.commit_runtime_authority(&fixture.request)?;
        let limit = i64::try_from(limit)?;
        let fill = format!("WITH RECURSIVE counts(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM counts WHERE n < ?1) {insert}");
        fixture.store.lock_connection()?.execute(&fill, params![limit - 1])?;
        fixture.store.commit_runtime_authority(&fixture.request)?;
        let overflow = format!("WITH counts(n) AS (SELECT ?1) {insert}");
        fixture.store.lock_connection()?.execute(&overflow, params![limit])?;
        assert_eq!(fixture.store.commit_runtime_authority(&fixture.request).err().ok_or("over-limit authority accepted")?.code(), "treaty_epoch_capacity", "{table}");
    }
    Ok(())
}
