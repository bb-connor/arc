//! Revocation progress at a full passport status registry.
//!
//! The fixture fills a registry through the real publish and save path to the
//! exact admission boundary: one more byte of any admitted record would be
//! refused. Revocations of admitted records must still persist from there.

use super::*;
use crate::signed_input::{MAX_SIGNED_FILE_BYTES, REVOCATION_REASON_LIMIT_BYTES as REASON_LIMIT};
use chio_credentials::{
    build_agent_passport, issue_reputation_credential, AttestationWindow, ChioCredentialEvidence,
};
use std::sync::OnceLock;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

const ISSUED_AT: u64 = 1_710_000_000;
pub(crate) const PUBLISHED_AT: u64 = ISSUED_AT + 60;
const ISSUER_SEED: u8 = 71;
const BULK_SUBJECT_SEED: u8 = 72;
const TOP_OFF_SUBJECT_SEED: u8 = 73;
const FRESH_SUBJECT_SEED: u8 = 74;
const CACHE_TTL_SECS: u64 = 300;

pub(crate) fn passport_issued_at(subject_seed: u8, issued_at: u64) -> Fallible<AgentPassport> {
    let subject = Keypair::from_seed(&[subject_seed; 32]);
    let scorecard = chio_reputation::compute_local_scorecard(
        &subject.public_key().to_hex(),
        issued_at,
        &chio_reputation::LocalReputationCorpus::default(),
        &chio_reputation::ReputationConfig::default(),
    );
    let credential = issue_reputation_credential(
        &Keypair::from_seed(&[ISSUER_SEED; 32]),
        scorecard,
        ChioCredentialEvidence {
            query: AttestationWindow {
                since: None,
                until: issued_at,
            },
            receipt_count: 0,
            receipt_ids: Vec::new(),
            checkpoint_roots: Vec::new(),
            receipt_log_urls: Vec::new(),
            lineage_records: 0,
            uncheckpointed_receipts: 0,
            runtime_attestation: None,
        },
        issued_at,
        issued_at + 7_200,
    )?;
    let subject_did = credential.unsigned.credential_subject.id.clone();
    Ok(build_agent_passport(&subject_did, vec![credential])?)
}

pub(crate) fn passport(subject_seed: u8) -> Fallible<AgentPassport> {
    passport_issued_at(subject_seed, ISSUED_AT)
}

/// A distribution whose resolve URL carries `pad` extra ASCII bytes, so each
/// pad byte adds exactly one byte to the stored record.
fn distribution(pad: usize) -> PassportStatusDistribution {
    PassportStatusDistribution {
        resolve_urls: vec![format!(
            "https://status.example.test/v1/passport/statuses/resolve/{}",
            "p".repeat(pad)
        )],
        cache_ttl_secs: Some(CACHE_TTL_SECS),
    }
}

/// A reason whose JSON-escaped content is exactly the bound, built from the
/// characters whose escapes are longest.
pub(crate) fn largest_reason() -> String {
    let reason = format!("{}{}ab", "\"".repeat(64), "\u{1}".repeat(21));
    debug_assert_eq!(escaped_len(&reason), REASON_LIMIT);
    reason
}

fn escaped_len(text: &str) -> usize {
    serde_json::to_string(text).map_or(usize::MAX, |encoded| encoded.len() - 2)
}

fn compact_len(registry: &PassportStatusRegistry) -> Fallible<usize> {
    Ok(serde_json::to_vec(registry)?.len())
}

/// `true` when the save persisted, `false` when it was refused for size;
/// any other failure is an error.
fn admitted(registry: &PassportStatusRegistry, path: &Path) -> Fallible<bool> {
    match registry.save(path) {
        Ok(()) => Ok(true),
        Err(error) if error.to_string().contains("registry file would exceed the") => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// The admission boundary, found through the real save path.
struct Boundary {
    template: PassportLifecycleRecord,
    top_off: AgentPassport,
    bulk: usize,
    pad: usize,
}

impl Boundary {
    fn registry(&self, bulk: usize, pad: usize) -> Fallible<PassportStatusRegistry> {
        let mut registry = PassportStatusRegistry::default();
        for index in 0..bulk {
            let mut record = self.template.clone();
            record.passport_id = format!("{index:064x}");
            registry
                .passports
                .insert(record.passport_id.clone(), record);
        }
        registry.publish(&self.top_off, PUBLISHED_AT, distribution(pad))?;
        Ok(registry)
    }

    fn search() -> Fallible<Self> {
        let mut seed = PassportStatusRegistry::default();
        let template =
            seed.publish(&passport(BULK_SUBJECT_SEED)?, PUBLISHED_AT, distribution(0))?;
        let mut boundary = Self {
            template,
            top_off: passport(TOP_OFF_SUBJECT_SEED)?,
            bulk: 0,
            pad: 0,
        };
        let directory = chio_test_support::private_tempdir()?;
        let path = directory.path().join("probe.json");
        let per_record =
            compact_len(&boundary.registry(2, 0)?)? - compact_len(&boundary.registry(1, 0)?)?;

        let (mut low, mut high) = (0, MAX_SIGNED_FILE_BYTES / per_record + 2);
        if !admitted(&boundary.registry(low, 0)?, &path)?
            || admitted(&boundary.registry(high, 0)?, &path)?
        {
            return Err("record count search does not bracket the boundary".into());
        }
        while high - low > 1 {
            let middle = low + (high - low) / 2;
            if admitted(&boundary.registry(middle, 0)?, &path)? {
                low = middle;
            } else {
                high = middle;
            }
        }
        boundary.bulk = low;

        let (mut low, mut high) = (0, per_record + 4_096);
        if admitted(&boundary.registry(boundary.bulk, high)?, &path)? {
            return Err("pad search does not bracket the boundary".into());
        }
        while high - low > 1 {
            let middle = low + (high - low) / 2;
            if admitted(&boundary.registry(boundary.bulk, middle)?, &path)? {
                low = middle;
            } else {
                high = middle;
            }
        }
        boundary.pad = low;
        Ok(boundary)
    }
}

fn boundary() -> Fallible<&'static Boundary> {
    static BOUNDARY: OnceLock<Result<Boundary, String>> = OnceLock::new();
    BOUNDARY
        .get_or_init(|| Boundary::search().map_err(|error| error.to_string()))
        .as_ref()
        .map_err(|error| error.clone().into())
}

/// Saves at `path` a registry filled to the exact admission boundary and
/// returns it. The last record was admitted through the real publish path.
pub(crate) fn full_registry(path: &Path) -> Fallible<PassportStatusRegistry> {
    let boundary = boundary()?;
    let registry = boundary.registry(boundary.bulk, boundary.pad)?;
    registry.save(path)?;
    Ok(registry)
}

fn one_published(path: &Path) -> Fallible<(PassportStatusRegistry, String)> {
    let mut registry = PassportStatusRegistry::default();
    let record = registry.publish(
        &passport(FRESH_SUBJECT_SEED)?,
        PUBLISHED_AT,
        distribution(0),
    )?;
    registry.save(path)?;
    Ok((registry, record.passport_id))
}

fn assert_reloads_exactly(registry: &PassportStatusRegistry, path: &Path) -> TestResult {
    let bytes = fs::read(path)?;
    assert!(bytes.len() <= MAX_SIGNED_FILE_BYTES);
    assert_eq!(bytes, serde_json::to_vec(registry)?);
    let reloaded = PassportStatusRegistry::load(path)?;
    assert_eq!(serde_json::to_vec(&reloaded)?, bytes);
    Ok(())
}

#[test]
fn every_admitted_passport_revokes_at_a_full_registry_and_reloads_exactly() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("passport-statuses.json");
    let mut registry = full_registry(&path)?;
    let ids: Vec<String> = registry.passports.keys().cloned().collect();
    let reason = largest_reason();
    for (index, passport_id) in ids.iter().enumerate() {
        let record = registry.revoke(passport_id, Some(&reason), Some(u64::MAX))?;
        assert_eq!(record.status, PassportLifecycleState::Revoked);
        if index < 3 || index % 2_048 == 0 || index + 1 == ids.len() {
            registry
                .save(&path)
                .map_err(|error| format!("revocation {index} of {}: {error}", ids.len()))?;
        }
    }
    assert_reloads_exactly(&registry, &path)?;
    // Every record now holds its largest revoked form, which is exactly what
    // admission reserved for it, so the file sits exactly at the cap.
    assert_eq!(
        fs::metadata(&path)?.len(),
        u64::try_from(MAX_SIGNED_FILE_BYTES)?
    );
    let reloaded = PassportStatusRegistry::load(&path)?;
    assert_eq!(reloaded.passports.len(), ids.len());
    for record in reloaded.passports.values() {
        assert_eq!(record.status, PassportLifecycleState::Revoked);
        assert_eq!(record.revoked_at, Some(u64::MAX));
        assert_eq!(record.revoked_reason.as_deref(), Some(reason.as_str()));
    }
    Ok(())
}

#[test]
fn publish_past_the_revocation_reserve_is_refused_and_the_file_is_unchanged() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("passport-statuses.json");
    let mut registry = full_registry(&path)?;
    let before = fs::read(&path)?;
    let record = registry.publish(
        &passport(FRESH_SUBJECT_SEED)?,
        PUBLISHED_AT,
        distribution(0),
    )?;
    assert_eq!(record.status, PassportLifecycleState::Active);
    let error = registry
        .save(&path)
        .err()
        .ok_or("a publish past the revocation reserve must be refused")?;
    assert!(matches!(error, CliError::Chio(_)));
    assert!(
        error.to_string().contains(&format!(
            "registry file would exceed the {MAX_SIGNED_FILE_BYTES} byte limit once "
        )),
        "{error}"
    );
    assert!(error
        .to_string()
        .contains("bytes are kept for revoking its records; the existing file was left unchanged"));
    assert_eq!(fs::read(&path)?, before);
    assert!(PassportStatusRegistry::load(&path)?
        .get(&record.passport_id)
        .is_none());
    Ok(())
}

#[test]
fn revocation_reason_past_the_bound_is_refused_and_the_record_stays_active() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("passport-statuses.json");
    let (mut registry, passport_id) = one_published(&path)?;
    let plain = "r".repeat(REASON_LIMIT + 1);
    let escaped = format!("{}c", largest_reason());
    for reason in [plain.as_str(), escaped.as_str()] {
        assert_eq!(escaped_len(reason), REASON_LIMIT + 1);
        let error = registry
            .revoke(&passport_id, Some(reason), Some(PUBLISHED_AT + 1))
            .err()
            .ok_or("a reason past the bound must be refused")?;
        assert!(matches!(error, CliError::Chio(_)));
        assert!(
            error.to_string().contains(&format!(
                "revocation reason must be at most {REASON_LIMIT} bytes once JSON-escaped"
            )),
            "{error}"
        );
        let record = registry.get(&passport_id).ok_or("record kept")?;
        assert_eq!(record.status, PassportLifecycleState::Active);
        assert_eq!(record.revoked_reason, None);
    }
    let reason = largest_reason();
    registry.revoke(&passport_id, Some(&reason), Some(PUBLISHED_AT + 1))?;
    registry.save(&path)?;
    assert_reloads_exactly(&registry, &path)
}

#[test]
fn revocation_that_load_would_refuse_is_refused_and_the_registry_stays_loadable() -> TestResult {
    let cases: [(Option<&str>, u64, &str); 3] = [
        (Some("compromised"), 0, "before its publication at"),
        (
            Some("compromised"),
            PUBLISHED_AT - 1,
            "before its publication at",
        ),
        (
            Some(" \t "),
            PUBLISHED_AT,
            "revocation reason must not be blank when present",
        ),
    ];
    for (reason, revoked_at, message) in cases {
        let directory = chio_test_support::private_tempdir()?;
        let path = directory.path().join("passport-statuses.json");
        let (mut registry, passport_id) = one_published(&path)?;
        let error = registry
            .revoke(&passport_id, reason, Some(revoked_at))
            .err()
            .ok_or("a revocation load would refuse must be refused")?;
        assert!(matches!(error, CliError::Chio(_)));
        assert!(error.to_string().contains(message), "{error}");
        assert_eq!(
            registry.get(&passport_id).map(|record| record.status),
            Some(PassportLifecycleState::Active)
        );
        registry.save(&path)?;
        assert_reloads_exactly(&registry, &path)?;
    }
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("passport-statuses.json");
    let (mut registry, passport_id) = one_published(&path)?;
    registry.revoke(&passport_id, None, Some(PUBLISHED_AT))?;
    registry.save(&path)?;
    assert_reloads_exactly(&registry, &path)
}

#[test]
fn publish_that_load_would_refuse_is_refused_and_the_registry_stays_loadable() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("passport-statuses.json");
    let (mut registry, _) = one_published(&path)?;
    let before = serde_json::to_vec(&registry)?;
    let unloadable = PassportStatusDistribution {
        resolve_urls: vec!["https://status.example.test/resolve".to_string()],
        cache_ttl_secs: None,
    };
    let error = registry
        .publish(&passport(TOP_OFF_SUBJECT_SEED)?, PUBLISHED_AT, unloadable)
        .err()
        .ok_or("a lifecycle record load would refuse must not be published")?;
    assert!(matches!(error, CliError::Chio(_)));
    assert!(
        error.to_string().contains("must include cache_ttl_secs"),
        "{error}"
    );
    assert_eq!(serde_json::to_vec(&registry)?, before);
    registry.save(&path)?;
    assert_reloads_exactly(&registry, &path)
}

#[test]
fn revocation_is_terminal_across_reopen_republish_and_supersede() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("passport-statuses.json");
    let first = passport(FRESH_SUBJECT_SEED)?;
    let (mut registry, passport_id) = one_published(&path)?;
    registry.revoke(&passport_id, Some("compromised"), Some(PUBLISHED_AT + 1))?;
    registry.save(&path)?;

    let mut reopened = PassportStatusRegistry::load(&path)?;
    let republished = reopened.publish(&first, PUBLISHED_AT + 2, distribution(0))?;
    assert_eq!(republished.status, PassportLifecycleState::Revoked);
    let successor = passport_issued_at(FRESH_SUBJECT_SEED, ISSUED_AT + 1)?;
    let newer = reopened.publish(&successor, PUBLISHED_AT + 3, distribution(0))?;
    assert_ne!(newer.passport_id, passport_id);
    assert_eq!(newer.status, PassportLifecycleState::Active);
    reopened.save(&path)?;

    let reloaded = PassportStatusRegistry::load(&path)?;
    let record = reloaded.get(&passport_id).ok_or("revoked record kept")?;
    assert_eq!(record.status, PassportLifecycleState::Revoked);
    assert_eq!(record.revoked_at, Some(PUBLISHED_AT + 1));
    assert_eq!(record.superseded_by, None);
    assert_eq!(
        reloaded.resolve_at(&passport_id, PUBLISHED_AT + 4).state,
        PassportLifecycleState::Revoked
    );
    assert_reloads_exactly(&reopened, &path)
}

fn encoded(record: &PassportLifecycleRecord) -> Fallible<usize> {
    Ok(crate::signed_input::encoded_len(record)?)
}

/// Records in every state a registry can hold, including a revoked record
/// whose reason predates the bound.
fn records_in_every_state() -> Fallible<Vec<PassportLifecycleRecord>> {
    let mut registry = PassportStatusRegistry::default();
    let superseded = registry.publish(
        &passport(FRESH_SUBJECT_SEED)?,
        PUBLISHED_AT,
        distribution(0),
    )?;
    registry.publish(
        &passport_issued_at(FRESH_SUBJECT_SEED, ISSUED_AT + 1)?,
        PUBLISHED_AT + 1,
        distribution(0),
    )?;
    let active = registry.publish(
        &passport(TOP_OFF_SUBJECT_SEED)?,
        PUBLISHED_AT,
        distribution(7),
    )?;
    let superseded = registry
        .get(&superseded.passport_id)
        .cloned()
        .ok_or("superseded record kept")?;
    assert_eq!(superseded.status, PassportLifecycleState::Superseded);
    let mut revoked = active.clone();
    revoked.status = PassportLifecycleState::Revoked;
    revoked.revoked_at = Some(PUBLISHED_AT + 2);
    revoked.updated_at = PUBLISHED_AT + 2;
    revoked.revoked_reason = Some("short".to_string());
    let mut unreasoned = revoked.clone();
    unreasoned.revoked_reason = None;
    let mut legacy = revoked.clone();
    legacy.revoked_reason = Some("l".repeat(4 * REASON_LIMIT));
    Ok(vec![active, superseded, revoked, unreasoned, legacy])
}

#[test]
fn revoking_never_grows_a_record_past_its_reserved_form() -> TestResult {
    let reason = largest_reason();
    let revocations: [(Option<&str>, u64); 4] = [
        (None, PUBLISHED_AT + 1),
        (Some(reason.as_str()), u64::MAX),
        (Some("short"), PUBLISHED_AT + 5),
        (Some(reason.as_str()), PUBLISHED_AT + 1),
    ];
    for record in records_in_every_state()? {
        let reserved = encoded(&largest_revoked_lifecycle_record(&record)?)?;
        assert!(encoded(&record)? <= reserved, "{record:?}");
        let mut registry = PassportStatusRegistry::default();
        registry
            .passports
            .insert(record.passport_id.clone(), record.clone());
        for (reason, revoked_at) in revocations {
            let revoked = registry.revoke(&record.passport_id, reason, Some(revoked_at))?;
            assert!(encoded(&revoked)? <= reserved, "{revoked:?}");
            assert!(
                encoded(&largest_revoked_lifecycle_record(&revoked)?)? <= reserved,
                "{revoked:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn revocations_never_raise_the_reserved_registry_size() -> TestResult {
    let mut registry = PassportStatusRegistry::default();
    for (index, mut record) in records_in_every_state()?.into_iter().enumerate() {
        record.passport_id = format!("{index:064x}");
        registry
            .passports
            .insert(record.passport_id.clone(), record);
    }
    let reserved_size = |registry: &PassportStatusRegistry| -> Fallible<usize> {
        Ok(compact_len(registry)? + registry.revocation_reserve()?)
    };
    let mut bound = reserved_size(&registry)?;
    let ids: Vec<String> = registry.passports.keys().cloned().collect();
    let reason = largest_reason();
    for round in [u64::MAX, PUBLISHED_AT + 3] {
        for passport_id in &ids {
            registry.revoke(passport_id, Some(&reason), Some(round))?;
            let next = reserved_size(&registry)?;
            assert!(next <= bound, "{next} > {bound}");
            assert!(compact_len(&registry)? <= next);
            bound = next;
        }
    }
    Ok(())
}
