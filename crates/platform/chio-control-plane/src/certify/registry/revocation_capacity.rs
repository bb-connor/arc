//! Revocation progress at a full certification registry.
//!
//! The fixture fills a registry to the exact admission boundary through the
//! real save path. Every entry is the one publish builds for its signed
//! artifact. Revocations of admitted entries must still persist from there.

use std::fs;
use std::sync::OnceLock;

use chio_core::Keypair;

use super::*;
use crate::certify::artifact::sign_artifact;
use crate::certify::schema::{
    CERTIFICATION_PROVENANCE_MODE_ARTIFACT_SIGNER, CERTIFICATION_SCHEMA,
    CRITERIA_PROFILE_ALL_PASS_V1, EVIDENCE_PROFILE_CONFORMANCE_REPORT_BUNDLE_V1,
    GENERATED_REPORT_MEDIA_TYPE_MARKDOWN,
};
use crate::certify::types::{
    CertificationCheckBody, CertificationEvidence, CertificationFinding, CertificationSummary,
    CertificationTarget, CertificationVerdict,
};
use crate::signed_input::{MAX_SIGNED_FILE_BYTES, REVOCATION_REASON_LIMIT_BYTES as REASON_LIMIT};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

const CHECKED_AT: u64 = 1_710_000_000;
pub(crate) const PUBLISHED_AT: u64 = CHECKED_AT + 60;
const SIGNER_SEED: u8 = 81;
const BULK_PAD: usize = 16 * 1024;

/// A signed check for `tool_server_id` whose single finding carries `pad`
/// extra ASCII bytes.
pub(crate) fn artifact(tool_server_id: &str, pad: usize) -> Fallible<SignedCertificationCheck> {
    let digest = "0".repeat(64);
    let body = CertificationCheckBody {
        schema: CERTIFICATION_SCHEMA.to_string(),
        criteria_profile: CRITERIA_PROFILE_ALL_PASS_V1.to_string(),
        checked_at: CHECKED_AT,
        target: CertificationTarget {
            tool_server_id: tool_server_id.to_string(),
            tool_server_name: Some("Capacity Fixture".to_string()),
        },
        verdict: CertificationVerdict::Pass,
        summary: CertificationSummary {
            scenario_count: 1,
            result_count: 1,
            evaluated_peer_count: 1,
            pass_count: 1,
            fail_count: 0,
            unsupported_count: 0,
            skipped_count: 0,
            xfail_count: 0,
            missing_scenarios_count: 0,
            unknown_results_count: 0,
        },
        criteria: Vec::new(),
        evidence: CertificationEvidence {
            evidence_profile: EVIDENCE_PROFILE_CONFORMANCE_REPORT_BUNDLE_V1.to_string(),
            scenarios_dir: "scenarios".to_string(),
            results_dir: "results".to_string(),
            normalized_scenarios_sha256: digest.clone(),
            normalized_results_sha256: digest.clone(),
            generated_report_sha256: digest,
            generated_report_bytes: 1,
            generated_report_media_type: GENERATED_REPORT_MEDIA_TYPE_MARKDOWN.to_string(),
            provenance_mode: CERTIFICATION_PROVENANCE_MODE_ARTIFACT_SIGNER.to_string(),
            report_output: None,
        },
        findings: vec![CertificationFinding {
            kind: "note".to_string(),
            message: format!("capacity fixture {}", "p".repeat(pad)),
            scenario_id: None,
            peer: None,
            deployment_mode: None,
            transport: None,
            status: None,
        }],
    };
    Ok(sign_artifact(
        body,
        &Keypair::from_seed(&[SIGNER_SEED; 32]),
    )?)
}

/// The entry publish records for `artifact` at `published_at`.
pub(crate) fn published_entry(
    artifact: SignedCertificationCheck,
    published_at: u64,
) -> Fallible<CertificationRegistryEntry> {
    verify_signed_certification_check(&artifact)?;
    let artifact_id = certification_artifact_id(&artifact)?;
    Ok(CertificationRegistryEntry {
        artifact_sha256: artifact_id.clone(),
        artifact_id,
        tool_server_id: artifact.body.target.tool_server_id.clone(),
        tool_server_name: artifact.body.target.tool_server_name.clone(),
        verdict: artifact.body.verdict,
        checked_at: artifact.body.checked_at,
        published_at,
        status: CertificationRegistryState::Active,
        superseded_at: None,
        superseded_by: None,
        revoked_at: None,
        revoked_reason: None,
        dispute: None,
        artifact,
    })
}

fn insert(registry: &mut CertificationRegistry, entry: CertificationRegistryEntry) {
    registry.artifacts.insert(entry.artifact_id.clone(), entry);
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

fn compact_len(registry: &CertificationRegistry) -> Fallible<usize> {
    Ok(serde_json::to_vec(registry)?.len())
}

/// `true` when the save persisted, `false` when it was refused for size;
/// any other failure is an error.
fn admitted(registry: &CertificationRegistry, path: &Path) -> Fallible<bool> {
    match registry.save(path) {
        Ok(()) => Ok(true),
        Err(error) if error.to_string().contains("registry file would exceed the") => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// The admission boundary, found through the real save path.
struct Boundary {
    bulk_entries: Vec<CertificationRegistryEntry>,
    bulk: usize,
    pad: usize,
}

impl Boundary {
    fn registry(&self, bulk: usize, pad: usize) -> Fallible<CertificationRegistry> {
        let mut registry = CertificationRegistry::default();
        for entry in self.bulk_entries.iter().take(bulk) {
            insert(&mut registry, entry.clone());
        }
        insert(
            &mut registry,
            published_entry(artifact("tool-server-top-off", pad)?, PUBLISHED_AT)?,
        );
        Ok(registry)
    }

    fn search() -> Fallible<Self> {
        let first = published_entry(artifact(&bulk_id(0), BULK_PAD)?, PUBLISHED_AT)?;
        let mut one = CertificationRegistry::default();
        insert(&mut one, first.clone());
        let single = compact_len(&one)?;
        let mut two = one.clone();
        insert(
            &mut two,
            published_entry(artifact(&bulk_id(1), BULK_PAD)?, PUBLISHED_AT)?,
        );
        let per_entry = compact_len(&two)? - single;
        let ceiling = MAX_SIGNED_FILE_BYTES / per_entry + 2;
        let mut bulk_entries = vec![first];
        for index in 1..ceiling {
            bulk_entries.push(published_entry(
                artifact(&bulk_id(index), BULK_PAD)?,
                PUBLISHED_AT,
            )?);
        }
        let mut boundary = Self {
            bulk_entries,
            bulk: 0,
            pad: 0,
        };
        let directory = chio_test_support::private_tempdir()?;
        let path = directory.path().join("probe.json");

        let (mut low, mut high) = (0, ceiling);
        if !admitted(&boundary.registry(low, 0)?, &path)?
            || admitted(&boundary.registry(high, 0)?, &path)?
        {
            return Err("entry count search does not bracket the boundary".into());
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

        let (mut low, mut high) = (0, per_entry + 4_096);
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

fn bulk_id(index: usize) -> String {
    format!("tool-server-{index:06}")
}

fn boundary() -> Fallible<&'static Boundary> {
    static BOUNDARY: OnceLock<Result<Boundary, String>> = OnceLock::new();
    BOUNDARY
        .get_or_init(|| Boundary::search().map_err(|error| error.to_string()))
        .as_ref()
        .map_err(|error| error.clone().into())
}

/// Saves at `path` a registry filled to the exact admission boundary and
/// returns it.
pub(crate) fn full_registry(path: &Path) -> Fallible<CertificationRegistry> {
    let boundary = boundary()?;
    let registry = boundary.registry(boundary.bulk, boundary.pad)?;
    registry.save(path)?;
    Ok(registry)
}

/// Saves at `path` a registry holding one active entry and returns it with
/// that entry's artifact id.
pub(crate) fn one_published(path: &Path) -> Fallible<(CertificationRegistry, String)> {
    let mut registry = CertificationRegistry::default();
    let entry = published_entry(artifact("tool-server-single", 0)?, PUBLISHED_AT)?;
    let artifact_id = entry.artifact_id.clone();
    insert(&mut registry, entry);
    registry.save(path)?;
    Ok((registry, artifact_id))
}

fn assert_reloads_exactly(registry: &CertificationRegistry, path: &Path) -> TestResult {
    let bytes = fs::read(path)?;
    assert!(bytes.len() <= MAX_SIGNED_FILE_BYTES);
    assert_eq!(bytes, serde_json::to_vec(registry)?);
    let reloaded = CertificationRegistry::load(path)?;
    assert_eq!(&reloaded, registry);
    assert_eq!(serde_json::to_vec(&reloaded)?, bytes);
    Ok(())
}

#[test]
fn every_admitted_certification_revokes_at_a_full_registry_and_reloads_exactly() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("certifications.json");
    let mut registry = full_registry(&path)?;
    let ids: Vec<String> = registry.artifacts.keys().cloned().collect();
    let reason = largest_reason();
    for (index, artifact_id) in ids.iter().enumerate() {
        let entry = registry.revoke(artifact_id, Some(&reason), Some(u64::MAX))?;
        assert_eq!(entry.status, CertificationRegistryState::Revoked);
        if index < 3 || index % 256 == 0 || index + 1 == ids.len() {
            registry
                .save(&path)
                .map_err(|error| format!("revocation {index} of {}: {error}", ids.len()))?;
        }
    }
    assert_reloads_exactly(&registry, &path)?;
    // Every entry now holds its largest revoked form, which is exactly what
    // admission reserved for it, so the file sits exactly at the cap.
    assert_eq!(
        fs::metadata(&path)?.len(),
        u64::try_from(MAX_SIGNED_FILE_BYTES)?
    );
    for entry in CertificationRegistry::load(&path)?.artifacts.values() {
        assert_eq!(entry.status, CertificationRegistryState::Revoked);
        assert_eq!(entry.revoked_at, Some(u64::MAX));
        assert_eq!(entry.revoked_reason.as_deref(), Some(reason.as_str()));
    }
    Ok(())
}

#[test]
fn publish_past_the_revocation_reserve_is_refused_and_the_file_is_unchanged() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("certifications.json");
    let mut registry = full_registry(&path)?;
    let before = fs::read(&path)?;
    let entry = published_entry(artifact("tool-server-fresh", 0)?, PUBLISHED_AT)?;
    let artifact_id = entry.artifact_id.clone();
    insert(&mut registry, entry);
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
    assert!(CertificationRegistry::load(&path)?
        .get(&artifact_id)
        .is_none());
    Ok(())
}

#[test]
fn revocation_reason_past_the_bound_is_refused_and_the_entry_stays_active() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("certifications.json");
    let (mut registry, artifact_id) = one_published(&path)?;
    let plain = "r".repeat(REASON_LIMIT + 1);
    let escaped = format!("{}c", largest_reason());
    for reason in [plain.as_str(), escaped.as_str()] {
        assert_eq!(escaped_len(reason), REASON_LIMIT + 1);
        let error = registry
            .revoke(&artifact_id, Some(reason), Some(PUBLISHED_AT + 1))
            .err()
            .ok_or("a reason past the bound must be refused")?;
        assert!(matches!(error, CliError::Chio(_)));
        assert!(
            error.to_string().contains(&format!(
                "revocation reason must be at most {REASON_LIMIT} bytes once JSON-escaped"
            )),
            "{error}"
        );
        let entry = registry.get(&artifact_id).ok_or("entry kept")?;
        assert_eq!(entry.status, CertificationRegistryState::Active);
        assert_eq!(entry.revoked_reason, None);
    }
    registry.revoke(
        &artifact_id,
        Some(&largest_reason()),
        Some(PUBLISHED_AT + 1),
    )?;
    registry.save(&path)?;
    assert_reloads_exactly(&registry, &path)
}

#[test]
fn dispute_note_past_the_bound_or_unloadable_dispute_is_refused() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("certifications.json");
    let (mut registry, artifact_id) = one_published(&path)?;
    let before = registry.clone();
    let over = CertificationDisputeRequest {
        state: CertificationDisputeState::ResolvedRevoked,
        note: Some("n".repeat(REASON_LIMIT + 1)),
        updated_at: Some(PUBLISHED_AT + 1),
    };
    let error = registry
        .dispute(&artifact_id, &over)
        .err()
        .ok_or("a dispute note past the bound must be refused")?;
    assert!(matches!(error, CliError::Chio(_)));
    assert!(
        error.to_string().contains(&format!(
            "dispute note must be at most {REASON_LIMIT} bytes once JSON-escaped"
        )),
        "{error}"
    );
    let unloadable = CertificationDisputeRequest {
        state: CertificationDisputeState::Open,
        note: None,
        updated_at: Some(0),
    };
    let error = registry
        .dispute(&artifact_id, &unloadable)
        .err()
        .ok_or("a dispute load would refuse must be refused")?;
    assert!(matches!(error, CliError::Chio(_)));
    assert!(
        error
            .to_string()
            .contains("dispute updated_at must be nonzero"),
        "{error}"
    );
    assert_eq!(registry, before);

    let at_bound = CertificationDisputeRequest {
        state: CertificationDisputeState::ResolvedRevoked,
        note: Some(largest_reason()),
        updated_at: Some(PUBLISHED_AT + 1),
    };
    let entry = registry.dispute(&artifact_id, &at_bound)?;
    assert_eq!(entry.status, CertificationRegistryState::Revoked);
    assert_eq!(
        entry.revoked_reason.as_deref(),
        Some(largest_reason().as_str())
    );
    registry.save(&path)?;
    assert_reloads_exactly(&registry, &path)
}

#[test]
fn revocation_is_terminal_across_reopen_and_disputes() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("certifications.json");
    let (mut registry, artifact_id) = one_published(&path)?;
    registry.revoke(&artifact_id, Some("compromised"), Some(PUBLISHED_AT + 1))?;
    registry.save(&path)?;

    let mut reopened = CertificationRegistry::load(&path)?;
    for state in [
        CertificationDisputeState::Open,
        CertificationDisputeState::UnderReview,
        CertificationDisputeState::ResolvedNoChange,
    ] {
        let entry = reopened.dispute(
            &artifact_id,
            &CertificationDisputeRequest {
                state,
                note: Some("reviewed".to_string()),
                updated_at: Some(PUBLISHED_AT + 2),
            },
        )?;
        assert_eq!(entry.status, CertificationRegistryState::Revoked);
    }
    reopened.save(&path)?;
    let reloaded = CertificationRegistry::load(&path)?;
    let entry = reloaded.get(&artifact_id).ok_or("revoked entry kept")?;
    assert_eq!(entry.status, CertificationRegistryState::Revoked);
    assert_eq!(entry.revoked_at, Some(PUBLISHED_AT + 1));
    assert_eq!(entry.revoked_reason.as_deref(), Some("compromised"));
    assert_reloads_exactly(&reopened, &path)
}

fn encoded(entry: &CertificationRegistryEntry) -> Fallible<usize> {
    Ok(crate::signed_input::encoded_len(entry)?)
}

/// Entries in every state a registry can hold, including a revoked entry
/// whose reason predates the bound.
fn entries_in_every_state() -> Fallible<Vec<CertificationRegistryEntry>> {
    let active = published_entry(artifact("tool-server-states", 3)?, PUBLISHED_AT)?;
    let mut superseded = published_entry(artifact("tool-server-states", 5)?, PUBLISHED_AT)?;
    superseded.status = CertificationRegistryState::Superseded;
    superseded.superseded_at = Some(PUBLISHED_AT + 1);
    superseded.superseded_by = Some(active.artifact_id.clone());
    let mut revoked = active.clone();
    revoked.status = CertificationRegistryState::Revoked;
    revoked.revoked_at = Some(PUBLISHED_AT + 2);
    revoked.revoked_reason = Some("short".to_string());
    let mut unreasoned = revoked.clone();
    unreasoned.revoked_reason = None;
    let mut legacy = revoked.clone();
    legacy.revoked_reason = Some("l".repeat(4 * REASON_LIMIT));
    let mut disputed = active.clone();
    disputed.dispute = Some(CertificationDisputeRecord {
        state: CertificationDisputeState::Open,
        updated_at: PUBLISHED_AT + 3,
        note: Some(largest_reason()),
    });
    Ok(vec![
        active, superseded, revoked, unreasoned, legacy, disputed,
    ])
}

#[test]
fn revoking_never_grows_an_entry_past_its_reserved_form() -> TestResult {
    let reason = largest_reason();
    let revocations: [(Option<&str>, u64); 4] = [
        (None, 1),
        (Some(reason.as_str()), u64::MAX),
        (Some("short"), PUBLISHED_AT + 5),
        (Some(""), 0),
    ];
    for entry in entries_in_every_state()? {
        let reserved = encoded(&largest_revoked_entry(&entry)?)?;
        assert!(encoded(&entry)? <= reserved, "{entry:?}");
        let mut registry = CertificationRegistry::default();
        insert(&mut registry, entry.clone());
        for (reason, revoked_at) in revocations {
            let revoked = registry.revoke(&entry.artifact_id, reason, Some(revoked_at))?;
            assert!(encoded(&revoked)? <= reserved, "{revoked:?}");
            assert!(
                encoded(&largest_revoked_entry(&revoked)?)? <= reserved,
                "{revoked:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn revocations_never_raise_the_reserved_registry_size() -> TestResult {
    let mut registry = CertificationRegistry::default();
    for (index, mut entry) in entries_in_every_state()?.into_iter().enumerate() {
        entry.artifact_id = format!("{index:064x}");
        registry.artifacts.insert(entry.artifact_id.clone(), entry);
    }
    let reserved_size = |registry: &CertificationRegistry| -> Fallible<usize> {
        Ok(compact_len(registry)? + registry.revocation_reserve()?)
    };
    let mut bound = reserved_size(&registry)?;
    let ids: Vec<String> = registry.artifacts.keys().cloned().collect();
    let reason = largest_reason();
    for round in [u64::MAX, 1] {
        for artifact_id in &ids {
            registry.revoke(artifact_id, Some(&reason), Some(round))?;
            let next = reserved_size(&registry)?;
            assert!(next <= bound, "{next} > {bound}");
            assert!(compact_len(&registry)? <= next);
            bound = next;
        }
    }
    Ok(())
}
