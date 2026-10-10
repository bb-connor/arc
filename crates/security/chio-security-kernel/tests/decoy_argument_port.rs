#![cfg(unix)]
//! Real registry controls for the decoy kinds used by argument inspection.

use std::path::PathBuf;
use std::sync::Arc;

use chio_core::sha256;
use chio_decoy::{
    DecoyCreateRequest, DecoyDetector, FileMaterializer, OwnershipKey, PrivateDecoyRegistry,
    PrivilegedExportCredential, RegistryError, RegistryExportAuthorizer, RegistryExportGrant,
    RegistryKey, RegistryKeyProvider, SecretMaterial,
};
use chio_security_kernel::DecoyTripwireDetectorPort;
use chio_security_types::clock::FixedClock;
use chio_security_types::ports::{
    ArtifactId, CanonicalBody, Digest32, PortError, PortResult, RecordId, RequestId, TenantId,
    TripwireDecision, TripwireDetectorPort, TripwireInput, TripwireKind,
};
use chio_security_types::{
    DecoyLifecycle, DecoyOperationAttempt, DecoyOperationKind, DecoyRecord, DecoySurface,
    DecoyVersion,
};
use chio_store_sqlite::SqliteSealedDecoyRegistryStore;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TENANT: &str = "tenant-port-a";
const OTHER_TENANT: &str = "tenant-port-b";
const MARKER: &str = "synthetic-credential-port-marker/with-padding==";
const OBSERVED_AT: u64 = 1_000;
const EXPIRES_AT: u64 = 2_000;

struct FixtureKeys;

impl RegistryKeyProvider for FixtureKeys {
    fn key_for(&self, tenant_id: &TenantId) -> Result<RegistryKey, RegistryError> {
        match tenant_id.as_str() {
            TENANT => Ok(RegistryKey::from_bytes([53; 64])),
            OTHER_TENANT => Ok(RegistryKey::from_bytes([54; 64])),
            _ => Err(RegistryError::KeyUnavailable),
        }
    }
}

struct NoExports;

impl RegistryExportAuthorizer for NoExports {
    fn authorize(
        &self,
        _: &PrivilegedExportCredential,
        _: u64,
    ) -> Result<RegistryExportGrant, RegistryError> {
        Err(RegistryError::AuthorizationDenied)
    }
}

struct Fixture {
    registry: Arc<PrivateDecoyRegistry>,
    materializer: FileMaterializer,
    database: PathBuf,
    directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let directory = chio_test_support::private_tempdir()?;
        let database = directory.path().join("decoys.sqlite3");
        let store = Arc::new(SqliteSealedDecoyRegistryStore::open(&database)?);
        let registry = Arc::new(PrivateDecoyRegistry::new(
            store,
            Arc::new(FixtureKeys),
            Arc::new(NoExports),
        ));
        let materializer =
            FileMaterializer::open(directory.path(), OwnershipKey::from_bytes([55; 32]))?;
        Ok(Self {
            registry,
            materializer,
            database,
            directory,
        })
    }

    fn create(
        &self,
        artifact: &str,
        surface: DecoySurface,
        marker: &str,
    ) -> TestResult<DecoyRecord> {
        let materialization_payload = if matches!(
            surface,
            DecoySurface::CredentialFile | DecoySurface::FileMarker
        ) {
            Some(SecretMaterial::new(marker.as_bytes().to_vec())?)
        } else {
            None
        };
        Ok(self.registry.create(
            DecoyCreateRequest {
                tenant_id: TenantId::new(TENANT)?,
                artifact_id: ArtifactId::new(artifact)?,
                surface,
                scope_id: RecordId::new("scope-port-fixture")?,
                creation_policy_id: RecordId::new("policy-port-fixture")?,
                version: DecoyVersion::new(1)?,
                expires_at_unix_ms: EXPIRES_AT,
                predecessor_artifact_id: None,
                marker: SecretMaterial::new(marker.as_bytes().to_vec())?,
                materialization_payload,
            },
            RecordId::new(format!("create-{artifact}"))?,
        )?)
    }

    fn transition(
        &self,
        record: &DecoyRecord,
        kind: DecoyOperationKind,
        successor: Option<&DecoyRecord>,
    ) -> TestResult<DecoyRecord> {
        Ok(self.registry.apply_transition(
            &record.tenant_id,
            &record.artifact_id,
            &DecoyOperationAttempt {
                operation_id: RecordId::new(format!(
                    "transition-{}-{}",
                    record.artifact_id.as_str(),
                    record.generation
                ))?,
                kind,
                expected_generation: record.generation,
                expected_version: record.version,
                successor_artifact_id: successor.map(|record| record.artifact_id.clone()),
            },
        )?)
    }

    fn arm(&self, record: DecoyRecord) -> TestResult<DecoyRecord> {
        if matches!(
            record.surface,
            DecoySurface::CredentialFile | DecoySurface::FileMarker
        ) {
            let relative_path = PathBuf::from(format!("{}.txt", record.artifact_id.as_str()));
            self.registry.materialize_file(
                &record.tenant_id,
                &record.artifact_id,
                &RecordId::new(format!("materialize-{}", record.artifact_id.as_str()))?,
                &relative_path,
                &self.materializer,
                OBSERVED_AT,
            )?;
            return self
                .registry
                .load_private(&record.tenant_id, &record.artifact_id)?
                .ok_or_else(|| "materialized record disappeared".into());
        }
        let materializing =
            self.transition(&record, DecoyOperationKind::BeginMaterialization, None)?;
        self.transition(&materializing, DecoyOperationKind::Arm, None)
    }

    fn detect(
        &self,
        tenant: &str,
        kind: TripwireKind,
        presented: &str,
        observed_at: u64,
    ) -> PortResult<TripwireDecision> {
        let input = TripwireInput {
            tenant_id: TenantId::new(tenant)?,
            request_id: RequestId::new("request-port-fixture")?,
            kind,
            content: CanonicalBody::new(presented.as_bytes().to_vec())
                .map_err(|_| PortError::invalid_data())?,
            content_digest: Digest32::new(*sha256(presented.as_bytes()).as_bytes()),
            canonical_context_digest: Digest32::new([56; 32]),
        };
        DecoyTripwireDetectorPort::decoy_only(
            Arc::new(DecoyDetector::new(Arc::clone(&self.registry))),
            Arc::new(FixedClock::from_millis(observed_at)),
        )
        .detect(&input)
    }
}

fn assert_active_match(decision: TripwireDecision, record: &DecoyRecord) {
    assert!(
        matches!(decision, TripwireDecision::Match { .. }),
        "active registered decoy was reported clear: {decision:?}"
    );
    if let TripwireDecision::Match {
        artifact_id_hash,
        artifact_version_hash,
    } = decision
    {
        assert_ne!(artifact_id_hash, Digest32::new([0; 32]));
        assert_eq!(artifact_version_hash, record.version_hash);
    }
}

#[test]
fn active_credential_artifact_matches_credential_tripwire() -> TestResult {
    let fixture = Fixture::new()?;
    let record = fixture.arm(fixture.create(
        "credential-artifact",
        DecoySurface::CredentialArtifact,
        MARKER,
    )?)?;
    assert_active_match(
        fixture.detect(
            TENANT,
            TripwireKind::CredentialArtifact,
            MARKER,
            OBSERVED_AT,
        )?,
        &record,
    );
    Ok(())
}

#[test]
fn materialized_credential_file_matches_credential_tripwire() -> TestResult {
    let fixture = Fixture::new()?;
    let record =
        fixture.arm(fixture.create("credential-file", DecoySurface::CredentialFile, MARKER)?)?;
    assert_eq!(record.lifecycle, DecoyLifecycle::Armed);
    let planted = std::fs::read_to_string(fixture.directory.path().join("credential-file.txt"))?;
    assert_eq!(planted, MARKER);
    assert_active_match(
        fixture.detect(
            TENANT,
            TripwireKind::CredentialArtifact,
            &planted,
            OBSERVED_AT,
        )?,
        &record,
    );
    Ok(())
}

#[test]
fn inactive_artifact_does_not_shadow_active_credential_file() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.create(
        "inactive-credential",
        DecoySurface::CredentialArtifact,
        MARKER,
    )?;
    let record =
        fixture.arm(fixture.create("active-file", DecoySurface::CredentialFile, MARKER)?)?;
    assert_active_match(
        fixture.detect(
            TENANT,
            TripwireKind::CredentialArtifact,
            MARKER,
            OBSERVED_AT,
        )?,
        &record,
    );
    Ok(())
}

#[test]
fn materialized_file_marker_matches_file_marker_tripwire() -> TestResult {
    let fixture = Fixture::new()?;
    let record = fixture.arm(fixture.create(
        "file-marker",
        DecoySurface::FileMarker,
        "synthetic-file-marker",
    )?)?;
    let planted = std::fs::read_to_string(fixture.directory.path().join("file-marker.txt"))?;
    assert_eq!(planted, "synthetic-file-marker");
    assert_active_match(
        fixture.detect(TENANT, TripwireKind::FileMarker, &planted, OBSERVED_AT)?,
        &record,
    );
    Ok(())
}

#[test]
fn active_browser_cookie_and_hostname_match_their_tripwire_kinds() -> TestResult {
    for (surface, kind, marker) in [
        (
            DecoySurface::BrowserCookie,
            TripwireKind::BrowserCookie,
            "synthetic-cookie-value",
        ),
        (
            DecoySurface::InternalHostname,
            TripwireKind::InternalHostname,
            "synthetic.decoy.invalid",
        ),
    ] {
        let fixture = Fixture::new()?;
        let record = fixture.arm(fixture.create("active-marker", surface, marker)?)?;
        assert_active_match(fixture.detect(TENANT, kind, marker, OBSERVED_AT)?, &record);
    }
    Ok(())
}

#[test]
fn planned_credentials_are_not_active_matches() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.create("planned-artifact", DecoySurface::CredentialArtifact, MARKER)?;
    fixture.create("planned-file", DecoySurface::CredentialFile, MARKER)?;
    assert_eq!(
        fixture.detect(
            TENANT,
            TripwireKind::CredentialArtifact,
            MARKER,
            OBSERVED_AT
        )?,
        TripwireDecision::Clear
    );
    Ok(())
}

#[test]
fn retired_credential_artifact_is_not_an_active_match() -> TestResult {
    let fixture = Fixture::new()?;
    let active = fixture.arm(fixture.create(
        "retired-artifact",
        DecoySurface::CredentialArtifact,
        MARKER,
    )?)?;
    let triggered = fixture.transition(&active, DecoyOperationKind::Trigger, None)?;
    let successor = fixture.registry.create(
        DecoyCreateRequest {
            tenant_id: triggered.tenant_id.clone(),
            artifact_id: ArtifactId::new("retirement-successor")?,
            surface: DecoySurface::CredentialArtifact,
            scope_id: triggered.scope_id.clone(),
            creation_policy_id: triggered.creation_policy_id.clone(),
            version: DecoyVersion::new(2)?,
            expires_at_unix_ms: EXPIRES_AT,
            predecessor_artifact_id: Some(triggered.artifact_id.clone()),
            marker: SecretMaterial::new(b"synthetic-retirement-successor".to_vec())?,
            materialization_payload: None,
        },
        RecordId::new("create-retirement-successor")?,
    )?;
    let successor = fixture.arm(successor)?;
    let rotating = fixture.transition(
        &triggered,
        DecoyOperationKind::BeginRotation,
        Some(&successor),
    )?;
    let retired = fixture.transition(&rotating, DecoyOperationKind::Retire, Some(&successor))?;
    assert_eq!(retired.lifecycle, DecoyLifecycle::Retired);
    assert_eq!(
        fixture.detect(
            TENANT,
            TripwireKind::CredentialArtifact,
            MARKER,
            OBSERVED_AT
        )?,
        TripwireDecision::Clear
    );
    assert_active_match(
        fixture.detect(
            TENANT,
            TripwireKind::CredentialArtifact,
            "synthetic-retirement-successor",
            OBSERVED_AT,
        )?,
        &successor,
    );
    Ok(())
}

#[test]
fn both_credential_surfaces_expire_at_the_record_deadline() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.arm(fixture.create("expired-artifact", DecoySurface::CredentialArtifact, MARKER)?)?;
    fixture.arm(fixture.create("expired-file", DecoySurface::CredentialFile, MARKER)?)?;
    assert_eq!(
        fixture.detect(TENANT, TripwireKind::CredentialArtifact, MARKER, EXPIRES_AT)?,
        TripwireDecision::Clear
    );
    Ok(())
}

#[test]
fn active_credential_markers_do_not_cross_tenants() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.arm(fixture.create("tenant-artifact", DecoySurface::CredentialArtifact, MARKER)?)?;
    fixture.arm(fixture.create("tenant-file", DecoySurface::CredentialFile, MARKER)?)?;
    assert_eq!(
        fixture.detect(
            OTHER_TENANT,
            TripwireKind::CredentialArtifact,
            MARKER,
            OBSERVED_AT
        )?,
        TripwireDecision::Clear
    );
    Ok(())
}

#[test]
fn credential_port_requires_the_exact_registered_marker() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.arm(fixture.create("exact-artifact", DecoySurface::CredentialArtifact, MARKER)?)?;
    fixture.arm(fixture.create("exact-file", DecoySurface::CredentialFile, MARKER)?)?;
    for presented in [
        "ordinary-value".to_string(),
        format!("prefix-{MARKER}"),
        format!("{MARKER}-suffix"),
    ] {
        assert_eq!(
            fixture.detect(
                TENANT,
                TripwireKind::CredentialArtifact,
                &presented,
                OBSERVED_AT
            )?,
            TripwireDecision::Clear
        );
    }
    Ok(())
}

#[test]
fn corrupt_second_credential_file_lookup_is_an_error_instead_of_clear() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.arm(fixture.create("corrupt-file", DecoySurface::CredentialFile, MARKER)?)?;
    // Damage only the real credential-file envelope. The first surface is clear.
    let connection = rusqlite::Connection::open(&fixture.database)?;
    let changed = connection.execute(
        "UPDATE sealed_decoy_records_v1 SET ciphertext = zeroblob(32) \
         WHERE tenant_id = ?1 AND surface = 'credential_file'",
        [TENANT],
    )?;
    assert_eq!(changed, 1);
    drop(connection);
    assert_eq!(
        fixture.detect(
            TENANT,
            TripwireKind::CredentialArtifact,
            MARKER,
            OBSERVED_AT
        ),
        Err(PortError::integrity_failure())
    );
    Ok(())
}
