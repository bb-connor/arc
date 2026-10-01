#![cfg(unix)]

mod support;

use std::fs;
use std::path::Path;
use std::sync::Arc;

use chio_decoy::{
    DecoyCreateRequest, FileMaterializer, MaterializationIdentity, MaterializationRequest,
    MaterializeError, OwnershipKey, RegistryError, SecretMaterial,
};
use chio_security_types::ports::{ArtifactId, RecordId, TenantId};
use chio_security_types::{
    DecoyErrorClass, DecoyLifecycle, DecoyLifecycleState, DecoyOperationAttempt,
    DecoyOperationKind, DecoySurface, DecoyVersion,
};
use chio_test_support::prelude::*;
use support::{registry, MemoryStore};

fn tenant() -> TenantId {
    TenantId::new("tenant-a").test_expect("valid tenant")
}

fn artifact(value: &str) -> ArtifactId {
    ArtifactId::new(value).test_expect("valid artifact")
}

fn create_file_decoy(
    registry: &chio_decoy::PrivateDecoyRegistry,
    artifact_id: &str,
    marker: &[u8],
    payload: &[u8],
    version: u64,
    predecessor: Option<&str>,
) {
    registry
        .create(
            DecoyCreateRequest {
                tenant_id: tenant(),
                artifact_id: artifact(artifact_id),
                surface: DecoySurface::CredentialFile,
                scope_id: RecordId::new("scope-a").test_expect("valid scope"),
                creation_policy_id: RecordId::new("policy-a").test_expect("valid policy"),
                version: DecoyVersion::new(version).test_expect("valid version"),
                expires_at_unix_ms: 9_000_000,
                predecessor_artifact_id: predecessor.map(artifact),
                marker: SecretMaterial::new(marker.to_vec()).test_expect("valid marker"),
                materialization_payload: Some(
                    SecretMaterial::new(payload.to_vec()).test_expect("valid payload"),
                ),
            },
            RecordId::new(format!("create-{artifact_id}")).test_expect("valid operation"),
        )
        .test_expect("create file decoy");
}

fn materializer(root: &Path) -> FileMaterializer {
    FileMaterializer::open(root, OwnershipKey::from_bytes([23; 32]))
        .test_expect("open materializer")
}

fn transition(
    registry: &chio_decoy::PrivateDecoyRegistry,
    artifact_id: &str,
    operation_id: &str,
    kind: DecoyOperationKind,
    successor: Option<&str>,
) -> chio_security_types::DecoyRecord {
    let current = registry
        .load_private(&tenant(), &artifact(artifact_id))
        .test_expect("load decoy")
        .test_expect("decoy exists");
    registry
        .apply_transition(
            &tenant(),
            &artifact(artifact_id),
            &DecoyOperationAttempt {
                operation_id: RecordId::new(operation_id).test_expect("valid operation"),
                kind,
                expected_generation: current.generation,
                expected_version: current.version,
                successor_artifact_id: successor.map(artifact),
            },
        )
        .test_expect("transition decoy")
}

#[test]
fn durable_materializing_intent_recovers_after_file_creation_and_exact_retry_is_stable() {
    let directory = tempfile::tempdir().test_expect("tempdir");
    let materializer = materializer(directory.path());
    let registry = registry(Arc::new(MemoryStore::default()));
    let operation_id = RecordId::new("materialize-v1").test_expect("valid operation");
    let payload = b"credential-shaped decoy";
    create_file_decoy(&registry, "artifact-v1", b"marker-v1", payload, 1, None);

    let planned = registry
        .load_private(&tenant(), &artifact("artifact-v1"))
        .test_expect("load planned")
        .test_expect("planned record");
    let materializing = registry
        .apply_transition(
            &tenant(),
            &artifact("artifact-v1"),
            &DecoyOperationAttempt {
                operation_id: operation_id.clone(),
                kind: DecoyOperationKind::BeginMaterialization,
                expected_generation: planned.generation,
                expected_version: planned.version,
                successor_artifact_id: None,
            },
        )
        .test_expect("persist materializing intent");
    let identity = MaterializationIdentity {
        operation_id: operation_id.as_str().to_string(),
        tenant_id: tenant().as_str().to_string(),
        artifact_id: materializing.artifact_id.as_str().to_string(),
        version_hash: *materializing.version_hash.as_bytes(),
    };
    let precrash_receipt = materializer
        .materialize(&MaterializationRequest {
            identity: &identity,
            relative_path: Path::new("private/v1.txt"),
            content: payload,
        })
        .test_expect("materialize before simulated crash");

    let recovered = registry
        .materialize_file(
            &tenant(),
            &artifact("artifact-v1"),
            &operation_id,
            Path::new("private/v1.txt"),
            &materializer,
            1_000,
        )
        .test_expect("recover materialization");
    assert_eq!(recovered, precrash_receipt);
    assert_eq!(
        registry
            .load_private(&tenant(), &artifact("artifact-v1"))
            .test_expect("load armed")
            .test_expect("armed record")
            .lifecycle,
        DecoyLifecycle::Armed
    );
    assert_eq!(
        registry
            .materialize_file(
                &tenant(),
                &artifact("artifact-v1"),
                &operation_id,
                Path::new("private/v1.txt"),
                &materializer,
                1_001,
            )
            .test_expect("exact retry"),
        recovered
    );
}

#[test]
fn materialization_failure_is_durable_and_only_the_same_operation_can_retry() {
    let directory = tempfile::tempdir().test_expect("tempdir");
    fs::write(directory.path().join("occupied.txt"), b"foreign").test_expect("seed foreign file");
    let materializer = materializer(directory.path());
    let registry = registry(Arc::new(MemoryStore::default()));
    let operation_id = RecordId::new("materialize-error").test_expect("valid operation");
    create_file_decoy(
        &registry,
        "artifact-error",
        b"marker-error",
        b"decoy payload",
        1,
        None,
    );

    let foreign_result = registry.materialize_file(
        &tenant(),
        &artifact("artifact-error"),
        &operation_id,
        Path::new("occupied.txt"),
        &materializer,
        1_000,
    );
    assert!(
        matches!(
            foreign_result,
            Err(RegistryError::Materialization(
                MaterializeError::ForeignExisting
                    | MaterializeError::OwnershipMismatch
                    | MaterializeError::MetadataMismatch
            ))
        ),
        "unexpected foreign-file result: {foreign_result:?}"
    );
    let failed = registry
        .load_private(&tenant(), &artifact("artifact-error"))
        .test_expect("load error")
        .test_expect("error record");
    assert!(matches!(
        failed.lifecycle,
        DecoyLifecycle::Error {
            prior: DecoyLifecycleState::Materializing,
            error_class: DecoyErrorClass::IntegrityFailure,
            ..
        }
    ));
    assert_eq!(
        registry.materialize_file(
            &tenant(),
            &artifact("artifact-error"),
            &RecordId::new("different-materialization").test_expect("valid operation"),
            Path::new("occupied.txt"),
            &materializer,
            1_001,
        ),
        Err(RegistryError::Conflict)
    );

    fs::remove_file(directory.path().join("occupied.txt")).test_expect("remove foreign file");
    registry
        .materialize_file(
            &tenant(),
            &artifact("artifact-error"),
            &operation_id,
            Path::new("occupied.txt"),
            &materializer,
            1_002,
        )
        .test_expect("exact recovery");
}

#[test]
fn changed_content_blocks_retirement_and_exact_retry_recovers() {
    let directory = tempfile::tempdir().test_expect("tempdir");
    let materializer = materializer(directory.path());
    let registry = registry(Arc::new(MemoryStore::default()));
    create_file_decoy(
        &registry,
        "artifact-v1",
        b"marker-v1",
        b"old payload",
        1,
        None,
    );
    registry
        .materialize_file(
            &tenant(),
            &artifact("artifact-v1"),
            &RecordId::new("materialize-v1").test_expect("valid operation"),
            Path::new("old.txt"),
            &materializer,
            1_000,
        )
        .test_expect("materialize old");
    transition(
        &registry,
        "artifact-v1",
        "trigger-v1",
        DecoyOperationKind::Trigger,
        None,
    );
    create_file_decoy(
        &registry,
        "artifact-v2",
        b"marker-v2",
        b"new payload",
        2,
        Some("artifact-v1"),
    );
    registry
        .materialize_file(
            &tenant(),
            &artifact("artifact-v2"),
            &RecordId::new("materialize-v2").test_expect("valid operation"),
            Path::new("new.txt"),
            &materializer,
            1_000,
        )
        .test_expect("materialize replacement");
    let rotating = transition(
        &registry,
        "artifact-v1",
        "rotate-v1",
        DecoyOperationKind::BeginRotation,
        Some("artifact-v2"),
    );
    let retire = DecoyOperationAttempt {
        operation_id: RecordId::new("retire-v1").test_expect("valid operation"),
        kind: DecoyOperationKind::Retire,
        expected_generation: rotating.generation,
        expected_version: rotating.version,
        successor_artifact_id: Some(artifact("artifact-v2")),
    };
    fs::write(directory.path().join("old.txt"), b"tampered").test_expect("tamper old file");
    assert!(matches!(
        registry.retire_materialized_file(
            &tenant(),
            &artifact("artifact-v1"),
            &retire,
            &materializer,
        ),
        Err(RegistryError::Materialization(
            MaterializeError::ContentMismatch | MaterializeError::MetadataMismatch
        ))
    ));
    assert!(directory.path().join("old.txt").exists());
    fs::write(directory.path().join("old.txt"), b"old payload").test_expect("restore old file");
    let retired = registry
        .retire_materialized_file(&tenant(), &artifact("artifact-v1"), &retire, &materializer)
        .test_expect("retry retirement");
    assert_eq!(retired.lifecycle, DecoyLifecycle::Retired);
    assert!(!directory.path().join("old.txt").exists());
    assert!(directory.path().join("new.txt").exists());
}
