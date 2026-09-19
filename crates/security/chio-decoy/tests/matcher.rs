mod support;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use chio_decoy::{
    DecoyCreateRequest, DecoyDetection, DecoyDetector, DetectionConfidence, DetectionFailure,
    ObservationClass, SecretMaterial, TripwireObservation,
};
use chio_security_types::ports::{ArtifactId, RecordId, TenantId};
use chio_security_types::{
    DecoyErrorClass, DecoyLifecycleState, DecoyOperationAttempt, DecoyOperationKind, DecoySurface,
    DecoyVersion,
};
use chio_test_support::prelude::*;
use support::{registry, MemoryStore};

fn create_decoy(
    registry: &chio_decoy::PrivateDecoyRegistry,
    artifact: &str,
    marker: &[u8],
    expires_at_unix_ms: u64,
) {
    registry
        .create(
            DecoyCreateRequest {
                tenant_id: TenantId::new("tenant-a").test_expect("valid tenant"),
                artifact_id: ArtifactId::new(artifact).test_expect("valid artifact"),
                surface: DecoySurface::BrowserCookie,
                scope_id: RecordId::new("scope-a").test_expect("valid scope"),
                creation_policy_id: RecordId::new("policy-a").test_expect("valid policy"),
                version: DecoyVersion::new(1).test_expect("valid version"),
                expires_at_unix_ms,
                predecessor_artifact_id: None,
                marker: SecretMaterial::new(marker.to_vec()).test_expect("valid marker"),
                materialization_payload: None,
            },
            RecordId::new(format!("create-{artifact}")).test_expect("valid transition"),
        )
        .test_expect("create decoy");
}

fn tenant() -> TenantId {
    TenantId::new("tenant-a").test_expect("valid tenant")
}

fn artifact() -> ArtifactId {
    ArtifactId::new("artifact-a").test_expect("valid artifact")
}

fn arm(registry: &chio_decoy::PrivateDecoyRegistry) {
    let planned = registry
        .load_private(&tenant(), &artifact())
        .test_expect("load planned")
        .test_expect("planned record");
    let begin = DecoyOperationAttempt {
        operation_id: RecordId::new("begin-materialization").test_expect("valid operation"),
        kind: DecoyOperationKind::BeginMaterialization,
        expected_generation: planned.generation,
        expected_version: planned.version,
        successor_artifact_id: None,
    };
    let materializing = registry
        .apply_transition(&tenant(), &artifact(), &begin)
        .test_expect("begin materialization");
    let arm = DecoyOperationAttempt {
        operation_id: RecordId::new("arm").test_expect("valid operation"),
        kind: DecoyOperationKind::Arm,
        expected_generation: materializing.generation,
        expected_version: materializing.version,
        successor_artifact_id: None,
    };
    registry
        .apply_transition(&tenant(), &artifact(), &arm)
        .test_expect("arm decoy");
}

#[test]
fn active_direct_presentation_is_high_confidence_and_requires_immediate_deny() {
    let store = Arc::new(MemoryStore::default());
    let registry = Arc::new(registry(Arc::clone(&store)));
    create_decoy(&registry, "artifact-a", b"marker-a", 9_000_000);
    arm(&registry);
    let detector = DecoyDetector::new(registry);

    let detection = detector
        .detect(&TripwireObservation {
            tenant_id: &tenant(),
            surface: DecoySurface::BrowserCookie,
            presented: b"marker-a",
            class: ObservationClass::DirectPresentation,
            observed_at_unix_ms: 1_000,
        })
        .test_expect("detect marker");
    let DecoyDetection::ActiveMatch {
        evidence,
        confidence,
        malice_proven,
        requires_immediate_deny,
    } = detection
    else {
        panic!("expected active match");
    };
    assert_eq!(confidence, DetectionConfidence::High);
    assert!(!malice_proven);
    assert!(requires_immediate_deny);
    assert_ne!(
        evidence.artifact_id_hash.as_bytes(),
        artifact().as_str().as_bytes()
    );
}

#[test]
fn scanner_and_operator_touches_are_signals_but_never_proof_of_malice() {
    let store = Arc::new(MemoryStore::default());
    let registry = Arc::new(registry(store));
    create_decoy(&registry, "artifact-a", b"marker-a", 9_000_000);
    arm(&registry);
    let detector = DecoyDetector::new(registry);

    for class in [
        ObservationClass::InventoryScanner,
        ObservationClass::OperatorTouch,
    ] {
        let detection = detector
            .detect(&TripwireObservation {
                tenant_id: &tenant(),
                surface: DecoySurface::BrowserCookie,
                presented: b"marker-a",
                class,
                observed_at_unix_ms: 1_000,
            })
            .test_expect("detect marker");
        assert!(matches!(
            detection,
            DecoyDetection::ActiveMatch {
                confidence: DetectionConfidence::High,
                malice_proven: false,
                requires_immediate_deny: false,
                ..
            }
        ));
    }
}

#[test]
fn inactive_marker_is_distinct_from_clear() {
    let store = Arc::new(MemoryStore::default());
    let registry = Arc::new(registry(store));
    create_decoy(&registry, "artifact-a", b"marker-a", 500);
    let detector = DecoyDetector::new(registry);

    let inactive = detector
        .detect(&TripwireObservation {
            tenant_id: &tenant(),
            surface: DecoySurface::BrowserCookie,
            presented: b"marker-a",
            class: ObservationClass::InventoryScanner,
            observed_at_unix_ms: 1_000,
        })
        .test_expect("inactive observation");
    assert!(matches!(
        inactive,
        DecoyDetection::InactiveObservation {
            lifecycle: DecoyLifecycleState::Planned,
            expired: true,
            ..
        }
    ));

    let clear = detector
        .detect(&TripwireObservation {
            tenant_id: &tenant(),
            surface: DecoySurface::BrowserCookie,
            presented: b"unknown-marker",
            class: ObservationClass::InventoryScanner,
            observed_at_unix_ms: 1_000,
        })
        .test_expect("clear observation");
    assert_eq!(clear, DecoyDetection::Clear);
}

#[test]
fn registry_or_lifecycle_errors_never_collapse_to_clear() {
    let store = Arc::new(MemoryStore::default());
    let registry = Arc::new(registry(Arc::clone(&store)));
    create_decoy(&registry, "artifact-a", b"marker-a", 9_000_000);
    arm(&registry);
    let armed = registry
        .load_private(&tenant(), &artifact())
        .test_expect("load armed")
        .test_expect("armed record");
    let trigger = DecoyOperationAttempt {
        operation_id: RecordId::new("trigger").test_expect("valid operation"),
        kind: DecoyOperationKind::Trigger,
        expected_generation: armed.generation,
        expected_version: armed.version,
        successor_artifact_id: None,
    };
    registry
        .fail_transition(
            &tenant(),
            &artifact(),
            &trigger,
            DecoyErrorClass::Unavailable,
        )
        .test_expect("record error");
    let detector = DecoyDetector::new(Arc::clone(&registry));
    assert_eq!(
        detector.detect(&TripwireObservation {
            tenant_id: &tenant(),
            surface: DecoySurface::BrowserCookie,
            presented: b"marker-a",
            class: ObservationClass::DirectPresentation,
            observed_at_unix_ms: 1_000,
        }),
        Err(DetectionFailure::LifecycleError)
    );

    store.fail_reads.store(true, Ordering::SeqCst);
    assert_eq!(
        detector.detect(&TripwireObservation {
            tenant_id: &tenant(),
            surface: DecoySurface::BrowserCookie,
            presented: b"marker-a",
            class: ObservationClass::DirectPresentation,
            observed_at_unix_ms: 1_000,
        }),
        Err(DetectionFailure::RegistryUnavailable)
    );
}
