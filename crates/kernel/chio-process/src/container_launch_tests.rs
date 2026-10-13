use super::*;
use chio_test_support::prelude::*;

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn enforced() -> ContainerLaunchRecord {
    ContainerLaunchRecord {
        schema: CONTAINER_LAUNCH_RECORD_SCHEMA.to_owned(),
        process_id: "root".to_owned(),
        attempt: 2,
        image_id: format!("sha256:{}", digest('1')),
        container_id: digest('a'),
        engine_identity: "test-engine".to_owned(),
        profile_digest: digest('2'),
        inspected_config_digest: Some(digest('3')),
        state: CageEnforcementState::FullyEnforced,
        started_at: Some("2026-01-01T00:00:00Z".to_owned()),
        failed_at_unix_ms: None,
        failure_class: None,
    }
}

fn failed(state: CageEnforcementState, class: ContainerLaunchFailure) -> ContainerLaunchRecord {
    ContainerLaunchRecord {
        state,
        started_at: None,
        failed_at_unix_ms: Some(1_000),
        failure_class: Some(class),
        ..enforced()
    }
}

fn shape_error(record: ContainerLaunchRecord) -> bool {
    matches!(
        record.validate(),
        Err(ProcessError::Invalid("container launch record state"))
    )
}

#[test]
fn signed_fully_enforced_launch_yields_a_bound_container_profile() {
    let signer = Keypair::from_seed(&[7; 32]);
    let signed = SignedContainerLaunchRecord::sign(enforced(), &signer).test_expect("signed");
    assert_eq!(
        signed.verify(&signer.public_key()).test_expect("verified"),
        &enforced()
    );
    let profile = signed.worker_profile().test_expect("profile");
    assert_eq!(profile.kind, WorkerProfileKind::Container);
    assert_eq!(profile.launch_attempt, 2);
    assert_eq!(profile.launch_ref.record_id, digest('a'));
    assert_eq!(
        profile.launch_ref.record_sha256,
        chio_core_types::sha256_hex(
            &chio_core_types::canonical_json_bytes(&signed).test_expect("canonical")
        )
    );
    assert_eq!(
        serde_json::to_value(&profile).test_expect("encode")["kind"],
        "container"
    );
}

#[test]
fn launch_records_reject_contradictory_states() {
    assert!(failed(
        CageEnforcementState::Rejected,
        ContainerLaunchFailure::ProfileMismatch
    )
    .validate()
    .is_ok());
    for class in [
        ContainerLaunchFailure::StartFailed,
        ContainerLaunchFailure::StartUnconfirmed,
    ] {
        assert!(failed(CageEnforcementState::BootstrapFailed, class)
            .validate()
            .is_ok());
    }
    assert!(shape_error(ContainerLaunchRecord {
        started_at: None,
        ..enforced()
    }));
    assert!(shape_error(ContainerLaunchRecord {
        inspected_config_digest: None,
        ..enforced()
    }));
    assert!(shape_error(ContainerLaunchRecord {
        failure_class: Some(ContainerLaunchFailure::StartFailed),
        ..enforced()
    }));
    assert!(shape_error(failed(
        CageEnforcementState::Rejected,
        ContainerLaunchFailure::StartFailed
    )));
    assert!(shape_error(failed(
        CageEnforcementState::BootstrapFailed,
        ContainerLaunchFailure::ProfileMismatch
    )));
    assert!(shape_error(ContainerLaunchRecord {
        started_at: Some("2026-01-01T00:00:00Z".to_owned()),
        ..failed(
            CageEnforcementState::BootstrapFailed,
            ContainerLaunchFailure::StartUnconfirmed
        )
    }));
    for state in [
        CageEnforcementState::Unsupported,
        CageEnforcementState::Exited,
    ] {
        assert!(shape_error(ContainerLaunchRecord {
            state,
            ..enforced()
        }));
    }
    for record in [
        ContainerLaunchRecord {
            attempt: 0,
            ..enforced()
        },
        ContainerLaunchRecord {
            image_id: digest('1'),
            ..enforced()
        },
        ContainerLaunchRecord {
            container_id: "short".to_owned(),
            ..enforced()
        },
        ContainerLaunchRecord {
            schema: "chio.process.container-launch.v2".to_owned(),
            ..enforced()
        },
    ] {
        assert!(matches!(
            record.validate(),
            Err(ProcessError::Invalid("container launch record identity"))
        ));
    }
}

#[test]
fn launch_record_verification_fails_closed() {
    let signer = Keypair::from_seed(&[8; 32]);
    let other = Keypair::from_seed(&[9; 32]);
    let signed = SignedContainerLaunchRecord::sign(enforced(), &signer).test_expect("signed");
    assert!(matches!(
        signed.verify(&other.public_key()),
        Err(ProcessError::Invalid("container launch record signature"))
    ));
    let mut tampered = signed.clone();
    tampered.record.attempt = 3;
    assert!(matches!(
        tampered.verify(&signer.public_key()),
        Err(ProcessError::Invalid("container launch record signature"))
    ));
    let mut extra = serde_json::to_value(&signed).test_expect("encode");
    extra["record"]["network"] = serde_json::json!("host");
    assert!(serde_json::from_value::<SignedContainerLaunchRecord>(extra)
        .test_unwrap_err()
        .to_string()
        .starts_with("unknown field `network`"));

    let rejected = SignedContainerLaunchRecord::sign(
        failed(
            CageEnforcementState::Rejected,
            ContainerLaunchFailure::ProfileMismatch,
        ),
        &signer,
    )
    .test_expect("signed rejection");
    assert!(matches!(
        rejected.worker_profile(),
        Err(ProcessError::Invalid(
            "only a fully enforced container launch supports a worker profile"
        ))
    ));
    assert!(matches!(
        SignedContainerLaunchRecord::sign(
            ContainerLaunchRecord {
                started_at: None,
                ..enforced()
            },
            &signer
        ),
        Err(ProcessError::Invalid("container launch record state"))
    ));
}
