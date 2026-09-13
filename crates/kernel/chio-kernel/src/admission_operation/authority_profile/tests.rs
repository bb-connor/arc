use super::*;
use crate::admission_operation::{AdmissionDigest, AdmissionIdentifier};
use crate::dpop::authority::DpopReplayAuthorityInputV1;

fn identifier(value: &str) -> AdmissionIdentifier {
    AdmissionIdentifier::try_new("profile", value).expect("fixture identifier")
}

fn profile() -> AdmissionAuthorityProfileV1 {
    AdmissionAuthorityProfileV1::new(AdmissionAuthoritySelectionV1 {
        runtime_hook_installed: true,
        swarm_admission_required: false,
        runtime_enforces_swarm_authority: true,
        runtime_requires_dispatch_revalidation: true,
        runtime: Some(RuntimeParticipantAuthorityBindingV1::new(
            identifier("runtime"),
            identifier("runtime-generation"),
        )),
        approval: Some(GovernedApprovalAuthorityBindingV1::new(
            identifier("approval"),
            identifier("approval-generation"),
        )),
        dpop: Some(
            DpopReplayAuthorityV1::new(DpopReplayAuthorityInputV1 {
                destination_store_uuid: identifier("11111111-1111-4111-8111-111111111111"),
                dpop_authority_id: identifier("dpop"),
                expectation_id: AdmissionDigest::try_new("dpop generation", "a".repeat(64))
                    .expect("digest"),
                proof_ttl_secs: 60,
                max_clock_skew_secs: 30,
            })
            .expect("DPoP policy"),
        ),
    })
    .expect("profile")
}

#[test]
fn profile_codec_checks_schema_fields_and_each_selected_generation() {
    let original = profile();
    let wire = serde_json::to_value(&original).expect("wire");
    assert_eq!(
        serde_json::from_value::<AdmissionAuthorityProfileV1>(wire.clone()).expect("roundtrip"),
        original
    );
    for pointer in [
        "/selection/runtime/runtime_authority_id",
        "/selection/runtime/expectation_id",
        "/selection/approval/approval_authority_id",
        "/selection/approval/expectation_id",
        "/selection/dpop/dpop_authority_id",
    ] {
        let mut changed = wire.clone();
        *changed.pointer_mut(pointer).expect("field") = "replacement".into();
        let decoded: AdmissionAuthorityProfileV1 =
            serde_json::from_value(changed).expect("well-formed alternate selection");
        assert_ne!(decoded, original, "{pointer}");
    }
    for pointer in [
        "/selection/runtime",
        "/selection/approval",
        "/selection/dpop",
    ] {
        let mut changed = wire.clone();
        *changed.pointer_mut(pointer).expect("field") = serde_json::Value::Null;
        assert_ne!(
            serde_json::from_value::<AdmissionAuthorityProfileV1>(changed)
                .expect("explicit absence"),
            original
        );
    }
    for mutate in 0..5 {
        let mut invalid = wire.clone();
        match mutate {
            0 => invalid["schema"] = "chio.admission-authority-profile.v2".into(),
            1 => invalid["extra"] = true.into(),
            2 => invalid["selection"]["extra"] = true.into(),
            3 => invalid["selection"]["runtime"]["extra"] = true.into(),
            _ => invalid["selection"]["dpop"]["proof_ttl_secs"] = 0.into(),
        }
        assert!(
            serde_json::from_value::<AdmissionAuthorityProfileV1>(invalid).is_err(),
            "mutation {mutate}"
        );
    }
}

#[test]
fn profile_requires_explicit_absence_and_consistent_runtime_declarations() {
    let wire = serde_json::to_value(profile()).expect("wire");
    for field in ["runtime", "approval", "dpop"] {
        let mut invalid = wire.clone();
        invalid["selection"]
            .as_object_mut()
            .expect("selection")
            .remove(field);
        assert!(
            serde_json::from_value::<AdmissionAuthorityProfileV1>(invalid).is_err(),
            "missing {field}"
        );
    }
    for field in [
        "runtime_hook_installed",
        "runtime_requires_dispatch_revalidation",
    ] {
        let mut invalid = wire.clone();
        invalid["selection"][field] = false.into();
        assert!(
            serde_json::from_value::<AdmissionAuthorityProfileV1>(invalid).is_err(),
            "inconsistent {field}"
        );
    }
    let mut invalid = wire;
    invalid["selection"]["swarm_admission_required"] = true.into();
    invalid["selection"]["runtime_enforces_swarm_authority"] = false.into();
    // An unmet requirement is a representable configuration, not admission.
    // The runtime gate must still emit its specific signed swarm denial.
    assert!(serde_json::from_value::<AdmissionAuthorityProfileV1>(invalid).is_ok());
}

#[test]
fn profile_debug_contains_no_authority_identifiers() {
    let debug = format!("{:?}", profile());
    for private in [
        "runtime-generation",
        "approval-generation",
        "11111111",
        "max_clock_skew_secs",
    ] {
        assert!(!debug.contains(private));
    }
}

#[test]
fn pinned_executor_is_versioned_and_cannot_be_downgraded_or_null(
) -> Result<(), Box<dyn std::error::Error>> {
    let legacy = profile();
    let before = chio_core::canonical::canonical_json_bytes(&legacy)?;
    let executor = crate::caller_delivery::CallerExecutorIdentityV1 {
        executor_id: AdmissionIdentifier::try_new("executor_id", "executor")?,
        public_key: chio_core::crypto::Keypair::generate().public_key(),
        key_epoch: 42,
    };
    let pinned = legacy.clone().with_caller_executor(executor.clone())?;
    assert_eq!(pinned.caller_executor(), Some(&executor));
    assert_eq!(before, chio_core::canonical::canonical_json_bytes(&legacy)?);
    let value = serde_json::to_value(&pinned)?;
    assert_eq!(value["schema"], CALLER_SCHEMA);
    assert_eq!(pinned, serde_json::from_value(value.clone())?);
    for (schema, selection) in [
        (SCHEMA, serde_json::to_value(executor)?),
        (SCHEMA, serde_json::Value::Null),
        (CALLER_SCHEMA, serde_json::Value::Null),
    ] {
        let mut invalid = value.clone();
        invalid["schema"] = schema.into();
        invalid["caller_executor"] = selection;
        assert!(serde_json::from_value::<AdmissionAuthorityProfileV1>(invalid).is_err());
    }
    let mut missing = value;
    missing
        .as_object_mut()
        .ok_or("profile object")?
        .remove("caller_executor");
    assert!(serde_json::from_value::<AdmissionAuthorityProfileV1>(missing).is_err());
    Ok(())
}
