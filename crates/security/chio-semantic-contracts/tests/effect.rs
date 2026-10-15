use chio_core_types::{canonical_json_bytes, recovery::decode_contract};
use chio_security_types::recovery::{
    BoundedList, ContractError, DeploymentDigest, EnforcementFeature, ProviderAccountId,
    ProviderId, ProviderResourceId, RecoveryAttachmentProfile, RecoveryProfileRequirementsV1,
    SafeInteger, VersionV1,
};
use chio_semantic_contracts::{
    DeduplicationPolicy, EffectContractInput, EffectContractSchema, EffectContractV1,
    LookupFinality, PartialSettlementPolicy, SubmissionIdentity, TransportRetryPolicy,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn input(cardinality: u64, finality: LookupFinality) -> TestResult<EffectContractInput> {
    Ok(EffectContractInput {
        schema: EffectContractSchema::V1,
        version: VersionV1,
        provider_id: ProviderId::new("provider")?,
        account_id: ProviderAccountId::new("account")?,
        resource_id: ProviderResourceId::new("resource")?,
        effect_cardinality: SafeInteger::new(cardinality)?,
        submission_identity: SubmissionIdentity::OriginalNativeOperation,
        transport_retry: TransportRetryPolicy::NoAutomaticRetries,
        deduplication: DeduplicationPolicy::NotAssumed,
        lookup_finality: finality,
        partial_settlement: PartialSettlementPolicy::PreserveSpentIdentity,
        recovery_profile: RecoveryProfileRequirementsV1::new(
            DeploymentDigest::from_bytes([7; 32]),
            RecoveryAttachmentProfile::Ordinary,
            BoundedList::new(vec![
                EnforcementFeature::NativeCapture,
                EnforcementFeature::RecoveryBoundGrant,
                EnforcementFeature::ExactRequestCustody,
                EnforcementFeature::CurrentAudience,
            ])?,
        )?,
    })
}

#[test]
fn bounded_cardinality_and_both_explicit_finality_choices_round_trip() -> TestResult {
    for cardinality in [1, 16] {
        for finality in [
            LookupFinality::Unavailable,
            LookupFinality::ExactOperationAuthoritativeFinal,
        ] {
            let contract = EffectContractV1::new(input(cardinality, finality)?)?;
            assert_eq!(contract.effect_cardinality().get(), cardinality);
            assert_eq!(contract.lookup_finality(), finality);
            assert_eq!(
                contract.recovery_profile().attachment_profile(),
                RecoveryAttachmentProfile::Ordinary
            );
            assert_eq!(
                decode_contract::<EffectContractV1>(&canonical_json_bytes(&contract)?)?,
                contract
            );
        }
    }
    Ok(())
}

#[test]
fn invalid_cardinality_is_refused_by_construction_and_decoding() -> TestResult {
    let valid = EffectContractV1::new(input(1, LookupFinality::Unavailable)?)?;
    for cardinality in [0, 17] {
        assert_eq!(
            EffectContractV1::new(input(cardinality, LookupFinality::Unavailable)?).err(),
            Some(ContractError::LimitExceeded)
        );
        let mut wire = serde_json::to_value(&valid)?;
        wire["effect_cardinality"] = serde_json::json!(cardinality);
        assert_eq!(
            decode_contract::<EffectContractV1>(&canonical_json_bytes(&wire)?).err(),
            Some(ContractError::Malformed)
        );
    }
    Ok(())
}

#[test]
fn wire_refuses_retry_deduplication_version_and_unknown_field_substitution() -> TestResult {
    let valid = serde_json::to_value(EffectContractV1::new(input(
        1,
        LookupFinality::Unavailable,
    )?)?)?;
    for (field, replacement) in [
        (
            "schema",
            serde_json::json!("chio.semantic.effect-contract.v2"),
        ),
        ("version", serde_json::json!(2)),
        ("submission_identity", serde_json::json!("fresh_operation")),
        ("transport_retry", serde_json::json!("automatic_retries")),
        ("deduplication", serde_json::json!("assumed")),
        ("lookup_finality", serde_json::json!("best_effort")),
        ("partial_settlement", serde_json::json!("reuse_identity")),
        ("unexpected", serde_json::json!(true)),
    ] {
        let mut wire = valid.clone();
        wire[field] = replacement;
        assert_eq!(
            decode_contract::<EffectContractV1>(&canonical_json_bytes(&wire)?).err(),
            Some(ContractError::Malformed),
            "{field}"
        );
    }
    Ok(())
}

#[test]
fn every_effect_binding_and_enforcement_profile_is_required() -> TestResult {
    let valid = serde_json::to_value(EffectContractV1::new(input(
        1,
        LookupFinality::Unavailable,
    )?)?)?;
    let fields = valid
        .as_object()
        .ok_or("effect object")?
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    for field in fields {
        let mut wire = valid.clone();
        wire.as_object_mut().ok_or("effect object")?.remove(&field);
        assert_eq!(
            decode_contract::<EffectContractV1>(&canonical_json_bytes(&wire)?).err(),
            Some(ContractError::Malformed),
            "{field}"
        );
    }
    let mut missing_capture = valid;
    missing_capture["recovery_profile"]["required_features"] = serde_json::json!([
        "recovery_bound_grant",
        "exact_request_custody",
        "current_audience"
    ]);
    assert_eq!(
        decode_contract::<EffectContractV1>(&canonical_json_bytes(&missing_capture)?).err(),
        Some(ContractError::Malformed)
    );
    Ok(())
}
