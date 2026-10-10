use chio_security_types::recovery::*;
use serde::{Deserialize, Deserializer};
use std::sync::atomic::{AtomicUsize, Ordering};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
static DECODED: AtomicUsize = AtomicUsize::new(0);
struct Probe;
impl<'de> Deserialize<'de> for Probe {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        DECODED.fetch_add(1, Ordering::SeqCst);
        let _ = u8::deserialize(d)?;
        Ok(Self)
    }
}

#[test]
fn collection_ceiling_precedes_next_element_decoding() -> Result {
    DECODED.store(0, Ordering::SeqCst);
    let _: BoundedList<Probe, 1> = serde_json::from_str("[1]")?;
    assert_eq!(DECODED.load(Ordering::SeqCst), 1);
    DECODED.store(0, Ordering::SeqCst);
    assert!(serde_json::from_str::<BoundedList<Probe, 1>>("[1,{\"secret\":[1,2,3]}]").is_err());
    assert_eq!(
        DECODED.load(Ordering::SeqCst),
        1,
        "decoded the overflowing element"
    );
    assert!(serde_json::from_str::<BoundedList<u8, 0>>("[1]").is_err());
    assert!(serde_json::from_str::<NonEmptyBoundedList<u8, 2>>("[]").is_err());
    Ok(())
}

#[test]
fn identifier_and_integer_boundaries_are_closed() -> Result {
    assert!(WorkflowId::new(&"a".repeat(128)).is_ok());
    for id in [
        "",
        " ",
        "../file",
        "https://host",
        "contains spaces",
        "secret\n",
        "é",
        &"a".repeat(129),
    ] {
        assert!(WorkflowId::new(id).is_err());
    }
    assert!(SafeInteger::new(SafeInteger::MAX).is_ok());
    assert!(SafeInteger::new(SafeInteger::MAX + 1).is_err());
    assert_eq!(
        SafeInteger::new(SafeInteger::MAX)?.checked_add(SafeInteger::new(1)?),
        Err(ContractError::ArithmeticOverflow)
    );
    assert!(ServingEpoch::new(0).is_err());
    assert!(OperationRef::new(
        OperationId::new("operation-a")?,
        NativeAdmissionDigest::from_bytes([3; 32]),
        SafeInteger::ZERO,
    )
    .is_err());
    assert!(serde_json::from_str::<OperationRef>(
        r#"{"operation_id":"operation-a","native_admission_digest":[3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3],"operation_version":0}"#,
    ).is_err());
    assert!(serde_json::from_str::<VersionV1>("null").is_err());
    assert!(serde_json::from_str::<VersionV1>("2").is_err());
    Ok(())
}

#[test]
fn old_host_wrong_deployment_and_stripped_participant_refuse() -> Result {
    use EnforcementFeature::*;
    let baseline = BoundedList::new(vec![
        NativeCapture,
        RecoveryBoundGrant,
        ExactRequestCustody,
        CurrentAudience,
    ])?;
    let deployment = DeploymentDigest::from_bytes([9; 32]);
    let profile = RecoveryProfileRequirementsV1::new(
        deployment,
        RecoveryAttachmentProfile::Ordinary,
        baseline.clone(),
    )?;
    profile.check_inventory(deployment, &baseline)?;
    assert_eq!(
        profile.check_inventory(deployment, &BoundedList::new(vec![])?),
        Err(ContractError::UnsupportedProfile)
    );
    assert_eq!(
        profile.check_inventory(DeploymentDigest::from_bytes([8; 32]), &baseline),
        Err(ContractError::BindingMismatch)
    );
    assert_eq!(
        RecoveryProfileRequirementsV1::new(
            deployment,
            RecoveryAttachmentProfile::OperationOwnedNonce,
            baseline
        )
        .err(),
        Some(ContractError::UnsupportedProfile)
    );
    Ok(())
}
