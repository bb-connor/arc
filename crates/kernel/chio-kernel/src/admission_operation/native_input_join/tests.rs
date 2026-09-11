use super::*;
use chio_security_types::ports::{IsolationEpochId, LineageId, SessionId, TenantId};
use chio_security_types::{Compartment, PrincipalId};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn input() -> TestResult<NativeSecurityInputJoinRequestV1> {
    Ok(NativeSecurityInputJoinRequestV1::new(
        AdmissionOperationId::from_persisted(sha256_hex(b"original-operation"))?,
        FlowStateKey {
            tenant_id: TenantId::new("private-tenant")?,
            principal_id: PrincipalId::new("private-principal")?,
            lineage_id: LineageId::new("private-lineage")?,
            session_id: SessionId::new("private-session")?,
            isolation_epoch_id: IsolationEpochId::new("private-epoch")?,
        },
        InformationLabel::bottom(),
    )?)
}

fn label() -> TestResult<InformationLabel> {
    Ok(InformationLabel::try_known(
        Default::default(),
        std::collections::BTreeSet::from([Compartment::new("private-category")?]),
    )?)
}

fn resolution(
    input: &NativeSecurityInputJoinRequestV1,
) -> TestResult<(FlowJoinRequest, FlowStateSnapshot)> {
    let source = label()?;
    Ok((
        FlowJoinRequest {
            key: input.key().clone(),
            transition_id: input.transition_id().clone(),
            principal_join: source.clone(),
            lineage_join: source.clone(),
            session_join: source.clone(),
        },
        FlowStateSnapshot {
            key: input.key().clone(),
            principal_label: source.clone(),
            lineage_label: source.clone(),
            session_label: source,
            context_generation: 1,
        },
    ))
}

#[test]
fn input_transition_binds_operation_each_identity_and_classified_label() -> TestResult {
    let input = input()?;
    let again = NativeSecurityInputJoinRequestV1::new(
        input.operation_id().clone(),
        input.key().clone(),
        input.input_label().clone(),
    )?;
    assert_eq!(input, again);
    input.validate(input.operation_id())?;
    assert_eq!(canonical_json_bytes(&input)?, canonical_json_bytes(&again)?);
    for field in [
        "tenant_id",
        "principal_id",
        "lineage_id",
        "session_id",
        "isolation_epoch_id",
    ] {
        let mut value = serde_json::to_value(input.key())?;
        value[field] = "substituted".into();
        let changed = NativeSecurityInputJoinRequestV1::new(
            input.operation_id().clone(),
            serde_json::from_value(value)?,
            input.input_label().clone(),
        )?;
        assert_ne!(changed.transition_id(), input.transition_id(), "{field}");
    }
    let changed = NativeSecurityInputJoinRequestV1::new(
        AdmissionOperationId::from_persisted(sha256_hex(b"other-operation"))?,
        input.key().clone(),
        input.input_label().clone(),
    )?;
    assert_ne!(changed.transition_id(), input.transition_id());
    assert!(input.validate(changed.operation_id()).is_err());
    let changed = NativeSecurityInputJoinRequestV1::new(
        input.operation_id().clone(),
        input.key().clone(),
        label()?,
    )?;
    assert_ne!(changed.transition_id(), input.transition_id());
    Ok(())
}

#[test]
fn decoded_input_intent_rejects_unknown_fields_and_recomputed_binding_mismatch() -> TestResult {
    let input = input()?;
    let bytes = canonical_json_bytes(&input)?;
    let decoded: NativeSecurityInputJoinRequestV1 = serde_json::from_slice(&bytes)?;
    assert_eq!(decoded, input);
    for field in ["operation_id", "key", "input_label", "transition_id"] {
        let mut value = serde_json::to_value(&input)?;
        value[field] = match field {
            "operation_id" => sha256_hex(b"other-operation").into(),
            "key" => {
                let mut key = value[field].clone();
                key["session_id"] = "changed".into();
                key
            }
            "input_label" => serde_json::to_value(label()?)?,
            _ => "native-input:forged".into(),
        };
        let decoded: NativeSecurityInputJoinRequestV1 = serde_json::from_value(value)?;
        assert!(decoded.validate(input.operation_id()).is_err(), "{field}");
    }
    let mut value = serde_json::to_value(&input)?;
    value["authority"] = "not-authority".into();
    assert!(serde_json::from_value::<NativeSecurityInputJoinRequestV1>(value).is_err());
    Ok(())
}

#[test]
fn input_resolution_requires_complete_propagation_exact_keys_and_safe_generation() -> TestResult {
    let input = input()?;
    let (command, snapshot) = resolution(&input)?;
    input.validate_resolution(input.operation_id(), &command, &snapshot)?;
    for field in [
        "principal_join",
        "lineage_join",
        "session_join",
        "transition_id",
        "key",
    ] {
        let mut value = serde_json::to_value(&command)?;
        value[field] = match field {
            "transition_id" => "wrong".into(),
            "key" => {
                let mut key = value[field].clone();
                key["session_id"] = "wrong".into();
                key
            }
            _ => serde_json::to_value(InformationLabel::bottom())?,
        };
        assert!(
            input
                .validate_resolution(
                    input.operation_id(),
                    &serde_json::from_value(value)?,
                    &snapshot
                )
                .is_err(),
            "{field}"
        );
    }
    for field in ["principal_label", "lineage_label", "session_label", "key"] {
        let mut value = serde_json::to_value(&snapshot)?;
        value[field] = if field == "key" {
            let mut key = value[field].clone();
            key["session_id"] = "wrong".into();
            key
        } else {
            serde_json::to_value(InformationLabel::bottom())?
        };
        assert!(
            input
                .validate_resolution(
                    input.operation_id(),
                    &command,
                    &serde_json::from_value(value)?
                )
                .is_err(),
            "{field}"
        );
    }
    for generation in [0, 1_u64 << 53] {
        let mut changed = snapshot.clone();
        changed.context_generation = generation;
        assert!(input
            .validate_resolution(input.operation_id(), &command, &changed)
            .is_err());
    }
    Ok(())
}

#[test]
fn input_resolution_cannot_discard_the_classified_input_label() -> TestResult {
    let original = input()?;
    let input = NativeSecurityInputJoinRequestV1::new(
        original.operation_id().clone(),
        original.key().clone(),
        label()?,
    )?;
    let (mut command, mut snapshot) = resolution(&input)?;
    command.principal_join = InformationLabel::bottom();
    command.lineage_join = InformationLabel::bottom();
    command.session_join = InformationLabel::bottom();
    snapshot.principal_label = InformationLabel::bottom();
    snapshot.lineage_label = InformationLabel::bottom();
    snapshot.session_label = InformationLabel::bottom();
    assert!(input
        .validate_resolution(input.operation_id(), &command, &snapshot)
        .is_err());
    assert_eq!(
        format!("{input:?}"),
        "NativeSecurityInputJoinRequestV1 { .. }"
    );
    Ok(())
}
