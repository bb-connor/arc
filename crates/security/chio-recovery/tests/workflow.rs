use chio_core_types::{canonical_json_bytes, recovery::decode_contract};
use chio_recovery::{advise_workflow, WorkflowDirective};
use chio_security_types::recovery::{AdmissionIntentRef, RecoveryObservationV1};
use serde_json::{json, Value};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn observation(effect: Value, control: &str, release: Value) -> Result<RecoveryObservationV1> {
    let mut wire: Value = serde_json::from_str(include_str!(
        "../../../../spec/vectors/recovery/v1/observation.json"
    ))?;
    wire["effect"] = effect;
    wire["control"] = control.into();
    wire["release"] = release;
    Ok(decode_contract(&canonical_json_bytes(&wire)?)?)
}
fn operation() -> Value {
    json!({"operation_id":"operation-original","native_admission_digest":vec![3;32],"operation_version":1})
}

#[test]
fn unknown_and_pending_operations_keep_identity_across_cancellation() -> Result {
    for control in ["active", "cancel_requested", "cancelled"] {
        let observation = observation(
            json!({"kind":"unknown","operation":operation()}),
            control,
            json!({"kind":"not_available"}),
        )?;
        let original = observation
            .effect()
            .operation()
            .ok_or("missing operation")?;
        assert_eq!(
            advise_workflow(&observation),
            WorkflowDirective::Reconcile(original.clone())
        );
        for kind in ["in_flight", "awaiting_caller_report"] {
            let pending = observation_from_kind(kind, control)?;
            assert_eq!(
                advise_workflow(&pending),
                WorkflowDirective::AwaitOutcome(original.clone())
            );
        }
    }
    Ok(())
}
fn observation_from_kind(kind: &str, control: &str) -> Result<RecoveryObservationV1> {
    observation(
        json!({"kind":kind,"operation":operation()}),
        control,
        json!({"kind":"not_available"}),
    )
}

#[test]
fn unresolved_admission_never_recommends_a_new_submission() -> Result {
    for control in ["active", "cancel_requested", "cancelled"] {
        let observed = observation(
            json!({"kind":"admission_unresolved","admission_intent":"intent-original"}),
            control,
            json!({"kind":"not_available"}),
        )?;
        assert_eq!(
            advise_workflow(&observed),
            WorkflowDirective::ResolveAdmission(AdmissionIntentRef::new("intent-original")?)
        );
        assert!(observed.effect().operation().is_none());
        assert_eq!(observed.knowledge_digest().as_bytes(), &[5; 32]);
    }
    let quarantined = observation(
        json!({"kind":"admission_unresolved","admission_intent":"intent-original"}),
        "quarantined",
        json!({"kind":"not_available"}),
    )?;
    assert_eq!(advise_workflow(&quarantined), WorkflowDirective::Halt);
    Ok(())
}

#[test]
fn settled_effects_do_not_become_another_submission_when_output_is_denied() -> Result {
    for kind in ["complete", "partial", "failed_after_effect"] {
        let mut effect = json!({"kind":kind,"operation":operation()});
        effect[if kind == "complete" {
            "effect_count"
        } else {
            "applied_effects"
        }] = 1.into();
        for release in [
            json!({"kind":"withheld","evidence":"retained-output"}),
            json!({"kind":"denied","reason":"audience_denied"}),
        ] {
            for control in ["active", "cancel_requested", "cancelled"] {
                let observed = observation(effect.clone(), control, release.clone())?;
                let original = observed.effect().operation().ok_or("missing operation")?;
                assert_eq!(
                    advise_workflow(&observed),
                    WorkflowDirective::ProjectOutcome(original.clone())
                );
                assert_eq!(observed.knowledge_digest().as_bytes(), &[5; 32]);
                assert_eq!(
                    observed.effect().applied_effects().map(|count| count.get()),
                    Some(1)
                );
            }
        }
    }
    Ok(())
}

#[test]
fn useful_pre_admission_and_native_approval_advice_have_positive_controls() -> Result {
    let fresh = observation(
        json!({"kind":"never_admitted"}),
        "active",
        json!({"kind":"not_available"}),
    )?;
    assert_eq!(
        advise_workflow(&fresh),
        WorkflowDirective::Materialize(fresh.step_id().clone())
    );
    let cancelled = observation(
        json!({"kind":"never_admitted"}),
        "cancelled",
        json!({"kind":"not_available"}),
    )?;
    assert_eq!(advise_workflow(&cancelled), WorkflowDirective::Halt);
    let pending = observation_from_kind("awaiting_approval", "active")?;
    let original = pending.effect().operation().ok_or("missing operation")?;
    assert_eq!(
        advise_workflow(&pending),
        WorkflowDirective::ResumeNativeApproval(original.clone())
    );
    let quarantined = observation_from_kind("unknown", "quarantined")?;
    assert_eq!(advise_workflow(&quarantined), WorkflowDirective::Halt);
    Ok(())
}
