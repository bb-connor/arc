//! Codec negative controls. Physical episode capture is exercised separately
//! through the qualified SQLite authority, not inferred from these DTOs.

use super::*;

#[test]
fn caller_custody_rejects_each_selected_family_without_its_physical_ledger() -> TestResult {
    use crate::admission_operation::{
        governed_approval_claim::GovernedApprovalAuthorityBindingV1,
        runtime_participant::RuntimeParticipantAuthorityBindingV1, AdmissionAuthorityProfileV1,
        AdmissionAuthoritySelectionV1,
    };
    use crate::dpop::authority::{DpopReplayAuthorityInputV1, DpopReplayAuthorityV1};
    for selected in 0_u8..8 {
        let mut fixture = fixture()?;
        let id = |value: &str| AdmissionIdentifier::try_new("test", value.to_owned());
        let runtime = selected & 1 != 0;
        let approval = selected & 2 != 0;
        let dpop = selected & 4 != 0;
        let profile = AdmissionAuthorityProfileV1::new(AdmissionAuthoritySelectionV1 {
            runtime_hook_installed: runtime,
            swarm_admission_required: false,
            runtime_enforces_swarm_authority: false,
            runtime_requires_dispatch_revalidation: runtime,
            runtime: runtime
                .then(|| {
                    Ok::<_, Box<dyn std::error::Error>>(RuntimeParticipantAuthorityBindingV1::new(
                        id("runtime")?,
                        id("generation")?,
                    ))
                })
                .transpose()?,
            approval: approval
                .then(|| {
                    Ok::<_, Box<dyn std::error::Error>>(GovernedApprovalAuthorityBindingV1::new(
                        id("approval")?,
                        id("generation")?,
                    ))
                })
                .transpose()?,
            dpop: if dpop {
                Some(DpopReplayAuthorityV1::new(DpopReplayAuthorityInputV1 {
                    destination_store_uuid: id("d70c4490-9782-4d9c-a5a0-7990ba4c2836")?,
                    dpop_authority_id: id("dpop")?,
                    expectation_id: AdmissionDigest::try_new("generation", "a".repeat(64))?,
                    proof_ttl_secs: 60,
                    max_clock_skew_secs: 5,
                })?)
            } else {
                None
            },
        })?;
        let request = fixture
            .admission
            .original_retained_request()
            .ok_or("original")?
            .request_for_revalidation()
            .clone();
        let matching = resolve_required_matching_grants(
            &request.capability,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
            request.model_metadata.as_ref(),
        )?;
        fixture.admission.retained_request =
            Some(RetainedToolAdmissionRequestV1::from_admission_with_profile(
                &request,
                &matching,
                &[],
                None,
                Some(&profile),
            )?);
        let result = fixture.kernel.read_caller_participant_custody(
            &fixture.admission,
            0,
            current_unix_timestamp_ms(),
        );
        if selected == 0 {
            let custody = result?;
            assert_eq!(
                serde_json::to_value(custody)?,
                serde_json::json!({"runtime": null, "approval": null, "dpop": null})
            );
        } else {
            let expected = if runtime {
                "runtime"
            } else if approval {
                "approval"
            } else {
                "DPoP"
            };
            let error = result
                .err()
                .ok_or("selected authority incorrectly accepted absent custody")?;
            assert!(
                error.to_string().contains(&format!(
                    "caller custody omitted its selected {expected} authority"
                )),
                "{error}"
            );
        }
    }
    // A truly unselected historical request has no profile and remains readable.
    let fixture = fixture()?;
    let custody = fixture.kernel.read_caller_participant_custody(
        &fixture.admission,
        0,
        current_unix_timestamp_ms(),
    )?;
    assert_eq!(
        serde_json::to_value(custody)?,
        serde_json::json!({"runtime": null, "approval": null, "dpop": null})
    );
    Ok(())
}

#[test]
fn caller_return_custody_requires_explicit_absence_and_rejects_unowned_claims() -> TestResult {
    let fixture = fixture()?;
    let original: serde_json::Value = serde_json::from_slice(fixture.frame.kernel_context_json())?;
    assert_eq!(
        original["participant_custody"],
        serde_json::json!({
            "runtime": null, "approval": null, "dpop": null
        })
    );
    for family in ["runtime", "approval", "dpop"] {
        for remove in [true, false] {
            let mut changed = original.clone();
            let custody = changed["participant_custody"]
                .as_object_mut()
                .ok_or("custody")?;
            if remove {
                custody.remove(family);
            } else {
                custody.insert(
                    family.into(),
                    serde_json::json!({
                        "episode_id": "forged-episode",
                        "claim_digest": "a".repeat(64),
                        "intent_digest": "b".repeat(64),
                        "history_digest": "c".repeat(64)
                    }),
                );
            }
            assert!(
                fixture
                    .kernel
                    .decode_caller_return_payload(
                        &fixture.admission,
                        &canonical_json_bytes(&changed)?,
                        current_unix_timestamp_ms(),
                    )
                    .is_err(),
                "accepted {family}, removed={remove}"
            );
        }
    }
    for replacement in [
        serde_json::Value::Null,
        serde_json::json!({
            "runtime": null, "approval": null, "dpop": null, "unknown": null
        }),
    ] {
        let mut changed = original.clone();
        changed["participant_custody"] = replacement;
        assert!(fixture
            .kernel
            .decode_caller_return_payload(
                &fixture.admission,
                &canonical_json_bytes(&changed)?,
                current_unix_timestamp_ms(),
            )
            .is_err());
    }
    Ok(())
}

#[test]
fn caller_return_v3_remains_readable_but_cannot_acquire_custody_on_reissue() -> TestResult {
    let fixture = fixture()?;
    let mut payload: serde_json::Value =
        serde_json::from_slice(fixture.frame.kernel_context_json())?;
    payload["schema"] = serde_json::json!(PARTICIPANT_SCHEMA);
    assert!(
        fixture
            .kernel
            .decode_caller_return_payload(
                &fixture.admission,
                &canonical_json_bytes(&payload)?,
                current_unix_timestamp_ms(),
            )
            .is_err(),
        "v3 cannot smuggle a new custody snapshot"
    );
    payload
        .as_object_mut()
        .ok_or("caller object")?
        .remove("participant_custody");
    let legacy = fixture.kernel.decode_caller_return_payload(
        &fixture.admission,
        &canonical_json_bytes(&payload)?,
        current_unix_timestamp_ms(),
    )?;
    assert!(legacy.participants.is_some());
    assert!(legacy.caller_participant_custody.is_none());
    assert!(
        fixture
            .kernel
            .frame_caller_return_context(&fixture.admission, &legacy, current_unix_timestamp_ms(),)
            .is_err(),
        "historical framing cannot infer missing custody"
    );
    payload["schema"] = serde_json::json!(SCHEMA);
    assert!(
        fixture
            .kernel
            .decode_caller_return_payload(
                &fixture.admission,
                &canonical_json_bytes(&payload)?,
                current_unix_timestamp_ms(),
            )
            .is_err(),
        "v4 requires the original custody snapshot"
    );
    Ok(())
}
