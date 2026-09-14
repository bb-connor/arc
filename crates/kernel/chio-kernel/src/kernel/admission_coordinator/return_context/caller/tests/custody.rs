//! Codec negative controls. Physical episode capture is exercised separately
//! through the qualified SQLite authority, not inferred from these DTOs.

use super::*;

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
