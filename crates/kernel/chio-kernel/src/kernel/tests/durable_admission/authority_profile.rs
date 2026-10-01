//! Original selection tests use coordinator doubles, not activation credentials.

use super::*;
use crate::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1;
use std::sync::Arc;

struct SelectedRuntime(RuntimeParticipantAuthorityBindingV1);

impl RuntimeAdmissionHook for SelectedRuntime {
    fn name(&self) -> &str {
        "original-authority-profile"
    }

    fn runtime_participant_binding(&self) -> Option<&RuntimeParticipantAuthorityBindingV1> {
        Some(&self.0)
    }

    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }

    fn evaluate(
        &self,
        _: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        panic!("profile binding cannot acquire legacy authority");
    }
}

fn select(kernel: &mut ChioKernel, authority: &str, generation: &str) {
    kernel.set_runtime_admission_hook(Arc::new(SelectedRuntime(
        RuntimeParticipantAuthorityBindingV1::new(
            AdmissionIdentifier::try_new("authority", authority).expect("authority"),
            AdmissionIdentifier::try_new("generation", generation).expect("generation"),
        ),
    )));
}

fn changed_runtime_selection_is_not_an_exact_retry(authority: &str, generation: &str) {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("original-runtime-profile");
    select(&mut kernel, "runtime-original", "generation-original");
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )
    .expect("matching grants");
    let now = current_unix_timestamp_ms();
    let original = kernel
        .begin_durable_tool_admission(&request, &matching, now)
        .expect("original admission")
        .expect("durable operation");
    select(&mut kernel, authority, generation);
    let retry = kernel.begin_durable_tool_admission(&request, &matching, now);
    assert!(
        retry.is_err(),
        "changed runtime selection reused the original operation"
    );
    assert_eq!(
        store.state.lock().expect("store").operation.as_ref(),
        Some(original.operation())
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn changed_runtime_authority_cannot_reuse_original_admission() {
    changed_runtime_selection_is_not_an_exact_retry("runtime-replacement", "generation-original");
}

#[test]
fn changed_runtime_generation_cannot_reuse_original_admission() {
    changed_runtime_selection_is_not_an_exact_retry("runtime-original", "generation-replacement");
}

#[test]
fn prepared_credentials_cannot_rebind_the_original_authority_profile() {
    struct ChangingRuntime {
        original: SelectedRuntime,
        replacement: SelectedRuntime,
        changed: AtomicBool,
    }
    impl RuntimeAdmissionHook for ChangingRuntime {
        fn name(&self) -> &str {
            "changing-runtime-profile"
        }
        fn requires_dispatch_revalidation(&self) -> bool {
            true
        }
        fn runtime_participant_binding(&self) -> Option<&RuntimeParticipantAuthorityBindingV1> {
            if self.changed.load(Ordering::SeqCst) {
                self.replacement.runtime_participant_binding()
            } else {
                self.original.runtime_participant_binding()
            }
        }
        fn evaluate(
            &self,
            _: &RuntimeAdmissionContext<'_>,
        ) -> Result<RuntimeAdmissionDecision, KernelError> {
            panic!("origin validation cannot evaluate or acquire runtime custody");
        }
    }
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("prepared-profile-origin");
    let selected = |name| {
        SelectedRuntime(RuntimeParticipantAuthorityBindingV1::new(
            AdmissionIdentifier::try_new("runtime", name).expect("authority"),
            AdmissionIdentifier::try_new("generation", "original-generation").expect("generation"),
        ))
    };
    let hook = Arc::new(ChangingRuntime {
        original: selected("original-runtime"),
        replacement: selected("replacement-runtime"),
        changed: AtomicBool::new(false),
    });
    kernel.set_runtime_admission_hook(hook.clone());
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )
    .expect("matching");
    let now = current_unix_timestamp_ms();
    let admission = kernel
        .begin_durable_tool_admission(&request, &matching, now)
        .expect("begin")
        .expect("durable");
    let original = store
        .state
        .lock()
        .expect("store")
        .retained_request
        .clone()
        .expect("original request");
    let prepared = kernel
        .prepare_dispatch_credentials(&request, &request.capability, false, now / 1000, false)
        .expect("non-consuming preparation");
    prepared
        .validate_origin(&kernel, &original)
        .expect("same original profile");
    hook.changed.store(true, Ordering::SeqCst);
    assert!(
        prepared.validate_origin(&kernel, &original).is_err(),
        "prepared origin ignored a replaced authority profile"
    );
    assert_eq!(
        store.state.lock().expect("state").operation.as_ref(),
        Some(admission.operation())
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn immutable_request_commits_to_every_original_profile_selection(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::admission_operation::{
        immutable_tool_request_hash, immutable_tool_request_hash_with_profile,
        AdmissionAuthorityProfileV1, RetainedToolAdmissionRequestV1,
    };
    let (_, request, _, _) = durable_admission_fixture("profile-hash-contract");
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )?;
    // Codec inputs are descriptive data, not configured or activated authorities.
    let wire = serde_json::json!({
        "schema": "chio.admission-authority-profile.v1", "selection": {
            "runtime_hook_installed": true, "swarm_admission_required": false,
            "runtime_enforces_swarm_authority": true, "runtime_requires_dispatch_revalidation": true,
            "runtime": {"runtime_authority_id": "runtime", "expectation_id": "runtime-generation"},
            "approval": {"approval_authority_id": "approval", "expectation_id": "approval-generation"},
            "dpop": {"destination_store_uuid": "11111111-1111-4111-8111-111111111111",
                "dpop_authority_id": "dpop", "expectation_id": "a".repeat(64),
                "proof_ttl_secs": 60, "max_clock_skew_secs": 30}
        }
    });
    let profile: AdmissionAuthorityProfileV1 = serde_json::from_value(wire.clone())?;
    let old_hash = immutable_tool_request_hash(&request, &matching, &[], None)?;
    let actual =
        immutable_tool_request_hash_with_profile(&request, &matching, &[], None, Some(&profile))?;
    let independent = serde_json::json!({
        "schema": "chio.tool-admission-request.v4", "prior_request_hash": old_hash,
        "authority_profile": wire
    });
    assert_eq!(
        actual.as_str(),
        sha256_hex(&canonical_json_bytes(&independent)?)
    );
    assert_ne!(actual, old_hash);
    let retained = RetainedToolAdmissionRequestV1::from_admission_with_profile(
        &request,
        &matching,
        &[],
        None,
        Some(&profile),
    )?;
    let decoded = RetainedToolAdmissionRequestV1::from_canonical_bytes(retained.canonical_bytes())?;
    assert_eq!(decoded.authority_profile(), Some(&profile));
    decoded.validate_request_material(&request)?;
    for (pointer, value) in [
        (
            "/selection/runtime/runtime_authority_id",
            serde_json::json!("other-runtime"),
        ),
        (
            "/selection/runtime/expectation_id",
            serde_json::json!("other-runtime-generation"),
        ),
        (
            "/selection/approval/approval_authority_id",
            serde_json::json!("other-approval"),
        ),
        (
            "/selection/approval/expectation_id",
            serde_json::json!("other-approval-generation"),
        ),
        (
            "/selection/dpop/destination_store_uuid",
            serde_json::json!("22222222-2222-4222-8222-222222222222"),
        ),
        (
            "/selection/dpop/dpop_authority_id",
            serde_json::json!("other-dpop"),
        ),
        (
            "/selection/dpop/expectation_id",
            serde_json::json!("b".repeat(64)),
        ),
        ("/selection/dpop/proof_ttl_secs", serde_json::json!(61)),
        ("/selection/dpop/max_clock_skew_secs", serde_json::json!(31)),
        (
            "/selection/swarm_admission_required",
            serde_json::json!(true),
        ),
        (
            "/selection/runtime_enforces_swarm_authority",
            serde_json::json!(false),
        ),
        ("/selection/runtime", serde_json::Value::Null),
        ("/selection/approval", serde_json::Value::Null),
        ("/selection/dpop", serde_json::Value::Null),
    ] {
        let mut changed = wire.clone();
        *changed
            .pointer_mut(pointer)
            .ok_or("missing profile field")? = value;
        let profile: AdmissionAuthorityProfileV1 = serde_json::from_value(changed)?;
        assert_ne!(
            immutable_tool_request_hash_with_profile(
                &request,
                &matching,
                &[],
                None,
                Some(&profile)
            )?,
            actual,
            "{pointer}"
        );
    }
    Ok(())
}
