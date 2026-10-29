use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn treaty_payload_is_hashed_independently_of_the_stores_advertised_digest() -> TestResult {
    for (kind, expected) in [
        ("treaty_scope", "chio_treaty_scope_hash_mismatch"),
        ("ladder_intersection", "chio_treaty_intersection_mismatch"),
        (
            "cross_kernel_continuation",
            "chio_treaty_continuation_hash_mismatch",
        ),
        (
            "receipt_lineage_bundle",
            "chio_treaty_lineage_hash_mismatch",
        ),
        (
            "bilateral_dsse_envelope",
            "chio_treaty_bilateral_hash_mismatch",
        ),
    ] {
        let inner = InMemoryRuntimeAdmissionStore::new();
        let (request, metadata) = preparation_request(&inner, false)?;
        let mut store = PreparationStore::new(inner);
        store.artifact_tamper_kind = Some(kind);
        let observer = store.clone();
        let hook = allowing_chio_policy_hook(store)?;
        let decision = evaluate(&hook, &request, metadata.as_ref())?;
        assert_no_reservation_claims(&decision)?;
        let metadata = decision.metadata.as_ref().ok_or("denial metadata")?;
        assert_eq!(
            metadata["chio_runtime"]["failure_code"], expected,
            "{kind}: {metadata}"
        );
        assert_eq!(observer.trust_floor_writes(), 0);
    }
    Ok(())
}

fn evaluate(
    hook: &ChioRuntimeAdmissionHook<PreparationStore>,
    request: &ToolCallRequest,
    extra_metadata: Option<&serde_json::Value>,
) -> Result<chio_kernel::RuntimeAdmissionDecision, chio_kernel::KernelError> {
    prepare_denial(
        hook,
        &RuntimeAdmissionContext {
            request,
            extra_metadata,
            now_unix_secs: 1_800_000_001,
            now_unix_ms: 1_800_000_001_000,
            matched_grant_index: Some(0),
            local_kernel_id: "kernel.vendor-b".to_string(),
        },
    )
}

fn assert_no_reservation_claims(decision: &chio_kernel::RuntimeAdmissionDecision) -> TestResult {
    assert!(!decision.allowed, "{decision:?}");
    assert!(!decision.has_verified_treaty_material());
    let metadata = decision
        .metadata
        .as_ref()
        .ok_or("missing denial metadata")?;
    assert_eq!(metadata["chio_runtime"]["accepted"], false);
    for key in [
        "reserved_destructive_lease_id",
        "reserved_treaty_continuation_id",
        "reserved_swarm_continuation_id",
        "reservation_release_failed",
    ] {
        assert!(metadata["chio_runtime"].get(key).is_none(), "{metadata}");
    }
    Ok(())
}

#[test]
fn invalid_core_preparation_never_updates_trust_floor() -> TestResult {
    for expected_code in [
        "unsupported_profile_schema",
        "stale_profile",
        "unsupported_bundle_schema",
        "admission_bundle_id_mismatch",
        "host_kernel_mismatch",
        "request_binding_mismatch",
        "missing_destructive_lease",
        "missing_governance_receipt",
        "runtime_pheromone_policy_deny",
    ] {
        let inner = InMemoryRuntimeAdmissionStore::new();
        let (mut request, extra_metadata) = preparation_request(&inner, true)?;
        let mut original = inner.bundle("adm-live-1")?.ok_or("original bundle")?;
        let mut first_bundle = original.clone();
        let mut admission_profile = profile();
        let mut strength = 0.10;
        match expected_code {
            "unsupported_profile_schema" => admission_profile.schema = "invalid-profile".into(),
            "stale_profile" => admission_profile.expires_at_unix_ms = 1_800_000_001_000,
            "unsupported_bundle_schema" => first_bundle.schema = "invalid-bundle".into(),
            "admission_bundle_id_mismatch" => first_bundle.admission_id = "adm-other".into(),
            "host_kernel_mismatch" => admission_profile.local_kernel_id = "other-kernel".into(),
            "request_binding_mismatch" => first_bundle.binding.request_id = "other-request".into(),
            "missing_destructive_lease" => first_bundle.lease_id = None,
            "missing_governance_receipt" => first_bundle.governance_receipt_id = None,
            "runtime_pheromone_policy_deny" => strength = 0.95,
            _ => return Err("unhandled invalid preparation case".into()),
        }
        let swarm_only = matches!(
            expected_code,
            "missing_destructive_lease" | "missing_governance_receipt"
        );
        if swarm_only {
            // The treaty DSSE independently requires its original lease and
            // governance refs. Keep swarm authority valid while isolating the
            // later core check of those prerequisites.
            request.federated_origin_kernel_id = None;
            original.binding.origin_kernel_id = None;
            first_bundle.binding.origin_kernel_id = None;
        }
        // Pin the exact invalid first response. A second lookup would return the
        // valid original, so validating that different snapshot would hide the fault.
        let request_context = request
            .governed_intent
            .as_mut()
            .and_then(|intent| intent.context.as_mut())
            .ok_or("request runtime context")?;
        if swarm_only {
            request_context
                .as_object_mut()
                .ok_or("runtime context object")?
                .remove("chioTreaty");
        }
        request_context["chioAdmission"]["bundleSha256"] =
            serde_json::json!(runtime_admission_bundle_sha256(&first_bundle)?);
        let mut store = PreparationStore::new(inner.clone());
        store.bundle_snapshots = Some((first_bundle, original));
        let observer = store.clone();
        let (signed_trust, trusted, advisory, signed_policy, signed_weights) =
            signed_policy_inputs(strength)?;
        let hook = ChioRuntimeAdmissionHook::new(admission_profile, store, uninstalled_binding()?)
            .with_runtime_trust_input(signed_trust, trusted)
            .with_pheromone_query_report(advisory)
            .with_runtime_pheromone_policy(signed_policy, signed_weights)
            .with_swarm_witness_keys(trusted_swarm_witness_keys())
            .with_swarm_graph_source(retained_swarm_graphs(&runtime_swarm_bundle(false)?));

        let decision = evaluate(&hook, &request, extra_metadata.as_ref())?;
        assert_no_reservation_claims(&decision)?;
        let metadata = decision.metadata.as_ref().ok_or("denial metadata")?;
        assert_eq!(metadata["chio_runtime"]["failure_code"], expected_code);
        assert_eq!(observer.trust_floor_writes(), 0, "{expected_code}");
        assert!(
            observer
                .bundle_calls
                .load(std::sync::atomic::Ordering::SeqCst)
                <= 1
        );
        assert!(inner
            .runtime_trust_floor("did:chio:buyer-verifier", "verifier-key-1")?
            .is_none());
    }
    Ok(())
}

#[test]
fn first_bundle_lookup_panic_never_enters_participant_commit() -> TestResult {
    let inner = InMemoryRuntimeAdmissionStore::new();
    let (request, extra_metadata) = preparation_request(&inner, true)?;
    let mut store = PreparationStore::new(inner.clone());
    store.panic_bundle_on_call = Some(0);
    let observer = store.clone();
    let hook = allowing_chio_policy_hook(store)?
        .with_swarm_witness_keys(trusted_swarm_witness_keys())
        .with_swarm_graph_source(retained_swarm_graphs(&runtime_swarm_bundle(false)?));

    let decision = evaluate(&hook, &request, extra_metadata.as_ref())?;
    assert_no_reservation_claims(&decision)?;
    let metadata = decision.metadata.as_ref().ok_or("denial metadata")?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "admission_bundle_store_error"
    );
    assert_eq!(
        observer
            .bundle_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(observer.trust_floor_writes(), 0);
    Ok(())
}

#[test]
fn pinned_bundle_is_the_only_snapshot_used_by_treaty_and_core_admission() -> TestResult {
    for panic_on_second_read in [false, true] {
        let inner = InMemoryRuntimeAdmissionStore::new();
        let (request, extra_metadata) = preparation_request(&inner, true)?;
        let original = inner.bundle("adm-live-1")?.ok_or("original bundle")?;
        let mut substituted = original.clone();
        substituted.destructive = false;
        substituted.lease_id = None;
        substituted.governance_receipt_id = None;
        substituted.workflow_id = "substituted-workflow".into();
        let mut store = PreparationStore::new(inner.clone());
        store.bundle_snapshots = Some((original.clone(), substituted));
        store.panic_bundle_on_call = panic_on_second_read.then_some(1);
        let observer = store.clone();
        let hook = allowing_chio_policy_hook(store)?
            .with_swarm_witness_keys(trusted_swarm_witness_keys())
            .with_swarm_graph_source(retained_swarm_graphs(&runtime_swarm_bundle(false)?));

        let context = RuntimeAdmissionContext {
            request: &request,
            extra_metadata: extra_metadata.as_ref(),
            now_unix_secs: 1_800_000_001,
            now_unix_ms: 1_800_000_001_000,
            matched_grant_index: Some(0),
            local_kernel_id: "kernel.vendor-b".to_string(),
        };
        let super::super::super::preparation::HookAdmissionPreparation::Prepared(prepared) =
            hook.prepare_request(&context)?
        else {
            return Err("valid pinned evidence did not prepare".into());
        };
        assert!(prepared.federation_treaty_material.is_some());
        assert_eq!(
            observer
                .bundle_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(observer.trust_floor_writes(), 0);
        assert_eq!(
            prepared.core.bundle_digest,
            runtime_admission_bundle_sha256(&original)?
        );
        assert_eq!(
            prepared.core.destructive_resource().map(|(id, _)| id),
            Some("lease-live-1")
        );
        assert_eq!(
            prepared.treaty_continuation_id_to_consume.as_deref(),
            Some("continue-runtime-1")
        );
        assert_eq!(
            prepared.swarm_continuation_id_to_consume.as_deref(),
            Some("continuation-child-a")
        );
    }
    Ok(())
}

#[test]
fn trust_floor_commit_panic_refuses_and_preserves_monotonic_floor() -> TestResult {
    let inner = InMemoryRuntimeAdmissionStore::new();
    let (request, extra_metadata) = preparation_request(&inner, true)?;
    let mut store = PreparationStore::new(inner.clone());
    store.panic_trust_floor = true;
    let observer = store.clone();
    let hook = allowing_chio_policy_hook(store)?
        .with_swarm_witness_keys(trusted_swarm_witness_keys())
        .with_swarm_graph_source(retained_swarm_graphs(&runtime_swarm_bundle(false)?));
    let context = RuntimeAdmissionContext {
        request: &request,
        extra_metadata: extra_metadata.as_ref(),
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    };
    let super::super::super::preparation::HookAdmissionPreparation::Prepared(prepared) =
        hook.prepare_request(&context)?
    else {
        return Err("valid evidence did not prepare".into());
    };
    assert_eq!(observer.trust_floor_writes(), 0);
    let report = prepared.core.commit_operation_owned(&observer)?;
    assert!(!report.accepted);
    assert_eq!(
        report.failure_code.as_deref(),
        Some("runtime_trust_floor_error")
    );
    assert_eq!(observer.trust_floor_writes(), 1);
    let floor = inner
        .runtime_trust_floor("did:chio:buyer-verifier", "verifier-key-1")?
        .ok_or("trust floor mutation must remain monotonic")?;
    assert_eq!(floor.highest_version, 1);
    Ok(())
}
