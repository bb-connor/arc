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
        let (request, metadata) = runtime_hook_cleanup_request(&inner, false)?;
        let mut store = FaultInjectingAdmissionStore::new(inner);
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
        assert_eq!(observer.mutation_counts(), [0; 7]);
    }
    Ok(())
}

fn evaluate(
    hook: &impl RuntimeAdmissionHook,
    request: &ToolCallRequest,
    extra_metadata: Option<&serde_json::Value>,
) -> Result<chio_kernel::RuntimeAdmissionDecision, chio_kernel::KernelError> {
    hook.evaluate(&RuntimeAdmissionContext {
        request,
        extra_metadata,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    })
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

fn assert_all_participants_available(store: &InMemoryRuntimeAdmissionStore) -> TestResult {
    store.consume_treaty_continuation("continue-runtime-1", "adm-live-1")?;
    store.consume_swarm_continuation("continuation-child-a", "adm-live-1")?;
    store.consume_destructive_lease("lease-live-1", "adm-live-1")?;
    store.release_treaty_continuation("continue-runtime-1", "adm-live-1")?;
    store.release_swarm_continuation("continuation-child-a", "adm-live-1")?;
    store.release_destructive_lease("lease-live-1", "adm-live-1")?;
    Ok(())
}

#[test]
fn invalid_core_preparation_never_consumes_continuations_or_updates_trust_floor() -> TestResult {
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
        let (mut request, extra_metadata) = runtime_hook_cleanup_request(&inner, true)?;
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
        let mut store = FaultInjectingAdmissionStore::new(inner.clone());
        store.bundle_snapshots = Some((first_bundle, original));
        let observer = store.clone();
        let (signed_trust, trusted, advisory, signed_policy, signed_weights) =
            signed_policy_inputs(strength)?;
        let hook = ChioRuntimeAdmissionHook::new(admission_profile, store)
            .with_runtime_trust_input(signed_trust, trusted)
            .with_pheromone_query_report(advisory)
            .with_runtime_pheromone_policy(signed_policy, signed_weights)
            .with_swarm_witness_keys(trusted_swarm_witness_keys());

        let decision = evaluate(&hook, &request, extra_metadata.as_ref())?;
        assert_no_reservation_claims(&decision)?;
        let metadata = decision.metadata.as_ref().ok_or("denial metadata")?;
        assert_eq!(metadata["chio_runtime"]["failure_code"], expected_code);
        assert_eq!(observer.mutation_counts(), [0; 7], "{expected_code}");
        assert!(
            observer
                .bundle_calls
                .load(std::sync::atomic::Ordering::SeqCst)
                <= 1
        );
        assert!(inner
            .runtime_trust_floor("did:chio:buyer-verifier", "verifier-key-1")?
            .is_none());
        assert_all_participants_available(&inner)?;
    }
    Ok(())
}

#[test]
fn first_bundle_lookup_panic_never_enters_participant_commit() -> TestResult {
    let inner = InMemoryRuntimeAdmissionStore::new();
    let (request, extra_metadata) = runtime_hook_cleanup_request(&inner, true)?;
    let mut store = FaultInjectingAdmissionStore::new(inner.clone());
    store.panic_bundle_on_call = Some(0);
    let observer = store.clone();
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());

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
    assert_eq!(observer.mutation_counts(), [0; 7]);
    assert_all_participants_available(&inner)?;
    Ok(())
}

#[test]
fn pinned_bundle_is_the_only_snapshot_used_by_treaty_and_core_admission() -> TestResult {
    for panic_on_second_read in [false, true] {
        let inner = InMemoryRuntimeAdmissionStore::new();
        let (request, extra_metadata) = runtime_hook_cleanup_request(&inner, true)?;
        let original = inner.bundle("adm-live-1")?.ok_or("original bundle")?;
        let mut substituted = original.clone();
        substituted.destructive = false;
        substituted.lease_id = None;
        substituted.governance_receipt_id = None;
        substituted.workflow_id = "substituted-workflow".into();
        let mut store = FaultInjectingAdmissionStore::new(inner.clone());
        store.bundle_snapshots = Some((original.clone(), substituted));
        store.panic_bundle_on_call = panic_on_second_read.then_some(1);
        let observer = store.clone();
        let hook =
            allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());

        let decision = evaluate(&hook, &request, extra_metadata.as_ref())?;
        assert!(decision.allowed, "{decision:?}");
        assert!(decision.has_verified_treaty_material());
        assert_eq!(
            observer
                .bundle_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(observer.mutation_counts(), [1, 1, 1, 1, 0, 0, 0]);
        let metadata = decision.metadata.as_ref().ok_or("allowed metadata")?;
        assert_eq!(
            metadata["chio_runtime"]["workflow_id"],
            original.workflow_id
        );
        assert_eq!(metadata["chio_runtime"]["destructive"], true);
        assert_eq!(
            metadata["chio_runtime"]["reserved_destructive_lease_id"],
            "lease-live-1"
        );
        assert_eq!(
            metadata["chio_runtime"]["reserved_treaty_continuation_id"],
            "continue-runtime-1"
        );
        assert_eq!(
            metadata["chio_runtime"]["reserved_swarm_continuation_id"],
            "continuation-child-a"
        );
        assert!(inner
            .consume_destructive_lease("lease-live-1", "adm-live-1")
            .is_err());
        hook.release_reserved(metadata)?;
        assert_all_participants_available(&inner)?;
    }
    Ok(())
}

#[test]
fn trust_floor_write_then_panic_denies_and_releases_only_confirmed_reservations() -> TestResult {
    let inner = InMemoryRuntimeAdmissionStore::new();
    let (request, extra_metadata) = runtime_hook_cleanup_request(&inner, true)?;
    let mut store = FaultInjectingAdmissionStore::new(inner.clone());
    store.panic_trust_floor = true;
    let observer = store.clone();
    let hook =
        allowing_chio_policy_hook(store)?.with_swarm_witness_keys(trusted_swarm_witness_keys());

    let decision = evaluate(&hook, &request, extra_metadata.as_ref())?;
    assert_no_reservation_claims(&decision)?;
    let metadata = decision.metadata.as_ref().ok_or("denial metadata")?;
    assert_eq!(
        metadata["chio_runtime"]["failure_code"],
        "runtime_trust_floor_error"
    );
    assert_eq!(observer.mutation_counts(), [1, 1, 1, 1, 1, 1, 1]);
    let floor = inner
        .runtime_trust_floor("did:chio:buyer-verifier", "verifier-key-1")?
        .ok_or("trust floor mutation must remain monotonic")?;
    assert_eq!(floor.highest_version, 1);
    assert_all_participants_available(&inner)?;
    Ok(())
}
