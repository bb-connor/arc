//! Replay reservations follow complete read-only preparation.

use super::preparation::PreparedHookAdmission;
use super::*;

impl<S: RuntimeAdmissionStore + Send + Sync> PreparedHookAdmission<'_, S> {
    pub(super) fn reserve(self) -> Result<KernelRuntimeAdmissionDecision, KernelError> {
        let Self {
            hook,
            admission_id,
            core,
            treaty_continuation_id_to_consume,
            swarm_continuation_id_to_consume,
            verified_swarm_route_metadata,
            verified_swarm_request_binding,
            federation_treaty_material,
            treaty_artifact_digest: _,
            treaty_evidence_digest: _,
            swarm_artifact_digest: _,
            swarm_evidence_digest: _,
            valid_until_unix_ms: _,
        } = self;
        if let Some(continuation_id) = treaty_continuation_id_to_consume.as_deref() {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                hook.store
                    .consume_treaty_continuation(continuation_id, &admission_id)
            })) {
                Ok(Ok(())) => {}
                Ok(Err(ChioRuntimeError::Rejected { code, .. })) => {
                    return Ok(KernelRuntimeAdmissionDecision::deny(
                        "chio treaty-bound runtime continuation replay denied",
                        Some(runtime_denial_metadata(&admission_id, code)),
                    ));
                }
                Ok(Err(error)) => {
                    let metadata = ambiguous_consumption_metadata(
                        runtime_denial_metadata(&admission_id, "treaty_continuation_consume_error"),
                        "ambiguous_treaty_continuation_id",
                        continuation_id,
                        &error.to_string(),
                    );
                    return Ok(KernelRuntimeAdmissionDecision::deny(
                        format!("chio treaty-bound runtime continuation failed: {error}"),
                        Some(metadata),
                    ));
                }
                Err(_) => {
                    let metadata = ambiguous_consumption_metadata(
                        runtime_denial_metadata(&admission_id, "treaty_continuation_consume_error"),
                        "ambiguous_treaty_continuation_id",
                        continuation_id,
                        "treaty continuation consume callback panicked",
                    );
                    return Ok(KernelRuntimeAdmissionDecision::deny(
                        "chio treaty-bound runtime continuation callback panicked",
                        Some(metadata),
                    ));
                }
            }
        }
        if let Some(continuation_id) = swarm_continuation_id_to_consume.as_deref() {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                hook.store
                    .consume_swarm_continuation(continuation_id, &admission_id)
            })) {
                Ok(Ok(())) => {}
                Ok(Err(ChioRuntimeError::Rejected { code, .. })) => {
                    let reservations = continuation_reservation_metadata(
                        &admission_id,
                        None,
                        treaty_continuation_id_to_consume.as_deref(),
                        None,
                    );
                    let metadata = hook.denial_metadata_after_release(
                        runtime_denial_metadata(&admission_id, code),
                        &reservations,
                    );
                    return Ok(KernelRuntimeAdmissionDecision::deny(
                        "chio swarm-bound runtime continuation replay denied",
                        Some(metadata),
                    ));
                }
                Ok(Err(error)) => {
                    let reservations = continuation_reservation_metadata(
                        &admission_id,
                        None,
                        treaty_continuation_id_to_consume.as_deref(),
                        None,
                    );
                    let base_metadata = ambiguous_consumption_metadata(
                        runtime_denial_metadata(&admission_id, "swarm_continuation_consume_error"),
                        "ambiguous_swarm_continuation_id",
                        continuation_id,
                        &error.to_string(),
                    );
                    let metadata = hook.denial_metadata_after_release(base_metadata, &reservations);
                    return Ok(KernelRuntimeAdmissionDecision::deny(
                        format!("chio swarm-bound runtime continuation failed: {error}"),
                        Some(metadata),
                    ));
                }
                Err(_) => {
                    let reservations = continuation_reservation_metadata(
                        &admission_id,
                        None,
                        treaty_continuation_id_to_consume.as_deref(),
                        None,
                    );
                    let base_metadata = ambiguous_consumption_metadata(
                        runtime_denial_metadata(&admission_id, "swarm_continuation_consume_error"),
                        "ambiguous_swarm_continuation_id",
                        continuation_id,
                        "swarm continuation consume callback panicked",
                    );
                    let metadata = hook.denial_metadata_after_release(base_metadata, &reservations);
                    return Ok(KernelRuntimeAdmissionDecision::deny(
                        "chio swarm-bound runtime continuation callback panicked",
                        Some(metadata),
                    ));
                }
            }
        }
        let reservation_tracker = RuntimeAdmissionReservationTracker::default();
        let report = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            commit_prepared_runtime_admission(core, &hook.store, Some(&reservation_tracker))
        })) {
            Ok(Ok(report)) => report,
            Ok(Err(error)) => {
                let reservations = continuation_reservation_metadata(
                    &admission_id,
                    None,
                    treaty_continuation_id_to_consume.as_deref(),
                    swarm_continuation_id_to_consume.as_deref(),
                );
                let metadata = hook.denial_metadata_after_release(
                    runtime_denial_metadata(&admission_id, "runtime_admission_evaluation_error"),
                    &reservations,
                );
                return Ok(KernelRuntimeAdmissionDecision::deny(
                    format!("chio runtime admission evaluation failed: {error}"),
                    Some(metadata),
                ));
            }
            Err(_) => {
                let destructive_lease_id = reservation_tracker.destructive_lease_id();
                let reservations = continuation_reservation_metadata(
                    &admission_id,
                    destructive_lease_id.as_deref(),
                    treaty_continuation_id_to_consume.as_deref(),
                    swarm_continuation_id_to_consume.as_deref(),
                );
                let metadata = hook.denial_metadata_after_release(
                    runtime_denial_metadata(&admission_id, "runtime_admission_evaluation_error"),
                    &reservations,
                );
                return Ok(KernelRuntimeAdmissionDecision::deny(
                    "chio runtime admission evaluation panicked",
                    Some(metadata),
                ));
            }
        };
        if report.accepted {
            let mut metadata = report.receipt_metadata;
            let runtime_metadata_key = "chio_runtime";
            if let Some(continuation_id) = treaty_continuation_id_to_consume.as_deref() {
                metadata[runtime_metadata_key]["reserved_treaty_continuation_id"] =
                    serde_json::json!(continuation_id);
            }
            if let Some(continuation_id) = swarm_continuation_id_to_consume.as_deref() {
                metadata[runtime_metadata_key]["reserved_swarm_continuation_id"] =
                    serde_json::json!(continuation_id);
            }
            if let Some(route_metadata) = verified_swarm_route_metadata {
                metadata[runtime_metadata_key]["verified_swarm_route_metadata"] = route_metadata;
            }
            if let Some(binding) = verified_swarm_request_binding {
                metadata[runtime_metadata_key]["verified_swarm_request_binding"] = binding;
            }
            if let Some(material) = federation_treaty_material {
                return Ok(
                    KernelRuntimeAdmissionDecision::allow_with_verified_treaty_material(
                        Some(metadata),
                        material,
                    ),
                );
            }
            Ok(KernelRuntimeAdmissionDecision::allow(Some(metadata)))
        } else {
            // A failed release has ambiguous effects. Retrying it could erase
            // a marker reacquired after the callback returned.
            let release_previously_failed = report
                .receipt_metadata
                .get("chio_runtime")
                .and_then(|runtime| runtime.get("reservation_release_failed"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let destructive_lease_id = (!release_previously_failed)
                .then(|| {
                    report
                        .receipt_metadata
                        .get("chio_runtime")
                        .and_then(|runtime| runtime.get("reserved_destructive_lease_id"))
                        .and_then(serde_json::Value::as_str)
                })
                .flatten();
            let reservations = continuation_reservation_metadata(
                &admission_id,
                destructive_lease_id,
                treaty_continuation_id_to_consume.as_deref(),
                swarm_continuation_id_to_consume.as_deref(),
            );
            let metadata = match hook.release_reservations(&reservations) {
                Ok(()) => {
                    strip_released_reservation_metadata(report.receipt_metadata, &reservations)
                }
                Err(failure) => release_failure_metadata(
                    report.receipt_metadata,
                    &failure.reservations,
                    &failure,
                ),
            };
            Ok(KernelRuntimeAdmissionDecision::deny(
                "chio runtime admission denied",
                Some(metadata),
            ))
        }
    }
}
