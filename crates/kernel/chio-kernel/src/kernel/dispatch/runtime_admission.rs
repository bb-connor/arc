//! Runtime admission policy, hook invocation and verified treaty retention.

use super::*;
use crate::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1;

impl ChioKernel {
    /// Read trusted configuration without granting custody. A failed selector
    /// must not become an absent selection and enable a legacy fallback.
    pub(crate) fn configured_runtime_participant_binding(
        &self,
    ) -> Result<Option<&RuntimeParticipantAuthorityBindingV1>, KernelError> {
        let Some(hook) = self.runtime_admission_hook.as_ref() else {
            return Ok(None);
        };
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            hook.runtime_participant_binding()
        }))
        .map_err(|_| {
            KernelError::DurableAdmission(
                "runtime authority selection panicked (fail-closed)".into(),
            )
        })
    }

    pub(crate) fn run_runtime_admission_hook(
        &self,
        request: &ToolCallRequest,
        extra_metadata: Option<&serde_json::Value>,
        now: u64,
        now_unix_ms: u64,
        matched_grant_index: Option<usize>,
        durable_admission: Option<&mut DurableToolAdmission>,
    ) -> RuntimeAdmissionDecision {
        if self.swarm_admission_required {
            if let Some(denial) =
                required_swarm_admission_denial(request, self.runtime_admission_hook.as_deref())
            {
                return denial;
            }
        }
        let Some(hook) = self.runtime_admission_hook.as_ref() else {
            let has_runtime_context = request
                .governed_intent
                .as_ref()
                .and_then(|intent| intent.context.as_ref())
                .is_some_and(|context| {
                    context.get("chioAdmission").is_some()
                        || context.get("chioTreaty").is_some()
                        || context.get("chioSwarm").is_some()
                });
            if has_runtime_context {
                return RuntimeAdmissionDecision::deny(
                    "chio runtime admission hook is required for governed runtime requests",
                    Some(serde_json::json!({
                        "chio_runtime": {
                            "accepted": false,
                            "failure_code": "runtime_admission_hook_missing"
                        }
                    })),
                );
            }
            if request.federated_origin_kernel_id.is_some() {
                return RuntimeAdmissionDecision::deny(
                    "chio treaty-bound runtime admission context missing",
                    Some(serde_json::json!({
                        "chio_runtime": {
                            "accepted": false,
                            "failure_code": "missing_chio_treaty_context"
                        }
                    })),
                );
            }
            return RuntimeAdmissionDecision::allow(None);
        };
        let context = RuntimeAdmissionContext {
            request,
            extra_metadata,
            now_unix_secs: now,
            now_unix_ms,
            matched_grant_index,
            local_kernel_id: self.federation_local_kernel_id(),
        };
        let evaluated = match self.configured_runtime_participant_binding() {
            Ok(Some(binding)) => durable_admission
                .ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "operation-owned runtime hook requires a live durable admission".into(),
                    )
                })
                .and_then(|admission| {
                    self.evaluate_operation_owned_runtime_hook(
                        hook.as_ref(),
                        &context,
                        admission,
                        binding,
                    )
                }),
            Ok(None) => hook.evaluate(&context),
            Err(error) => {
                // Do not call another hook method, including its diagnostic
                // name, after authority selection has already failed.
                return RuntimeAdmissionDecision::deny(
                    error.to_string(),
                    Some(serde_json::json!({
                        "runtime_admission": {
                            "accepted": false,
                            "failure_code": "runtime_admission_hook_error"
                        }
                    })),
                );
            }
        };
        match evaluated {
            Ok(mut decision) => {
                if decision.allowed {
                    match decision.verified_treaty_material.take() {
                        Some(material) => {
                            decision.metadata = merge_metadata_objects(
                                decision.metadata,
                                Some(material.receipt_metadata()),
                            );
                            if let Err(error) = self.install_verified_treaty_material_for_request(
                                &request.request_id,
                                material,
                            ) {
                                return RuntimeAdmissionDecision::deny(
                                    format!(
                                        "verified federation treaty material could not be retained (fail-closed): {error}"
                                    ),
                                    decision.metadata,
                                );
                            }
                        }
                        None if request.federated_origin_kernel_id.is_some() => {
                            let mut metadata = decision.metadata;
                            if let Some(runtime) = metadata
                                .as_mut()
                                .and_then(serde_json::Value::as_object_mut)
                                .and_then(|metadata| metadata.get_mut("chio_runtime"))
                                .and_then(serde_json::Value::as_object_mut)
                            {
                                runtime.remove("federation_treaty_dsse");
                            }
                            return RuntimeAdmissionDecision::deny(
                                "verified federation treaty material missing from allowed runtime admission",
                                metadata,
                            );
                        }
                        None => {}
                    }
                }
                decision
            }
            Err(error) => RuntimeAdmissionDecision::deny(
                format!(
                    "runtime admission hook \"{}\" error (fail-closed): {error}",
                    hook.name()
                ),
                Some(serde_json::json!({
                    "runtime_admission": {
                        "hook": hook.name(),
                        "accepted": false,
                        "failure_code": "runtime_admission_hook_error"
                    }
                })),
            ),
        }
    }
}

fn required_swarm_admission_denial(
    request: &ToolCallRequest,
    hook: Option<&dyn RuntimeAdmissionHook>,
) -> Option<RuntimeAdmissionDecision> {
    let swarm = request
        .governed_intent
        .as_ref()
        .and_then(|intent| intent.context.as_ref())
        .and_then(|context| context.get("chioSwarm"));
    let (code, reason) = match swarm {
        None => ("missing_chio_swarm_context", "kernel policy requires swarm context on every tool call"),
        Some(value) if !value.is_object() => ("invalid_chio_swarm_context", "required swarm context must be an object"),
        Some(_) => match hook {
            None => ("runtime_admission_hook_missing", "kernel policy requires a swarm-verifying runtime admission hook"),
            Some(hook) if !hook.enforces_swarm_authority() || !hook.requires_dispatch_revalidation() => (
                "runtime_admission_swarm_unsupported",
                "runtime admission hook does not enforce swarm authority with dispatch revalidation",
            ),
            Some(_) => return None,
        },
    };
    Some(RuntimeAdmissionDecision::deny(
        reason,
        Some(serde_json::json!({
            "chio_runtime": { "accepted": false, "failure_code": code }
        })),
    ))
}
