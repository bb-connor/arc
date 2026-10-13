#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RuntimeLoopbackScenario {
    pub(crate) run_id: String,
    pub(crate) steps: Vec<RuntimeLoopbackStep>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RuntimeLoopbackStep {
    pub(crate) admission_profile: chio_runtime_core::RuntimeAdmissionProfile,
    pub(crate) admission_bundle: chio_runtime_core::RuntimeAdmissionBundle,
    pub(crate) request: chio_runtime_core::RuntimeRequestBinding,
    #[serde(default)]
    pub(crate) arguments: Option<serde_json::Value>,
}

pub(crate) fn normalize_runtime_loopback_steps(
    scenario: RuntimeLoopbackScenario,
) -> Result<(String, Vec<RuntimeLoopbackStep>), crate::RuntimeLoopbackError> {
    let RuntimeLoopbackScenario { run_id, steps } = scenario;
    if run_id.is_empty() || run_id.trim() != run_id {
        return Err(crate::RuntimeLoopbackError::message(
            "Chio runtime loopback scenario runId must be non-empty and unpadded".to_string(),
        ));
    }
    if steps.is_empty() {
        return Err(crate::RuntimeLoopbackError::message(
            "Chio runtime loopback scenario requires at least one step".to_string(),
        ));
    }
    Ok((run_id, steps))
}

#[cfg(test)]
mod tests {
    use super::{normalize_runtime_loopback_steps, RuntimeLoopbackScenario};

    fn fixed_hash(ch: char) -> String {
        ch.to_string().repeat(64)
    }

    fn runtime_request() -> chio_runtime_core::RuntimeRequestBinding {
        chio_runtime_core::RuntimeRequestBinding {
            request_id: "req-loopback-scenario".to_string(),
            capability_id: "cap-loopback-scenario".to_string(),
            server_id: "server.loopback".to_string(),
            tool_name: "tool.loopback".to_string(),
            tool_args_sha256: fixed_hash('a'),
            origin_kernel_id: None,
            host_kernel_id: "kernel.loopback".to_string(),
        }
    }

    fn runtime_profile() -> chio_runtime_core::RuntimeAdmissionProfile {
        chio_runtime_core::RuntimeAdmissionProfile {
            schema: chio_runtime_core::CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.to_string(),
            profile_id: "profile-loopback-scenario".to_string(),
            local_kernel_id: "kernel.loopback".to_string(),
            verifier_id: "did:chio:verifier".to_string(),
            issued_at_unix_ms: 1_800_000_000_000,
            expires_at_unix_ms: 1_800_003_600_000,
        }
    }

    fn runtime_bundle(
        request: chio_runtime_core::RuntimeRequestBinding,
    ) -> chio_runtime_core::RuntimeAdmissionBundle {
        chio_runtime_core::RuntimeAdmissionBundle {
            schema: chio_runtime_core::CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA.to_string(),
            admission_id: "adm-loopback-scenario".to_string(),
            binding: request,
            workflow_id: "wf-loopback-scenario".to_string(),
            workflow_grant_id: "grant-loopback-scenario".to_string(),
            step_index: 0,
            destructive: false,
            lease_id: None,
            governance_receipt_id: None,
            trust_bundle_sha256: fixed_hash('b'),
            verification_context_sha256: fixed_hash('c'),
        }
    }

    fn scenario_with_run_id(run_id: &str) -> RuntimeLoopbackScenario {
        RuntimeLoopbackScenario {
            run_id: run_id.to_string(),
            steps: Vec::new(),
        }
    }

    #[test]
    fn scenario_run_id_must_be_non_empty_and_unpadded() {
        for run_id in ["", " runtime-loopback-1", "runtime-loopback-1 "] {
            let error = match normalize_runtime_loopback_steps(scenario_with_run_id(run_id)) {
                Ok(_) => panic!("accepted invalid runtime loopback run id"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("runId"), "{error}");
        }
    }

    #[test]
    fn scenario_requires_steps() {
        let error =
            match normalize_runtime_loopback_steps(scenario_with_run_id("runtime-loopback-1")) {
                Ok(_) => panic!("accepted a scenario without steps"),
                Err(error) => error,
            };
        assert_eq!(
            error.to_string(),
            "Chio runtime loopback scenario requires at least one step"
        );
    }

    #[test]
    fn scenario_with_top_level_admission_fields_is_refused() {
        let request = runtime_request();
        let scenario = serde_json::json!({
            "runId": "runtime-loopback-1",
            "admissionProfile": runtime_profile(),
            "admissionBundle": runtime_bundle(request.clone()),
            "request": request,
        });
        let error = match serde_json::from_value::<RuntimeLoopbackScenario>(scenario) {
            Ok(_) => panic!("accepted top-level admission fields"),
            Err(error) => error,
        };
        let message = error.to_string();
        assert!(
            message.starts_with("unknown field `admission")
                && message.contains("expected `runId` or `steps`"),
            "{message}"
        );
    }
}
