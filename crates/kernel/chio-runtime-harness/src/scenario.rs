#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RuntimeLoopbackScenario {
    pub(crate) run_id: String,
    #[serde(default)]
    pub(crate) admission_profile: Option<chio_runtime_core::RuntimeAdmissionProfile>,
    #[serde(default)]
    pub(crate) admission_bundle: Option<chio_runtime_core::RuntimeAdmissionBundle>,
    #[serde(default)]
    pub(crate) request: Option<chio_runtime_core::RuntimeRequestBinding>,
    #[serde(default)]
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
    let RuntimeLoopbackScenario {
        run_id,
        admission_profile,
        admission_bundle,
        request,
        steps,
    } = scenario;
    if run_id.is_empty() || run_id.trim() != run_id {
        return Err(crate::RuntimeLoopbackError::message(
            "Chio runtime loopback scenario runId must be non-empty and unpadded".to_string(),
        ));
    }
    let steps = if steps.is_empty() {
        let admission_profile = admission_profile.ok_or_else(|| {
            crate::RuntimeLoopbackError::message(
                "Chio runtime loopback scenario missing admissionProfile".to_string(),
            )
        })?;
        let admission_bundle = admission_bundle.ok_or_else(|| {
            crate::RuntimeLoopbackError::message(
                "Chio runtime loopback scenario missing admissionBundle".to_string(),
            )
        })?;
        let request = request.ok_or_else(|| {
            crate::RuntimeLoopbackError::message(
                "Chio runtime loopback scenario missing request".to_string(),
            )
        })?;
        vec![RuntimeLoopbackStep {
            admission_profile,
            admission_bundle,
            request,
            arguments: None,
        }]
    } else {
        if admission_profile.is_some() || admission_bundle.is_some() || request.is_some() {
            return Err(crate::RuntimeLoopbackError::message(
                "Chio runtime loopback scenario cannot mix top-level admission fields with steps"
                    .to_string(),
            ));
        }
        steps
    };
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

    fn runtime_step() -> super::RuntimeLoopbackStep {
        let request = runtime_request();
        super::RuntimeLoopbackStep {
            admission_profile: runtime_profile(),
            admission_bundle: runtime_bundle(request.clone()),
            request,
            arguments: None,
        }
    }

    fn scenario_with_run_id(run_id: &str) -> RuntimeLoopbackScenario {
        RuntimeLoopbackScenario {
            run_id: run_id.to_string(),
            admission_profile: None,
            admission_bundle: None,
            request: None,
            steps: Vec::new(),
        }
    }

    fn runtime_scenario_value() -> Result<serde_json::Value, serde_json::Error> {
        let request = runtime_request();
        let admission_profile = serde_json::to_value(runtime_profile())?;
        let admission_bundle = serde_json::to_value(runtime_bundle(request.clone()))?;
        let request = serde_json::to_value(request)?;

        Ok(serde_json::json!({
            "runId": "runtime-loopback-1",
            "steps": [{
                "admissionProfile": admission_profile,
                "admissionBundle": admission_bundle,
                "request": request
            }]
        }))
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
    fn scenario_rejects_mixed_legacy_fields_and_steps() {
        let scenario = RuntimeLoopbackScenario {
            run_id: "runtime-loopback-1".to_string(),
            admission_profile: Some(runtime_profile()),
            admission_bundle: None,
            request: None,
            steps: vec![runtime_step()],
        };

        let error = match normalize_runtime_loopback_steps(scenario) {
            Ok(_) => panic!("accepted mixed top-level fields and step list"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("cannot mix top-level admission fields with steps"),
            "{error}"
        );
    }

    #[test]
    fn scenario_step_and_request_reject_manifest_security_authority_fields(
    ) -> Result<(), serde_json::Error> {
        for field in ["flowV1", "toolManifest", "chio_manifest_security_v1"] {
            for (layer, pointer) in [
                ("scenario", ""),
                ("step", "/steps/0"),
                ("request", "/steps/0/request"),
            ] {
                let mut value = runtime_scenario_value()?;
                let target = match pointer {
                    "" => value.as_object_mut(),
                    _ => value
                        .pointer_mut(pointer)
                        .and_then(serde_json::Value::as_object_mut),
                };
                let target = match target {
                    Some(target) => target,
                    None => panic!("runtime loopback {layer} test fixture is not an object"),
                };
                target.insert(
                    field.to_string(),
                    serde_json::json!({ "callerAsserted": true }),
                );

                let error = match serde_json::from_value::<RuntimeLoopbackScenario>(value) {
                    Ok(_) => {
                        panic!("accepted authoritative manifest security field {field} on {layer}")
                    }
                    Err(error) => error,
                };
                let message = error.to_string();
                assert!(
                    message.contains("unknown field"),
                    "{layer} {field}: {message}"
                );
                assert!(message.contains(field), "{layer} {field}: {message}");
            }
        }
        Ok(())
    }

    #[test]
    fn arguments_preserve_manifest_security_shaped_json_as_tool_data(
    ) -> Result<(), serde_json::Error> {
        let arguments = serde_json::json!({
            "flowV1": { "egress": true },
            "toolManifest": { "serverId": "caller.asserted" },
            "chio_manifest_security_v1": { "manifest_digest": "caller-asserted" }
        });
        let mut value = runtime_scenario_value()?;
        let step = match value
            .pointer_mut("/steps/0")
            .and_then(serde_json::Value::as_object_mut)
        {
            Some(step) => step,
            None => panic!("runtime loopback step test fixture is not an object"),
        };
        step.insert("arguments".to_string(), arguments.clone());

        let scenario = serde_json::from_value::<RuntimeLoopbackScenario>(value)?;
        assert_eq!(
            scenario
                .steps
                .first()
                .and_then(|step| step.arguments.as_ref()),
            Some(&arguments)
        );
        Ok(())
    }
}
