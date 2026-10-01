use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type RequestMutation = (&'static str, fn(&mut ToolCallRequest));

fn prepared_request() -> (ChioKernel, ToolCallRequest) {
    let (kernel, agent, scope, config) = kernel_with_nonce();
    let capability = make_capability(&kernel, &agent, scope, 300);
    let mut request = make_request("nonce-admission", &capability, "read_file", "srv-a");
    request.execution_nonce = Some(mint_nonce_for_request(
        &kernel,
        &capability,
        &request,
        &config,
    ));
    (kernel, request)
}

fn consumed(kernel: &ChioKernel, request: &ToolCallRequest) -> Result<bool, KernelError> {
    let nonce = request
        .execution_nonce
        .as_ref()
        .ok_or_else(|| KernelError::Internal("test omitted its signed execution nonce".into()))?;
    kernel
        .execution_nonce_store
        .as_ref()
        .ok_or_else(|| KernelError::Internal("test omitted its execution nonce store".into()))?
        .is_consumed(nonce.nonce_id())
}

#[test]
fn nonce_admission_reservation_checks_every_request_binding_before_consumption() -> TestResult {
    let (kernel, request) = prepared_request();
    let mutations: [RequestMutation; 6] = [
        ("subject_id", |request| {
            request.capability.subject = make_keypair().public_key()
        }),
        ("capability_id", |request| {
            request.capability.id.push_str("-changed")
        }),
        ("request_id", |request| {
            request.request_id.push_str("-changed")
        }),
        ("tool_server", |request| {
            request.server_id.push_str("-changed")
        }),
        ("tool_name", |request| {
            request.tool_name.push_str("-changed")
        }),
        ("parameter_hash", |request| {
            request.arguments = serde_json::json!({"changed": true})
        }),
    ];
    for (field, mutate) in mutations {
        let mut changed = request.clone();
        mutate(&mut changed);
        let error = kernel
            .reserve_presented_execution_nonce(&changed, &changed.capability)
            .expect_err("unvalidated binding reached nonce consumption");
        assert!(error.to_string().contains(field), "{field}: {error}");
        assert!(!consumed(&kernel, &request)?);
    }
    kernel.reserve_presented_execution_nonce(&request, &request.capability)?;
    assert!(consumed(&kernel, &request)?);
    assert!(kernel
        .reserve_presented_execution_nonce(&request, &request.capability)
        .is_err());
    Ok(())
}

#[test]
fn nonce_admission_all_gates_reject_forged_signature_without_consumption() -> TestResult {
    let (kernel, mut request) = prepared_request();
    request
        .execution_nonce
        .as_mut()
        .ok_or("missing signed nonce")?
        .nonce
        .nonce_id
        .push_str("-forged");
    for result in [
        kernel.validate_required_execution_nonce(&request, &request.capability),
        kernel
            .validate_execution_nonce_non_consuming(
                &request,
                &request.capability,
                current_unix_timestamp(),
            )
            .map(|_| ()),
        kernel.require_presented_execution_nonce(&request, &request.capability),
        kernel.reserve_presented_execution_nonce(&request, &request.capability),
    ] {
        let error = result.expect_err("forged signature crossed a nonce gate");
        assert!(
            error.to_string().contains("signature is invalid"),
            "{error}"
        );
        assert!(!consumed(&kernel, &request)?);
    }
    Ok(())
}

#[test]
fn nonce_admission_validation_is_non_consuming_and_debug_is_opaque() -> TestResult {
    let (kernel, request) = prepared_request();
    for _ in 0..2 {
        kernel.validate_required_execution_nonce(&request, &request.capability)?;
        let validated = kernel
            .validate_execution_nonce_non_consuming(
                &request,
                &request.capability,
                current_unix_timestamp(),
            )?
            .ok_or("validation lost the presented nonce")?;
        assert_eq!(format!("{validated:?}"), "ValidatedExecutionNonce { .. }");
        assert!(!consumed(&kernel, &request)?);
    }
    kernel.require_presented_execution_nonce(&request, &request.capability)?;
    assert!(consumed(&kernel, &request)?);
    Ok(())
}

#[test]
fn nonce_admission_strict_reservation_requires_a_presented_nonce() -> TestResult {
    let (mut kernel, mut request) = prepared_request();
    request.execution_nonce = None;
    kernel.reserve_presented_execution_nonce(&request, &request.capability)?;
    let config = ExecutionNonceConfig {
        require_nonce: true,
        ..ExecutionNonceConfig::default()
    };
    kernel.set_execution_nonce_store(
        config.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&config)),
    );
    for result in [
        kernel.validate_required_execution_nonce(&request, &request.capability),
        kernel.require_presented_execution_nonce(&request, &request.capability),
        kernel.reserve_presented_execution_nonce(&request, &request.capability),
    ] {
        let error = result.expect_err("strict reservation accepted missing authority");
        assert!(
            error.to_string().contains("required but not presented"),
            "{error}"
        );
    }
    Ok(())
}

#[test]
fn nonce_admission_reservation_rejects_unsupported_schema_before_consumption() -> TestResult {
    let (kernel, mut request) = prepared_request();
    request
        .execution_nonce
        .as_mut()
        .ok_or("missing signed nonce")?
        .nonce
        .schema = "unsupported".into();
    let error = kernel
        .reserve_presented_execution_nonce(&request, &request.capability)
        .expect_err("unsupported nonce schema reached consumption");
    assert!(error.to_string().contains("unsupported schema"), "{error}");
    assert!(!consumed(&kernel, &request)?);
    Ok(())
}
