//! Actual RequestEvaluator capability parsing and operator event custody.
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const CHILD: &str = "CHIO_API_PROTECT_CAPABILITY_DIAGNOSTIC_CHILD";

fn evaluate_case(node: &str, capability: Option<&str>, signed_input_chain: bool) -> TestResult {
    if std::env::var_os(CHILD).is_none() {
        let child = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", node, "--nocapture"])
            .env(CHILD, "1")
            .output()?;
        assert!(
            child.status.success(),
            "real evaluator failed with {}: {}",
            child.status,
            String::from_utf8_lossy(&child.stderr)
        );
        let diagnostic = String::from_utf8(child.stderr)?;
        let lines: Vec<&str> = diagnostic.lines().collect();
        assert_eq!(
            lines.len(),
            if capability.is_some() { 2 } else { 0 },
            "one event for each actual evaluator entry: {diagnostic}"
        );
        assert!(!diagnostic.contains("private-capability"));
        if let Some(capability) = capability {
            assert!(!diagnostic.contains(capability));
        }
        for line in lines {
            assert!(line.len() < 2048);
            let event: Value = serde_json::from_str(line)?;
            assert_eq!(event["event"], "api_protect_capability_input_error");
            assert!(event["code"]
                .as_str()
                .is_some_and(|code| code.starts_with("urn:chio:error:attest:signed-json-")));
            assert_eq!(event["causes"][0]["class"], "shared_json");
            if signed_input_chain {
                // The signed reader wraps malformed syntax in CanonicalJson(String).
                // That terminal source has no native parser coordinate accessor.
                let code = "urn:chio:error:attest:signed-json-invalid-input";
                assert_eq!(event["code"], code);
                assert_eq!(
                    event["causes"],
                    serde_json::json!([
                        {"class":"shared_json", "code":code},
                        {"class":"original_json", "code":code},
                        {"class":"core_validation"},
                    ])
                );
                assert_eq!(event["truncated"], false);
            }
        }
        return Ok(());
    }
    let signer = Keypair::generate();
    let evaluator = RequestEvaluator::new_ephemeral(
        vec![RouteEntry {
            pattern: "/data".into(),
            method: HttpMethod::Get,
            operation_id: Some("getData".into()),
            policy: PolicyDecision::SessionAllow,
        }],
        signer.clone(),
        "capability-diagnostic-test".into(),
    )
    .with_anonymous_reads(true);
    let mut headers = HashMap::new();
    if let Some(capability) = capability {
        headers.insert("x-chio-capability".into(), capability.to_owned());
    }
    let result =
        evaluator.evaluate(HttpMethod::Get, "/data", &HashMap::new(), &headers, None, 0)?;
    check_result(&result, capability, &signer)?;
    let mut request = ChioHttpRequest::new(
        "normalized-diagnostic-test".into(),
        HttpMethod::Get,
        "/data".into(),
        "/data".into(),
        CallerIdentity::anonymous(),
    );
    request.headers = headers;
    let result = evaluator.evaluate_chio_request(request, None)?;
    check_result(&result, capability, &signer)
}

fn check_result(
    result: &EvaluationResult,
    capability: Option<&str>,
    signer: &Keypair,
) -> TestResult {
    assert_eq!(result.receipt.kernel_key, signer.public_key());
    assert!(result.receipt.verify_signature()?);
    let projection = serde_json::to_string(&(result.verdict.clone(), result.receipt.clone()))?;
    if let Some(capability) = capability {
        assert!(result.execution_nonce.is_none());
        assert!(result.verdict.is_denied());
        assert_eq!(result.receipt.response_status, 403);
        assert!(!projection.contains("private-capability"));
        assert!(!projection.contains(capability));
    } else {
        assert!(result.verdict.is_allowed());
        assert_eq!(result.receipt.response_status, 200);
    }
    Ok(())
}

macro_rules! capability_test {
    ($name:ident, $capability:expr, $signed_input_chain:expr) => {
        #[test]
        fn $name() -> TestResult {
            evaluate_case(
                concat!(
                    "evaluator::capability_diagnostics_tests::",
                    stringify!($name)
                ),
                $capability,
                $signed_input_chain,
            )
        }
    };
}
capability_test!(
    api_capability_operator_malformed_json,
    Some("{\"private-capability-marker\":"),
    true
);
capability_test!(
    api_capability_operator_duplicate_json,
    Some("{\"private-capability-marker\":1,\"private-capability-marker\":2}"),
    false
);
capability_test!(
    api_capability_operator_noncanonical_json,
    Some(" {\"private-capability-marker\":1} "),
    false
);
capability_test!(api_capability_operator_success_control, None, false);
