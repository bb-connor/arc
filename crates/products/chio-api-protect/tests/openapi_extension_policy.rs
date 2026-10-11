use chio_api_protect::{ProtectConfig, ProtectError, ProtectProxy};
use chio_http_core::HttpMethod;
use chio_openapi::PolicyDecision;
use std::{
    error::Error,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

type TestResult = Result<(), Box<dyn Error>>;

fn spec(lines: &str) -> String {
    format!("openapi: 3.1.0\ninfo:\n  title: Protected extensions\n  version: 1.0.0\npaths:\n  /data:\n    get:\n      operationId: readData\n{lines}      responses:\n        '200':\n          description: ok\n")
}

#[test]
fn f069_actual_route_policy_requires_sensitive_restricted_approval() -> TestResult {
    for sensitivity in ["sensitive", "restricted"] {
        let routes = ProtectProxy::routes_from_spec(&spec(&format!(
            "      x-chio-sensitivity: {sensitivity}\n      x-chio-approval-required: false\n      x-chio-side-effects: false\n"
        )))?;
        let route = routes.first().ok_or("missing actual route")?;
        assert_eq!(route.method, HttpMethod::Get);
        assert_eq!(route.policy, PolicyDecision::DenyByDefault);
    }
    Ok(())
}

#[test]
fn f069_actual_route_loader_refuses_invalid_authority_extensions() {
    for lines in [
        "      x-chio-approval-required: 'true'\n",
        "      x-chio-sensitivity: Restricted\n",
        "      x-chio-budget-limit: 5000\n",
        "      x-chio-private-unknown-marker: private-value-marker\n",
    ] {
        assert!(matches!(
            ProtectProxy::routes_from_spec(&spec(lines)),
            Err(ProtectError::SpecParse(_))
        ));
    }
}

#[tokio::test]
async fn f069_invalid_extension_never_activates_issuance_or_proxy_listener() -> TestResult {
    let observed = Arc::new(AtomicBool::new(false));
    let captured = Arc::clone(&observed);
    let config = ProtectConfig {
        transport: Default::default(),
        upstream: "http://127.0.0.1:1".into(),
        spec_content: Some(spec("      x-chio-approval-required: 'true'\n")),
        spec_path: None,
        spec_sha256: None,
        allow_anonymous_reads: true,
        listen_addr: "127.0.0.1:0".into(),
        receipt_db: None,
        allow_ephemeral_receipts: true,
        sidecar_control_token: Some("F069-local-test-control".into()),
        receipt_retention: None,
        signer_seed_file: None,
        signer_seed_hex: None,
        trusted_capability_issuers: Vec::new(),
        approval: None,
        control_url: None,
        control_token: None,
        budget_db: None,
        revocation_db: None,
        require_nonce: true,
        allow_advisory: false,
        upstream_request_timeout: Duration::from_millis(100),
    };
    let result = tokio::time::timeout(
        Duration::from_millis(500),
        ProtectProxy::new(config)
            .run_with_observer(move |_| captured.store(true, Ordering::SeqCst)),
    )
    .await;
    assert!(
        matches!(result, Ok(Err(ProtectError::SpecParse(_)))),
        "invalid extension passed startup validation: {result:?}"
    );
    assert!(
        !observed.load(Ordering::SeqCst),
        "authority/proxy listener activated for rejected spec"
    );
    Ok(())
}
