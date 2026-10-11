//! Real auth-router failures and the nonexposed lifecycle producer's HTTP projection.
use super::*;
use async_trait::async_trait;
use chio_finding_market_port::{
    HostedApiKeyRecord, HostedAuthPort, HostedCapabilityAdmission,
    HostedCapabilityAdmissionOutcome, HostedMarketPortError, HostedPortWriteOutcome,
    HostedPrincipal, HostedTenantId,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tower::ServiceExt as _;

use crate::{
    ApiKeyPepper, HostedApiKeyIssueRequest, HostedApiKeyLifecycleRepository, HostedApiKeyManager,
    HostedApiKeySecret, HostedAuthMethod, HostedAuthenticatorConfig, HostedTenantAuthPolicy,
    StaticApiKeyPepper,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
const CHILD: &str = "CHIO_HOSTED_DURABLE_CLASSIFICATION_CHILD";
const MARKER: &str = "private-durable-field";

fn corrupt_source(
) -> Result<chio_core_types::canonical::SharedUntrustedJsonError, Box<dyn std::error::Error>> {
    crate::input::decode::<serde_json::Value>(
        br#"{"private-durable-field":1,"private-durable-field":2}"#,
        1024,
    )
    .err()
    .ok_or_else(|| "duplicate fixture unexpectedly accepted".into())
}

fn run_child(node: &str, code: &str, status: u16, retryable: bool, cause: bool) -> TestResult {
    let child = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", node, "--nocapture"])
        .env(CHILD, "1")
        .output()?;
    assert!(
        child.status.success(),
        "producer failed with {}: {}",
        child.status,
        String::from_utf8_lossy(&child.stderr)
    );
    let stderr = String::from_utf8(child.stderr)?;
    assert_eq!(
        stderr.lines().count(),
        1,
        "one failed conversion must emit one event: {stderr}"
    );
    assert!(stderr.len() <= 2048);
    assert!(!stderr.contains("private-"));
    let record: serde_json::Value = serde_json::from_str(stderr.trim())?;
    assert_eq!(record["event"], "hosted_request_error");
    assert_eq!(record["code"], code);
    assert_eq!(record["status"], status);
    assert_eq!(record["retryable"], retryable);
    if cause {
        assert_eq!(record["causes"][0]["class"], "shared_json");
        assert!(record["causes"][0]["code"]
            .as_str()
            .is_some_and(|code| code.starts_with("urn:chio:error:")));
    }
    Ok(())
}

async fn check_response(
    response: Response,
    status: u16,
    code: &str,
    retryable: bool,
) -> TestResult {
    assert_eq!(response.status().as_u16(), status);
    let bytes = to_bytes(response.into_body(), 4096).await?;
    assert!(!String::from_utf8_lossy(&bytes).contains("private-"));
    let body: serde_json::Value = serde_json::from_slice(&bytes)?;
    assert_eq!(body["code"], code);
    assert_eq!(body["retryable"], retryable);
    assert_eq!(body.as_object().ok_or("non-object error")?.len(), 5);
    Ok(())
}

#[derive(Clone, Copy)]
enum Lookup {
    Key,
    Principal,
}

struct FailingAuthRepository {
    stage: Lookup,
    failure: HostedMarketPortError,
    key: HostedApiKeyRecord,
    key_reads: AtomicUsize,
    principal_reads: AtomicUsize,
}

#[async_trait]
impl HostedAuthPort for FailingAuthRepository {
    async fn principal_by_capability_key(
        &self,
        _: &HostedTenantId,
        _: &str,
        _: u64,
    ) -> Result<Option<HostedPrincipal>, HostedMarketPortError> {
        Err(self.failure.clone())
    }
    async fn principal(
        &self,
        _: &HostedTenantId,
        _: &str,
    ) -> Result<Option<HostedPrincipal>, HostedMarketPortError> {
        self.principal_reads.fetch_add(1, Ordering::SeqCst);
        Err(self.failure.clone())
    }
    async fn active_api_key(
        &self,
        _: &HostedTenantId,
        _: &str,
        _: u64,
    ) -> Result<Option<HostedApiKeyRecord>, HostedMarketPortError> {
        self.key_reads.fetch_add(1, Ordering::SeqCst);
        match self.stage {
            Lookup::Key => Err(self.failure.clone()),
            Lookup::Principal => Ok(Some(self.key.clone())),
        }
    }
    async fn consume_capability_dpop_admission(
        &self,
        _: &HostedTenantId,
        _: &HostedCapabilityAdmission<'_>,
    ) -> Result<HostedCapabilityAdmissionOutcome, HostedMarketPortError> {
        Err(self.failure.clone())
    }
}

async fn auth_case(
    node: &str,
    stage: Lookup,
    failure: HostedMarketPortError,
    status: u16,
    code: &str,
    retryable: bool,
    malformed: bool,
) -> TestResult {
    let source = match &failure {
        HostedMarketPortError::CorruptInput(source)
        | HostedMarketPortError::InvalidInput(source)
            if !malformed =>
        {
            Some(source.clone())
        }
        _ => None,
    };
    if std::env::var_os(CHILD).is_none() {
        return run_child(node, code, status, retryable, source.is_some());
    }
    let tenant = HostedTenantId::new("tenant:test")?;
    let pepper = Arc::new(StaticApiKeyPepper::new(vec![9; 32])?);
    let repository = Arc::new(FailingAuthRepository {
        stage,
        failure,
        key: HostedApiKeyRecord {
            tenant_id: tenant.clone(),
            key_id: "key-test".into(),
            principal_id: "buyer-test".into(),
            verifier_sha256: pepper.hmac_verifier(&tenant, "key-test", &[0; 32])?,
            allowed_actions: ["finding.read".into()].into_iter().collect(),
            active_from: 1,
            expires_at: u64::MAX,
            revoked_at: None,
            rotated_from_key_id: None,
            created_at: 1,
        },
        key_reads: AtomicUsize::new(0),
        principal_reads: AtomicUsize::new(0),
    });
    let mut state = super::tests::server_state()?;
    let authenticator = Arc::new(HostedAuthenticator::new(
        HostedAuthenticatorConfig {
            deployment_id: "deployment:test".into(),
            public_endpoint: "https://market.example".into(),
            capability_authorities: vec![state.config.kernel_receipt_key.clone()],
            maximum_capability_ttl_secs: 300,
            dpop_proof_ttl_secs: 30,
            dpop_clock_skew_secs: 5,
            dpop_nonce_capacity_per_tenant: 1000,
            tenant_policies: vec![HostedTenantAuthPolicy {
                tenant_id: tenant.clone(),
                allowed_methods: [HostedAuthMethod::ApiKey].into_iter().collect(),
            }],
        },
        repository.clone(),
        pepper,
    )?);
    let secret = if malformed {
        "private-credential-token".into()
    } else {
        URL_SAFE_NO_PAD.encode([0; 32])
    };
    let error = authenticator
        .authenticate(HostedAuthRequest {
            tenant_id: tenant,
            action: "finding.read".into(),
            method: "GET".into(),
            canonical_target: "https://market.example/v1/findings/finding-1".into(),
            body_sha256: sha256_hex(&[]),
            idempotency_key: None,
            required_role: HostedPrincipalRole::Buyer,
            credential: HostedAuthCredential::ApiKey {
                key_id: "key-test".into(),
                secret: secret.clone(),
            },
            now_unix_secs: 1_700_000_000,
        })
        .await
        .err()
        .ok_or("corrupt repository authenticated")?;
    if let Some(source) = source {
        let retained = std::error::Error::source(&error)
            .and_then(|source| {
                source.downcast_ref::<chio_core_types::canonical::SharedUntrustedJsonError>()
            })
            .ok_or("typed cause lost")?;
        assert_eq!(retained, &source);
        assert!(!format!("{error} {error:?}").contains(MARKER));
    }
    state.authenticator = authenticator;
    let response = hosted_market_router(state)
        .oneshot(super::tests::proxied_request(
            Request::builder()
                .uri("/v1/findings/finding-1")
                .header(HOSTED_TENANT_HEADER, "tenant:test")
                .header(REQUEST_ID_HEADER, "classification-test")
                .header(API_KEY_ID_HEADER, "key-test")
                .header(API_KEY_SECRET_HEADER, secret),
            Body::empty(),
        ))
        .await?;
    assert_eq!(
        repository.key_reads.load(Ordering::SeqCst),
        if malformed { 0 } else { 2 }
    );
    assert_eq!(
        repository.principal_reads.load(Ordering::SeqCst),
        if !malformed && matches!(stage, Lookup::Principal) {
            2
        } else {
            0
        }
    );
    check_response(response, status, code, retryable).await
}

macro_rules! auth_test {
    ($name:ident, $stage:expr, $failure:expr, $status:expr, $code:expr, $retryable:expr) => {
        #[tokio::test]
        async fn $name() -> TestResult {
            auth_case(
                concat!("server::durable_classification_tests::", stringify!($name)),
                $stage,
                $failure,
                $status,
                $code,
                $retryable,
                false,
            )
            .await
        }
    };
}
auth_test!(
    hosted_durable_classification_key_corruption,
    Lookup::Key,
    HostedMarketPortError::CorruptInput(corrupt_source()?),
    503,
    "integrity_failure",
    false
);
auth_test!(
    hosted_durable_classification_principal_corruption,
    Lookup::Principal,
    HostedMarketPortError::CorruptInput(corrupt_source()?),
    503,
    "integrity_failure",
    false
);
auth_test!(
    hosted_durable_classification_key_integrity,
    Lookup::Key,
    HostedMarketPortError::Integrity,
    503,
    "integrity_failure",
    false
);
auth_test!(
    hosted_durable_classification_principal_integrity,
    Lookup::Principal,
    HostedMarketPortError::Integrity,
    503,
    "integrity_failure",
    false
);
auth_test!(
    hosted_durable_classification_key_lease_loss,
    Lookup::Key,
    HostedMarketPortError::LeaseLost,
    503,
    "authentication_dependency_unavailable",
    true
);
auth_test!(
    hosted_durable_classification_key_retention_hold,
    Lookup::Key,
    HostedMarketPortError::RetentionHeld,
    503,
    "authentication_dependency_unavailable",
    true
);
auth_test!(
    hosted_durable_classification_invalid_credential_control,
    Lookup::Key,
    HostedMarketPortError::InvalidInput(corrupt_source()?),
    401,
    "authentication_failed",
    false
);

struct FailingLifecycleRepository {
    failure: HostedMarketPortError,
    calls: AtomicUsize,
}
#[async_trait]
impl HostedApiKeyLifecycleRepository for FailingLifecycleRepository {
    async fn issue_with_event(
        &self,
        _: &HostedTenantId,
        _: &str,
        _: &str,
        _: &str,
        _: &BTreeSet<String>,
        _: u64,
        _: u64,
        _: Option<&str>,
        _: &str,
        _: &[u8],
        _: u64,
    ) -> Result<HostedPortWriteOutcome, HostedMarketPortError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(self.failure.clone())
    }
    async fn revoke_with_event(
        &self,
        _: &HostedTenantId,
        _: &str,
        _: u64,
        _: &str,
        _: &[u8],
    ) -> Result<HostedPortWriteOutcome, HostedMarketPortError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(self.failure.clone())
    }
}

async fn lifecycle_case(
    node: &str,
    revoke: bool,
    failure: HostedMarketPortError,
    status: u16,
    code: &str,
    retryable: bool,
    malformed: bool,
) -> TestResult {
    let source = match &failure {
        HostedMarketPortError::CorruptInput(source)
        | HostedMarketPortError::InvalidInput(source)
            if !malformed =>
        {
            Some(source.clone())
        }
        _ => None,
    };
    if std::env::var_os(CHILD).is_none() {
        return run_child(node, code, status, retryable, source.is_some());
    }
    let repository = Arc::new(FailingLifecycleRepository {
        failure,
        calls: AtomicUsize::new(0),
    });
    let manager = HostedApiKeyManager::new(
        repository.clone(),
        Arc::new(StaticApiKeyPepper::new(vec![9; 32])?),
        Arc::new(chio_core_types::Ed25519Backend::generate()),
    )?;
    let tenant = HostedTenantId::new("tenant:test")?;
    let error = if revoke {
        manager
            .revoke(
                tenant,
                if malformed {
                    "".into()
                } else {
                    "key-test".into()
                },
                100,
            )
            .await
            .err()
    } else {
        manager
            .issue(HostedApiKeyIssueRequest {
                tenant_id: tenant,
                key_id: if malformed {
                    "".into()
                } else {
                    "key-test".into()
                },
                principal_id: "buyer-test".into(),
                allowed_actions: ["finding.read".into()].into_iter().collect(),
                active_from: 101,
                expires_at: 1000,
                rotated_from_key_id: None,
                issued_at: 100,
                secret: HostedApiKeySecret::generate(),
            })
            .await
            .err()
    }
    .ok_or("failing repository produced lifecycle success")?;
    assert_eq!(
        repository.calls.load(Ordering::SeqCst),
        if malformed { 0 } else { 1 }
    );
    if let Some(source) = source {
        let retained = std::error::Error::source(&error)
            .and_then(|source| {
                source.downcast_ref::<chio_core_types::canonical::SharedUntrustedJsonError>()
            })
            .ok_or("typed lifecycle cause lost")?;
        assert_eq!(retained, &source);
        assert!(!format!("{error} {error:?}").contains(MARKER));
    }
    // No production lifecycle route exists. Qualify the real library producer
    // and the existing HTTP converter without inventing an exposed endpoint.
    check_response(
        error_response(error, "classification-test"),
        status,
        code,
        retryable,
    )
    .await
}
macro_rules! lifecycle_test {
    ($name:ident, $revoke:expr, $failure:expr, $status:expr, $code:expr, $retryable:expr) => {
        #[tokio::test]
        async fn $name() -> TestResult {
            lifecycle_case(
                concat!("server::durable_classification_tests::", stringify!($name)),
                $revoke,
                $failure,
                $status,
                $code,
                $retryable,
                false,
            )
            .await
        }
    };
}
lifecycle_test!(
    hosted_durable_classification_issue_corruption,
    false,
    HostedMarketPortError::CorruptInput(corrupt_source()?),
    503,
    "integrity_failure",
    false
);
lifecycle_test!(
    hosted_durable_classification_revoke_corruption,
    true,
    HostedMarketPortError::CorruptInput(corrupt_source()?),
    503,
    "integrity_failure",
    false
);
lifecycle_test!(
    hosted_durable_classification_issue_integrity,
    false,
    HostedMarketPortError::Integrity,
    503,
    "integrity_failure",
    false
);
lifecycle_test!(
    hosted_durable_classification_issue_conflict,
    false,
    HostedMarketPortError::Conflict,
    409,
    "conflict",
    false
);
lifecycle_test!(
    hosted_durable_classification_issue_lease_loss,
    false,
    HostedMarketPortError::LeaseLost,
    503,
    "authentication_dependency_unavailable",
    true
);
lifecycle_test!(
    hosted_durable_classification_invalid_request_control,
    false,
    HostedMarketPortError::InvalidInput(corrupt_source()?),
    400,
    "invalid_request",
    false
);

#[tokio::test]
async fn hosted_durable_classification_malformed_credential_control() -> TestResult {
    auth_case("server::durable_classification_tests::hosted_durable_classification_malformed_credential_control", Lookup::Key, HostedMarketPortError::CorruptInput(corrupt_source()?), 401, "authentication_failed", false, true).await
}

lifecycle_test!(
    hosted_durable_classification_revoke_not_found,
    true,
    HostedMarketPortError::NotFound,
    404,
    "not_found",
    false
);

#[tokio::test]
async fn hosted_durable_classification_malformed_request_control() -> TestResult {
    lifecycle_case("server::durable_classification_tests::hosted_durable_classification_malformed_request_control", true, HostedMarketPortError::CorruptInput(corrupt_source()?), 400, "invalid_request", false, true).await
}
