//! A single pinned HTTPS issue sink with one physical submission attempt.
use chio_core_types::recovery::{decode_contract, SignedRecoveryProviderFinalityV1};
use chio_egress_contract::{
    client_builder_with_contract, send_with_contract, ContractResponse, HttpEgressContract,
};
use chio_kernel::recovery::{
    RecordName, RecoveryEffectContractV1, RecoveryProviderLookup, RecoveryProviderLookupBudget,
};
use chio_kernel::{
    KernelError, NestedFlowBridge, ToolInvocationContext, ToolInvocationCost, ToolServerConnection,
};
use chio_security_types::recovery::ProtectedText;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

mod submission;

/// Credentials and resource selection belong to the trusted host. Tool inputs
/// carry only the exact reviewed title and body, never credentials or a URL.
#[derive(Clone)]
pub struct PinnedSupportIssueConnector {
    server: String,
    tool: String,
    contract: RecoveryEffectContractV1,
    egress_contract: HttpEgressContract,
    resource: reqwest::Url,
    submit_token: zeroize::Zeroizing<String>,
    lookup_token: zeroize::Zeroizing<String>,
    client: reqwest::Client,
    capacity: Arc<Semaphore>,
    lookup_capacity: Arc<Semaphore>,
    request_timeout: Duration,
}

/// Local readiness has no provider authority. Its owned slot remains live
/// while the native owner selects and consumes one original-only observation.
pub(super) struct PreparedProviderObservation<'a> {
    connector: &'a PinnedSupportIssueConnector,
    _permit: OwnedSemaphorePermit,
    expires_at_unix_ms: u64,
    budget: RecoveryProviderLookupBudget,
}
impl PreparedProviderObservation<'_> {
    pub(super) const fn request_budget(&self) -> RecoveryProviderLookupBudget {
        self.budget
    }
    pub(super) async fn observe(
        self,
        lookup: RecoveryProviderLookup,
    ) -> Result<SignedRecoveryProviderFinalityV1, KernelError> {
        if lookup
            .request_budget()
            .is_some_and(|budget| budget != self.budget)
        {
            return Err(refused());
        }
        let PreparedProviderObservation {
            connector,
            _permit,
            expires_at_unix_ms,
            ..
        } = self;
        let deadline = expires_at_unix_ms.min(lookup.expires_at_unix_ms());
        let result = connector.observe_reserved(lookup, deadline).await;
        drop(_permit);
        result
    }
}
impl core::fmt::Debug for PinnedSupportIssueConnector {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PinnedSupportIssueConnector([redacted])")
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueCreated {
    outcome: IssueSucceeded,
    issue_reference: ProtectedText<2048>,
}
#[derive(Serialize, Deserialize)]
enum IssueSucceeded {
    #[serde(rename = "succeeded")]
    Succeeded,
}
fn refused() -> KernelError {
    KernelError::Internal("pinned recovery connector refused or unavailable".into())
}
impl PinnedSupportIssueConnector {
    pub fn new(
        server: String,
        tool: String,
        contract: RecoveryEffectContractV1,
        mut egress_contract: HttpEgressContract,
        submit_token: String,
        lookup_token: String,
    ) -> Result<Self, KernelError> {
        let resource = reqwest::Url::parse(contract.resource.as_str()).map_err(|_| refused())?;
        if resource.scheme() != "https"
            || resource.as_str() != contract.resource.as_str()
            || resource.host_str().is_none()
            || !resource.username().is_empty()
            || resource.password().is_some()
            || resource.fragment().is_some()
            || resource.query().is_some()
            || resource.path().ends_with('/')
            || submit_token.is_empty()
            || lookup_token.is_empty()
            || submit_token.len() > 4096
            || lookup_token.len() > 4096
            || !(1..=65536).contains(&contract.max_response_bytes.get())
            || RecordName::new(&server).is_err()
            || RecordName::new(&tool).is_err()
            || reqwest::header::HeaderValue::from_str(&format!("Bearer {submit_token}")).is_err()
            || reqwest::header::HeaderValue::from_str(&format!("Bearer {lookup_token}")).is_err()
        {
            return Err(refused());
        }
        egress_contract
            .validate_dispatchable_with_pinned_dns()
            .and_then(|()| {
                egress_contract
                    .enforce_url(resource.as_str(), 0)
                    .map(|_| ())
            })
            .map_err(|_| refused())?;
        egress_contract.max_redirect_chain = 0;
        egress_contract.max_response_bytes = egress_contract
            .max_response_bytes
            .min(contract.max_response_bytes.get());
        let client = client_builder_with_contract(&egress_contract)
            .https_only(true)
            .no_retries()
            .connect_timeout(Duration::from_secs(5))
            .timeout(REQUEST_TIMEOUT)
            .pool_max_idle_per_host(4)
            .build()
            .map_err(|_| refused())?;
        Ok(Self {
            server,
            tool,
            contract,
            egress_contract,
            resource,
            submit_token: zeroize::Zeroizing::new(submit_token),
            lookup_token: zeroize::Zeroizing::new(lookup_token),
            client,
            capacity: Arc::new(Semaphore::new(4)),
            lookup_capacity: Arc::new(Semaphore::new(4)),
            request_timeout: REQUEST_TIMEOUT,
        })
    }
    pub(super) fn prepare_observation(
        &self,
        expires_at_unix_ms: u64,
    ) -> Result<PreparedProviderObservation<'_>, KernelError> {
        let now = super::materialize::now().map_err(|_| refused())?;
        let budget = RecoveryProviderLookupBudget::from_duration(self.request_timeout)?;
        let required = budget.request_millis();
        if expires_at_unix_ms
            .checked_sub(now)
            .is_none_or(|remaining| remaining < required)
        {
            return Err(refused());
        }
        let permit = self
            .lookup_capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| refused())?;
        Ok(PreparedProviderObservation {
            connector: self,
            _permit: permit,
            expires_at_unix_ms,
            budget,
        })
    }
    fn submit_request(
        &self,
        operation: &str,
        attempt: &str,
        wire: Vec<u8>,
    ) -> Result<reqwest::Request, KernelError> {
        self.client
            .post(self.resource.clone())
            .bearer_auth(self.submit_token.as_str())
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header("idempotency-key", operation)
            .header("chio-attempt-id", attempt)
            .body(wire)
            .build()
            .map_err(|_| refused())
    }
    async fn dispatch(&self, request: reqwest::Request) -> Result<ContractResponse, KernelError> {
        let response = send_with_contract(&self.egress_contract, &self.client, request)
            .await
            .map_err(|_| refused())?;
        if !response.status().is_success() {
            return Err(refused());
        }
        Ok(response)
    }
    /// Only an affine kernel-selected lookup can use the independent read-only
    /// credential. The original agent's grant and spending budget are irrelevant.
    pub async fn observe_original(
        &self,
        lookup: RecoveryProviderLookup,
    ) -> Result<SignedRecoveryProviderFinalityV1, KernelError> {
        self.prepare_observation(lookup.expires_at_unix_ms())?
            .observe(lookup)
            .await
    }
    async fn observe_reserved(
        &self,
        lookup: RecoveryProviderLookup,
        expires_at_unix_ms: u64,
    ) -> Result<SignedRecoveryProviderFinalityV1, KernelError> {
        let captured = &lookup.captured_deployment().effect_contract;
        let current = &lookup.deployment().effect_contract;
        if self.contract.provider != captured.provider
            || self.contract.account != captured.account
            || self.contract.resource != captured.resource
            || self.contract.observation_key != current.observation_key
            || self.contract.max_response_bytes.get()
                > captured
                    .max_response_bytes
                    .get()
                    .min(current.max_response_bytes.get())
            || lookup.workflow().provider_lookups.get() == 0
            || super::materialize::now().map_err(|_| refused())? >= expires_at_unix_ms
        {
            return Err(refused());
        }
        let intent = lookup.workflow().admission.as_ref().ok_or_else(refused)?;
        let mut url = self.resource.clone();
        url.path_segments_mut()
            .map_err(|_| refused())?
            .push("operations")
            .push(intent.native_operation_id.as_str());
        let request = self
            .client
            .get(url)
            .bearer_auth(self.lookup_token.as_str())
            .header("accept", "application/json")
            .build()
            .map_err(|_| refused())?;
        let remaining = expires_at_unix_ms
            .checked_sub(super::materialize::now().map_err(|_| refused())?)
            .filter(|remaining| *remaining != 0)
            .ok_or_else(refused)?;
        let response = tokio::time::timeout(
            self.request_timeout.min(Duration::from_millis(remaining)),
            self.dispatch(request),
        )
        .await
        .map_err(|_| refused())??;
        if super::materialize::now().map_err(|_| refused())? >= expires_at_unix_ms {
            return Err(refused());
        }
        // Canonical closed provider evidence is verified by the native authority
        // after the await, against current assignment, fence and exact operation.
        decode_contract(response.body()).map_err(|_| refused())
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for PinnedSupportIssueConnector {
    fn recovery_effect_contract(&self) -> Option<RecoveryEffectContractV1> {
        Some(self.contract.clone())
    }
    fn server_id(&self) -> &str {
        &self.server
    }
    fn tool_names(&self) -> Vec<String> {
        vec![self.tool.clone()]
    }
    async fn invoke(
        &self,
        _: &str,
        _: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Err(refused())
    }
    async fn prepare_invocation_connection(
        &self,
        context: &chio_kernel::ToolDispatchContext,
    ) -> Result<Option<Arc<dyn ToolServerConnection>>, KernelError> {
        submission::prepare(self, context).map(Some)
    }

    async fn invoke_with_context(
        &self,
        _: &ToolInvocationContext,
        _: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        // Only the invocation-owned prepared connection can submit. An
        // unprepared factory must not acquire workload capacity after capture.
        Err(refused())
    }
    async fn invoke_with_cost_and_context(
        &self,
        _: &ToolInvocationContext,
        _: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(Value, Option<ToolInvocationCost>), KernelError> {
        Err(refused())
    }
}

#[cfg(test)]
pub(super) mod capacity_test_support {
    use super::*;
    use tokio::sync::{OwnedSemaphorePermit, TryAcquireError};

    pub(in crate::recovery) fn hold_submission_capacity(
        connector: &PinnedSupportIssueConnector,
    ) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        connector.capacity.clone().try_acquire_many_owned(4)
    }

    pub(in crate::recovery) fn hold_lookup_capacity(
        connector: &PinnedSupportIssueConnector,
    ) -> Result<OwnedSemaphorePermit, TryAcquireError> {
        connector.lookup_capacity.clone().try_acquire_many_owned(4)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    fn egress(resource: &str) -> Result<HttpEgressContract> {
        let url = reqwest::Url::parse(resource)?;
        Ok(HttpEgressContract {
            tenant_egress_namespace: "tests.recovery.issues".to_owned(),
            allowed_schemes: std::collections::BTreeSet::from(["https".to_owned()]),
            allowed_authority_set: std::collections::BTreeSet::from([url
                .host_str()
                .ok_or("host")?
                .to_owned()]),
            deny_loopback: true,
            deny_link_local: true,
            deny_ipv6_ula: true,
            max_redirect_chain: 0,
            max_response_bytes: 65536,
        })
    }
    fn contract(resource: &str) -> Result<RecoveryEffectContractV1> {
        use chio_security_types::recovery::*;
        Ok(RecoveryEffectContractV1 {
            schema: chio_kernel::recovery::RecoveryEffectContractSchema::V1,
            provider: RecoveryEffectProviderId::new("test-provider")?,
            account: RecoveryEffectAccountId::new("test-account")?,
            resource: ProtectedText::new(resource)?,
            observation_key: chio_core_types::Keypair::from_seed(&[150; 32]).public_key(),
            max_response_bytes: SafeInteger::new(65536)?,
        })
    }
    #[test]
    fn pinned_connector_request_keeps_credentials_and_native_correlation_out_of_input() -> Result {
        let connector = PinnedSupportIssueConnector::new(
            "issues".into(),
            "create".into(),
            contract("https://provider.example/issues")?,
            egress("https://provider.example/issues")?,
            "submit-canary".into(),
            "lookup-canary".into(),
        )?;
        let wire = br#"{"body":"private-canary","title":"support"}"#.to_vec();
        let request =
            connector.submit_request("original-operation", "original-attempt", wire.clone())?;
        assert_eq!(request.method(), reqwest::Method::POST);
        assert_eq!(request.url().as_str(), "https://provider.example/issues");
        assert_eq!(request.headers()["idempotency-key"], "original-operation");
        assert_eq!(request.headers()["chio-attempt-id"], "original-attempt");
        assert_eq!(request.headers()["authorization"], "Bearer submit-canary");
        assert!(request.headers()["authorization"].is_sensitive());
        assert_eq!(
            request.body().and_then(reqwest::Body::as_bytes),
            Some(wire.as_slice())
        );
        assert!(!format!("{connector:?}").contains("canary"));
        assert!(decode_contract::<IssueCreated>(
            br#"{"issue_reference":"issue-1","outcome":"succeeded"}"#
        )
        .is_ok());
        for bytes in [
            br#"{"outcome":"unknown"}"#.as_slice(),
            br#"{"outcome":"failed_before_effect"}"#,
            br#"{"issue_reference":"issue-1","outcome":"succeeded","retry":true}"#,
            br#"{"issue_reference":null,"outcome":"succeeded"}"#,
        ] {
            assert!(decode_contract::<IssueCreated>(bytes).is_err());
        }
        Ok(())
    }
    #[tokio::test]
    async fn pinned_connector_refuses_unscoped_execution_and_unsafe_configuration() -> Result {
        for resource in [
            "http://provider.example/issues",
            "https://token@provider.example/issues",
            "https://provider.example/issues?auth=canary",
            "https://provider.example/issues#fragment",
            "https://provider.example/issues/",
            "https://PROVIDER.example/issues",
            "https://provider.example/base/../issues",
        ] {
            assert!(PinnedSupportIssueConnector::new(
                "issues".into(),
                "create".into(),
                contract(resource)?,
                egress(resource)?,
                "submit".into(),
                "lookup".into()
            )
            .is_err());
        }
        assert!(PinnedSupportIssueConnector::new(
            "issues".into(),
            "create".into(),
            contract("https://provider.example/issues")?,
            egress("https://provider.example/issues")?,
            "header\r\ncanary".into(),
            "lookup".into()
        )
        .is_err());
        let connector = PinnedSupportIssueConnector::new(
            "issues".into(),
            "create".into(),
            contract("https://provider.example/issues")?,
            egress("https://provider.example/issues")?,
            "submit".into(),
            "lookup".into(),
        )?;
        let error = connector
            .invoke(
                "create",
                serde_json::json!({"title":"canary","body":"canary"}),
                None,
            )
            .await
            .err()
            .ok_or("bare invoke accepted")?;
        assert!(!error.to_string().contains("canary"));
        Ok(())
    }
}
