use super::transport::canonical_endpoint;
use super::*;
use chio_egress_contract::{HttpEgressContract, client_builder_with_contract, send_with_contract};
use std::time::Duration;

/// One bounded HTTP request. Credentials are selected by trusted host setup,
/// never by tool arguments, package metadata or a recovered plan.
pub struct HttpSemanticTransport {
    destination: SemanticDestinationV1,
    token: zeroize::Zeroizing<String>,
    guarantee: ProviderPreconditionGuaranteeV1,
    client: reqwest::Client,
    egress_contract: HttpEgressContract,
}
impl std::fmt::Debug for HttpSemanticTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HttpSemanticTransport([redacted])")
    }
}
impl HttpSemanticTransport {
    pub fn new(
        destination: SemanticDestinationV1,
        mut egress_contract: HttpEgressContract,
        bearer: String,
        guarantee: ProviderPreconditionGuaranteeV1,
    ) -> Result<Self, KernelError> {
        let bearer = zeroize::Zeroizing::new(bearer);
        canonical_endpoint(destination.endpoint.as_str())?;
        if bearer.is_empty()
            || bearer.len() > 4096
            || bearer.contains(['\r', '\n'])
            || (destination.require_provider_precondition
                && guarantee != ProviderPreconditionGuaranteeV1::AtomicIfMatch)
        {
            return Err(refused());
        }
        egress_contract
            .validate_dispatchable_with_pinned_dns()
            .and_then(|()| {
                egress_contract
                    .enforce_url(destination.endpoint.as_str(), 0)
                    .map(|_| ())
            })
            .map_err(|_| refused())?;
        egress_contract.max_redirect_chain = 0;
        egress_contract.max_response_bytes = egress_contract
            .max_response_bytes
            .min(MAX_RECOVERY_WIRE_BYTES as u64);
        let client = client_builder_with_contract(&egress_contract)
            .https_only(true)
            .no_retries()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(3))
            .build()
            .map_err(|_| refused())?;
        Ok(Self {
            destination,
            token: bearer,
            guarantee,
            client,
            egress_contract,
        })
    }
}
impl HttpSemanticTransport {
    fn build_request(
        &self,
        request: &SemanticTransportRequestV1,
    ) -> Result<reqwest::Request, KernelError> {
        if request.destination != self.destination
            || request.kind == SemanticOperationKindV1::FieldProjection
        {
            return Err(refused());
        }
        let url = canonical_endpoint(self.destination.endpoint.as_str())?;
        let mut wire = self
            .client
            .request(
                match request.kind {
                    SemanticOperationKindV1::SupportRead => reqwest::Method::GET,
                    SemanticOperationKindV1::IssueWrite => reqwest::Method::POST,
                    SemanticOperationKindV1::FieldProjection => return Err(refused()),
                },
                url,
            )
            .bearer_auth(self.token.as_str())
            .header("accept", "application/json")
            .header("content-type", "application/json")
            .header("x-chio-operation-id", request.operation.as_str())
            .header("x-chio-attempt-id", request.attempt.as_str());
        if self.guarantee == ProviderPreconditionGuaranteeV1::AtomicIfMatch {
            let etag = request.provider_version.as_str();
            chio_semantic_contracts::validate_semantic_provider_version(etag)
                .map_err(|_| refused())?;
            wire = wire.header("if-match", etag);
        }
        let payload = chio_core_types::canonical_json_bytes(&SemanticProviderRequestV1 {
            domain_version: VersionV1,
            kind: request.kind,
            provider: self.destination.provider.clone(),
            account: self.destination.account.clone(),
            resource: self.destination.resource.clone(),
            provider_version: request.provider_version.clone(),
            operation: request.operation.clone(),
            attempt: request.attempt.clone(),
            payload: request.payload.clone(),
        })
        .map_err(|_| refused())?;
        if payload.len() > MAX_RECOVERY_WIRE_BYTES {
            return Err(refused());
        }
        wire.body(payload).build().map_err(|_| refused())
    }
    fn decode_response(
        &self,
        request: &SemanticTransportRequestV1,
        bytes: &[u8],
    ) -> Result<SemanticPayloadV1, KernelError> {
        let response: SemanticProviderResponseV1 = decode_contract(bytes).map_err(|_| refused())?;
        if response.provider != self.destination.provider
            || response.account != self.destination.account
            || response.resource != self.destination.resource
            || response.checked_provider_version != request.provider_version
            || response.operation != request.operation
            || response.attempt != request.attempt
        {
            return Err(refused());
        }
        Ok(response.payload)
    }
}
#[async_trait::async_trait]
impl SemanticTransport for HttpSemanticTransport {
    fn precondition_guarantee(&self) -> ProviderPreconditionGuaranteeV1 {
        self.guarantee
    }
    async fn submit(
        &self,
        submission: CapturedSemanticSubmissionV1,
    ) -> Result<SemanticPayloadV1, KernelError> {
        let request = submission.into_request();
        let wire = self.build_request(&request)?;
        let response = send_with_contract(&self.egress_contract, &self.client, wire)
            .await
            .map_err(|_| refused())?;
        if !response.status().is_success() {
            return Err(refused());
        }
        self.decode_response(&request, response.body())
    }
}

#[cfg(test)]
#[path = "http/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "http/submission_tests.rs"]
mod submission_tests;
