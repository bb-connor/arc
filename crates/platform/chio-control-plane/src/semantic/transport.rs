use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderPreconditionGuaranteeV1 {
    AtomicIfMatch,
    LastLocalCheckOnly,
}

/// A private host transport receives one pinned endpoint and one native attempt.
/// Implementations must report bounded typed values and suppress diagnostics.
/// Transport attempt identity cannot be assigned as provider-version text.
/// ```compile_fail
/// use chio_control_plane::semantic::SemanticTransportRequestV1;
/// use chio_security_types::recovery::ProtectedText;
/// fn confuse(request: SemanticTransportRequestV1) -> ProtectedText<128> {
///     request.attempt
/// }
/// ```
#[derive(Clone)]
pub struct SemanticTransportRequestV1 {
    pub kind: SemanticOperationKindV1,
    pub destination: SemanticDestinationV1,
    pub provider_version: ProtectedText<128>,
    pub operation: OperationId,
    pub attempt: SemanticProviderAttemptId,
    pub payload: SemanticPayloadV1,
}
impl std::fmt::Debug for SemanticTransportRequestV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SemanticTransportRequestV1([redacted])")
    }
}

#[async_trait::async_trait]
pub trait SemanticTransport: Send + Sync {
    fn precondition_guarantee(&self) -> ProviderPreconditionGuaranteeV1;
    async fn submit(
        &self,
        submission: CapturedSemanticSubmissionV1,
    ) -> Result<SemanticPayloadV1, KernelError>;
}

/// An accepted alternate destination selects a separately configured transport
/// and credential. It cannot rewrite an endpoint or reuse another account's key.
pub struct SemanticTransportRouter {
    routes: Vec<(SemanticDestinationV1, Arc<dyn SemanticTransport>)>,
}
impl SemanticTransportRouter {
    pub fn new(
        routes: Vec<(SemanticDestinationV1, Arc<dyn SemanticTransport>)>,
    ) -> Result<Self, KernelError> {
        if routes.is_empty() || routes.len() > 16 {
            return Err(refused());
        }
        for (index, (destination, _)) in routes.iter().enumerate() {
            canonical_endpoint(destination.endpoint.as_str())?;
            if routes[..index]
                .iter()
                .any(|(prior, _)| prior.destination == destination.destination)
            {
                return Err(refused());
            }
        }
        Ok(Self { routes })
    }
}
#[async_trait::async_trait]
impl SemanticTransport for SemanticTransportRouter {
    fn precondition_guarantee(&self) -> ProviderPreconditionGuaranteeV1 {
        if self.routes.iter().all(|(_, transport)| {
            transport.precondition_guarantee() == ProviderPreconditionGuaranteeV1::AtomicIfMatch
        }) {
            ProviderPreconditionGuaranteeV1::AtomicIfMatch
        } else {
            ProviderPreconditionGuaranteeV1::LastLocalCheckOnly
        }
    }
    async fn submit(
        &self,
        submission: CapturedSemanticSubmissionV1,
    ) -> Result<SemanticPayloadV1, KernelError> {
        let transport = self
            .routes
            .iter()
            .find(|(destination, _)| *destination == submission.request().destination)
            .map(|(_, transport)| transport)
            .ok_or_else(refused)?;
        transport.submit(submission).await
    }
}

pub(super) fn canonical_endpoint(value: &str) -> Result<reqwest::Url, KernelError> {
    let url = reqwest::Url::parse(value).map_err(|_| refused())?;
    if url.scheme() != "https"
        || url.as_str() != value
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path().ends_with('/')
    {
        return Err(refused());
    }
    Ok(url)
}
