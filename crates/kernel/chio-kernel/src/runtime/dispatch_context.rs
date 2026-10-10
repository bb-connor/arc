use chio_core_types::provider_attempt::ProviderAttemptBindingV1;

/// Identity the kernel binds to one durable tool dispatch.
///
/// The attempt is the provider attempt the admission operation registered
/// before the dispatch was committed, so a remote server that records the
/// idempotency key sees the same key for every delivery of one operation and
/// can refuse a second execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolDispatchContext {
    request_id: String,
    attempt: ProviderAttemptBindingV1,
    caller_capability_sha256: Option<String>,
}

impl ToolDispatchContext {
    pub fn new(request_id: impl Into<String>, attempt: ProviderAttemptBindingV1) -> Self {
        Self {
            request_id: request_id.into(),
            attempt,
            caller_capability_sha256: None,
        }
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn operation_id(&self) -> &str {
        &self.attempt.operation_id
    }

    pub fn attempt_id(&self) -> &str {
        &self.attempt.attempt_id
    }

    pub fn transport_key_epoch(&self) -> u64 {
        self.attempt.transport_key_epoch
    }

    /// The key a remote server may deduplicate on: the admission operation id.
    pub fn idempotency_key(&self) -> &str {
        self.operation_id()
    }

    pub fn attempt(&self) -> &ProviderAttemptBindingV1 {
        &self.attempt
    }

    /// Exact signed capability selected by the kernel for this invocation.
    ///
    /// This digest is caller binding on a trusted tool connection, not a bearer
    /// credential or a signed wire assertion. A resource must authenticate its
    /// connection before using forwarded metadata to authorize a mutation.
    pub fn caller_capability_sha256(&self) -> Option<&str> {
        self.caller_capability_sha256.as_deref()
    }

    pub(crate) fn bind_caller_capability(mut self, digest: String) -> Self {
        self.caller_capability_sha256 = Some(digest);
        self
    }
}
