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
}

impl ToolDispatchContext {
    pub fn new(request_id: impl Into<String>, attempt: ProviderAttemptBindingV1) -> Self {
        Self {
            request_id: request_id.into(),
            attempt,
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
}
