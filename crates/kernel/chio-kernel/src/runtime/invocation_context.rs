//! Caller binding for trusted native tool connections. This is not a wire credential.

use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};

use super::ToolCallRequest;
use crate::KernelError;

/// Kernel-selected identity and route for the current admitted tool call.
///
/// Only the kernel constructs this value. It carries no capability token,
/// signing key or bearer credential. Native connections can bind local state
/// to the exact signed capability and subject without trusting caller-supplied
/// tool arguments. Serialized copies of these fields are not an attestation.
#[derive(Clone, Debug)]
pub struct ToolInvocationContext {
    request_id: String,
    server_id: String,
    tool_name: String,
    capability_id: String,
    subject_key: String,
    capability_hash: String,
}

impl ToolInvocationContext {
    pub(crate) fn from_request(request: &ToolCallRequest) -> Result<Self, KernelError> {
        let capability = canonical_json_bytes(&request.capability)
            .map_err(|_| KernelError::Internal("cannot bind invocation capability".to_owned()))?;
        Ok(Self {
            request_id: request.request_id.clone(),
            server_id: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            capability_id: request.capability.id.clone(),
            subject_key: request.capability.subject.to_hex(),
            capability_hash: sha256_hex(&capability),
        })
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    pub fn server_id(&self) -> &str {
        &self.server_id
    }
    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }
    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }
    pub fn subject_key(&self) -> &str {
        &self.subject_key
    }
    pub fn capability_hash(&self) -> &str {
        &self.capability_hash
    }
}
