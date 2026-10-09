//! A2A-to-Chio adapter.
//!
//! Mediates between the Agent-to-Agent (A2A) protocol and the Chio kernel:
//! agent-card discovery, `SendMessage` invocation and streaming, task-registry
//! tracking, OAuth token handling, and HTTP transport bound by the egress
//! contract.

#![forbid(unsafe_code)]

pub use config::A2aAdapterConfig;
pub use invoke::A2aAdapter;
pub use mapping::AdapterError;
pub use partner_policy::A2aPartnerPolicy;
pub use protocol::{
    A2aAgentCapabilities, A2aAgentCard, A2aAgentInterface, A2aAgentSkill, A2aAuthenticationInfo,
    A2aCancelTaskRequest, A2aDeleteTaskPushNotificationConfigRequest,
    A2aGetTaskPushNotificationConfigRequest, A2aGetTaskRequest,
    A2aListTaskPushNotificationConfigsRequest, A2aListTaskPushNotificationConfigsResponse,
    A2aMessage, A2aPart, A2aSendMessageConfiguration, A2aSendMessageRequest,
    A2aSendMessageResponse, A2aSubscribeToTaskRequest, A2aTaskPushNotificationConfig,
};
use std::time::Duration;

mod clock;
mod oauth_cache;

const MAX_A2A_JSON_BYTES: usize = 16 * 1024 * 1024;

const DEFAULT_AGENT_CARD_PATH: &str = "/.well-known/agent-card.json";
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const A2A_VERSION_HEADER: &str = "A2A-Version";
const A2A_PROTOCOL_MAJOR: &str = "1.";
const A2A_PROTOCOL_VERSION_HEADER_VALUE: &str = "1.0";
const SSE_CONTENT_TYPE: &str = "text/event-stream";
const OAUTH_CACHE_SKEW_SECS: u64 = 30;
const TASK_REGISTRY_VERSION: &str = "chio.a2a-task-registry.v1";

pub mod loaded_weights;

mod auth;
mod config;
mod discovery;
#[cfg(feature = "fuzz")]
pub mod fuzz;
mod invoke;
mod mapping;
mod partner_policy;
mod protocol;
mod task_registry;
#[cfg(test)]
mod tests;
mod transport;
