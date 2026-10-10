//! A2A-to-Chio adapter.
//!
//! Mediates between the Agent-to-Agent (A2A) protocol and the Chio kernel:
//! agent-card discovery, `SendMessage` invocation and streaming, task-registry
//! tracking, OAuth token handling, and HTTP transport bound by the egress
//! contract.

#![forbid(unsafe_code)]

use chio_security_types::clock::{AuthorityDeadline, Clock, ClockError, ClockReading, SystemClock};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};
mod clock;
mod oauth_cache;
use clock::ClockSource;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use chio_core::sha256_hex;
use chio_egress_contract::HttpEgressContract;
use chio_kernel::{
    KernelError, NestedFlowBridge, ToolCallChunk, ToolCallStream, ToolDispatchContext,
    ToolServerConnection, ToolServerStreamResult,
};
use chio_manifest::{validate_manifest, LatencyHint, ToolDefinition, ToolManifest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use ureq::rustls::pki_types::pem::PemObject as _;
use url::form_urlencoded::{byte_serialize, Serializer as UrlFormSerializer};
use url::Url;

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

include!("config.rs");
include!("partner_policy.rs");
include!("invoke.rs");
include!("protocol.rs");
include!("task_registry.rs");
include!("mapping.rs");
include!("discovery.rs");
include!("auth.rs");
include!("transport.rs");
#[cfg(test)]
mod tests;
#[cfg(feature = "fuzz")]
include!("fuzz.rs");
