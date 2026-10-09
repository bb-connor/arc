#![forbid(unsafe_code)]
#![allow(clippy::result_large_err)]

mod rate_limit;
use rate_limit::{rate_limit_mcp_request, McpRateLimiter};
mod clock;
use chio_security_types::clock::{AuthorityDeadline, Clock, ClockError, UnixMillis};
pub use clock::RemoteClock;
mod oauth_error;
pub use oauth_error::{OAuthError, OAuthRejection};
#[path = "remote_mcp/sender_constraint.rs"]
mod sender_constraint;
use sender_constraint::SenderConstraintVerifier;
mod input;
mod transport_identity;
use input::{
    decode as decode_json, BoundedJson, SenderConstraintError, MAX_AUTH_JSON_BYTES,
    MAX_SESSION_JSON_BYTES,
};
pub use transport_identity::TrustedProxyConfig;
use transport_identity::{SenderRequest, TransportIdentity};

pub use chio_control_plane::{CliError, JwtProviderProfile};

#[path = "remote_mcp/admin.rs"]
mod remote_mcp_admin;
#[path = "remote_mcp/approval_policy.rs"]
mod remote_mcp_approval_policy;
pub use remote_mcp_approval_policy::RemoteApprovalConfig;
#[path = "remote_mcp/blocking.rs"]
mod blocking;
use blocking::{blocking_cli, blocking_response, run_blocking};
#[path = "remote_mcp/http_body.rs"]
mod http_body;
#[path = "remote_mcp/protocol_refusal_http.rs"]
mod protocol_refusal_http;
#[path = "remote_mcp/approvals.rs"]
mod remote_mcp_approvals;
#[path = "remote_mcp/session_credentials.rs"]
mod remote_mcp_session_credentials;
#[path = "remote_mcp/session_worker.rs"]
mod session_worker;
use http_body::read_limited_mcp_post_body;
#[path = "remote_mcp/session_store.rs"]
mod remote_mcp_session_store;

use remote_mcp_session_store::*;

#[cfg(test)]
use chio_mcp_adapter::edge::ingress::McpInboxReceiver;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::convert::Infallible;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::thread;
use std::time::Duration;

use async_stream::stream;
use axum::extract::{Form, Path as AxumPath, Query, Request, State};
use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, ORIGIN, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::token::CapabilityToken;
use chio_core::crypto::{sha256_hex, Keypair, PublicKey, Signature as Ed25519Signature};
use chio_core::session::{
    ChioIdentityAssertion, EnterpriseFederationMethod, EnterpriseIdentityContext,
    OAuthBearerFederatedClaims, RequestOwnershipSnapshot, SessionAuthContext, SessionAuthMethod,
    SessionId,
};
use chio_egress_contract::{client_builder_with_contract, send_with_contract, HttpEgressContract};
use chio_kernel::operator_report::{
    CHIO_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_CLAIM,
    CHIO_OAUTH_REQUEST_TIME_TRANSACTION_CONTEXT_CLAIM,
};
use chio_kernel::{
    is_supported_dpop_schema, ChioKernel, ChioOAuthAuthorizationProfile, DpopConfig,
    DpopNonceStore, DpopProof, GovernedAuthorizationDetail,
    GovernedAuthorizationTransactionContext, KernelError, PeerCapabilities, RevocationStore,
    ToolServerConnection, CHIO_OAUTH_AUTHORIZATION_COMMERCE_DETAIL_TYPE,
    CHIO_OAUTH_AUTHORIZATION_METERED_BILLING_DETAIL_TYPE, CHIO_OAUTH_AUTHORIZATION_PROFILE_ID,
    CHIO_OAUTH_AUTHORIZATION_PROFILE_SCHEMA, CHIO_OAUTH_AUTHORIZATION_TOOL_DETAIL_TYPE,
    CHIO_OAUTH_SENDER_BINDING_CAPABILITY_SUBJECT, CHIO_OAUTH_SENDER_PROOF_CHIO_DPOP,
};
use chio_mcp_adapter::adapter::{McpAdapter, McpAdapterConfig, SerializedMcpTransport};
use chio_mcp_adapter::edge::ingress::{
    mcp_inbox, AccountedMessage, McpInboxSender, McpRequestGeneration, McpResponseContext,
};
use chio_mcp_adapter::edge::{AdapterError, ChioMcpEdge, McpEdgeConfig, McpTransport};
use chio_mcp_adapter::server::AdaptedMcpServer;
use chio_mcp_adapter::transport::StdioMcpTransport;
use hmac::{Hmac, Mac};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};
use p384::ecdsa::{Signature as P384Signature, VerifyingKey as P384VerifyingKey};
use reqwest::Client as HttpClient;
use rsa::pkcs1v15::{Signature as RsaPkcs1v15Signature, VerifyingKey as RsaPkcs1v15VerifyingKey};
use rsa::pss::{Signature as RsaPssSignature, VerifyingKey as RsaPssVerifyingKey};
use rsa::signature::Verifier as _;
use rsa::{BigUint, RsaPublicKey as JwtRsaPublicKey};
use serde::de::{DeserializeOwned, Deserializer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::{broadcast, Mutex};
use tracing::{error, info, warn};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use chio_control_plane::policy::{load_policy, LoadedPolicy};
use chio_control_plane::trust_control::service_runtime::remote_authority::build_pinned_remote_capability_authority_with_clock;
use chio_control_plane::trust_control::{
    self, ChildReceiptQuery, RevocationQuery, ToolReceiptQuery,
};
use chio_control_plane::{
    authority_public_key_from_seed_file, configure_budget_store, configure_capability_authority,
    configure_receipt_store, configure_revocation_store, durable_admission_sidecar_path,
    enterprise_federation::{
        EnterpriseProviderKind, EnterpriseProviderRecord, EnterpriseProviderRegistry,
    },
    issue_default_capabilities, load_or_create_authority_keypair, open_durable_admission_runtime,
    require_control_token, rotate_authority_keypair, validate_distinct_database_paths,
    validate_durable_admission_participant_paths, DurableAdmissionRuntime,
};
#[path = "remote_mcp/session_core.rs"]
mod session_core;
pub use session_core::*;
#[path = "remote_mcp/session_identity.rs"]
mod session_identity;
pub use session_identity::*;
#[path = "remote_mcp/session_resume.rs"]
mod session_resume;
use session_resume::*;
#[path = "remote_mcp/session_forms.rs"]
mod session_forms;
#[path = "remote_mcp/session_shared_upstream.rs"]
mod session_shared_upstream;
use session_forms::*;
#[cfg(test)]
use session_shared_upstream::*;
#[path = "remote_mcp/session_recovery.rs"]
mod session_recovery;
use session_recovery::{restore_persisted_sessions, resume_deadline};
#[path = "remote_mcp/http_service.rs"]
mod http_service;
pub use http_service::*;
#[path = "remote_mcp/http_service_auth.rs"]
mod http_service_auth;
use http_service_auth::*;
#[path = "remote_mcp/oauth.rs"]
mod oauth;
use oauth::*;
#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
#[path = "remote_mcp/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "remote_mcp/hosted_tests/mod.rs"]
mod hosted_tests;
