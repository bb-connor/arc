//! Protocol-agnostic HTTP security types for the ARC kernel.
//!
//! This crate defines the shared types that every HTTP substrate adapter uses:
//! request model, caller identity, session context, HTTP receipts, and verdicts.
//! It is the foundation for `arc-openapi`, `arc-config`, `arc api protect`,
//! and all language-specific middleware crates.

mod authority;
pub mod emergency;
mod evaluation;
mod identity;
mod method;
mod receipt;
mod request;
pub mod routes;
mod session;
mod verdict;

pub use authority::{
    HttpAuthority, HttpAuthorityError, HttpAuthorityEvaluation, HttpAuthorityInput,
    HttpAuthorityPolicy, PreparedHttpEvaluation,
};
pub use emergency::{
    handle_emergency_resume, handle_emergency_status, handle_emergency_stop, EmergencyAdmin,
    EmergencyHandlerError, EmergencyResumeResponse, EmergencyStatusResponse,
    EmergencyStopRequest, EmergencyStopResponse,
};
pub use evaluation::{EvaluateResponse, HealthResponse, SidecarStatus, VerifyReceiptResponse};
pub use identity::{AuthMethod, CallerIdentity};
pub use method::HttpMethod;
pub use receipt::{
    http_status_metadata_decision, http_status_metadata_final, http_status_scope, HttpReceipt,
    HttpReceiptBody, ARC_DECISION_RECEIPT_ID_KEY, ARC_HTTP_STATUS_SCOPE_DECISION,
    ARC_HTTP_STATUS_SCOPE_FINAL, ARC_HTTP_STATUS_SCOPE_KEY, ARC_KERNEL_RECEIPT_ID_KEY,
};
pub use request::ArcHttpRequest;
pub use routes::{
    emergency_route_registrations, EmergencyRouteRegistration, EMERGENCY_ADMIN_TOKEN_HEADER,
    EMERGENCY_RESUME_PATH, EMERGENCY_STATUS_PATH, EMERGENCY_STOP_PATH,
};
pub use session::SessionContext;
pub use verdict::{DenyDetails, Verdict};

// Re-export types from arc-core-types that HTTP adapters commonly need.
pub use arc_core_types::canonical::{canonical_json_bytes, canonical_json_string};
pub use arc_core_types::crypto::{Keypair, PublicKey, Signature};
pub use arc_core_types::receipt::GuardEvidence;
pub use arc_core_types::{sha256_hex, Error, Result};
