//! Plan-level evaluation HTTP surface.
//!
//! Mirrors the structure of [`crate::emergency`]: `chio-http-core` does
//! not embed an HTTP server, so this module exposes a substrate-agnostic
//! handler that accepts raw request bytes, delegates to the kernel, and
//! returns a structured response. Each substrate adapter wires the
//! handler into its own framework-native route handler.
//!
//! Unlike the emergency endpoints, `/evaluate-plan` does NOT require an
//! admin token: any caller in possession of a valid capability token
//! can ask the kernel whether a prospective plan would be allowed. The
//! pre-flight check is explicitly designed to be consulted often by
//! agent planners during plan generation.
//!
//! The handler returns `200 OK` regardless of the aggregate plan
//! verdict: denials are conveyed inside the JSON body, not as HTTP
//! status codes. Only malformed request bodies produce a 400.

use std::sync::Arc;

use chio_core_types::canonical::{UntrustedJsonError, UntrustedJsonText};
use chio_core_types::{PlanEvaluationRequest, PlanEvaluationResponse};
use chio_kernel::ChioKernel;
use serde::Deserialize;

/// Error surfaced by [`handle_evaluate_plan`] when the request body is
/// malformed. Aggregate plan denials are NOT represented here; those
/// are carried inside the successful response.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanHandlerError {
    /// Request body could not be parsed as a `PlanEvaluationRequest`.
    #[error("invalid evaluate-plan request body")]
    BadRequest(#[source] chio_core_types::canonical::SharedUntrustedJsonError),
}

impl PlanHandlerError {
    /// HTTP status code for this error. Always 400 in v1.
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
        }
    }

    /// Stable machine-readable error code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
        }
    }

    /// Human-readable message.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::BadRequest(_) => "invalid evaluate-plan request body".to_string(),
        }
    }

    /// Wire body for this error response, matching the emergency-
    /// handler error shape so adapters can reuse their serialisation.
    #[must_use]
    pub fn body(&self) -> serde_json::Value {
        serde_json::json!({
            "error": self.code(),
            "message": self.message(),
        })
    }
}

/// Handler for `POST /evaluate-plan`.
///
/// Takes the raw request body as bytes, parses it into a
/// [`PlanEvaluationRequest`], and returns the kernel's
/// [`PlanEvaluationResponse`]. Denials are always `Ok`: the HTTP layer
/// only errors out on malformed bodies.
pub fn handle_evaluate_plan(
    kernel: &Arc<ChioKernel>,
    body: &[u8],
) -> Result<PlanEvaluationResponse, PlanHandlerError> {
    let parsed = decode_plan(body).map_err(PlanHandlerError::BadRequest)?;

    Ok(kernel.evaluate_plan_blocking(&parsed))
}

fn decode_plan(
    body: &[u8],
) -> Result<PlanEvaluationRequest, chio_core_types::canonical::SharedUntrustedJsonError> {
    // Parameters are unsigned tool arguments and accept ordinary JSON floats.
    // The embedded capability has its own signed original-token contract.
    let value = UntrustedJsonText::from_wire(body, crate::input::MAX_REQUEST_BYTES)?
        .decode_document::<serde_json::Value>()?;
    #[derive(Deserialize)]
    struct OriginalCapability<'a> {
        #[serde(borrow)]
        planner_capability: &'a serde_json::value::RawValue,
    }
    let original: OriginalCapability<'_> =
        serde_json::from_slice(body).map_err(UntrustedJsonError::Decode)?;
    let capability = crate::input::decode(
        original.planner_capability.get().as_bytes(),
        crate::input::MAX_CAPABILITY_BYTES,
    )?;
    let mut parsed: PlanEvaluationRequest =
        serde_json::from_value(value).map_err(UntrustedJsonError::Decode)?;
    parsed.planner_capability = capability;
    Ok(parsed)
}
