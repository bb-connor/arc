use chio_core::{
    receipt::kinds::BoundaryClass, receipt::kinds::ReceiptKind, receipt::kinds::RedactionMode,
    receipt::kinds::ToolOrigin, receipt::signing::ReceiptSigningHandle,
};
use chio_log_redact::redacted;

use super::*;

mod allow_responses;
mod deny_responses;
mod finalization;
mod pending_responses;
mod prepared_response;
mod receipt_persistence;
mod terminal_responses;

pub(crate) use allow_responses::{AllowResponseNonce, PreflightNonceSource, ReservedHoldStamp};
#[cfg(any(test, feature = "finding-market"))]
pub(crate) use finalization::FinalizeToolOutputCostContext;
pub(in crate::kernel) use finalization::PrepareToolOutputCostContext;
pub(in crate::kernel) use prepared_response::PreparedResponse;

#[derive(Clone, Copy)]
pub(in crate::kernel) enum ReceiptRecordMode {
    WithFederation,
    LocalOnly,
}
