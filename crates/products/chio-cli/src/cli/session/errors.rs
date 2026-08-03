use super::*;

pub(crate) fn control_request_id(session_id: &SessionId, suffix: &str) -> RequestId {
    RequestId::new(format!("{session_id}::{suffix}"))
}

/// Record a kernel-authoritative error receipt when session evaluation fails.
pub(crate) fn record_internal_error_receipt(
    kernel: &ChioKernel,
    request: &KernelToolCallRequest,
    observation: &chio_kernel::TransportReceiptObservation,
) -> Result<chio_core::receipt::body::ChioReceipt, chio_kernel::KernelError> {
    kernel.record_transport_internal_error_deny_receipt(request, observation)
}
