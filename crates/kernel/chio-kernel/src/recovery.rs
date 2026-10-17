//! Recovery orchestration shares the original serving authority and admission.
//! Wire values and journal projections carry data, never dispatch permission.
#![forbid(unsafe_code)]

mod command_selection;
pub use command_selection::*;
mod original_scope;
mod ports;
mod provider_budget;
mod records;
mod request_review;
mod server;
pub use original_scope::{RecoveryOriginalRequestError, RecoveryOriginalRequestScope};
pub use ports::*;
pub use provider_budget::*;
pub use records::*;
pub use request_review::{recovery_review_digest, RecoveryRequestProjection};
pub use server::RecoveryToolServerConnection;
#[cfg(test)]
mod vector_test_fixture;

/// Recovery digests use the established canonical encoder and SHA-256 primitive.
/// A refusal is the canonical encoder's own error.
pub fn recovery_digest<T: serde::Serialize>(
    domain: chio_core_types::recovery::RecoveryDigestDomain,
    value: &T,
) -> Result<[u8; 32], chio_core_types::Error> {
    let canonical = chio_core_types::canonical::CanonicalBytes::new(value)?;
    Ok(*domain.digest(&canonical).as_bytes())
}
