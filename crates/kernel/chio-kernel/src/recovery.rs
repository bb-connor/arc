//! Recovery orchestration shares the original serving authority and admission.
//! Wire values and journal projections carry data, never dispatch permission.
#![forbid(unsafe_code)]

mod command_selection;
pub use command_selection::*;
mod observation;
mod original_scope;
mod ports;
mod provider_budget;
mod records;
pub(crate) use original_scope::PreparedOriginalProcessOrigin;
pub use original_scope::{RecoveryOriginalRequestError, RecoveryOriginalRequestScope};
pub use ports::*;
pub use provider_budget::*;
pub use records::*;

/// Recovery digests use the established canonical encoder and SHA-256 primitive.
pub fn recovery_digest<T: serde::Serialize>(
    domain: chio_core_types::recovery::RecoveryDigestDomain,
    value: &T,
) -> Result<[u8; 32], crate::KernelError> {
    let canonical = chio_core_types::canonical::CanonicalBytes::new(value)
        .map_err(|_| crate::KernelError::DurableAdmission("recovery encoding refused".into()))?;
    Ok(*domain.digest(&canonical).as_bytes())
}

mod semantic;
pub use semantic::semantic_request_semantics;
