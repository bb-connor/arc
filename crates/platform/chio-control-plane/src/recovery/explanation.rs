//! Advisory report composition is independent of native execution composition.
#![forbid(unsafe_code)]
mod native;
mod service;
mod transport;
pub use service::{ProtectedRecoveryExplanationV1, RecoveryExplanationService};
pub use transport::recovery_explanation_router;
#[cfg(test)]
mod tests;
