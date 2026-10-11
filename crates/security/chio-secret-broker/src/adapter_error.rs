//! Operator-owned native causes behind unchanged, closed broker peer categories.
#[cfg(target_os = "linux")]
use crate::BrokerError;
use std::{error::Error, fmt};

/// A native adapter failure whose default renderings never expose its payload.
/// Trusted local diagnostics inspect the original typed error through `source`.
pub struct AdapterErrorCause {
    source: Box<dyn Error + Send + Sync + 'static>,
}

impl fmt::Debug for AdapterErrorCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdapterErrorCause(redacted)")
    }
}

impl fmt::Display for AdapterErrorCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("adapter native cause retained")
    }
}

impl Error for AdapterErrorCause {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn denied(source: impl Error + Send + Sync + 'static) -> BrokerError {
    BrokerError::AdapterAuthorizationDenied(AdapterErrorCause {
        source: Box::new(source),
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn upstream(source: impl Error + Send + Sync + 'static) -> BrokerError {
    BrokerError::AdapterUpstream(AdapterErrorCause {
        source: Box::new(source),
    })
}
