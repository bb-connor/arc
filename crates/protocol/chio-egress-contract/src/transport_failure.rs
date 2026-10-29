use crate::HttpEgressError;
use std::error::Error;
use std::io;
use std::sync::Arc;

/// Cloneable local source. Public formatting never exposes request URLs or bodies.
#[derive(Clone)]
pub struct RequestFailure(Arc<dyn Error + Send + Sync>);

impl RequestFailure {
    pub(crate) fn new(error: impl Error + Send + Sync + 'static) -> Self {
        Self(Arc::new(error))
    }
}

impl std::fmt::Display for RequestFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("urn:chio:error:transport:http-failed")
    }
}

impl std::fmt::Debug for RequestFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl Error for RequestFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}

impl PartialEq for RequestFailure {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for RequestFailure {}

/// The contract refusal a transport error carries in its source chain. A
/// resolver reports a refusal directly or wrapped in `io::Error`.
pub(crate) fn contract_refusal(error: &(dyn Error + 'static)) -> Option<HttpEgressError> {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(refusal) = error.downcast_ref::<HttpEgressError>() {
            return Some(refusal.clone());
        }
        if let Some(refusal) = error
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
            .and_then(|inner| inner.downcast_ref::<HttpEgressError>())
        {
            return Some(refusal.clone());
        }
        current = error.source();
    }
    None
}
