//! Native request causes remain local; public diagnostics exclude provider text.
use std::{error::Error, fmt, sync::Arc};

#[derive(Clone)]
pub struct OracleRequestError(Arc<dyn Error + Send + Sync>);
impl OracleRequestError {
    pub(crate) fn new(error: impl Error + Send + Sync + 'static) -> Self {
        Self(Arc::new(error))
    }
}
impl fmt::Display for OracleRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("oracle request failed")
    }
}
impl fmt::Debug for OracleRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl Error for OracleRequestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}
