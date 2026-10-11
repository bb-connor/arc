//! Registry diagnostics with private, downcastable local causes.

use chio_errors::ErrorCodeSpec;
use chio_kernel::StructuredErrorReport;
use std::{error::Error, fmt};

pub struct RegisteredSourceError {
    spec: &'static ErrorCodeSpec,
    public_message: Option<&'static str>,
    source: Box<dyn Error + Send + Sync>,
}

impl RegisteredSourceError {
    pub(super) fn new(
        spec: &'static ErrorCodeSpec,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            spec,
            public_message: None,
            source: Box::new(source),
        }
    }

    pub(super) fn with_public_message(mut self, message: &'static str) -> Self {
        self.public_message = Some(message);
        self
    }

    pub(super) fn report(&self) -> StructuredErrorReport {
        StructuredErrorReport::new(
            self.spec.urn,
            self.public_message.unwrap_or(self.spec.summary),
            serde_json::json!({
                "domain": self.spec.domain.as_str(),
                "severity": self.spec.severity.as_str(),
                "string_code": self.spec.string_code,
                "stability": self.spec.stability,
            }),
            self.spec.help,
        )
    }
}

impl Error for RegisteredSourceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl fmt::Display for RegisteredSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.spec.urn)
    }
}

impl fmt::Debug for RegisteredSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CliError;
    use chio_errors::_generated::error_codes::ATTEST_RECEIPT_SIGNING_FAILED;

    #[test]
    fn registered_cli_source_remains_inspectable_without_public_disclosure() {
        let error = CliError::with_source(
            &ATTEST_RECEIPT_SIGNING_FAILED,
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "/private/secret-key"),
        );
        let native = error
            .source()
            .and_then(Error::source)
            .and_then(|source| source.downcast_ref::<std::io::Error>());
        assert_eq!(
            native.map(std::io::Error::kind),
            Some(std::io::ErrorKind::PermissionDenied)
        );
        let report = error.report();
        assert_eq!(report.code, ATTEST_RECEIPT_SIGNING_FAILED.urn);
        assert!(!format!("{error:?} {error} {report:?}").contains("secret-key"));
    }
}
