//! Audit-local parser cause. Display never prints rejected values.
use std::{error::Error, fmt};

pub struct AuditInputError {
    offset: usize,
    rule: &'static str,
    source: Option<Box<crate::BrokerError>>,
}

impl AuditInputError {
    #[cfg(unix)]
    pub(crate) fn rule(offset: usize, rule: &'static str) -> Self {
        Self {
            offset,
            rule,
            source: None,
        }
    }

    #[cfg(unix)]
    pub(crate) fn caused_by(offset: usize, rule: &'static str, source: crate::BrokerError) -> Self {
        Self {
            offset,
            rule,
            source: Some(Box::new(source)),
        }
    }
}

impl fmt::Debug for AuditInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditInputError")
            .field("offset", &self.offset)
            .field("rule", &self.rule)
            .field("has_source", &self.source.is_some())
            .finish()
    }
}

impl fmt::Display for AuditInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "privileged audit input {} at byte {}",
            self.rule, self.offset
        )
    }
}

impl Error for AuditInputError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| -> &(dyn Error + 'static) { source })
    }
}
