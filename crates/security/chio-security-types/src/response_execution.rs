//! Signed separation between simulated response plans and live execution.

use core::fmt;
use serde::{Deserialize, Serialize};

pub const RESPONSE_EXECUTION_BINDING_SCHEMA_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseExecutionMode {
    DryRun,
    Live,
}

impl ResponseExecutionMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DryRun => "dry_run",
            Self::Live => "live",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseExecutionBinding {
    pub schema_version: u8,
    pub mode: ResponseExecutionMode,
}

impl ResponseExecutionBinding {
    #[must_use]
    pub const fn new(mode: ResponseExecutionMode) -> Self {
        Self {
            schema_version: RESPONSE_EXECUTION_BINDING_SCHEMA_VERSION,
            mode,
        }
    }

    pub fn validate(&self) -> Result<(), ResponseExecutionBindingError> {
        if self.schema_version != RESPONSE_EXECUTION_BINDING_SCHEMA_VERSION {
            return Err(ResponseExecutionBindingError::UnsupportedSchemaVersion {
                expected: RESPONSE_EXECUTION_BINDING_SCHEMA_VERSION,
                observed: self.schema_version,
            });
        }
        Ok(())
    }
}

/// Why an execution binding was refused. The payload is the pair of versions
/// the rule compared, which is what a receipt needs and nothing the binding's
/// author supplied beyond that number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseExecutionBindingError {
    UnsupportedSchemaVersion { expected: u8, observed: u8 },
}

impl fmt::Display for ResponseExecutionBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion { expected, observed } => write!(
                formatter,
                "response execution binding schema version {observed} is not the supported version {expected}"
            ),
        }
    }
}

impl core::error::Error for ResponseExecutionBindingError {}
