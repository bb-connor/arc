//! Signed separation between simulated response plans and live execution.

use crate::ports::{PortError, PortResult};
use serde::{Deserialize, Serialize};

pub const RESPONSE_EXECUTION_BINDING_SCHEMA_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseExecutionMode {
    DryRun,
    Live,
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

    pub fn validate(&self) -> PortResult<()> {
        if self.schema_version != RESPONSE_EXECUTION_BINDING_SCHEMA_VERSION {
            return Err(PortError::invalid_data());
        }
        Ok(())
    }
}
