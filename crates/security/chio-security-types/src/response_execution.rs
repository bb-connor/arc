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

/// A validated execution binding. Unknown versions are rejected when decoded.
///
/// ```compile_fail
/// use chio_security_types::{ResponseExecutionBinding, ResponseExecutionMode};
/// let invalid = ResponseExecutionBinding {
///     schema_version: 0,
///     mode: ResponseExecutionMode::Live,
/// };
/// ```
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "ResponseExecutionBindingWire")]
pub struct ResponseExecutionBinding {
    schema_version: u8,
    mode: ResponseExecutionMode,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseExecutionBindingWire {
    schema_version: u8,
    mode: ResponseExecutionMode,
}

impl ResponseExecutionBinding {
    #[must_use]
    pub const fn new(mode: ResponseExecutionMode) -> Self {
        Self {
            schema_version: RESPONSE_EXECUTION_BINDING_SCHEMA_VERSION,
            mode,
        }
    }

    #[must_use]
    pub const fn schema_version(self) -> u8 {
        self.schema_version
    }

    #[must_use]
    pub const fn mode(self) -> ResponseExecutionMode {
        self.mode
    }
}

impl TryFrom<ResponseExecutionBindingWire> for ResponseExecutionBinding {
    type Error = ResponseExecutionBindingError;

    fn try_from(wire: ResponseExecutionBindingWire) -> Result<Self, Self::Error> {
        if wire.schema_version != RESPONSE_EXECUTION_BINDING_SCHEMA_VERSION {
            return Err(ResponseExecutionBindingError::UnsupportedSchemaVersion {
                expected: RESPONSE_EXECUTION_BINDING_SCHEMA_VERSION,
                observed: wire.schema_version,
            });
        }
        Ok(Self::new(wire.mode))
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

/// Whether a retained plan predates execution-mode binding or commits to a mode.
///
/// Legacy is a recovery compatibility state, never fresh admission authority.
/// Its wire form remains an absent (or decoded null) execution field. Bound
/// provenance uses the original binding object without an additional enum tag.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PlanProvenance {
    #[default]
    Legacy,
    Bound(ResponseExecutionBinding),
}

impl PlanProvenance {
    #[must_use]
    pub const fn is_legacy(&self) -> bool {
        matches!(self, Self::Legacy)
    }
}

impl Serialize for PlanProvenance {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Legacy => serializer.serialize_none(),
            Self::Bound(binding) => binding.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for PlanProvenance {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Option::<ResponseExecutionBinding>::deserialize(deserializer)? {
            None => Ok(Self::Legacy),
            Some(binding) => Ok(Self::Bound(binding)),
        }
    }
}

/// An immutable plan whose signed provenance permits fresh live admission.
/// This is not an approval or capability; the kernel still verifies all other
/// authority inputs. It cannot be deserialized or constructed with a struct literal.
///
/// ```compile_fail
/// use chio_security_types::{FreshLiveAdmission, ResponsePlan};
/// fn bypass(plan: ResponsePlan) -> FreshLiveAdmission {
///     FreshLiveAdmission { plan }
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreshLiveAdmission {
    plan: crate::ResponsePlan,
}

impl FreshLiveAdmission {
    pub fn new(plan: crate::ResponsePlan) -> Result<Self, crate::DispatchRejection> {
        plan.require_live_execution()?;
        Ok(Self { plan })
    }

    #[must_use]
    pub const fn plan(&self) -> &crate::ResponsePlan {
        &self.plan
    }
}
