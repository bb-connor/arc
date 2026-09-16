//! Trusted host route selection carried alongside process attribution.

use serde::Serialize;

use crate::ProcessError;

/// A route selected by the host that registered the actual tool connection.
///
/// This is evidence input to the kernel's admission hook, not authorization.
/// A signed swarm route must independently match all three fields. Worker
/// request context cannot install or override these values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessRoute {
    bridge: String,
    protocol_target: String,
    selected_route: String,
}

impl ProcessRoute {
    pub fn new(
        bridge: impl Into<String>,
        protocol_target: impl Into<String>,
        selected_route: impl Into<String>,
    ) -> Result<Self, ProcessError> {
        let route = Self {
            bridge: bridge.into(),
            protocol_target: protocol_target.into(),
            selected_route: selected_route.into(),
        };
        for value in [&route.bridge, &route.protocol_target, &route.selected_route] {
            if value.is_empty()
                || value.len() > 4096
                || value.trim() != value
                || value.chars().any(char::is_control)
            {
                return Err(ProcessError::Configuration("invalid host process route"));
            }
        }
        Ok(route)
    }
}

/// A trusted host's reference to its actual persisted tool-launch receipt.
/// This observation grants no authority. Offline verification must load the
/// referenced envelope and verify its digest, signer and confinement claims.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProcessLaunchReceipt {
    receipt_id: String,
    receipt_sha256: String,
}

impl ProcessLaunchReceipt {
    pub fn new(receipt_id: String, receipt_sha256: String) -> Result<Self, ProcessError> {
        for digest in [&receipt_id, &receipt_sha256] {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(ProcessError::Configuration(
                    "invalid host launch receipt reference",
                ));
            }
        }
        Ok(Self {
            receipt_id,
            receipt_sha256,
        })
    }
}
