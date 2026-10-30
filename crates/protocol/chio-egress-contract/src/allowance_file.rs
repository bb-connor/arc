//! The operator egress allowance document.
//!
//! The document is TOML with one `[[allow]]` table per allowance, each naming
//! `host`, `port` and `cidr`, and optionally `scheme` (`https` when absent).
//! Unknown keys are refused, and every entry passes the same validation as
//! [`EgressAllowanceSet::new`]. Reading the document from storage belongs to
//! the caller; this module only parses text it is handed.

use serde::Deserialize;

use crate::allowance::{EgressAllowanceSet, PrivateNetworkAllowance, PrivateNetworkAllowanceError};

/// Largest allowance document [`EgressAllowanceSet::from_toml_bytes`] parses.
pub const MAX_EGRESS_ALLOWANCE_DOCUMENT_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowanceDocument {
    allow: Vec<PrivateNetworkAllowance>,
}

impl EgressAllowanceSet {
    /// Parse and validate an allowance document of at most
    /// [`MAX_EGRESS_ALLOWANCE_DOCUMENT_BYTES`] bytes.
    pub fn from_toml_bytes(bytes: &[u8]) -> Result<Self, PrivateNetworkAllowanceError> {
        if bytes.len() > MAX_EGRESS_ALLOWANCE_DOCUMENT_BYTES {
            return Err(PrivateNetworkAllowanceError::DocumentTooLarge {
                max_bytes: MAX_EGRESS_ALLOWANCE_DOCUMENT_BYTES,
            });
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| PrivateNetworkAllowanceError::DocumentNotUtf8)?;
        let document: AllowanceDocument =
            toml::from_str(text).map_err(|error: toml::de::Error| {
                PrivateNetworkAllowanceError::DocumentInvalid {
                    reason: error.message().to_string(),
                }
            })?;
        EgressAllowanceSet::new(document.allow)
    }
}
