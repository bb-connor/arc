//! The kernel-owned `session_anchor` receipt metadata block.
//!
//! A receipt signed for an evaluation inside a session binds that session's
//! anchor. The block carries a domain-separated commitment to the anchor
//! reference rather than the reference itself. The reference hash is an
//! unsalted digest over the session auth context, and the receipt itself does
//! not carry it. A verifier holding the reference recomputes the commitment.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::super::validation::{require_exact, require_lowercase_hex_chars};
use crate::canonical::canonical_json_bytes;
use crate::crypto::sha256_hex;
use crate::error::{Error, Result};
use crate::session::SessionAnchorReference;

/// Top-level receipt metadata key of the block.
pub const SESSION_ANCHOR_METADATA_KEY: &str = "session_anchor";
/// Schema identifier the block pins.
pub const RECEIPT_SESSION_ANCHOR_SCHEMA: &str = "chio.receipt-session-anchor.v1";
const COMMITMENT_DOMAIN: &[u8] = b"chio.receipt-session-anchor.v1\0";

/// The receipt's own session anchor, as a commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptSessionAnchorV1 {
    pub schema: String,
    pub session_anchor_commitment: String,
}

fn commitment(reference: &SessionAnchorReference) -> Result<String> {
    let mut preimage: Vec<u8> = COMMITMENT_DOMAIN.to_vec();
    preimage.extend_from_slice(&canonical_json_bytes(reference)?);
    Ok(sha256_hex(&preimage))
}

impl ReceiptSessionAnchorV1 {
    /// Commit to `reference` for a receipt signed in its session.
    pub fn commit(reference: &SessionAnchorReference) -> Result<Self> {
        if reference.session_anchor_id.is_empty() || reference.session_anchor_hash.is_empty() {
            return Err(Error::CanonicalJson(
                "session anchor reference must name an id and a hash".into(),
            ));
        }
        Ok(Self {
            schema: RECEIPT_SESSION_ANCHOR_SCHEMA.into(),
            session_anchor_commitment: commitment(reference)?,
        })
    }

    /// Whether this block commits to exactly `reference`.
    pub fn binds(&self, reference: &SessionAnchorReference) -> Result<bool> {
        Ok(self.session_anchor_commitment == commitment(reference)?)
    }

    fn validate(&self) -> Result<()> {
        require_exact(
            &self.schema,
            RECEIPT_SESSION_ANCHOR_SCHEMA,
            "session_anchor.schema",
        )?;
        require_lowercase_hex_chars(
            &self.session_anchor_commitment,
            64,
            "session_anchor.session_anchor_commitment",
        )
    }

    /// Encode the block as the value of [`SESSION_ANCHOR_METADATA_KEY`].
    pub fn to_metadata_value(&self) -> Result<serde_json::Value> {
        self.validate()?;
        Ok(serde_json::to_value(self)?)
    }

    /// Read the block from receipt metadata. `Ok(None)` means the receipt has
    /// no block; a present block that is not exactly this shape is an error.
    pub fn from_receipt_metadata(metadata: Option<&serde_json::Value>) -> Result<Option<Self>> {
        let Some(value) = metadata.and_then(|metadata| metadata.get(SESSION_ANCHOR_METADATA_KEY))
        else {
            return Ok(None);
        };
        let block: Self = serde_json::from_value(value.clone())?;
        block.validate()?;
        Ok(Some(block))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference() -> SessionAnchorReference {
        SessionAnchorReference::new("sess-a:anchor:0:0123456789ab", "ab".repeat(32))
    }

    #[test]
    fn the_block_binds_exactly_its_reference() -> Result<()> {
        let block = ReceiptSessionAnchorV1::commit(&reference())?;
        assert!(block.binds(&reference())?);
        let other_id = SessionAnchorReference::new("sess-b:anchor:0:0123456789ab", "ab".repeat(32));
        let other_hash =
            SessionAnchorReference::new("sess-a:anchor:0:0123456789ab", "cd".repeat(32));
        assert!(!block.binds(&other_id)?);
        assert!(!block.binds(&other_hash)?);
        Ok(())
    }

    #[test]
    fn the_block_never_carries_the_reference_in_plaintext() -> Result<()> {
        let value = ReceiptSessionAnchorV1::commit(&reference())?.to_metadata_value()?;
        let text = value.to_string();
        assert!(!text.contains("sess-a"));
        assert!(!text.contains(&"ab".repeat(32)));
        Ok(())
    }

    #[test]
    fn absent_and_malformed_blocks_are_distinguished() -> Result<()> {
        assert_eq!(ReceiptSessionAnchorV1::from_receipt_metadata(None)?, None);
        assert_eq!(
            ReceiptSessionAnchorV1::from_receipt_metadata(Some(&serde_json::json!({})))?,
            None
        );
        let good = ReceiptSessionAnchorV1::commit(&reference())?.to_metadata_value()?;
        let mut extra = good.clone();
        extra["session_id"] = serde_json::json!("sess-a");
        let mut schema = good.clone();
        schema["schema"] = serde_json::json!("chio.receipt-session-anchor.v2");
        let mut short = good.clone();
        short["session_anchor_commitment"] = serde_json::json!("abcd");
        for block in [extra, schema, short, serde_json::json!("text")] {
            assert!(ReceiptSessionAnchorV1::from_receipt_metadata(Some(
                &serde_json::json!({ SESSION_ANCHOR_METADATA_KEY: block })
            ))
            .is_err());
        }
        Ok(())
    }
}
