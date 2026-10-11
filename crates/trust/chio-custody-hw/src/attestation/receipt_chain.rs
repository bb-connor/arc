//! Bounded structural parsing of mobile receipt and attestation envelopes.
//!
//! These values carry no verification or authorization claim. Device evidence
//! must pass the platform verifier with trusted pins and issuer challenge binding.

use serde::Deserialize;

use super::errors::AttestationError;

const PLATFORM_APP_ATTEST: &str = "app_attest";
const PLATFORM_PLAY_INTEGRITY: &str = "play_integrity";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMobileReceiptEnvelopes {
    pub receipt_schema: String,
    pub evidence_schema: String,
    pub platform: String,
}

#[derive(Debug, Deserialize)]
struct ReceiptEnvelope {
    schema: String,
}

#[derive(Debug, Deserialize)]
struct EvidenceEnvelope {
    schema: String,
    platform: String,
}

pub fn parse_mobile_receipt_envelopes(
    receipt_json: &str,
    evidence_json: &str,
) -> Result<ParsedMobileReceiptEnvelopes, AttestationError> {
    let receipt: ReceiptEnvelope = chio_core_types::canonical::UntrustedJsonText::from_wire(
        receipt_json.as_bytes(),
        1024 * 1024,
    )?
    .decode_signed()?;
    let evidence: EvidenceEnvelope = chio_core_types::canonical::UntrustedJsonText::from_wire(
        evidence_json.as_bytes(),
        1024 * 1024,
    )?
    .decode_signed()?;
    if receipt.schema.is_empty() {
        return Err(AttestationError::InvalidCbor(
            "receipt schema must be a non-empty string".to_string(),
        ));
    }
    if evidence.schema.is_empty() {
        return Err(AttestationError::InvalidCbor(
            "evidence schema must be a non-empty string".to_string(),
        ));
    }
    if evidence.platform != PLATFORM_APP_ATTEST && evidence.platform != PLATFORM_PLAY_INTEGRITY {
        return Err(AttestationError::UnsupportedFormat(evidence.platform));
    }
    Ok(ParsedMobileReceiptEnvelopes {
        receipt_schema: receipt.schema,
        evidence_schema: evidence.schema,
        platform: evidence.platform,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn envelope_parse_rejects_duplicate_ignored_evidence_fields() {
        let result = parse_mobile_receipt_envelopes(
            r#"{"schema":"receipt"}"#,
            r#"{"schema":"evidence","platform":"app_attest","extra":{"x":1,"x":2}}"#,
        );
        assert!(matches!(result, Err(AttestationError::Input(_))));
    }
}
