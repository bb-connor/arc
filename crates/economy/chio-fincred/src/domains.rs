//! Financial source identity domains shared by issuer and verifier.

pub const FINANCIAL_SOURCE_ARTIFACT_DIGEST_DOMAIN: &[u8] = b"chio.fincred.source-artifact.v1\0";
pub const FINANCIAL_SOURCE_DISCLOSURE_DIGEST_DOMAIN: &[u8] = b"chio.fincred.source-disclosure.v1\0";

#[cfg(test)]
mod identity_fixture_tests {
    use super::*;

    #[test]
    fn shared_identifiers_match_canonical_fixture() -> Result<(), Box<dyn std::error::Error>> {
        let fixtures: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../../spec/fixtures/shared-security-identifiers.json"
        ))?;
        for identity in [
            FINANCIAL_SOURCE_ARTIFACT_DIGEST_DOMAIN,
            FINANCIAL_SOURCE_DISCLOSURE_DIGEST_DOMAIN,
        ] {
            let text = std::str::from_utf8(identity)?;
            let fixture = fixtures
                .iter()
                .find(|row| row["identity"].as_str() == Some(text))
                .ok_or("missing independent identity fixture")?;
            let payload: serde_json::Value = serde_json::from_str(
                fixture["canonical_payload"]
                    .as_str()
                    .ok_or("fixture payload")?,
            )?;
            let canonical = chio_core_types::canonical_json_bytes(&payload)?;
            assert_eq!(
                std::str::from_utf8(&canonical)?,
                fixture["canonical_payload"]
                    .as_str()
                    .ok_or("fixture canonical bytes")?
            );
            let mut preimage = identity.to_vec();
            preimage.extend_from_slice(&canonical);
            assert_eq!(
                chio_core_types::sha256_hex(&preimage),
                fixture["sha256"].as_str().ok_or("fixture digest")?
            );
        }
        Ok(())
    }
}
