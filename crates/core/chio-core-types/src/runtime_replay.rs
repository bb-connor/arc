//! Identity of independently sealed runtime replay sources.

pub const RUNTIME_REPLAY_SOURCE_SCHEMA: &str = "chio.runtime-replay-source-seal.v1";
pub const RUNTIME_REPLAY_SOURCE_DOMAIN: &[u8] = b"chio.runtime-replay-source-seal.v1\0";

#[cfg(test)]
mod identity_fixture_tests {
    use super::*;

    #[test]
    fn shared_identifiers_match_canonical_fixture() -> Result<(), Box<dyn std::error::Error>> {
        let fixtures: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../../spec/fixtures/shared-security-identifiers.json"
        ))?;
        for identity in [
            RUNTIME_REPLAY_SOURCE_DOMAIN,
            RUNTIME_REPLAY_SOURCE_SCHEMA.as_bytes(),
            crate::security_event::EVENT_EVIDENCE_HASH_DOMAIN,
            crate::security_event::EVENT_RECEIPT_EVIDENCE_HASH_DOMAIN,
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
            let canonical = crate::canonical_json_bytes(&payload)?;
            assert_eq!(
                std::str::from_utf8(&canonical)?,
                fixture["canonical_payload"]
                    .as_str()
                    .ok_or("fixture canonical bytes")?
            );
            let mut preimage = identity.to_vec();
            preimage.extend_from_slice(&canonical);
            assert_eq!(
                crate::sha256_hex(&preimage),
                fixture["sha256"].as_str().ok_or("fixture digest")?
            );
        }
        Ok(())
    }
}
