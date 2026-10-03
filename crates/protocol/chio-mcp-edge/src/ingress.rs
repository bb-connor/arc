//! Bounded MCP envelope parsing with original-byte validation of invocation proofs.
use chio_core::canonical::{UntrustedJsonError, UntrustedJsonText};
use serde::Deserialize;
use serde_json::{value::RawValue, Value};

#[derive(Deserialize)]
struct Envelope {
    params: Option<Box<RawValue>>,
}
#[derive(Deserialize)]
struct Params {
    #[serde(rename = "_meta")]
    meta: Option<Box<RawValue>>,
}
#[derive(Deserialize)]
struct Meta {
    #[serde(rename = "chioDpopProof")]
    proof: Option<Box<RawValue>>,
}

/// Validate the signed proof slice before projecting the unsigned envelope to `Value`.
/// Duplicate fields anywhere still reject; normal producer decimals in arguments work.
pub fn decode_mcp_request(bytes: &[u8], bound: usize) -> Result<Value, UntrustedJsonError> {
    let wire = UntrustedJsonText::from_wire(bytes, bound)?;
    // Malformed RPC parameter shapes belong to the protocol dispatcher. In
    // particular, invalid notifications must remain response-free. Only walk
    // object projections, retaining the original proof slice at every level.
    if bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        == Some(b'{')
    {
        let envelope: Envelope =
            serde_json::from_slice(bytes).map_err(UntrustedJsonError::Decode)?;
        if let Some(params) = envelope.params.filter(|raw| raw.get().starts_with('{')) {
            let params: Params =
                serde_json::from_str(params.get()).map_err(UntrustedJsonError::Decode)?;
            if let Some(meta) = params.meta.filter(|raw| raw.get().starts_with('{')) {
                let meta: Meta =
                    serde_json::from_str(meta.get()).map_err(UntrustedJsonError::Decode)?;
                if let Some(proof) = meta.proof {
                    let _: chio_kernel::dpop::DpopProof =
                        UntrustedJsonText::from_wire(proof.get().as_bytes(), bound)?
                            .decode_signed()?;
                }
            }
        }
    }
    wire.decode_document()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inbound_authority_original_proof_preserves_integers_and_rejects_duplicates(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = chio_core::crypto::Keypair::generate();
        let proof = chio_kernel::DpopProof::sign(
            chio_kernel::DpopProofBody {
                schema: chio_kernel::DPOP_SCHEMA.into(),
                replay_authority: None,
                capability_id: "cap".into(),
                tool_server: "srv".into(),
                tool_name: "read".into(),
                action_hash: chio_core::sha256_hex(b"{}"),
                nonce: "proof".into(),
                issued_at: 1,
                agent_key: key.public_key(),
            },
            &key,
        )?;
        let honest_proof = serde_json::to_string(
            &serde_json::json!({"params":{"_meta":{"chioDpopProof":proof}}}),
        )?;
        assert!(decode_mcp_request(honest_proof.as_bytes(), 4096).is_ok());
        // The native signed contract preserves the complete u64 domain.
        let full_width =
            honest_proof.replace("\"issued_at\":1", "\"issued_at\":18446744073709551615");
        assert!(decode_mcp_request(full_width.as_bytes(), 4096).is_ok());
        // A Value projection alone would collapse this to the honest proof.
        let malicious = honest_proof.replace(
            "\"nonce\":\"proof\"",
            "\"nonce\":\"shadow\",\"nonce\":\"proof\"",
        );
        assert_ne!(malicious, honest_proof);
        let projected: serde_json::Value = serde_json::from_str(&malicious)?;
        let collapsed: chio_kernel::DpopProof =
            serde_json::from_value(projected["params"]["_meta"]["chioDpopProof"].clone())?;
        assert_eq!(collapsed, proof);
        assert!(decode_mcp_request(malicious.as_bytes(), 4096).is_err());
        let duplicate = br#"{"params":{"_meta":{"chioDpopProof":{},"chioDpopProof":null}}}"#;
        assert!(decode_mcp_request(duplicate, 4096).is_err());
        let honest = br#"{"params":{"arguments":{"ratio":0.50,"tiny":1e-5}}}"#;
        assert!(decode_mcp_request(honest, 4096).is_ok());
        Ok(())
    }
}
