#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_federation::trust_establishment::PeerHandshakeEnvelope;

const SEED: &str = include_str!(
    "../../../../fuzz/corpus/federation_trust_establishment/invalid-signature-envelope.json"
);

#[test]
fn committed_placeholder_handshake_envelope_is_refused() {
    let error = serde_json::from_str::<PeerHandshakeEnvelope>(SEED).unwrap_err();
    assert_eq!(error.classify(), serde_json::error::Category::Data);
    assert!(error
        .to_string()
        .starts_with("missing field `capabilities`"));
}
