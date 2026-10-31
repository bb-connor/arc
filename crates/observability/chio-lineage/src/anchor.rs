//! Anchor pinning.
//!
//! Hashes the current lineage frontier through canonical bytes and
//! records a frontier digest. PQ signing is performed by the hybrid
//! signing backend when present (soft-dep); when absent, the command
//! produces an unsigned frontier and exits cleanly. Soft-dep absence is
//! recorded explicitly on the artifact so model-card anchoring can
//! distinguish a verified anchor from a degraded unsigned one.

use serde::{Deserialize, Serialize};

use chio_core_types::canonical::{canonical_json_bytes, CanonicalBytes};
use chio_core_types::crypto::{sha256_hex, verify_wrapped_bytes, PublicKey, Signature};

use crate::schema::{LineageEdge, LineageGraph, LineageNode};

/// Signing-wrapper schema id of a lineage frontier signature.
pub const LINEAGE_FRONTIER_SIGNATURE_SCHEMA: &str = "chio.lineage.frontier-signature.v1";

/// SHA-256 of the canonical JSON of a frontier projection. The frontier
/// is a deterministic sorted list of node ids and edge keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontierDigest {
    pub algo: String,
    pub hex: String,
}

/// Source of the canonical bytes used to compute the digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalSource {
    /// The `CanonicalBytes` newtype.
    CanonicalBytes,
    /// Documented byte-equivalence shim. Used when `CanonicalBytes` is absent.
    EquivalenceShim,
}

/// Soft-dep state for hybrid signing.
///
/// The `Signed` variant carries a signature payload from an external
/// signer. The artifact does not carry a trusted key, so consumers must
/// verify it with [`verify_frontier_signature`] or [`AnchoredFrontier::is_signed_by`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningState {
    /// Hybrid signing was used. The signature payload is included.
    Signed {
        algorithm: String,
        signature_hex: String,
    },
    /// Hybrid signing was absent. Frontier is recorded unsigned.
    UnsignedSoftDepAbsent,
    /// A signer was named but the soft-dep produced no signature payload.
    /// Distinct from `UnsignedSoftDepAbsent` so model-card anchoring can
    /// surface the partial-signing path explicitly. Verifiers MUST treat
    /// this state as unsigned.
    UnsignedSignerStubbed { algorithm: String },
}

/// The pinned-frontier artifact produced by [`pin_frontier`] or
/// [`pin_frontier_signed`]. `chio lineage roots` reads artifacts of this
/// shape from a directory; it does not produce them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchoredFrontier {
    pub schema_version: String,
    pub graph_schema: String,
    pub canonical_source: CanonicalSource,
    pub digest: FrontierDigest,
    pub signing: SigningState,
    pub node_count: usize,
    pub edge_count: usize,
}

/// Compute the canonical frontier projection bytes, sorted by node id and
/// edge key.
pub fn frontier_bytes(graph: &LineageGraph) -> Result<Vec<u8>, AnchorError> {
    let mut node_ids: Vec<&str> = graph
        .nodes
        .iter()
        .map(|n: &LineageNode| n.id.as_str())
        .collect();
    node_ids.sort_unstable();
    let mut edges = graph
        .edges
        .iter()
        .map(|e: &LineageEdge| {
            let kind = serde_json::to_string(&e.kind).map_err(not_canonical)?;
            Ok((e.from.clone(), e.to.clone(), kind))
        })
        .collect::<Result<Vec<(String, String, String)>, AnchorError>>()?;
    edges.sort_unstable();
    let payload = serde_json::json!({
        "schema_version": graph.schema_version,
        "nodes": node_ids,
        "edges": edges,
    });
    canonical_json_bytes(&payload).map_err(not_canonical)
}

fn not_canonical(error: impl std::fmt::Display) -> AnchorError {
    AnchorError::FrontierNotCanonical(error.to_string())
}

/// Stable sha256 hex digest of the frontier bytes.
pub fn frontier_digest(graph: &LineageGraph) -> Result<FrontierDigest, AnchorError> {
    Ok(FrontierDigest {
        algo: "sha256".to_string(),
        hex: sha256_hex(&frontier_bytes(graph)?),
    })
}

/// Canonical body the frontier signature wraps: the hex frontier bytes.
pub fn frontier_signature_body(graph: &LineageGraph) -> Result<CanonicalBytes, AnchorError> {
    use std::fmt::Write as _;
    let mut frontier = String::new();
    for byte in frontier_bytes(graph)? {
        let _ = write!(frontier, "{byte:02x}");
    }
    CanonicalBytes::from_value(&serde_json::json!({ "frontier": frontier }))
        .map_err(|error| AnchorError::SignaturePayloadInvalid(error.to_string()))
}

/// Pin a lineage frontier. Records the digest plus signing state. When
/// `signer_hint` is `None` the artifact is recorded as
/// `UnsignedSoftDepAbsent`. A signer hint without a signature payload
/// records `UnsignedSignerStubbed { algorithm }` rather than
/// `Signed { signature_hex: "" }`, so a verifier cannot mistake a
/// stub for a real PQ signature. Real signing is produced through
/// [`pin_frontier_signed`].
pub fn pin_frontier(
    graph: &LineageGraph,
    signer_hint: Option<&str>,
) -> Result<AnchoredFrontier, AnchorError> {
    let digest = frontier_digest(graph)?;
    let signing = match signer_hint {
        Some(algo) => SigningState::UnsignedSignerStubbed {
            algorithm: algo.to_string(),
        },
        None => SigningState::UnsignedSoftDepAbsent,
    };
    Ok(AnchoredFrontier {
        schema_version: "chio.lineage.frontier/v1".to_string(),
        graph_schema: graph.schema_version.clone(),
        canonical_source: CanonicalSource::CanonicalBytes,
        digest,
        signing,
        node_count: graph.nodes.len(),
        edge_count: graph.edges.len(),
    })
}

/// Return true when a signature payload is non-empty even-length lower-case hex.
#[must_use]
pub fn is_lowercase_hex_signature_payload(signature_hex: &str) -> bool {
    !signature_hex.is_empty()
        && signature_hex.len().is_multiple_of(2)
        && signature_hex
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_canonical_signing_algorithm_label(algorithm: &str) -> bool {
    !algorithm.is_empty() && algorithm.chars().all(|ch| !ch.is_whitespace())
}

/// Pin a frontier with a PQ signature payload.
///
/// The payload shape is validated and the signature must verify against
/// the caller-provided trusted signer key before the artifact is marked
/// `Signed`.
pub fn pin_frontier_signed(
    graph: &LineageGraph,
    algorithm: &str,
    trusted_signer: &PublicKey,
    signature_hex: &str,
) -> Result<AnchoredFrontier, AnchorError> {
    if algorithm.trim().is_empty() {
        return Err(AnchorError::EmptySigningAlgorithm);
    }
    if !is_canonical_signing_algorithm_label(algorithm) {
        return Err(AnchorError::InvalidSigningAlgorithmLabel);
    }
    if signature_hex.is_empty() {
        return Err(AnchorError::EmptySignaturePayload);
    }
    if !is_lowercase_hex_signature_payload(signature_hex) {
        return Err(AnchorError::SignaturePayloadNotHex);
    }
    let signature = Signature::from_hex(signature_hex)
        .map_err(|error| AnchorError::SignaturePayloadInvalid(error.to_string()))?;
    if verify_wrapped_bytes(
        trusted_signer,
        LINEAGE_FRONTIER_SIGNATURE_SCHEMA,
        &frontier_signature_body(graph)?,
        &signature,
    )
    .is_err()
    {
        return Err(AnchorError::SignatureVerificationFailed);
    }
    let digest = frontier_digest(graph)?;
    Ok(AnchoredFrontier {
        schema_version: "chio.lineage.frontier/v1".to_string(),
        graph_schema: graph.schema_version.clone(),
        canonical_source: CanonicalSource::CanonicalBytes,
        digest,
        signing: SigningState::Signed {
            algorithm: algorithm.to_string(),
            signature_hex: signature_hex.to_string(),
        },
        node_count: graph.nodes.len(),
        edge_count: graph.edges.len(),
    })
}

/// Verify a pinned frontier signature against a caller-provided trusted key.
///
/// The anchor artifact does not carry its own trusted key, so callers must
/// provide the authority key they already trust. This avoids treating an
/// attacker-supplied signature and attacker-supplied key as sufficient
/// proof of lineage authenticity.
pub fn verify_frontier_signature(
    frontier: &AnchoredFrontier,
    graph: &LineageGraph,
    trusted_signer: &PublicKey,
) -> Result<(), AnchorError> {
    let expected_digest = frontier_digest(graph)?;
    if frontier.digest != expected_digest {
        return Err(AnchorError::DigestMismatch);
    }
    let SigningState::Signed {
        algorithm,
        signature_hex,
    } = &frontier.signing
    else {
        return Err(AnchorError::UnsignedFrontier);
    };
    if !is_canonical_signing_algorithm_label(algorithm) {
        return Err(AnchorError::InvalidSigningAlgorithmLabel);
    }
    if !is_lowercase_hex_signature_payload(signature_hex) {
        return Err(AnchorError::SignaturePayloadNotHex);
    }
    let signature = Signature::from_hex(signature_hex)
        .map_err(|error| AnchorError::SignaturePayloadInvalid(error.to_string()))?;
    if verify_wrapped_bytes(
        trusted_signer,
        LINEAGE_FRONTIER_SIGNATURE_SCHEMA,
        &frontier_signature_body(graph)?,
        &signature,
    )
    .is_err()
    {
        return Err(AnchorError::SignatureVerificationFailed);
    }
    Ok(())
}

/// Errors surfaced when constructing a signed anchor.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AnchorError {
    /// The frontier projection could not be canonicalized.
    #[error("frontier could not be canonicalized: {0}")]
    FrontierNotCanonical(String),
    /// The signing algorithm label was empty.
    #[error("signing algorithm label was empty")]
    EmptySigningAlgorithm,
    /// The signing algorithm label contained whitespace.
    #[error("signing algorithm label was not canonical")]
    InvalidSigningAlgorithmLabel,
    /// The signature payload was empty.
    #[error("signature payload was empty")]
    EmptySignaturePayload,
    /// The signature payload was not lower-case hexadecimal.
    #[error("signature payload was not lower-case hexadecimal")]
    SignaturePayloadNotHex,
    /// The signature payload could not be parsed by the configured crypto backend.
    #[error("signature payload is invalid: {0}")]
    SignaturePayloadInvalid(String),
    /// The signature does not verify against the trusted signer key.
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    /// The anchor digest does not match the supplied graph.
    #[error("frontier digest does not match graph")]
    DigestMismatch,
    /// The frontier is not signed.
    #[error("frontier is unsigned")]
    UnsignedFrontier,
}

impl AnchoredFrontier {
    /// Return true only when the artifact carries a locally verified
    /// signature. This no-context helper has no trusted key, so it treats
    /// every current state as unsigned for fail-closed consumers.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        false
    }

    /// Return true when the frontier verifies against a caller-provided
    /// trusted signer key.
    #[must_use]
    pub fn is_signed_by(&self, graph: &LineageGraph, trusted_signer: &PublicKey) -> bool {
        verify_frontier_signature(self, graph, trusted_signer).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core_types::crypto::Keypair;

    #[test]
    fn pin_without_signer_records_unsigned_state() {
        let g = LineageGraph::empty();
        let pinned =
            pin_frontier(&g, None).unwrap_or_else(|error| panic!("frontier pins: {error}"));
        assert!(matches!(
            pinned.signing,
            SigningState::UnsignedSoftDepAbsent
        ));
        assert_eq!(pinned.digest.algo, "sha256");
        assert!(!pinned.is_signed());
    }

    #[test]
    fn pin_is_byte_stable_across_runs() {
        let g = LineageGraph::empty();
        let a = frontier_digest(&g)
            .unwrap_or_else(|error| panic!("frontier digests: {error}"))
            .hex;
        let b = frontier_digest(&g)
            .unwrap_or_else(|error| panic!("frontier digests: {error}"))
            .hex;
        assert_eq!(a, b);
    }

    #[test]
    fn pin_with_signer_hint_does_not_forge_signed_state() {
        // Regression: a signer hint without an actual signature must not
        // produce a `Signed { signature_hex: "" }` state. A verifier
        // checking `is_signed()` would otherwise be deceived by an
        // anchor that carries no signature payload.
        let g = LineageGraph::empty();
        let pinned = pin_frontier(&g, Some("ml-dsa-65"))
            .unwrap_or_else(|error| panic!("frontier pins: {error}"));
        assert!(matches!(
            pinned.signing,
            SigningState::UnsignedSignerStubbed { .. }
        ));
        assert!(!pinned.is_signed());
    }

    #[test]
    fn pin_signed_rejects_empty_signature() {
        let g = LineageGraph::empty();
        let keypair = Keypair::from_seed(&[7_u8; 32]);
        let err = pin_frontier_signed(&g, "ml-dsa-65", &keypair.public_key(), "")
            .err()
            .unwrap_or(AnchorError::EmptySigningAlgorithm);
        assert_eq!(err, AnchorError::EmptySignaturePayload);
    }

    #[test]
    fn pin_signed_rejects_non_hex_signature() {
        let g = LineageGraph::empty();
        let keypair = Keypair::from_seed(&[7_u8; 32]);
        let err = pin_frontier_signed(&g, "ml-dsa-65", &keypair.public_key(), "ZZZZ")
            .err()
            .unwrap_or(AnchorError::EmptySigningAlgorithm);
        assert_eq!(err, AnchorError::SignaturePayloadNotHex);
    }

    #[test]
    fn deserialized_signed_state_with_malformed_payload_is_unsigned() {
        for signature_hex in ["DEADBEEF", "dead beef", " deadbeef", "zz", "f"] {
            let value = serde_json::json!({
                "schema_version": "chio.lineage.frontier/v1",
                "graph_schema": "chio.lineage.graph/v1",
                "canonical_source": "equivalence_shim",
                "digest": {
                    "algo": "sha256",
                    "hex": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                },
                "signing": {
                    "signed": {
                        "algorithm": "ml-dsa-65",
                        "signature_hex": signature_hex
                    }
                },
                "node_count": 0,
                "edge_count": 0
            });
            let decoded: AnchoredFrontier = serde_json::from_value(value)
                .unwrap_or_else(|err| panic!("deserialize signed state: {err}"));
            assert!(
                !decoded.is_signed(),
                "malformed signature payload {signature_hex:?} must be unsigned"
            );
        }
    }

    #[test]
    fn pin_signed_rejects_empty_algorithm() {
        let g = LineageGraph::empty();
        let keypair = Keypair::from_seed(&[7_u8; 32]);
        let err = pin_frontier_signed(&g, "  ", &keypair.public_key(), "deadbeef")
            .err()
            .unwrap_or(AnchorError::EmptySignaturePayload);
        assert_eq!(err, AnchorError::EmptySigningAlgorithm);
    }

    #[test]
    fn pin_signed_rejects_whitespace_wrapped_algorithm_label() {
        let g = LineageGraph::empty();
        let keypair = Keypair::from_seed(&[7_u8; 32]);
        let err = pin_frontier_signed(&g, " ed25519 ", &keypair.public_key(), "deadbeef")
            .err()
            .unwrap_or(AnchorError::EmptySignaturePayload);
        assert_eq!(err, AnchorError::InvalidSigningAlgorithmLabel);
    }

    #[test]
    fn pin_signed_rejects_unparseable_payload() {
        let g = LineageGraph::empty();
        let keypair = Keypair::from_seed(&[7_u8; 32]);
        let err = pin_frontier_signed(&g, "ed25519", &keypair.public_key(), "deadbeef")
            .err()
            .unwrap_or(AnchorError::EmptySignaturePayload);
        assert!(matches!(err, AnchorError::SignaturePayloadInvalid(_)));
    }

    #[test]
    fn pin_signed_with_trusted_key_verifies() {
        let g = LineageGraph::empty();
        let keypair = Keypair::from_seed(&[7_u8; 32]);
        let body = frontier_signature_body(&g)
            .unwrap_or_else(|error| panic!("frontier body canonicalizes: {error}"));
        let signature = keypair
            .sign_wrapped(LINEAGE_FRONTIER_SIGNATURE_SCHEMA, &body)
            .unwrap_or_else(|error| panic!("frontier signs: {error}"));
        let pinned = pin_frontier_signed(&g, "ed25519", &keypair.public_key(), &signature.to_hex())
            .unwrap_or_else(|error| panic!("signed pin should verify: {error}"));
        assert!(!pinned.is_signed());
        assert!(pinned.is_signed_by(&g, &keypair.public_key()));
        assert!(verify_frontier_signature(&pinned, &g, &keypair.public_key()).is_ok());
    }

    #[test]
    fn verify_signed_frontier_rejects_wrong_key() {
        let g = LineageGraph::empty();
        let keypair = Keypair::from_seed(&[7_u8; 32]);
        let wrong_keypair = Keypair::from_seed(&[8_u8; 32]);
        let body = frontier_signature_body(&g)
            .unwrap_or_else(|error| panic!("frontier body canonicalizes: {error}"));
        let signature = keypair
            .sign_wrapped(LINEAGE_FRONTIER_SIGNATURE_SCHEMA, &body)
            .unwrap_or_else(|error| panic!("frontier signs: {error}"));
        let pinned = pin_frontier_signed(&g, "ed25519", &keypair.public_key(), &signature.to_hex())
            .unwrap_or_else(|error| panic!("signed pin should verify: {error}"));
        let err = verify_frontier_signature(&pinned, &g, &wrong_keypair.public_key())
            .err()
            .unwrap_or(AnchorError::EmptySignaturePayload);
        assert_eq!(err, AnchorError::SignatureVerificationFailed);
    }

    #[test]
    fn verify_signed_frontier_rejects_noncanonical_algorithm_label() {
        let g = LineageGraph::empty();
        let keypair = Keypair::from_seed(&[7_u8; 32]);
        let body = frontier_signature_body(&g)
            .unwrap_or_else(|error| panic!("frontier body canonicalizes: {error}"));
        let signature = keypair
            .sign_wrapped(LINEAGE_FRONTIER_SIGNATURE_SCHEMA, &body)
            .unwrap_or_else(|error| panic!("frontier signs: {error}"));
        let signature_hex = signature.to_hex();
        let mut pinned = pin_frontier_signed(&g, "ed25519", &keypair.public_key(), &signature_hex)
            .unwrap_or_else(|error| panic!("signed pin should verify: {error}"));
        pinned.signing = SigningState::Signed {
            algorithm: "ed25519\n".to_string(),
            signature_hex,
        };

        let err = verify_frontier_signature(&pinned, &g, &keypair.public_key())
            .err()
            .unwrap_or(AnchorError::EmptySignaturePayload);

        assert_eq!(err, AnchorError::InvalidSigningAlgorithmLabel);
        assert!(!pinned.is_signed_by(&g, &keypair.public_key()));
    }
}
