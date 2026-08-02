//! Rekor transparency log entry validation
//!
//! This module handles validation of different Rekor entry types against
//! bundle content to ensure consistency.

use crate::error::{Error, Result};
use base64::Engine;
use serde::Deserialize;
use sigstore_rekor::body::RekorEntryBody;
use sigstore_types::{
    Bundle, DerCertificate, DerPublicKey, PemContent, SignatureBytes, SignatureContent,
    TransparencyLogEntry,
};

#[derive(Clone, Copy)]
pub enum ExpectedDsseVerifier<'a> {
    Certificate(&'a DerCertificate),
    PublicKey(&'a DerPublicKey),
}

#[derive(Deserialize)]
struct IntotoBodyWithVerifiers {
    spec: IntotoSpecWithVerifiers,
}

#[derive(Deserialize)]
struct IntotoSpecWithVerifiers {
    content: IntotoContentWithVerifiers,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IntotoContentWithVerifiers {
    envelope: IntotoEnvelopeWithVerifiers,
    payload_hash: IntotoPayloadHash,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IntotoEnvelopeWithVerifiers {
    payload_type: String,
    signatures: Vec<IntotoSignatureWithVerifier>,
}

#[derive(Deserialize)]
struct IntotoPayloadHash {
    algorithm: String,
    value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IntotoSignatureWithVerifier {
    sig: SignatureBytes,
    public_key: PemContent,
}

/// Verify DSSE envelope matches Rekor entry (for DSSE bundles)
pub fn verify_dsse_entries(bundle: &Bundle) -> Result<usize> {
    let envelope = match &bundle.content {
        SignatureContent::DsseEnvelope(env) => env,
        _ => return Ok(0), // Not a DSSE bundle
    };

    let mut verified = 0;
    for entry in &bundle.verification_material.tlog_entries {
        if entry.kind_version.kind == "dsse" {
            match entry.kind_version.version.as_str() {
                "0.0.1" => {
                    verify_dsse_v001(entry, envelope, bundle)?;
                    verified += 1;
                }
                "0.0.2" => {
                    verify_dsse_v002(entry, envelope, bundle)?;
                    verified += 1;
                }
                _ => {} // Unknown version, skip
            }
        }
    }

    Ok(verified)
}

/// Verify DSSE v0.0.1 entry
///
/// NOTE: This does NOT verify the envelope hash.
/// The envelope hash in DSSE v0.0.1 entries cannot be reliably verified because:
/// 1. The hash is computed over uncanonicalized JSON during submission to Rekor
/// 2. JSON serialization can vary (field ordering, whitespace) between implementations
/// 3. We cannot reproduce the exact JSON representation that was originally submitted
///
/// Instead, we verify:
/// - Payload hash (hash of envelope.payload bytes)
/// - Signatures list matches between entry and envelope (both signature and verifier)
fn verify_dsse_v001(
    entry: &TransparencyLogEntry,
    envelope: &sigstore_types::DsseEnvelope,
    bundle: &Bundle,
) -> Result<()> {
    let body = RekorEntryBody::from_base64_json(
        &entry.canonicalized_body.to_base64(),
        &entry.kind_version.kind,
        &entry.kind_version.version,
    )
    .map_err(|e| Error::Verification(format!("failed to parse Rekor body: {}", e)))?;

    let (expected_hash, rekor_signatures) = match &body {
        RekorEntryBody::DsseV001(dsse_body) => (
            &dsse_body.spec.payload_hash.value,
            &dsse_body.spec.signatures,
        ),
        _ => {
            return Err(Error::Verification(
                "expected DSSE v0.0.1 body, got different type".to_string(),
            ))
        }
    };

    // Verify payload hash (v0.0.1 uses hex encoding)
    let payload_bytes = envelope.payload.as_bytes();
    let payload_hash = sigstore_crypto::sha256(payload_bytes);
    let payload_hash_hex = hex::encode(payload_hash);

    if &payload_hash_hex != expected_hash {
        return Err(Error::Verification(format!(
            "DSSE payload hash mismatch: computed {}, expected {}",
            payload_hash_hex, expected_hash
        )));
    }

    let cert = bundle.signing_certificate();

    // Verify that the signatures in the bundle match what's in Rekor
    // This prevents signature substitution attacks
    // Certificate-based bundles bind both the signature bytes and verifier certificate.
    // Managed-key bundles bind the exact signature here and verify it against the supplied
    // public key in `verify_with_key`.
    if envelope.signatures.len() != rekor_signatures.len() {
        return Err(Error::Verification(format!(
            "DSSE signature count mismatch: bundle has {}, Rekor entry has {}",
            envelope.signatures.len(),
            rekor_signatures.len()
        )));
    }

    // Check that each signature in the bundle exists in the Rekor entry
    // We must match both the signature AND the verifier to prevent signature substitution
    for bundle_sig in &envelope.signatures {
        let mut found = false;
        for rekor_sig in rekor_signatures {
            let verifier_matches = if let Some(cert) = cert {
                let rekor_cert_der = rekor_sig
                    .to_certificate()
                    .map_err(|e| Error::Verification(format!("{}", e)))?;
                cert.as_bytes() == rekor_cert_der.as_bytes()
            } else {
                true
            };

            if bundle_sig.sig.as_bytes() == rekor_sig.signature.as_bytes() && verifier_matches {
                found = true;
                break;
            }
        }
        if !found {
            return Err(Error::Verification(
                "DSSE signature in bundle does not match any signature in Rekor entry (signature or verifier mismatch)".to_string(),
            ));
        }
    }

    Ok(())
}

/// Verify DSSE v0.0.2 entry (payload hash and signature validation)
fn verify_dsse_v002(
    entry: &TransparencyLogEntry,
    envelope: &sigstore_types::DsseEnvelope,
    bundle: &Bundle,
) -> Result<()> {
    let body = RekorEntryBody::from_base64_json(
        &entry.canonicalized_body.to_base64(),
        &entry.kind_version.kind,
        &entry.kind_version.version,
    )
    .map_err(|e| Error::Verification(format!("failed to parse Rekor body: {}", e)))?;

    let (expected_hash, rekor_signatures) = match &body {
        RekorEntryBody::DsseV002(dsse_body) => (
            &dsse_body.spec.dsse_v002.payload_hash.digest,
            &dsse_body.spec.dsse_v002.signatures,
        ),
        _ => {
            return Err(Error::Verification(
                "expected DSSE v0.0.2 body, got different type".to_string(),
            ))
        }
    };

    // Compute actual payload hash
    let payload_bytes = envelope.payload.as_bytes();
    let payload_hash = sigstore_crypto::sha256(payload_bytes);

    // Compare hashes (expected_hash is Vec<u8>)
    if payload_hash.as_slice() != expected_hash.as_slice() {
        return Err(Error::Verification(format!(
            "DSSE payload hash mismatch: computed {}, expected {}",
            hex::encode(payload_hash),
            hex::encode(expected_hash)
        )));
    }

    let cert = bundle.signing_certificate();

    // Verify that the signatures in the bundle match what's in Rekor
    // This prevents signature substitution attacks
    // Certificate-based bundles bind both the signature bytes and verifier certificate.
    // Managed-key bundles bind the exact signature here and verify it against the supplied
    // public key in `verify_with_key`.

    if envelope.signatures.len() != rekor_signatures.len() {
        return Err(Error::Verification(format!(
            "DSSE signature count mismatch: bundle has {}, Rekor entry has {}",
            envelope.signatures.len(),
            rekor_signatures.len()
        )));
    }

    // Check that each signature in the bundle exists in the Rekor entry
    // We must match both the signature AND the verifier to prevent signature substitution
    for bundle_sig in &envelope.signatures {
        let mut found = false;
        for rekor_sig in rekor_signatures {
            let verifier_matches = match cert {
                Some(cert) => {
                    cert.as_bytes() == rekor_sig.verifier.x509_certificate.raw_bytes.as_bytes()
                }
                None => true,
            };
            if bundle_sig.sig.as_bytes() == rekor_sig.content.as_bytes() && verifier_matches {
                found = true;
                break;
            }
        }
        if !found {
            return Err(Error::Verification(
                "DSSE signature in bundle does not match any signature in Rekor entry (signature or verifier mismatch)".to_string(),
            ));
        }
    }

    Ok(())
}

/// Verify DSSE payload matches what's in Rekor (for intoto entries)
pub fn verify_intoto_entries(
    bundle: &Bundle,
    expected_verifier: ExpectedDsseVerifier<'_>,
) -> Result<usize> {
    let envelope = match &bundle.content {
        SignatureContent::DsseEnvelope(env) => env,
        _ => return Ok(0), // Not a DSSE bundle
    };

    let mut verified = 0;
    for entry in &bundle.verification_material.tlog_entries {
        if entry.kind_version.kind == "intoto" {
            verify_intoto_v002(entry, envelope, expected_verifier)?;
            verified += 1;
        }
    }

    Ok(verified)
}

/// Verify intoto v0.0.2 entry
fn verify_intoto_v002(
    entry: &TransparencyLogEntry,
    envelope: &sigstore_types::DsseEnvelope,
    expected_verifier: ExpectedDsseVerifier<'_>,
) -> Result<()> {
    if entry.kind_version.version != "0.0.2" {
        return Err(Error::Verification(
            "unsupported intoto Rekor entry version".to_string(),
        ));
    }
    let body: IntotoBodyWithVerifiers = serde_json::from_slice(entry.canonicalized_body.as_bytes())
        .map_err(|e| {
            Error::Verification(format!("failed to parse intoto v0.0.2 Rekor body: {e}"))
        })?;
    let logged_envelope = &body.spec.content.envelope;
    if logged_envelope.payload_type != envelope.payload_type {
        return Err(Error::Verification(
            "DSSE payload type in bundle does not match intoto Rekor entry".to_string(),
        ));
    }
    if body.spec.content.payload_hash.algorithm != "sha256" {
        return Err(Error::Verification(
            "intoto Rekor payload hash must use sha256".to_string(),
        ));
    }
    let payload_hash = hex::encode(sigstore_crypto::sha256(envelope.payload.as_bytes()));
    if payload_hash != body.spec.content.payload_hash.value {
        return Err(Error::Verification(
            "DSSE payload in bundle does not match intoto Rekor payload hash".to_string(),
        ));
    }
    if envelope.signatures.len() != 1 || logged_envelope.signatures.len() != 1 {
        return Err(Error::Verification(
            "intoto v0.0.2 verification requires exactly one bundle and Rekor signature"
                .to_string(),
        ));
    }

    let rekor_sig_decoded = base64::engine::general_purpose::STANDARD
        .decode(logged_envelope.signatures[0].sig.as_bytes())
        .map_err(|e| Error::Verification(format!("failed to decode Rekor signature: {e}")))?;
    if envelope.signatures[0].sig.as_bytes() != rekor_sig_decoded.as_slice() {
        return Err(Error::Verification(
            "DSSE signature in bundle does not match intoto Rekor entry".to_string(),
        ));
    }

    verify_intoto_verifier_identity(&logged_envelope.signatures[0].public_key, expected_verifier)?;

    Ok(())
}

fn verify_intoto_verifier_identity(
    logged_verifier: &PemContent,
    expected_verifier: ExpectedDsseVerifier<'_>,
) -> Result<()> {
    let pem = std::str::from_utf8(logged_verifier.as_bytes()).map_err(|e| {
        Error::Verification(format!("intoto Rekor verifier is not valid UTF-8: {e}"))
    })?;
    match expected_verifier {
        ExpectedDsseVerifier::Certificate(expected) => {
            let logged = DerCertificate::from_pem(pem).map_err(|e| {
                Error::Verification(format!(
                    "intoto Rekor verifier is not a valid certificate: {e}"
                ))
            })?;
            if logged.as_bytes() != expected.as_bytes() {
                return Err(Error::Verification(
                    "intoto Rekor verifier certificate does not match the bundle signer"
                        .to_string(),
                ));
            }
        }
        ExpectedDsseVerifier::PublicKey(expected) => {
            let logged = match DerCertificate::from_pem(pem) {
                Ok(certificate) => {
                    sigstore_crypto::parse_certificate_info(certificate.as_bytes())
                        .map_err(|e| {
                            Error::Verification(format!(
                                "failed to parse intoto Rekor verifier certificate: {e}"
                            ))
                        })?
                        .public_key
                }
                Err(_) => DerPublicKey::from_pem(pem).map_err(|e| {
                    Error::Verification(format!(
                        "intoto Rekor verifier is not a valid certificate or public key: {e}"
                    ))
                })?,
            };
            if logged.as_bytes() != expected.as_bytes() {
                return Err(Error::Verification(
                    "intoto Rekor verifier public key does not match the managed signer"
                        .to_string(),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTOTO_BUNDLE: &str = include_str!("../../test_data/bundles/dsse.sigstore.json");
    const MULTISIG_INTOTO_BUNDLE: &str =
        include_str!("../../test_data/bundles/dsse-2sigs.sigstore.json");
    const UNRELATED_CERTIFICATE_BUNDLE: &str =
        include_str!("../../test_data/bundles/cosign-v3-blob.sigstore.json");

    fn intoto_parts(bundle: &Bundle) -> (&TransparencyLogEntry, &sigstore_types::DsseEnvelope) {
        let envelope = match &bundle.content {
            SignatureContent::DsseEnvelope(envelope) => envelope,
            _ => panic!("expected DSSE envelope"),
        };
        (&bundle.verification_material.tlog_entries[0], envelope)
    }

    #[test]
    fn intoto_entry_binds_the_only_signature_and_certificate() {
        let bundle = Bundle::from_json(INTOTO_BUNDLE).expect("intoto bundle");
        let certificate = bundle.signing_certificate().expect("signing certificate");
        let (entry, envelope) = intoto_parts(&bundle);

        verify_intoto_v002(
            entry,
            envelope,
            ExpectedDsseVerifier::Certificate(certificate),
        )
        .expect("signature and verifier identity must match");
    }

    #[test]
    fn intoto_entry_rejects_ambiguous_multisignature_identity() {
        let bundle = Bundle::from_json(MULTISIG_INTOTO_BUNDLE).expect("multisig bundle");
        let certificate = bundle.signing_certificate().expect("signing certificate");
        let (entry, envelope) = intoto_parts(&bundle);

        let error = verify_intoto_v002(
            entry,
            envelope,
            ExpectedDsseVerifier::Certificate(certificate),
        )
        .expect_err("intoto v0.0.2 does not identify multiple signers unambiguously");
        assert!(error.to_string().contains("requires exactly one"));
    }

    #[test]
    fn intoto_entry_rejects_an_unrelated_verifier_identity() {
        let bundle = Bundle::from_json(INTOTO_BUNDLE).expect("intoto bundle");
        let unrelated =
            Bundle::from_json(UNRELATED_CERTIFICATE_BUNDLE).expect("unrelated certificate bundle");
        let unrelated_certificate = unrelated
            .signing_certificate()
            .expect("unrelated signing certificate");
        let (entry, envelope) = intoto_parts(&bundle);

        let error = verify_intoto_v002(
            entry,
            envelope,
            ExpectedDsseVerifier::Certificate(unrelated_certificate),
        )
        .expect_err("logged verifier identity must match the authenticated signer");
        assert!(error
            .to_string()
            .contains("does not match the bundle signer"));
    }
}
