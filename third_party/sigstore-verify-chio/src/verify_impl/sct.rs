//! Certificate Transparency SCT (Signed Certificate Timestamp) verification
//!
//! This module provides types and functions for verifying SCTs embedded in certificates,
//! as defined by RFC 6962. SCTs provide proof that a certificate has been submitted to
//! a Certificate Transparency log.

use crate::error::{Error, Result};
use const_oid::db::rfc6962::CT_PRECERT_SCTS;
use sigstore_crypto::{verify_signature, SigningScheme};
use sigstore_trust_root::TrustedRoot;
use sigstore_types::{DerPublicKey, SignatureBytes};
use tls_codec::{SerializeBytes, TlsByteVecU16, TlsByteVecU24, TlsSerializeBytes, TlsSize};
use x509_cert::{
    der::{Decode, Encode},
    ext::pkix::{sct::Version, SignedCertificateTimestamp, SignedCertificateTimestampList},
    Certificate,
};

// TLS SignatureAndHashAlgorithm constants (RFC 5246)
const ECDSA_SHA256: u16 = 0x0403;
const ECDSA_SHA384: u16 = 0x0503;
const RSA_PKCS1_SHA256: u16 = 0x0401;
const RSA_PKCS1_SHA384: u16 = 0x0501;
const RSA_PKCS1_SHA512: u16 = 0x0601;

/// SignatureType as defined in RFC 6962
#[derive(PartialEq, Debug, TlsSerializeBytes, TlsSize)]
#[repr(u8)]
enum SignatureType {
    CertificateTimestamp = 0,
    TreeHash = 1,
}

/// LogEntryType as defined in RFC 6962
#[derive(PartialEq, Debug)]
#[repr(u16)]
enum LogEntryType {
    X509Entry = 0,
    PrecertEntry = 1,
}

/// PreCert structure for precertificate entries
#[derive(PartialEq, Debug, TlsSerializeBytes, TlsSize)]
struct PreCert {
    /// SHA-256 hash of the issuer's SubjectPublicKeyInfo
    issuer_key_hash: [u8; 32],
    /// The TBSCertificate with SCT extension removed
    tbs_certificate: TlsByteVecU24,
}

/// SignedEntry enum for different log entry types
#[derive(PartialEq, Debug, TlsSerializeBytes, TlsSize)]
#[repr(u16)]
enum SignedEntry {
    #[allow(unused)]
    #[tls_codec(discriminant = "LogEntryType::X509Entry")]
    X509Entry(TlsByteVecU24),
    #[tls_codec(discriminant = "LogEntryType::PrecertEntry")]
    PrecertEntry(PreCert),
}

/// The digitally-signed structure that is verified against the CT log's signature
#[derive(PartialEq, Debug, TlsSerializeBytes, TlsSize)]
pub struct DigitallySigned {
    version: Version,
    signature_type: SignatureType,
    timestamp: u64,
    signed_entry: SignedEntry,
    extensions: TlsByteVecU16,

    // These fields are not encoded in the TLS blob, but needed for verification
    #[tls_codec(skip)]
    log_id: [u8; 32],
    #[tls_codec(skip)]
    signature: Vec<u8>,
}

impl DigitallySigned {
    /// Create a DigitallySigned from an embedded SCT in a certificate
    pub fn from_embedded_sct(
        cert: &Certificate,
        sct: &SignedCertificateTimestamp,
        issuer_key_hash: [u8; 32],
    ) -> Result<Self> {
        // Reconstruct the precertificate TBS by removing the SCT extension
        let mut tbs_precert = cert.tbs_certificate.clone();
        tbs_precert.extensions = tbs_precert.extensions.map(|exts| {
            exts.iter()
                .filter(|ext| ext.extn_id != CT_PRECERT_SCTS)
                .cloned()
                .collect()
        });

        let mut tbs_precert_der = Vec::new();
        tbs_precert
            .encode_to_vec(&mut tbs_precert_der)
            .map_err(|e| Error::Verification(format!("failed to encode precert TBS: {}", e)))?;

        Ok(DigitallySigned {
            version: match sct.version {
                Version::V1 => Version::V1,
            },
            signature_type: SignatureType::CertificateTimestamp,
            timestamp: sct.timestamp,
            signed_entry: SignedEntry::PrecertEntry(PreCert {
                issuer_key_hash,
                tbs_certificate: tbs_precert_der.as_slice().into(),
            }),
            extensions: sct.extensions.clone(),
            log_id: sct.log_id.key_id,
            signature: sct.signature.signature.clone().into(),
        })
    }

    /// Verify this DigitallySigned against a public key from the CT log and SCT signature
    pub fn verify(
        &self,
        public_key: &DerPublicKey,
        sig_alg: u16,
        signature: &SignatureBytes,
    ) -> Result<()> {
        // Serialize the signed data according to RFC 6962
        let signed_data = self
            .tls_serialize()
            .map_err(|e| Error::Verification(format!("failed to serialize SCT data: {}", e)))?;

        // Map the signature algorithm to a SigningScheme
        let scheme = match sig_alg {
            ECDSA_SHA256 => SigningScheme::EcdsaP256Sha256,
            ECDSA_SHA384 => SigningScheme::EcdsaP384Sha384,
            RSA_PKCS1_SHA256 => SigningScheme::RsaPkcs1Sha256,
            RSA_PKCS1_SHA384 => SigningScheme::RsaPkcs1Sha384,
            RSA_PKCS1_SHA512 => SigningScheme::RsaPkcs1Sha512,
            _ => {
                return Err(Error::Verification(format!(
                    "unsupported SCT signature algorithm: 0x{:04x}",
                    sig_alg
                )))
            }
        };

        verify_signature(public_key, &signed_data, signature, scheme)
            .map_err(|e| Error::Verification(format!("SCT signature verification failed: {}", e)))
    }
}

/// Extract the SCT from a certificate and prepare it for verification
pub fn extract_scts(
    cert: &Certificate,
    issuer_spki_der: &[u8],
) -> Result<(Vec<SignedCertificateTimestamp>, [u8; 32])> {
    // Extract the SCT list extension from the certificate
    let scts: SignedCertificateTimestampList = match cert.tbs_certificate.get() {
        Ok(Some((_, ext))) => ext,
        _ => {
            return Err(Error::Verification(
                "certificate is missing SCT extension (Signed Certificate Timestamp)".to_string(),
            ))
        }
    };

    // Parse the SCT structures
    let timestamps = scts
        .parse_timestamps()
        .map_err(|e| Error::Verification(format!("failed to parse SCT list: {:?}", e)))?;

    if timestamps.is_empty() {
        return Err(Error::Verification(
            "no SCTs found in certificate".to_string(),
        ));
    }
    let scts = timestamps
        .iter()
        .map(|timestamp| {
            timestamp
                .parse_timestamp()
                .map_err(|e| Error::Verification(format!("failed to parse SCT: {:?}", e)))
        })
        .collect::<Result<Vec<_>>>()?;

    // Calculate the issuer key hash (SHA-256 of issuer's SPKI)
    let issuer_key_hash = *sigstore_crypto::sha256(issuer_spki_der).as_bytes();

    Ok((scts, issuer_key_hash))
}

/// Verify the Signed Certificate Timestamp (SCT) embedded in the certificate
///
/// This is the main entry point for SCT verification. It extracts the SCT from the
/// certificate, reconstructs the signed data, and verifies it against the trusted
/// CT log keys.
pub fn verify_sct(
    cert_der: &[u8],
    issuer_spki_der: &[u8],
    trusted_root: &TrustedRoot,
) -> Result<()> {
    // Parse the certificate
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| Error::Verification(format!("failed to parse certificate: {}", e)))?;

    // Extract the SCT and calculate issuer key hash
    let (scts, issuer_key_hash) = extract_scts(&cert, issuer_spki_der)?;

    if trusted_root.ctlogs.is_empty() {
        return Err(Error::Verification(
            "no CT log keys in trusted root".to_string(),
        ));
    }

    const REQUIRED_TRUSTED_SCTS: usize = 1;
    let mut verified = 0_usize;
    let mut failures = Vec::new();
    for sct in scts {
        let result = (|| {
            let log_id = &sct.log_id.key_id;
            let ctlog = trusted_root
                .ctlogs
                .iter()
                .find(|ctlog| {
                    sigstore_crypto::sha256(ctlog.public_key.raw_bytes.as_bytes()).as_bytes()
                        == log_id
                })
                .ok_or_else(|| {
                    Error::Verification(format!(
                        "SCT log ID {:?} not found in trusted root CT logs",
                        hex::encode(log_id)
                    ))
                })?;
            let timestamp_seconds = i64::try_from(sct.timestamp / 1_000).map_err(|_| {
                Error::Verification("SCT timestamp cannot be represented".to_string())
            })?;
            let timestamp_nanos = u32::try_from((sct.timestamp % 1_000) * 1_000_000)
                .map_err(|_| Error::Verification("SCT timestamp is invalid".to_string()))?;
            let timestamp = chrono::DateTime::from_timestamp(timestamp_seconds, timestamp_nanos)
                .ok_or_else(|| {
                    Error::Verification("SCT timestamp cannot be represented".to_string())
                })?;
            if !super::helpers::validity_period_contains_datetime(
                ctlog.public_key.valid_for.as_ref(),
                timestamp,
                "CT log key",
            )? {
                return Err(Error::Verification(format!(
                    "CT log key is outside its validity period at SCT timestamp {}",
                    sct.timestamp
                )));
            }
            let digitally_signed =
                DigitallySigned::from_embedded_sct(&cert, &sct, issuer_key_hash)?;
            let sig_alg_bytes = sct.signature.algorithm.tls_serialize().map_err(|e| {
                Error::Verification(format!("failed to serialize signature algorithm: {}", e))
            })?;
            let sig_alg = u16::from_be_bytes([sig_alg_bytes[0], sig_alg_bytes[1]]);
            let signature = SignatureBytes::new(sct.signature.signature.clone().into_vec());
            digitally_signed.verify(&ctlog.public_key.raw_bytes, sig_alg, &signature)
        })();
        match result {
            Ok(()) => {
                verified += 1;
                if verified >= REQUIRED_TRUSTED_SCTS {
                    return Ok(());
                }
            }
            Err(error) => failures.push(error.to_string()),
        }
    }

    Err(Error::Verification(format!(
        "certificate has {verified} verified SCTs, requires {REQUIRED_TRUSTED_SCTS}: {}",
        failures.join("; ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigstore_types::Bundle;
    use x509_cert::{
        der::{asn1::OctetString, Encode},
        ext::pkix::sct::SerializedSct,
    };

    const COSIGN_V3_BLOB_BUNDLE: &str =
        include_str!("../../test_data/bundles/cosign-v3-blob.sigstore.json");

    #[test]
    fn extract_sct_accepts_multiple_timestamps() {
        let bundle = Bundle::from_json(COSIGN_V3_BLOB_BUNDLE).expect("cosign bundle");
        let certificate = bundle.signing_certificate().expect("signing certificate");
        let mut cert = Certificate::from_der(certificate.as_bytes()).expect("certificate");
        let existing: SignedCertificateTimestampList = cert
            .tbs_certificate
            .get()
            .expect("SCT extension decode")
            .expect("SCT extension")
            .1;
        let serialized = existing.parse_timestamps().expect("timestamp list");
        let first = serialized[0].parse_timestamp().expect("first SCT");
        let second = serialized[0].parse_timestamp().expect("second SCT");
        let duplicate = SignedCertificateTimestampList::new(&[
            SerializedSct::new(first).expect("serialized first SCT"),
            SerializedSct::new(second).expect("serialized second SCT"),
        ])
        .expect("duplicate SCT list");
        let extension = cert
            .tbs_certificate
            .extensions
            .as_mut()
            .and_then(|extensions| {
                extensions
                    .iter_mut()
                    .find(|extension| extension.extn_id == CT_PRECERT_SCTS)
            })
            .expect("SCT extension");
        extension.extn_value =
            OctetString::new(duplicate.to_der().expect("encoded SCT list")).expect("octets");

        let extracted = extract_scts(&cert, b"issuer SPKI")
            .expect("a certificate with redundant SCTs must remain verifiable");

        assert_eq!(extracted.0.len(), 2);

        let trusted_root = TrustedRoot::production().expect("production root");
        let issuer_spki = trusted_root
            .fulcio_certs()
            .expect("Fulcio certificates")
            .into_iter()
            .filter_map(|der| Certificate::from_der(&der).ok())
            .find(|issuer| issuer.tbs_certificate.subject == cert.tbs_certificate.issuer)
            .expect("matching issuer")
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .expect("issuer SPKI");
        let cert_der = cert.to_der().expect("certificate DER");

        verify_sct(&cert_der, &issuer_spki, &trusted_root)
            .expect("one valid SCT must satisfy the verification threshold");
    }

    #[test]
    fn sct_rejects_a_ct_key_outside_its_authority_window() {
        let bundle = Bundle::from_json(COSIGN_V3_BLOB_BUNDLE).expect("cosign bundle");
        let certificate = bundle.signing_certificate().expect("signing certificate");
        let cert = Certificate::from_der(certificate.as_bytes()).expect("certificate");
        let scts: SignedCertificateTimestampList = cert
            .tbs_certificate
            .get()
            .expect("SCT extension decode")
            .expect("SCT extension")
            .1;
        let sct = scts.parse_timestamps().expect("SCT list")[0]
            .parse_timestamp()
            .expect("SCT");
        let mut trusted_root = TrustedRoot::production().expect("production root");
        let matching_log = trusted_root
            .ctlogs
            .iter_mut()
            .find(|log| {
                sigstore_crypto::sha256(log.public_key.raw_bytes.as_bytes()).as_bytes()
                    == &sct.log_id.key_id
            })
            .expect("matching CT log");
        matching_log.public_key.valid_for = Some(sigstore_trust_root::ValidityPeriod {
            start: Some("2999-01-01T00:00:00Z".to_string()),
            end: None,
        });
        let issuer_spki = trusted_root
            .fulcio_certs()
            .expect("Fulcio certificates")
            .into_iter()
            .filter_map(|der| Certificate::from_der(&der).ok())
            .find(|issuer| issuer.tbs_certificate.subject == cert.tbs_certificate.issuer)
            .expect("matching issuer")
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .expect("issuer SPKI");

        let error = verify_sct(certificate.as_bytes(), &issuer_spki, &trusted_root)
            .expect_err("an inactive CT log key must not verify an SCT");

        assert!(error.to_string().contains("validity period"));
    }
}
