//! Helper functions for verification
//!
//! This module contains extracted helper functions to break down the
//! large verification logic into manageable pieces.

use crate::error::{Error, Result};
use const_oid::db::rfc5912::ID_KP_CODE_SIGNING;
use rustls_pki_types::{CertificateDer, UnixTime};
use sigstore_crypto::CertificateInfo;
use sigstore_trust_root::{TrustedRoot, ValidityPeriod};
use sigstore_types::bundle::VerificationMaterialContent;
use sigstore_types::{Bundle, DerCertificate, DerPublicKey, SignatureBytes, SignatureContent};
use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage, ALL_VERIFICATION_ALGS};

pub(crate) fn validity_period_contains(
    valid_for: Option<&ValidityPeriod>,
    timestamp: i64,
    authority: &str,
) -> Result<bool> {
    let timestamp = chrono::DateTime::from_timestamp(timestamp, 0).ok_or_else(|| {
        Error::Verification(format!("{authority} validation time cannot be represented"))
    })?;
    validity_period_contains_datetime(valid_for, timestamp, authority)
}

pub(crate) fn validity_period_contains_datetime(
    valid_for: Option<&ValidityPeriod>,
    timestamp: chrono::DateTime<chrono::Utc>,
    authority: &str,
) -> Result<bool> {
    let Some(valid_for) = valid_for else {
        return Ok(true);
    };
    let start = valid_for
        .start
        .as_deref()
        .map(chrono::DateTime::parse_from_rfc3339)
        .transpose()
        .map_err(|error| {
            Error::Verification(format!(
                "{authority} validity period has an invalid start: {error}"
            ))
        })?;
    let end = valid_for
        .end
        .as_deref()
        .map(chrono::DateTime::parse_from_rfc3339)
        .transpose()
        .map_err(|error| {
            Error::Verification(format!(
                "{authority} validity period has an invalid end: {error}"
            ))
        })?;

    Ok(start.as_ref().map_or(true, |start| timestamp >= *start)
        && end.as_ref().map_or(true, |end| timestamp <= *end))
}

fn timestamp_signer_certificate(
    timestamp_token_bytes: &[u8],
    trusted_root: &TrustedRoot,
) -> Result<DerCertificate> {
    use cms::{
        cert::CertificateChoices,
        content_info::ContentInfo,
        signed_data::{SignedData, SignerIdentifier},
    };
    use x509_cert::{
        der::{Decode, Encode},
        Certificate,
    };

    let content_info = match sigstore_tsa::TimeStampResp::from_der(timestamp_token_bytes) {
        Ok(response) => {
            let token = response.time_stamp_token.ok_or_else(|| {
                Error::Verification("TSA response is missing its timestamp token".to_string())
            })?;
            let token_der = token.to_der().map_err(|error| {
                Error::Verification(format!("failed to encode TSA timestamp token: {error}"))
            })?;
            ContentInfo::from_der(&token_der).map_err(|error| {
                Error::Verification(format!("failed to parse TSA timestamp token: {error}"))
            })?
        }
        Err(_) => ContentInfo::from_der(timestamp_token_bytes).map_err(|error| {
            Error::Verification(format!("failed to parse TSA timestamp token: {error}"))
        })?,
    };
    let signed_data_der = content_info.content.to_der().map_err(|error| {
        Error::Verification(format!("failed to encode TSA signed data: {error}"))
    })?;
    let signed_data = SignedData::from_der(&signed_data_der).map_err(|error| {
        Error::Verification(format!("failed to parse TSA signed data: {error}"))
    })?;
    let signer = signed_data
        .signer_infos
        .0
        .get(0)
        .ok_or_else(|| Error::Verification("TSA token has no signer info".to_string()))?;
    let mut certificates = Vec::new();
    if let Some(embedded) = &signed_data.certificates {
        certificates.extend(embedded.0.iter().filter_map(|choice| match choice {
            CertificateChoices::Certificate(certificate) => Some(certificate.clone()),
            CertificateChoices::Other(_) => None,
        }));
    }
    certificates.extend(
        trusted_root
            .timestamp_authorities
            .iter()
            .filter_map(|authority| authority.cert_chain.certificates.first())
            .filter_map(|entry| Certificate::from_der(entry.raw_bytes.as_bytes()).ok()),
    );
    let certificate = certificates
        .into_iter()
        .find(|certificate| match &signer.sid {
            SignerIdentifier::IssuerAndSerialNumber(issuer_serial) => {
                certificate.tbs_certificate.issuer == issuer_serial.issuer
                    && certificate.tbs_certificate.serial_number == issuer_serial.serial_number
            }
            SignerIdentifier::SubjectKeyIdentifier(expected) => certificate
                .tbs_certificate
                .extensions
                .as_ref()
                .and_then(|extensions| {
                    extensions
                        .iter()
                        .find(|extension| extension.extn_id.to_string() == "2.5.29.14")
                })
                .and_then(|extension| {
                    x509_cert::ext::pkix::SubjectKeyIdentifier::from_der(
                        extension.extn_value.as_bytes(),
                    )
                    .ok()
                })
                .is_some_and(|actual| &actual == expected),
        })
        .ok_or_else(|| {
            Error::Verification("TSA signer certificate is not present or trusted".to_string())
        })?;
    certificate
        .to_der()
        .map(DerCertificate::new)
        .map_err(|error| {
            Error::Verification(format!("failed to encode TSA signer certificate: {error}"))
        })
}

/// Extract and decode the signing certificate from verification material
pub fn extract_certificate(
    verification_material: &VerificationMaterialContent,
) -> Result<DerCertificate> {
    match verification_material {
        VerificationMaterialContent::Certificate(cert) => Ok(cert.raw_bytes.clone()),
        VerificationMaterialContent::X509CertificateChain { certificates } => {
            if certificates.is_empty() {
                return Err(Error::Verification("no certificates in chain".to_string()));
            }
            Ok(certificates[0].raw_bytes.clone())
        }
        VerificationMaterialContent::PublicKey { .. } => Err(Error::Verification(
            "public key verification not yet supported".to_string(),
        )),
    }
}

/// Extract signature from bundle content (needed for TSA verification)
pub fn extract_signature(content: &SignatureContent) -> Result<SignatureBytes> {
    match content {
        SignatureContent::MessageSignature(msg_sig) => Ok(msg_sig.signature.clone()),
        SignatureContent::DsseEnvelope(envelope) => {
            if envelope.signatures.is_empty() {
                return Err(Error::Verification(
                    "no signatures in DSSE envelope".to_string(),
                ));
            }
            Ok(envelope.signatures[0].sig.clone())
        }
    }
}

/// Extract and verify TSA RFC 3161 timestamps
/// Returns the earliest verified timestamp if any are present
pub fn extract_tsa_timestamp(
    bundle: &Bundle,
    signature_bytes: &[u8],
    trusted_root: &TrustedRoot,
) -> Result<Option<i64>> {
    use sigstore_tsa::{verify_timestamp_response, VerifyOpts as TsaVerifyOpts};

    // Check if bundle has TSA timestamps
    if bundle
        .verification_material
        .timestamp_verification_data
        .rfc3161_timestamps
        .is_empty()
    {
        return Ok(None);
    }

    let mut earliest_timestamp: Option<i64> = None;
    let mut failures = Vec::new();

    for ts in &bundle
        .verification_material
        .timestamp_verification_data
        .rfc3161_timestamps
    {
        // Get the timestamp bytes
        let ts_bytes = ts.signed_timestamp.as_bytes();

        // Build verification options from trusted root
        let mut opts = TsaVerifyOpts::new();

        // Get TSA root certificates
        if let Ok(tsa_roots) = trusted_root.tsa_root_certs() {
            opts = opts.with_roots(tsa_roots);
        }

        // Get TSA intermediate certificates
        if let Ok(tsa_intermediates) = trusted_root.tsa_intermediate_certs() {
            opts = opts.with_intermediates(tsa_intermediates);
        }

        // Get ALL TSA leaf certificates (there may be multiple TSAs)
        if let Ok(tsa_leaves) = trusted_root.tsa_leaf_certs() {
            opts = opts.with_tsa_certificates(tsa_leaves);
        }

        let attempt = (|| {
            let result =
                verify_timestamp_response(ts_bytes, signature_bytes, opts).map_err(|e| {
                    Error::Verification(format!("TSA timestamp verification failed: {e}"))
                })?;
            let signer = timestamp_signer_certificate(ts_bytes, trusted_root)?;
            let authority = trusted_root
                .timestamp_authorities
                .iter()
                .find(|authority| {
                    authority
                        .cert_chain
                        .certificates
                        .first()
                        .is_some_and(|entry| entry.raw_bytes == signer)
                })
                .ok_or_else(|| {
                    Error::Verification(
                        "TSA signer certificate does not identify a trusted authority".to_string(),
                    )
                })?;
            if !validity_period_contains_datetime(
                authority.valid_for.as_ref(),
                result.time,
                "TSA authority",
            )? {
                return Err(Error::Verification(format!(
                    "TSA authority is outside its validity period at timestamp {}",
                    result.time
                )));
            }
            Ok(result.time.timestamp())
        })();

        match attempt {
            Ok(timestamp) => {
                earliest_timestamp =
                    Some(earliest_timestamp.map_or(timestamp, |earliest| earliest.min(timestamp)));
            }
            Err(error) => failures.push(error.to_string()),
        }
    }

    if earliest_timestamp.is_none() {
        return Err(Error::Verification(format!(
            "TSA timestamps present but none could be verified against trusted root: {}",
            failures.join("; ")
        )));
    }

    Ok(earliest_timestamp)
}

/// Check if bundle contains V2 tlog entries (hashedrekord/dsse v0.0.2).
///
/// The legacy `intoto` schema also uses version 0.0.2, but it has V1 SET and
/// integrated-time semantics.
pub fn has_v2_tlog_entries(bundle: &Bundle) -> bool {
    bundle
        .verification_material
        .tlog_entries
        .iter()
        .any(|entry| {
            matches!(entry.kind_version.kind.as_str(), "hashedrekord" | "dsse")
                && entry.kind_version.version == "0.0.2"
        })
}

/// Determine validation time from timestamps.
///
/// At least one verified timestamp source is REQUIRED. This matches sigstore-python's
/// behavior which enforces `VERIFIED_TIME_THRESHOLD = 1`.
///
/// Valid timestamp sources (in priority order):
/// 1. TSA timestamp (RFC 3161) - most authoritative
/// 2. Integrated time from V1 tlog entries with inclusion promises
///
/// Note: There is NO fallback to current time. If no verified timestamp is found,
/// verification fails.
pub fn determine_validation_time(
    bundle: &Bundle,
    signature: &SignatureBytes,
    trusted_root: &TrustedRoot,
    content_bound_v1_integrated_time: Option<i64>,
) -> Result<i64> {
    // Try TSA timestamp first (most authoritative)
    if let Some(tsa_time) = extract_tsa_timestamp(bundle, signature.as_bytes(), trusted_root)? {
        return Ok(tsa_time);
    }

    if has_v2_tlog_entries(bundle) {
        return Err(Error::Verification(
            "V2 bundle requires RFC3161 timestamp but none could be verified. \
             V2 tlog entries have integrated_time=0 by design. \
             Ensure TSA certificates are present in the trusted root."
                .to_string(),
        ));
    }

    // The caller supplies time only after verifying that the exact V1 entry is
    // bound to this bundle's content and signer identity.
    if let Some(integrated_time) = content_bound_v1_integrated_time {
        return Ok(integrated_time);
    }

    // No verified timestamp found - fail verification
    // This matches sigstore-python's behavior: "not enough sources of verified time"
    Err(Error::Verification(
        "No verified timestamp found. V1 bundles require either an RFC3161 timestamp \
         or a tlog entry with both integrated_time > 0 and an inclusion_promise (SET)."
            .to_string(),
    ))
}

/// Determine certificate validation time from a verified-log time source only.
///
/// This deliberately ignores RFC 3161 material for callers that selected
/// `skip_timestamp`. The later transparency-log verification still validates
/// the inclusion promise that makes the integrated time authoritative.
pub fn determine_validation_time_from_tlog(
    bundle: &Bundle,
    content_bound_v1_integrated_time: Option<i64>,
) -> Result<i64> {
    if has_v2_tlog_entries(bundle) {
        return Err(Error::Verification(
            "timestamp verification is disabled and V2 transparency-log content has no signed integrated time"
                .to_string(),
        ));
    }
    if let Some(integrated_time) = content_bound_v1_integrated_time {
        return Ok(integrated_time);
    }
    Err(Error::Verification(
        "timestamp verification is disabled and no V1 transparency-log entry provides a signed integrated time"
            .to_string(),
    ))
}

/// Validate certificate is within validity period
pub fn validate_certificate_time(validation_time: i64, cert_info: &CertificateInfo) -> Result<()> {
    if validation_time < cert_info.not_before {
        return Err(Error::Verification(format!(
            "certificate not yet valid: validation time {} is before not_before {}",
            validation_time, cert_info.not_before
        )));
    }

    if validation_time > cert_info.not_after {
        return Err(Error::Verification(format!(
            "certificate has expired: validation time {} is after not_after {}",
            validation_time, cert_info.not_after
        )));
    }

    Ok(())
}

/// Verify the certificate chain to the Fulcio root of trust
///
/// This function verifies that the signing certificate chains to a trusted
/// Fulcio root certificate at the given verification time. It also verifies
/// that the certificate has the CODE_SIGNING extended key usage.
pub fn verify_certificate_chain(
    verification_material: &VerificationMaterialContent,
    validation_time: i64,
    trusted_root: &TrustedRoot,
) -> Result<()> {
    // Extract the end-entity certificate and any intermediates from the bundle
    let (ee_cert_der, intermediate_ders) = match verification_material {
        VerificationMaterialContent::Certificate(cert) => {
            (cert.raw_bytes.as_bytes().to_vec(), Vec::new())
        }
        VerificationMaterialContent::X509CertificateChain { certificates } => {
            if certificates.is_empty() {
                return Err(Error::Verification("no certificates in chain".to_string()));
            }
            let ee = certificates[0].raw_bytes.as_bytes().to_vec();
            let intermediates: Vec<Vec<u8>> = certificates[1..]
                .iter()
                .map(|c| c.raw_bytes.as_bytes().to_vec())
                .collect();
            (ee, intermediates)
        }
        VerificationMaterialContent::PublicKey { .. } => {
            return Err(Error::Verification(
                "public key verification not yet supported".to_string(),
            ));
        }
    };

    // Only authorities active at the trusted validation time may become trust
    // anchors. Retaining a retired CA in the root supports historical artifacts,
    // but must not extend that CA's signing authority.
    let mut fulcio_certs = Vec::new();
    for authority in &trusted_root.certificate_authorities {
        if !validity_period_contains(
            authority.valid_for.as_ref(),
            validation_time,
            "Fulcio authority",
        )? {
            continue;
        }
        fulcio_certs.extend(authority.cert_chain.certificates.iter().map(|certificate| {
            CertificateDer::from(certificate.raw_bytes.as_bytes()).into_owned()
        }));
    }

    if fulcio_certs.is_empty() {
        return Err(Error::Verification(
            "no Fulcio certificates are active in the trust root validity period".to_string(),
        ));
    }

    // Build trust anchors from Fulcio root certificates
    let trust_anchors: Vec<_> = fulcio_certs
        .iter()
        .filter_map(|cert_der| {
            let cert = CertificateDer::from(&cert_der[..]);
            anchor_from_trusted_cert(&cert)
                .map(|anchor| anchor.to_owned())
                .ok()
        })
        .collect();

    if trust_anchors.is_empty() {
        return Err(Error::Verification(
            "failed to create trust anchors from Fulcio certificates".to_string(),
        ));
    }

    // Convert intermediate certificates to CertificateDer
    let intermediate_certs: Vec<CertificateDer<'static>> = intermediate_ders
        .into_iter()
        .map(|der| CertificateDer::from(der).into_owned())
        .collect();

    // Parse the end-entity certificate for webpki
    let ee_cert_der_ref = CertificateDer::from(ee_cert_der.as_slice());
    let end_entity_cert = EndEntityCert::try_from(&ee_cert_der_ref).map_err(|e| {
        Error::Verification(format!("failed to parse end-entity certificate: {}", e))
    })?;

    // Convert validation time to webpki UnixTime
    let verification_time =
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(validation_time as u64));

    // Verify the certificate chain with CODE_SIGNING EKU
    // This performs:
    // - Chain building from end-entity to trust anchor
    // - Signature verification at each step
    // - Time validity checking
    // - Extended Key Usage validation (CODE_SIGNING)
    end_entity_cert
        .verify_for_usage(
            ALL_VERIFICATION_ALGS,
            &trust_anchors,
            &intermediate_certs,
            verification_time,
            KeyUsage::required(ID_KP_CODE_SIGNING.as_bytes()),
            None, // No CRL/OCSP revocation checking (matches sigstore-python)
            None, // No custom path validation callback needed
        )
        .map_err(|e| Error::Verification(format!("certificate chain validation failed: {}", e)))?;

    tracing::debug!("Certificate chain validated successfully with CODE_SIGNING EKU");

    Ok(())
}

/// Verify the Signed Certificate Timestamp (SCT) embedded in the certificate
///
/// SCTs provide proof that the certificate was submitted to a Certificate
/// Transparency log. This is a key part of Sigstore's security model.
///
/// This function uses the x509-cert crate's built-in SCT parsing and tls_codec
/// for proper RFC 6962 compliant verification.
pub fn verify_sct(
    verification_material: &VerificationMaterialContent,
    validation_time: i64,
    trusted_root: &TrustedRoot,
) -> Result<()> {
    // Extract certificate for verification
    let cert = extract_certificate(verification_material)?;

    // Get issuer SPKI for calculating the issuer key hash
    let issuer_spki = get_issuer_spki(verification_material, &cert, validation_time, trusted_root)?;

    // Delegate to the new sct module for verification
    super::sct::verify_sct(cert.as_bytes(), issuer_spki.as_bytes(), trusted_root)
}

/// Get the issuer's SubjectPublicKeyInfo DER bytes
///
/// This tries to find the issuer certificate in the verification material chain
/// or in the trusted root, and returns its SPKI for SCT verification.
fn get_issuer_spki(
    verification_material: &VerificationMaterialContent,
    cert: &DerCertificate,
    validation_time: i64,
    trusted_root: &TrustedRoot,
) -> Result<DerPublicKey> {
    use x509_cert::der::Decode;
    use x509_cert::Certificate;

    let parsed_cert = Certificate::from_der(cert.as_bytes())
        .map_err(|e| Error::Verification(format!("failed to parse certificate: {}", e)))?;
    let issuer_name = &parsed_cert.tbs_certificate.issuer;

    // Prefer a supplied intermediate, but require it to be the key that
    // actually signed the leaf. Chain validation has already established that
    // supplied intermediates lead to an active trusted authority.
    if let VerificationMaterialContent::X509CertificateChain { certificates } =
        verification_material
    {
        for candidate in certificates.iter().skip(1) {
            if let Some(spki) = issuer_spki_if_signs(
                cert,
                issuer_name,
                candidate.raw_bytes.as_bytes(),
                validation_time,
            )? {
                return Ok(spki);
            }
        }
    }

    // Search only authorities active at the trusted validation time. Subject
    // equality is insufficient during key rotation because old and new Fulcio
    // intermediates can share a name.
    for authority in &trusted_root.certificate_authorities {
        if !validity_period_contains(
            authority.valid_for.as_ref(),
            validation_time,
            "Fulcio authority",
        )? {
            continue;
        }
        for candidate in &authority.cert_chain.certificates {
            if let Some(spki) = issuer_spki_if_signs(
                cert,
                issuer_name,
                candidate.raw_bytes.as_bytes(),
                validation_time,
            )? {
                return Ok(spki);
            }
        }
    }

    Err(Error::Verification(
        "could not find issuer certificate for SCT verification".to_string(),
    ))
}

fn issuer_spki_if_signs(
    leaf: &DerCertificate,
    issuer_name: &x509_cert::name::Name,
    candidate_der: &[u8],
    validation_time: i64,
) -> Result<Option<DerPublicKey>> {
    use x509_cert::der::{Decode, Encode};
    use x509_cert::Certificate;

    let candidate = match Certificate::from_der(candidate_der) {
        Ok(candidate) if &candidate.tbs_certificate.subject == issuer_name => candidate,
        Ok(_) | Err(_) => return Ok(None),
    };
    let leaf_der = CertificateDer::from(leaf.as_bytes());
    let end_entity = EndEntityCert::try_from(&leaf_der).map_err(|error| {
        Error::Verification(format!("failed to parse end-entity certificate: {error}"))
    })?;
    let candidate_der = CertificateDer::from(candidate_der);
    let Ok(anchor) = anchor_from_trusted_cert(&candidate_der) else {
        return Ok(None);
    };
    let verification_time = u64::try_from(validation_time)
        .map(std::time::Duration::from_secs)
        .map(UnixTime::since_unix_epoch)
        .map_err(|_| Error::Verification("certificate validation time is negative".to_string()))?;
    if end_entity
        .verify_for_usage(
            ALL_VERIFICATION_ALGS,
            &[anchor],
            &[],
            verification_time,
            KeyUsage::required(ID_KP_CODE_SIGNING.as_bytes()),
            None,
            None,
        )
        .is_err()
    {
        return Ok(None);
    }
    let spki = candidate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|error| Error::Verification(format!("failed to encode issuer SPKI: {error}")))?;
    Ok(Some(DerPublicKey::new(spki)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigstore_crypto::parse_certificate_info;
    use sigstore_trust_root::ValidityPeriod;
    use sigstore_types::bundle::Rfc3161Timestamp;
    use x509_cert::der::{Decode, Encode};
    use x509_cert::Certificate;

    const COSIGN_V3_BLOB_BUNDLE: &str =
        include_str!("../../test_data/bundles/cosign-v3-blob.sigstore.json");

    #[test]
    fn certificate_chain_rejects_fulcio_anchors_outside_their_authority_window() {
        let bundle = Bundle::from_json(COSIGN_V3_BLOB_BUNDLE).expect("cosign bundle");
        let certificate = bundle.signing_certificate().expect("signing certificate");
        let certificate_info =
            parse_certificate_info(certificate.as_bytes()).expect("certificate info");
        let mut trusted_root = TrustedRoot::production().expect("production root");
        for authority in &mut trusted_root.certificate_authorities {
            authority.valid_for = Some(ValidityPeriod {
                start: Some("2999-01-01T00:00:00Z".to_string()),
                end: None,
            });
        }

        let error = verify_certificate_chain(
            &bundle.verification_material.content,
            certificate_info.not_before,
            &trusted_root,
        )
        .expect_err("an inactive Fulcio authority must not become a trust anchor");

        assert!(error.to_string().contains("validity period"));
    }

    #[test]
    fn sct_issuer_resolution_ignores_a_same_subject_key_that_did_not_sign_the_leaf() {
        let bundle = Bundle::from_json(COSIGN_V3_BLOB_BUNDLE).expect("cosign bundle");
        let certificate = bundle.signing_certificate().expect("signing certificate");
        let validation_time = bundle.verification_material.tlog_entries[0].integrated_time;
        let trusted_root = TrustedRoot::production().expect("production root");
        let expected = get_issuer_spki(
            &bundle.verification_material.content,
            &certificate,
            validation_time,
            &trusted_root,
        )
        .expect("actual issuer");

        let mut wrong_issuer =
            Certificate::from_der(certificate.as_bytes()).expect("parse signing certificate");
        wrong_issuer.tbs_certificate.subject = wrong_issuer.tbs_certificate.issuer.clone();
        let wrong_issuer = DerCertificate::new(
            wrong_issuer
                .to_der()
                .expect("serialize same-subject wrong-key certificate"),
        );
        let mut rotated_root = trusted_root;
        rotated_root.certificate_authorities[0]
            .cert_chain
            .certificates
            .insert(
                0,
                sigstore_trust_root::trusted_root::CertificateEntry {
                    raw_bytes: wrong_issuer,
                },
            );

        let resolved = get_issuer_spki(
            &bundle.verification_material.content,
            &certificate,
            validation_time,
            &rotated_root,
        )
        .expect("issuer selected by certificate signature");

        assert_eq!(resolved.as_bytes(), expected.as_bytes());
    }

    #[test]
    fn tsa_timestamp_is_bound_to_the_signing_authority_window() {
        let bundle = Bundle::from_json(COSIGN_V3_BLOB_BUNDLE).expect("cosign bundle");
        let signature = extract_signature(&bundle.content).expect("bundle signature");
        let mut trusted_root = TrustedRoot::production().expect("production root");
        let mut unrelated_authority = trusted_root.timestamp_authorities[0].clone();
        unrelated_authority.cert_chain.certificates[0] = trusted_root.certificate_authorities[0]
            .cert_chain
            .certificates[0]
            .clone();
        unrelated_authority.valid_for = None;
        trusted_root.timestamp_authorities[0].valid_for = Some(ValidityPeriod {
            start: Some("2999-01-01T00:00:00Z".to_string()),
            end: None,
        });
        trusted_root.timestamp_authorities.push(unrelated_authority);

        let error = extract_tsa_timestamp(&bundle, signature.as_bytes(), &trusted_root)
            .expect_err("another TSA's window must not authorize the signing TSA");

        assert!(error.to_string().contains("validity period"));
    }

    #[test]
    fn redundant_tsa_evidence_accepts_a_valid_timestamp_after_a_malformed_one() {
        let mut bundle = Bundle::from_json(COSIGN_V3_BLOB_BUNDLE).expect("cosign bundle");
        let signature = extract_signature(&bundle.content).expect("bundle signature");
        bundle
            .verification_material
            .timestamp_verification_data
            .rfc3161_timestamps
            .insert(
                0,
                Rfc3161Timestamp {
                    signed_timestamp: sigstore_types::TimestampToken::new(vec![0xff]),
                },
            );

        let timestamp = extract_tsa_timestamp(
            &bundle,
            signature.as_bytes(),
            &TrustedRoot::production().expect("production root"),
        )
        .expect("one valid timestamp must satisfy the evidence threshold");

        assert!(timestamp.is_some());
    }
}
