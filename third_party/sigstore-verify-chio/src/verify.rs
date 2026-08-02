//! High-level verification API
//!
//! This module provides the main entry point for verifying Sigstore signatures.

use crate::error::{Error, Result};
use sigstore_bundle::validate_bundle_with_options;
use sigstore_bundle::ValidationOptions;
use sigstore_crypto::parse_certificate_info;
use sigstore_trust_root::TrustedRoot;

use sigstore_types::{Artifact, Bundle, Sha256Hash, SignatureContent, Statement};

/// Default clock skew tolerance in seconds (60 seconds = 1 minute)
pub const DEFAULT_CLOCK_SKEW_SECONDS: i64 = 60;

/// Maximum accepted clock skew tolerance (1 hour).
pub const MAX_CLOCK_SKEW_SECONDS: i64 = 3_600;

const INTOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// Policy for verifying signatures
#[derive(Debug, Clone)]
pub struct VerificationPolicy {
    /// Expected identity (email or URI)
    pub identity: Option<String>,
    /// Expected issuer
    pub issuer: Option<String>,
    /// Verify transparency log inclusion
    pub verify_tlog: bool,
    /// Verify timestamp
    pub verify_timestamp: bool,
    /// Verify certificate chain
    pub verify_certificate: bool,
    /// Clock skew tolerance in seconds for time validation
    ///
    /// This allows for a tolerance when checking that integrated times
    /// are not in the future. Default is 60 seconds.
    pub clock_skew_seconds: i64,
}

impl Default for VerificationPolicy {
    fn default() -> Self {
        Self {
            identity: None,
            issuer: None,
            verify_tlog: true,
            verify_timestamp: true,
            verify_certificate: true,
            clock_skew_seconds: DEFAULT_CLOCK_SKEW_SECONDS,
        }
    }
}

impl VerificationPolicy {
    /// Create a policy that requires a specific identity
    pub fn with_identity(identity: impl Into<String>) -> Self {
        Self {
            identity: Some(identity.into()),
            ..Default::default()
        }
    }

    /// Create a policy that requires a specific issuer
    pub fn with_issuer(issuer: impl Into<String>) -> Self {
        Self {
            issuer: Some(issuer.into()),
            ..Default::default()
        }
    }

    /// Require a specific identity
    pub fn require_identity(mut self, identity: impl Into<String>) -> Self {
        self.identity = Some(identity.into());
        self
    }

    /// Require a specific issuer
    pub fn require_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Skip transparency log verification
    pub fn skip_tlog(mut self) -> Self {
        self.verify_tlog = false;
        self
    }

    /// Skip timestamp verification
    pub fn skip_timestamp(mut self) -> Self {
        self.verify_timestamp = false;
        self
    }

    /// Skip certificate chain verification
    ///
    /// WARNING: This is unsafe for production use. Only use for testing
    /// with bundles that don't chain to the trusted root.
    pub fn skip_certificate_chain(mut self) -> Self {
        self.verify_certificate = false;
        self
    }

    /// Set the clock skew tolerance in seconds
    ///
    /// This allows for a tolerance when checking that integrated times
    /// are not in the future. Default is 60 seconds.
    pub fn with_clock_skew_seconds(mut self, seconds: i64) -> Result<Self> {
        validate_clock_skew_seconds(seconds)?;
        self.clock_skew_seconds = seconds;
        Ok(self)
    }

    fn validate(&self) -> Result<()> {
        validate_clock_skew_seconds(self.clock_skew_seconds)
    }
}

pub(crate) fn validate_clock_skew_seconds(seconds: i64) -> Result<()> {
    if !(0..=MAX_CLOCK_SKEW_SECONDS).contains(&seconds) {
        return Err(Error::Verification(format!(
            "clock skew tolerance must be between 0 and {MAX_CLOCK_SKEW_SECONDS} seconds"
        )));
    }
    Ok(())
}

/// Result of verification
#[derive(Debug)]
pub struct VerificationResult {
    /// Whether verification succeeded
    pub success: bool,
    /// Identity from the certificate
    pub identity: Option<String>,
    /// Issuer from the certificate
    pub issuer: Option<String>,
    /// Integrated time from transparency log
    pub integrated_time: Option<i64>,
    /// Any warnings during verification
    pub warnings: Vec<String>,
}

impl VerificationResult {
    /// Create a successful result
    pub fn success() -> Self {
        Self {
            success: true,
            identity: None,
            issuer: None,
            integrated_time: None,
            warnings: Vec::new(),
        }
    }

    /// Create a failed result
    pub fn failure() -> Self {
        Self {
            success: false,
            identity: None,
            issuer: None,
            integrated_time: None,
            warnings: Vec::new(),
        }
    }
}

/// A verifier for Sigstore signatures
pub struct Verifier {
    /// Trusted root containing verification material
    trusted_root: TrustedRoot,
}

impl Verifier {
    /// Create a new verifier with a trusted root
    ///
    /// The trusted root is required and contains all cryptographic material
    /// needed for verification (Fulcio CA certs, Rekor keys, TSA certs, etc.)
    pub fn new(trusted_root: &TrustedRoot) -> Self {
        Self {
            trusted_root: trusted_root.clone(),
        }
    }

    /// Verify an artifact against a bundle
    ///
    /// The artifact can be provided as raw bytes or as a pre-computed SHA-256 digest.
    /// When using a pre-computed digest, the raw bytes are not needed, which is useful
    /// for large files or when the digest is already known (e.g., from a registry).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sigstore_verify::{Verifier, VerificationPolicy};
    /// use sigstore_trust_root::TrustedRoot;
    /// use sigstore_types::{Artifact, Bundle, Sha256Hash};
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let trusted_root = TrustedRoot::production()?;
    /// let verifier = Verifier::new(&trusted_root);
    /// let bundle: Bundle = todo!();
    /// let policy = VerificationPolicy::default();
    ///
    /// // Option 1: Verify with raw bytes
    /// let artifact_bytes = b"hello world";
    /// verifier.verify(artifact_bytes.as_slice(), &bundle, &policy)?;
    ///
    /// // Option 2: Verify with pre-computed digest (no raw bytes needed!)
    /// let digest = Sha256Hash::from_hex("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")?;
    /// verifier.verify(digest, &bundle, &policy)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// In order to verify an artifact, we need to achieve the following:
    ///
    /// 0. Establish a time for the signature.
    /// 1. Verify that the signing certificate chains to the root of trust
    ///    and is valid at the time of signing.
    /// 2. Verify the signing certificate's SCT.
    /// 3. Verify that the signing certificate conforms to the Sigstore
    ///    X.509 profile as well as the passed-in `VerificationPolicy`.
    /// 4. Verify the inclusion proof and signed checkpoint for the log
    ///    entry.
    /// 5. Verify the inclusion promise for the log entry, if present.
    /// 6. Verify the timely insertion of the log entry against the validity
    ///    period for the signing certificate.
    /// 7. Verify the signature and input against the signing certificate's
    ///    public key.
    /// 8. Verify the transparency log entry's consistency against the other
    ///    materials, to prevent variants of CVE-2022-36056.
    pub fn verify<'a>(
        &self,
        artifact: impl Into<Artifact<'a>>,
        bundle: &Bundle,
        policy: &VerificationPolicy,
    ) -> Result<VerificationResult> {
        let artifact = artifact.into();
        let mut result = VerificationResult::success();

        policy.validate()?;

        // Validate bundle structure first
        let options = ValidationOptions {
            require_inclusion_proof: policy.verify_tlog,
            require_timestamp: false, // Don't require timestamps, but verify if present
        };
        validate_bundle_with_options(bundle, &options)
            .map_err(|e| Error::Verification(format!("bundle validation failed: {}", e)))?;

        // Extract certificate for verification
        let cert = crate::verify_impl::helpers::extract_certificate(
            &bundle.verification_material.content,
        )?;
        let cert_info = parse_certificate_info(cert.as_bytes())
            .map_err(|e| Error::Verification(format!("failed to parse certificate: {}", e)))?;

        // Store identity and issuer in result
        result.identity = cert_info.identity.clone();
        result.issuer = cert_info.issuer.clone();

        // (0): Establish a time for the signature
        // First, establish verified times for the signature. This is required to
        // validate the certificate chain, so this step comes first.
        // These include TSA timestamps and (in the case of rekor v1 entries)
        // rekor log integrated time.
        let validation_time = if policy.verify_timestamp {
            let signature = crate::verify_impl::helpers::extract_signature(&bundle.content)?;
            Some(crate::verify_impl::helpers::determine_validation_time(
                bundle,
                &signature,
                &self.trusted_root,
            )?)
        } else if policy.verify_certificate {
            if !policy.verify_tlog {
                return Err(Error::Verification(
                    "certificate verification requires a trusted time source when timestamp and transparency-log verification are disabled"
                        .to_string(),
                ));
            }
            Some(crate::verify_impl::helpers::determine_validation_time_from_tlog(bundle)?)
        } else {
            None
        };

        // (1): Verify that the signing certificate chains to the root of trust,
        //      is valid at the time of signing, and has CODE_SIGNING EKU.
        if policy.verify_certificate {
            crate::verify_impl::helpers::verify_certificate_chain(
                &bundle.verification_material.content,
                validation_time.ok_or_else(|| {
                    Error::Verification(
                        "certificate verification has no trusted validation time".to_string(),
                    )
                })?,
                &self.trusted_root,
            )?;

            // Also verify the certificate is within its validity period
            crate::verify_impl::helpers::validate_certificate_time(
                validation_time.ok_or_else(|| {
                    Error::Verification(
                        "certificate verification has no trusted validation time".to_string(),
                    )
                })?,
                &cert_info,
            )?;

            // (2): Verify the signing certificate's SCT.
            crate::verify_impl::helpers::verify_sct(
                &bundle.verification_material.content,
                &self.trusted_root,
            )?;
        }

        // (3): Verify against the given `VerificationPolicy`.

        // Verify against policy constraints
        if let Some(ref expected_identity) = policy.identity {
            verify_identity_policy(expected_identity, result.identity.as_deref())?;
        }

        if let Some(ref expected_issuer) = policy.issuer {
            verify_issuer_policy(expected_issuer, result.issuer.as_deref())?;
        }

        // (4): Verify the inclusion proof and signed checkpoint for the log entry.
        // (5): Verify the inclusion promise for the log entry, if present.
        // (6): Verify the timely insertion of the log entry against the validity
        //      period for the signing certificate.
        if policy.verify_tlog {
            let integrated_time = crate::verify_impl::tlog::verify_tlog_entries(
                bundle,
                &self.trusted_root,
                cert_info.not_before,
                cert_info.not_after,
                policy.clock_skew_seconds,
            )?;

            if let Some(time) = integrated_time {
                result.integrated_time = Some(time);
            }
        }

        // (7): Verify the signature and input against the signing certificate's
        //      public key.
        // For DSSE envelopes, verify using PAE (Pre-Authentication Encoding)
        if let SignatureContent::DsseEnvelope(envelope) = &bundle.content {
            let payload_bytes = envelope.decode_payload();

            // Compute the PAE that was signed
            let pae = sigstore_types::pae(&envelope.payload_type, &payload_bytes);

            // Verify at least one signature is cryptographically valid
            let mut any_sig_valid = false;
            for sig in &envelope.signatures {
                if sigstore_crypto::verify_signature(
                    &cert_info.public_key,
                    &pae,
                    &sig.sig,
                    cert_info.signing_scheme,
                )
                .is_ok()
                {
                    any_sig_valid = true;
                    break;
                }
            }

            if !any_sig_valid {
                return Err(Error::Verification(
                    "DSSE signature verification failed: no valid signatures found".to_string(),
                ));
            }

            verify_dsse_artifact_binding(envelope, &artifact)?;
        }

        if let SignatureContent::MessageSignature(msg_sig) = &bundle.content {
            verify_message_signature(
                &artifact,
                msg_sig,
                &cert_info.public_key,
                cert_info.signing_scheme,
            )?;
        }

        // (8): Verify the transparency log entry's consistency against the other
        //      materials, to prevent variants of CVE-2022-36056.
        let content_bound_entries = verify_transparency_log_content_binding(
            bundle,
            &artifact,
            Some(crate::verify_impl::rekor::ExpectedDsseVerifier::Certificate(&cert)),
        )?;
        if policy.verify_tlog && content_bound_entries == 0 {
            return Err(Error::Verification(
                "no transparency log entry is bound to the bundle content".to_string(),
            ));
        }

        Ok(result)
    }
}

fn verify_dsse_artifact_binding(
    envelope: &sigstore_types::DsseEnvelope,
    artifact: &Artifact<'_>,
) -> Result<()> {
    if envelope.payload_type != INTOTO_PAYLOAD_TYPE {
        return Err(Error::Verification(format!(
            "unsupported DSSE payload type: {}",
            envelope.payload_type
        )));
    }

    let payload_bytes = envelope.decode_payload();
    let payload_str = std::str::from_utf8(&payload_bytes)
        .map_err(|e| Error::Verification(format!("payload is not valid UTF-8: {e}")))?;
    let statement: Statement = serde_json::from_str(payload_str)
        .map_err(|e| Error::Verification(format!("failed to parse in-toto statement: {e}")))?;
    let artifact_hash = compute_artifact_digest(artifact);
    verify_statement_artifact_binding(&statement, &artifact_hash.to_hex())
}

fn verify_statement_artifact_binding(statement: &Statement, artifact_hash_hex: &str) -> Result<()> {
    if statement.subject.is_empty() {
        return Err(Error::Verification(
            "in-toto statement must contain at least one subject".to_string(),
        ));
    }
    if !statement.matches_sha256(artifact_hash_hex) {
        return Err(Error::Verification(
            "artifact hash does not match any subject in attestation".to_string(),
        ));
    }
    Ok(())
}

fn verify_message_signature(
    artifact: &Artifact<'_>,
    message_signature: &sigstore_types::MessageSignature,
    public_key: &sigstore_types::DerPublicKey,
    signing_scheme: sigstore_crypto::SigningScheme,
) -> Result<()> {
    let artifact_hash = compute_artifact_digest(artifact);
    if let Some(digest) = &message_signature.message_digest {
        if digest.digest.as_bytes() != artifact_hash.as_bytes() {
            return Err(Error::Verification(
                "message digest in bundle does not match artifact hash".to_string(),
            ));
        }
    }

    match artifact {
        Artifact::Bytes(bytes) => sigstore_crypto::verify_signature(
            public_key,
            bytes,
            &message_signature.signature,
            signing_scheme,
        ),
        Artifact::Digest(hash)
            if signing_scheme.uses_sha256() && signing_scheme.supports_prehashed() =>
        {
            sigstore_crypto::verify_signature_prehashed(
                public_key,
                hash,
                &message_signature.signature,
                signing_scheme,
            )
        }
        Artifact::Digest(_) => {
            return Err(Error::Verification(
                "cannot verify message signature from a digest with this signing scheme"
                    .to_string(),
            ));
        }
    }
    .map_err(|error| Error::Verification(format!("message signature verification failed: {error}")))
}

fn verify_transparency_log_content_binding(
    bundle: &Bundle,
    artifact: &Artifact<'_>,
    dsse_verifier: Option<crate::verify_impl::rekor::ExpectedDsseVerifier<'_>>,
) -> Result<usize> {
    match &bundle.content {
        SignatureContent::MessageSignature(_) => {
            crate::verify_impl::verify_hashedrekord_entries(bundle, artifact)
        }
        SignatureContent::DsseEnvelope(_) => {
            let dsse_entries = crate::verify_impl::verify_dsse_entries(bundle)?;
            let expected_verifier = dsse_verifier.ok_or_else(|| {
                Error::Verification("DSSE content binding requires a verifier identity".to_string())
            })?;
            let intoto_entries =
                crate::verify_impl::verify_intoto_entries(bundle, expected_verifier)?;
            Ok(dsse_entries + intoto_entries)
        }
    }
}

fn verify_identity_policy(expected_identity: &str, actual_identity: Option<&str>) -> Result<()> {
    match actual_identity {
        Some(actual_identity) if actual_identity == expected_identity => Ok(()),
        Some(actual_identity) => Err(Error::Verification(format!(
            "identity mismatch: expected {}, got {}",
            expected_identity, actual_identity
        ))),
        None => Err(Error::Verification(format!(
            "certificate is missing identity (SAN), but policy requires: {}",
            expected_identity
        ))),
    }
}

fn verify_issuer_policy(expected_issuer: &str, actual_issuer: Option<&str>) -> Result<()> {
    match actual_issuer {
        Some(actual_issuer) if actual_issuer == expected_issuer => Ok(()),
        Some(actual_issuer) => Err(Error::Verification(format!(
            "issuer mismatch: expected {}, got {}",
            expected_issuer, actual_issuer
        ))),
        None => Err(Error::Verification(format!(
            "certificate is missing issuer (Fulcio OID extension), but policy requires: {}",
            expected_issuer
        ))),
    }
}

/// Compute the SHA-256 digest from an artifact
fn compute_artifact_digest(artifact: &Artifact<'_>) -> Sha256Hash {
    match artifact {
        Artifact::Bytes(bytes) => sigstore_crypto::sha256(bytes),
        Artifact::Digest(hash) => *hash,
    }
}

/// Convenience function to verify an artifact against a bundle
///
/// This uses the trusted root for all cryptographic material
/// (Rekor keys, Fulcio certs, TSA certs).
///
/// The artifact can be provided as raw bytes or as a pre-computed SHA-256 digest:
/// - `verify(artifact_bytes, ...)` - pass raw bytes
/// - `verify(Sha256Hash::from_hex("...")?, ...)` - pass pre-computed digest
pub fn verify<'a>(
    artifact: impl Into<Artifact<'a>>,
    bundle: &Bundle,
    policy: &VerificationPolicy,
    trusted_root: &TrustedRoot,
) -> Result<VerificationResult> {
    let verifier = Verifier::new(trusted_root);
    verifier.verify(artifact, bundle, policy)
}

/// Verify an artifact against a bundle using a provided public key
///
/// This is used for managed key verification where the bundle contains a public key
/// hint instead of a certificate. The actual public key is provided separately.
///
/// This verification:
/// - Verifies the signature using the provided public key
/// - Verifies transparency log entries (checkpoints, SETs)
/// - Skips certificate chain verification (no certificate present)
/// - Skips identity/issuer verification
///
/// # Example
///
/// ```no_run
/// use sigstore_verify::verify_with_key;
/// use sigstore_trust_root::TrustedRoot;
/// use sigstore_types::{Bundle, DerPublicKey};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let trusted_root = TrustedRoot::from_file("trusted_root.json")?;
/// let bundle_json = std::fs::read_to_string("artifact.sigstore.json")?;
/// let bundle = Bundle::from_json(&bundle_json)?;
/// let artifact = std::fs::read("artifact.txt")?;
/// let key_pem = std::fs::read_to_string("key.pub")?;
/// let public_key = DerPublicKey::from_pem(&key_pem)?;
///
/// let result = verify_with_key(&artifact, &bundle, &public_key, &trusted_root)?;
/// assert!(result.success);
/// # Ok(())
/// # }
/// ```
pub fn verify_with_key<'a>(
    artifact: impl Into<Artifact<'a>>,
    bundle: &Bundle,
    public_key: &sigstore_types::DerPublicKey,
    trusted_root: &TrustedRoot,
) -> Result<VerificationResult> {
    use sigstore_bundle::{validate_bundle_with_options, ValidationOptions};
    use sigstore_crypto::{detect_key_type, KeyType, SigningScheme};

    let artifact = artifact.into();
    let result = VerificationResult::success();

    // Validate bundle structure
    let options = ValidationOptions {
        require_inclusion_proof: true,
        require_timestamp: false,
    };
    validate_bundle_with_options(bundle, &options)
        .map_err(|e| Error::Verification(format!("bundle validation failed: {}", e)))?;

    // Determine signing scheme from public key
    let signing_scheme = match detect_key_type(public_key) {
        KeyType::Ed25519 => SigningScheme::Ed25519,
        KeyType::EcdsaP256 => SigningScheme::EcdsaP256Sha256,
        KeyType::Unknown => {
            return Err(Error::Verification(
                "unsupported or unrecognized public key type".to_string(),
            ));
        }
    };

    // Verify transparency log entries (checkpoints, SETs) without certificate time validation
    for entry in &bundle.verification_material.tlog_entries {
        // Verify checkpoint signature if present
        if let Some(ref inclusion_proof) = entry.inclusion_proof {
            crate::verify_impl::tlog::verify_checkpoint(
                &inclusion_proof.checkpoint.envelope,
                inclusion_proof,
                trusted_root,
            )?;
        }

        // Verify inclusion promise (SET) if present
        if entry.inclusion_promise.is_some() {
            crate::verify_impl::tlog::verify_set(entry, trusted_root)?;
        }
    }

    // Verify the signature
    match &bundle.content {
        SignatureContent::MessageSignature(msg_sig) => {
            verify_message_signature(&artifact, msg_sig, public_key, signing_scheme)?;
        }
        SignatureContent::DsseEnvelope(envelope) => {
            let payload_bytes = envelope.decode_payload();
            let pae = sigstore_types::pae(&envelope.payload_type, &payload_bytes);

            // Verify at least one signature is valid
            let mut any_sig_valid = false;
            for sig in &envelope.signatures {
                if sigstore_crypto::verify_signature(public_key, &pae, &sig.sig, signing_scheme)
                    .is_ok()
                {
                    any_sig_valid = true;
                    break;
                }
            }

            if !any_sig_valid {
                return Err(Error::Verification(
                    "DSSE signature verification failed: no valid signatures found".to_string(),
                ));
            }

            verify_dsse_artifact_binding(envelope, &artifact)?;
        }
    }

    if verify_transparency_log_content_binding(
        bundle,
        &artifact,
        Some(crate::verify_impl::rekor::ExpectedDsseVerifier::PublicKey(
            public_key,
        )),
    )? == 0
    {
        return Err(Error::Verification(
            "no transparency log entry is bound to the bundle content".to_string(),
        ));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigstore_crypto::KeyPair;
    use sigstore_types::{
        bundle::VerificationMaterialContent, DsseSignature, KeyId, PayloadBytes, SignatureBytes,
    };

    const COSIGN_V3_BLOB_BUNDLE: &str =
        include_str!("../test_data/bundles/cosign-v3-blob.sigstore.json");
    const COSIGN_V3_BLOB: &[u8] = include_bytes!("../test_data/bundles/cosign-v3-blob.txt");
    const CONDA_ATTESTATION_BUNDLE: &str =
        include_str!("../test_data/bundles/conda-attestation.sigstore.json");
    const CONDA_PACKAGE: &[u8] =
        include_bytes!("../test_data/bundles/signed-package-2.1.0-hb0f4dca_0.conda");

    #[test]
    fn test_verification_policy_default() {
        let policy = VerificationPolicy::default();
        assert!(policy.verify_tlog);
        assert!(policy.verify_timestamp);
        assert!(policy.verify_certificate);
    }

    #[test]
    fn test_verification_policy_builder() {
        let policy = VerificationPolicy::default()
            .require_identity("test@example.com")
            .require_issuer("https://accounts.google.com")
            .skip_tlog();

        assert_eq!(policy.identity, Some("test@example.com".to_string()));
        assert_eq!(
            policy.issuer,
            Some("https://accounts.google.com".to_string())
        );
        assert!(!policy.verify_tlog);
    }

    #[test]
    fn clock_skew_policy_rejects_invalid_tolerances() {
        for invalid in [-1, MAX_CLOCK_SKEW_SECONDS + 1, i64::MAX] {
            let result = VerificationPolicy::default().with_clock_skew_seconds(invalid);
            assert!(
                matches!(result, Err(Error::Verification(message)) if message.contains("clock skew tolerance")),
                "invalid tolerance {invalid} must fail closed"
            );
        }
        assert!(VerificationPolicy::default()
            .with_clock_skew_seconds(MAX_CLOCK_SKEW_SECONDS)
            .is_ok());
    }

    #[test]
    fn dsse_artifact_binding_rejects_unsupported_payload_types() {
        let mut bundle = Bundle::from_json(CONDA_ATTESTATION_BUNDLE).expect("DSSE bundle");
        let SignatureContent::DsseEnvelope(envelope) = &mut bundle.content else {
            panic!("expected DSSE bundle");
        };
        envelope.payload_type = "application/example+json".to_string();

        let result = verify_dsse_artifact_binding(envelope, &Artifact::Bytes(CONDA_PACKAGE));

        assert!(matches!(
            result,
            Err(Error::Verification(message)) if message.contains("unsupported DSSE payload type")
        ));
    }

    #[test]
    fn skip_timestamp_ignores_malformed_optional_rfc3161_data() {
        let mut bundle = Bundle::from_json(COSIGN_V3_BLOB_BUNDLE).expect("cosign bundle");
        bundle
            .verification_material
            .timestamp_verification_data
            .rfc3161_timestamps[0]
            .signed_timestamp = sigstore_types::TimestampToken::new(vec![0xff, 0x00, 0x7f]);

        let result = verify(
            COSIGN_V3_BLOB,
            &bundle,
            &VerificationPolicy::default().skip_timestamp(),
            &TrustedRoot::production().expect("production root"),
        );

        result.expect("trusted transparency-log time remains authoritative");
    }

    #[test]
    fn identity_policy_accepts_only_an_exact_claim() {
        assert!(verify_identity_policy("test@example.com", Some("test@example.com")).is_ok());

        let mismatch = verify_identity_policy("test@example.com", Some("other@example.com"));
        assert!(matches!(
            mismatch,
            Err(Error::Verification(message))
                if message
                    == "identity mismatch: expected test@example.com, got other@example.com"
        ));

        let missing = verify_identity_policy("test@example.com", None);
        assert!(matches!(
            missing,
            Err(Error::Verification(message))
                if message
                    == "certificate is missing identity (SAN), but policy requires: test@example.com"
        ));
    }

    #[test]
    fn issuer_policy_accepts_only_an_exact_claim() {
        assert!(
            verify_issuer_policy("https://issuer.example", Some("https://issuer.example")).is_ok()
        );

        let mismatch =
            verify_issuer_policy("https://issuer.example", Some("https://other.example"));
        assert!(matches!(
            mismatch,
            Err(Error::Verification(message))
                if message
                    == "issuer mismatch: expected https://issuer.example, got https://other.example"
        ));

        let missing = verify_issuer_policy("https://issuer.example", None);
        assert!(matches!(
            missing,
            Err(Error::Verification(message))
                if message
                    == "certificate is missing issuer (Fulcio OID extension), but policy requires: https://issuer.example"
        ));
    }

    #[test]
    fn skip_tlog_still_rejects_an_invalid_message_signature() {
        let mut bundle = Bundle::from_json(COSIGN_V3_BLOB_BUNDLE).expect("cosign bundle");
        let SignatureContent::MessageSignature(message_signature) = &mut bundle.content else {
            panic!("expected message signature bundle");
        };
        message_signature.signature = SignatureBytes::new(vec![0; 64]);
        bundle
            .verification_material
            .timestamp_verification_data
            .rfc3161_timestamps
            .clear();
        bundle.verification_material.tlog_entries[0]
            .kind_version
            .kind = "dsse".to_string();

        let policy = VerificationPolicy::default()
            .skip_tlog()
            .skip_timestamp()
            .skip_certificate_chain();
        let result = verify(
            COSIGN_V3_BLOB,
            &bundle,
            &policy,
            &TrustedRoot::production().expect("production root"),
        );

        let error = result
            .expect_err("message signature must be verified independently of hashedrekord entries");
        assert!(error
            .to_string()
            .contains("message signature verification failed"));
    }

    #[test]
    fn managed_key_verification_rejects_an_unrelated_transparency_entry() {
        let mut bundle = Bundle::from_json(COSIGN_V3_BLOB_BUNDLE).expect("cosign bundle");
        let unrelated = Bundle::from_json(CONDA_ATTESTATION_BUNDLE).expect("DSSE bundle");
        let certificate = bundle
            .signing_certificate()
            .expect("cosign bundle certificate")
            .clone();
        let public_key = parse_certificate_info(certificate.as_bytes())
            .expect("certificate info")
            .public_key;
        bundle.verification_material.content = VerificationMaterialContent::PublicKey {
            hint: "test-managed-key".to_string(),
        };
        bundle.verification_material.tlog_entries = unrelated.verification_material.tlog_entries;

        let result = verify_with_key(
            COSIGN_V3_BLOB,
            &bundle,
            &public_key,
            &TrustedRoot::production().expect("production root"),
        );

        let error = result.expect_err(
            "managed-key verification must bind a verified log entry to the message signature",
        );
        assert!(error
            .to_string()
            .contains("no transparency log entry is bound"));
    }

    #[test]
    fn managed_key_verification_rejects_a_subjectless_attestation() {
        let mut bundle = Bundle::from_json(CONDA_ATTESTATION_BUNDLE).expect("DSSE bundle");
        let key_pair = KeyPair::generate_ecdsa_p256().expect("generate managed signing key");
        let public_key = key_pair.public_key_der().expect("managed public key");
        let payload = serde_json::to_vec(&serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {}
        }))
        .expect("serialize subjectless statement");

        let SignatureContent::DsseEnvelope(envelope) = &mut bundle.content else {
            panic!("expected DSSE bundle");
        };
        envelope.payload = PayloadBytes::new(payload.clone());
        let pae = sigstore_types::pae(&envelope.payload_type, &payload);
        envelope.signatures = vec![DsseSignature {
            sig: key_pair.sign(&pae).expect("sign subjectless statement"),
            keyid: KeyId::default(),
        }];
        bundle.verification_material.content = VerificationMaterialContent::PublicKey {
            hint: "test-managed-key".to_string(),
        };

        let artifact = Sha256Hash::from_bytes([7; 32]);
        let result = verify_with_key(
            artifact,
            &bundle,
            &public_key,
            &TrustedRoot::production().expect("production root"),
        );

        let error =
            result.expect_err("in-toto attestations without subjects cannot bind the artifact");
        assert!(error
            .to_string()
            .contains("must contain at least one subject"));
    }

    #[test]
    fn managed_key_verification_accepts_matching_transparency_entries() {
        for (bundle_json, artifact) in [
            (COSIGN_V3_BLOB_BUNDLE, COSIGN_V3_BLOB),
            (CONDA_ATTESTATION_BUNDLE, CONDA_PACKAGE),
        ] {
            let mut bundle = Bundle::from_json(bundle_json).expect("fixture bundle");
            let certificate = bundle
                .signing_certificate()
                .expect("fixture certificate")
                .clone();
            let public_key = parse_certificate_info(certificate.as_bytes())
                .expect("certificate info")
                .public_key;
            bundle.verification_material.content = VerificationMaterialContent::PublicKey {
                hint: "test-managed-key".to_string(),
            };

            let result = verify_with_key(
                artifact,
                &bundle,
                &public_key,
                &TrustedRoot::production().expect("production root"),
            );
            assert!(result.is_ok(), "matching managed-key bundle: {result:?}");
        }
    }
}
