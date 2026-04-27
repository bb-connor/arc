//! Sigstore verification wiring for cached and streamed guard artifacts.
//!
//! This module is intentionally thin. It receives the shared
//! `chio_attest_verify::AttestVerifier` trait object, forwards bytes to that
//! trait, and maps every verifier failure into a fail-closed registry error.

use std::fs;

use chio_attest_verify::AttestError;

use crate::cache::GuardCacheLayout;
use crate::oci::{GuardRegistryError, Result};
use crate::{AttestVerifier, ExpectedIdentity, VerifiedAttestation};

/// Build the shared expected identity from operator configuration.
///
/// Callers should construct this once when loading registry configuration and
/// then reuse it for every verification call. The returned type is the
/// `chio-attest-verify` source-of-truth type, not a guard-registry shadow.
pub fn expected_identity_from_config(
    fulcio_subject_regex: impl Into<String>,
    fulcio_oidc_issuer: impl Into<String>,
) -> ExpectedIdentity
where
    ExpectedIdentity: Sized,
{
    chio_attest_verify::ExpectedIdentity {
        certificate_identity_regexp: fulcio_subject_regex.into(),
        certificate_oidc_issuer: fulcio_oidc_issuer.into(),
    }
}

/// Guard-registry wrapper around the shared attestation verifier.
pub struct GuardSigstoreVerifier<'a> {
    verifier: &'a dyn AttestVerifier,
    expected: &'a ExpectedIdentity,
}

impl<'a> GuardSigstoreVerifier<'a> {
    /// Create a verifier wrapper from injected trust-boundary dependencies.
    pub fn new(verifier: &'a dyn AttestVerifier, expected: &'a ExpectedIdentity) -> Self {
        Self { verifier, expected }
    }

    /// Verify cached `module.wasm` and `sigstore-bundle.json` bytes.
    ///
    /// This is the normal on-disk cache path and requires a verified Rekor
    /// inclusion proof. A verifier that returns success without Rekor inclusion
    /// is treated as fail-closed.
    pub fn verify_bundle(
        &self,
        artifact: &[u8],
        bundle_json: &[u8],
    ) -> Result<VerifiedAttestation> {
        let attestation = self
            .verifier
            .verify_bundle(artifact, bundle_json, self.expected)
            .map_err(map_attest_error)?;

        if !attestation.rekor_inclusion_verified {
            return Err(GuardRegistryError::VerifyMissingRekorProof);
        }

        Ok(attestation)
    }

    /// Read `module.wasm` and `sigstore-bundle.json` from a cache layout and
    /// verify them through [`Self::verify_bundle`].
    pub fn verify_cached_layout(&self, layout: &GuardCacheLayout) -> Result<VerifiedAttestation> {
        let artifact = read_cache_file(&layout.module_wasm_path())?;
        let bundle_json = read_cache_file(&layout.sigstore_bundle_json_path())?;
        self.verify_bundle(&artifact, &bundle_json)
    }

    /// Verify streamed artifact bytes with detached signature and PEM cert.
    ///
    /// Streamed verification does not have a bundle yet, so the returned
    /// attestation can legitimately carry `rekor_inclusion_verified = false`.
    /// Callers that require the stronger Rekor gate should use
    /// [`Self::verify_bundle`].
    pub fn verify_bytes(
        &self,
        artifact: &[u8],
        signature: &[u8],
        certificate_pem: &[u8],
    ) -> Result<VerifiedAttestation> {
        self.verifier
            .verify_bytes(artifact, signature, certificate_pem, self.expected)
            .map_err(map_attest_error)
    }
}

fn read_cache_file(path: &std::path::Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|source| GuardRegistryError::CacheIo {
        operation: "read",
        path: path.to_path_buf(),
        source,
    })
}

fn map_attest_error(error: AttestError) -> GuardRegistryError {
    match error {
        AttestError::Io(source) => GuardRegistryError::VerifyIo { source },
        AttestError::SignatureMismatch => GuardRegistryError::VerifySignatureMismatch,
        AttestError::IdentityMismatch => GuardRegistryError::VerifyWrongSubject,
        AttestError::IssuerMismatch => GuardRegistryError::VerifyWrongOidcIssuer,
        AttestError::RekorInclusion => GuardRegistryError::VerifyMissingRekorProof,
        AttestError::CertificateExpired => GuardRegistryError::VerifyCertificateExpired,
        AttestError::TrustRoot => GuardRegistryError::VerifyTrustRoot,
        AttestError::Malformed(message) => GuardRegistryError::VerifyMalformedBundle { message },
        _ => GuardRegistryError::VerifyFailedClosed {
            message: error.to_string(),
        },
    }
}
