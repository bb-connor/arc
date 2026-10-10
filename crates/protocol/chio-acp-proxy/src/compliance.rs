// Session compliance certificate generation and verification.
//
// Commits an ordered signed receipt set and explicitly configured tool-target,
// guard and allowed-receipt-count checks. Authenticated corpus collection is an
// independent reader boundary; snapshot references do not prove closed lifetimes.

use std::sync::atomic::{AtomicBool, Ordering};

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::Signature;
use chio_core::receipt::body::chio_receipt_id;

#[path = "compliance/bundle.rs"]
mod compliance_bundle;
pub use compliance_bundle::{
    ComplianceBundleError, ComplianceCheckStatus, ComplianceChecks, ComplianceCoverage,
    ComplianceProfile, ComplianceToolTarget,
};

/// One-shot guard for the empty-`trusted_kernel_keys` warning.
///
/// `ComplianceConfig` derives `Default`, which yields an empty
/// `trusted_kernel_keys` set. With the empty set, every receipt is
/// rejected with `UntrustedKernelKey` and neither generation nor
/// verification can succeed. That is the operator contract -- the
/// trust set MUST be populated -- but a silent rejection is hostile
/// for first-time callers. Emit a single tracing warning the first
/// time we observe an empty set during validation so operators see a
/// clear breadcrumb without flooding the log.
static EMPTY_TRUSTED_KEYS_WARNED: AtomicBool = AtomicBool::new(false);

fn warn_empty_compliance_trusted_keys_once() {
    if EMPTY_TRUSTED_KEYS_WARNED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        tracing::warn!(
            target: "chio_acp_proxy::compliance",
            "ComplianceConfig has no trusted_kernel_keys configured; all receipts will fail \
             integrity validation with UntrustedKernelKey, and compliance certificate \
             generation and verification will not succeed. Populate \
             ComplianceConfig::trusted_kernel_keys with the operator-pinned kernel keys \
             before calling generate_compliance_certificate or verify_compliance_certificate."
        );
    }
}

/// Error types that abort compliance certificate generation.
#[derive(thiserror::Error)]
pub enum ComplianceCertificateError {
    /// Trusted audit time or canonical serialization failed.
    #[error("{0}")]
    Audit(#[from] AcpAuditError),
    /// No receipts found for the given session.
    #[error("urn:chio:error:attest:provenance-missing")]
    EmptySession(String),

    /// A receipt's Ed25519 signature is invalid.
    #[error("urn:chio:error:attest:receipt-verification-failed")]
    InvalidReceiptSignature {
        /// The receipt ID whose signature failed.
        receipt_id: String,
    },

    /// A receipt ID does not match the content-addressed receipt body.
    #[error("urn:chio:error:attest:receipt-verification-failed")]
    InvalidReceiptId {
        /// The receipt ID whose content-addressed identity failed.
        receipt_id: String,
    },

    /// A receipt action hash does not match the canonical action parameters.
    #[error("urn:chio:error:attest:receipt-verification-failed")]
    InvalidActionHash {
        /// The receipt ID whose action hash failed.
        receipt_id: String,
    },

    /// A receipt does not belong to the certificate's named session.
    #[error("urn:chio:error:attest:receipt-verification-failed")]
    SessionMismatch {
        /// The receipt ID whose session binding failed.
        receipt_id: String,
        /// The session ID named by the certificate.
        session_id: String,
    },

    /// A receipt does not belong to the configured tenant.
    #[error("urn:chio:error:attest:receipt-verification-failed")]
    TenantMismatch {
        /// The receipt ID whose tenant binding failed.
        receipt_id: String,
        /// The expected tenant ID.
        tenant_id: String,
    },

    /// A receipt carries an allow decision without authorization semantics.
    #[error("urn:chio:error:attest:receipt-verification-failed")]
    NonAuthorizingReceipt {
        /// The receipt ID whose semantics failed.
        receipt_id: String,
    },

    /// A receipt was signed by a kernel key outside the verifier trust set.
    #[error("urn:chio:error:attest:receipt-verification-failed")]
    UntrustedKernelKey {
        /// The receipt ID whose signer was not trusted.
        receipt_id: String,
        /// The untrusted kernel key.
        kernel_key: String,
    },

    /// The selected receipt order went backwards or repeated an identity.
    #[error("urn:chio:error:attest:receipt-verification-failed")]
    ChainDiscontinuity {
        /// The expected sequence number.
        expected: u64,
        /// The actual sequence number found.
        found: u64,
    },

    /// An allowed receipt falls outside configured tool targets or tool-name prefixes.
    #[error("urn:chio:error:policy:decision-denied")]
    ScopeViolation {
        /// The receipt that violated scope.
        receipt_id: String,
        /// The tool name that failed the configured target/prefix check.
        resource: String,
    },

    /// The configured allowed-mediated-receipt count ceiling was exceeded.
    #[error("urn:chio:error:kernel:budget-exhausted")]
    BudgetExceeded {
        /// Number of allowed mediated receipts, not actual dispatch or spend.
        used: u64,
        /// The configured budget limit.
        limit: u64,
    },

    /// A configured applicable guard lacks passing evidence or records a denial.
    #[error("urn:chio:error:guard:denied")]
    GuardBypass {
        /// The guard that was expected to run.
        guard_name: String,
        /// The receipt missing the guard evidence.
        receipt_id: String,
    },

    /// Receipts in the session were signed by more than one kernel key.
    ///
    /// The compliance certificate names a single kernel key. A session that
    /// mixes receipts from different kernels would produce a certificate
    /// whose `kernel_key` field misrepresents the signer for some receipts;
    /// fail closed.
    #[error("urn:chio:error:attest:receipt-verification-failed")]
    KernelKeyMismatch {
        /// The receipt whose kernel_key did not match the session's first receipt.
        receipt_id: String,
    },

    /// Invalid or incomplete signed receipt-set data.
    #[error("{0}")]
    Bundle(#[from] ComplianceBundleError),

    /// Serialization error during certificate construction.
    #[error("urn:chio:error:attest:signed-json-canonicalization")]
    Canonical(#[from] chio_core::error::Error),

    /// Signing error during certificate construction.
    #[error("urn:chio:error:attest:receipt-verification-failed")]
    SelfVerification,
}

impl ComplianceCertificateError {
    /// Input-independent registered classification; the typed cause stays local.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Audit(AcpAuditError::Clock(error)) => error.code(),
            Self::Canonical(_) => "urn:chio:error:attest:signed-json-canonicalization",
            Self::Audit(AcpAuditError::Canonical(_) | AcpAuditError::Timestamp(_)) => {
                "urn:chio:error:transport:invalid-request-shape"
            }
            Self::EmptySession(_) => "urn:chio:error:attest:provenance-missing",
            Self::ScopeViolation { .. } => "urn:chio:error:policy:decision-denied",
            Self::BudgetExceeded { .. } => "urn:chio:error:kernel:budget-exhausted",
            Self::GuardBypass { .. } => "urn:chio:error:guard:denied",
            Self::InvalidReceiptSignature { .. }
            | Self::InvalidReceiptId { .. }
            | Self::InvalidActionHash { .. }
            | Self::SessionMismatch { .. }
            | Self::TenantMismatch { .. }
            | Self::NonAuthorizingReceipt { .. }
            | Self::UntrustedKernelKey { .. }
            | Self::ChainDiscontinuity { .. }
            | Self::KernelKeyMismatch { .. }
            | Self::SelfVerification
            | Self::Bundle(_) => "urn:chio:error:attest:receipt-verification-failed",
        }
    }
}

impl std::fmt::Debug for ComplianceCertificateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

/// A receipt entry used during compliance analysis.
#[derive(Debug, Clone)]
pub struct ComplianceReceiptEntry {
    /// The full signed receipt.
    pub receipt: ChioReceipt,
    /// Original global tool-receipt source identity. It is never renumbered.
    pub seq: u64,
    /// Authenticated claim-log ordering, when collecting retained history.
    pub entry_seq: Option<u64>,
}

/// Configuration for compliance certificate generation.
#[derive(Debug, Default, Clone)]
pub struct ComplianceConfig {
    /// Allowed mediated receipt count ceiling (0 = not evaluated), not financial spend.
    pub budget_limit: u64,
    /// Guard names that must pass on every applicable allowed mediated receipt.
    pub required_guards: Vec<String>,
    /// Explicit legacy tool-name prefixes. These do not certify resource scopes.
    pub authorized_scopes: Vec<String>,
    /// Exact server/tool identities. Combined with any configured legacy prefixes.
    pub authorized_tool_targets: Vec<ComplianceToolTarget>,
    /// Expected tenant for all receipts. None leaves that profile check unevaluated.
    /// Every committed set must still contain one consistent tenant identity.
    pub expected_tenant_id: Option<String>,
    /// Trusted kernel keys allowed to sign receipts and certificates.
    ///
    /// MUST be populated by the operator with the kernel public keys
    /// that are authorized to sign receipts in this deployment. An
    /// empty set is a misconfiguration: every receipt will be rejected
    /// with `UntrustedKernelKey`, blocking both generation and
    /// verification of compliance certificates. The first observed
    /// empty-set evaluation logs a one-shot tracing warning to make
    /// this contract visible to operators.
    pub trusted_kernel_keys: std::collections::BTreeSet<String>,
}

/// The body of a compliance certificate (unsigned).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComplianceCertificateBody {
    /// Schema identifier.
    pub schema: String,
    /// Session ID the certificate covers.
    pub session_id: String,
    /// Unix timestamp when the certificate was generated.
    pub issued_at: u64,
    /// Number of receipts examined.
    pub receipt_count: u64,
    /// First receipt timestamp in the session.
    pub first_receipt_at: u64,
    /// Last receipt timestamp in the session.
    pub last_receipt_at: u64,
    /// Whether all receipts passed signature verification.
    pub all_signatures_valid: bool,
    /// Whether selected claim/source ordering is increasing; global gaps are legitimate.
    pub chain_continuous: bool,
    /// Whether configured tool-target/prefix checks passed on applicable allowed receipts.
    pub scope_compliant: bool,
    /// Whether the configured allowed-mediated-receipt ceiling passed, not financial spend.
    pub budget_compliant: bool,
    /// Whether every configured guard passed on applicable allowed mediated receipts.
    pub guards_compliant: bool,
    /// Integrity anomalies. Unconfigured check applicability is reported separately.
    pub anomalies: Vec<String>,
    /// The kernel public key that signed the session receipts.
    pub kernel_key: PublicKey,
    /// Ordered, domain-separated commitment to every supplied signed receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_set_digest: Option<String>,
    /// Commitment to the exact configured checks, independent of signing pins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance_profile_digest: Option<String>,
    /// Count of allowed mediated receipts, not actual dispatch or financial spend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation_count: Option<u64>,
    /// Explicit check applicability; unconfigured checks are not claimed passed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checks: Option<ComplianceChecks>,
    /// A supplied set or descriptive signed snapshot reference, not independent history proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<ComplianceCoverage>,
}

/// A signed compliance certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComplianceCertificate {
    /// The unsigned body.
    pub body: ComplianceCertificateBody,
    /// Public key that signed the certificate.
    pub signer_key: PublicKey,
    /// Ed25519 signature over canonical JSON of `body`.
    pub signature: Signature,
}

/// Verification mode for compliance certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationMode {
    /// Lightweight: verify certificate signature and body consistency only.
    Lightweight,
    /// Verify the exact positive committed v2 receipt set and configured profile.
    FullBundle,
}

/// The established verification boundary, independently of signed coverage assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateVerificationScope {
    Unverified,
    SignatureAndBodyOnly,
    CommittedReceiptSet,
    /// Set only by private CLI orchestration after authenticated exact recollection.
    AuthenticatedRetainedToolSnapshot,
}

/// Result of certificate verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateVerificationResult {
    /// No corpus-authentication claim is inferred from deserialized coverage.
    pub verification_scope: CertificateVerificationScope,
    /// Whether the certificate signature is valid.
    #[serde(alias = "certificateSignatureValid")]
    pub certificate_signature_valid: bool,
    /// Whether the body fields are internally consistent.
    #[serde(alias = "bodyConsistent")]
    pub body_consistent: bool,
    /// Number of receipt signatures re-verified (full-bundle mode only).
    #[serde(alias = "receiptsReverified")]
    pub receipts_reverified: u64,
    /// Number of receipt signature failures (full-bundle mode only).
    #[serde(alias = "receiptFailures")]
    pub receipt_failures: u64,
    /// Overall pass/fail.
    pub passed: bool,
    /// Human-readable summary.
    pub summary: String,
}

pub const COMPLIANCE_CERTIFICATE_SCHEMA_V1: &str = "chio.compliance.certificate.v1";
pub const COMPLIANCE_CERTIFICATE_SCHEMA: &str = "chio.compliance.certificate.v2";

#[cfg(test)]
#[path = "compliance/bundle_tests.rs"]
mod compliance_bundle_tests;

fn receipt_session_id(receipt: &ChioReceipt) -> Option<&str> {
    let metadata = receipt.metadata.as_ref()?.as_object()?;
    let mut selected = None;
    for (namespace, key) in [
        ("acp", "sessionId"),
        ("receipt_context", "session_id"),
        ("protocol_refusal", "session_id"),
    ] {
        let Some(value) = metadata.get(namespace) else {
            continue;
        };
        let object = value.as_object()?;
        if namespace == "protocol_refusal"
            && object.get("schema").and_then(Value::as_str)
                != Some("chio.session.protocol-refusal.v1")
        {
            return None;
        }
        let Some(value) = object.get(key) else {
            continue;
        };
        let session = value.as_str()?;
        if session.is_empty()
            || session.trim() != session
            || selected.is_some_and(|prior| prior != session)
        {
            return None;
        }
        selected = Some(session);
    }
    selected
}

fn validate_compliance_receipt(
    session_id: &str,
    entry: &ComplianceReceiptEntry,
    config: &ComplianceConfig,
) -> Result<(), ComplianceCertificateError> {
    let receipt = &entry.receipt;
    let sig_ok = receipt
        .verify_signature()
        .map_err(ComplianceCertificateError::Canonical)?;
    if !sig_ok {
        return Err(ComplianceCertificateError::InvalidReceiptSignature {
            receipt_id: receipt.id.clone(),
        });
    }
    let id_ok = chio_receipt_id(&receipt.body()).map(|expected| expected == receipt.id)?;
    if !id_ok {
        return Err(ComplianceCertificateError::InvalidReceiptId {
            receipt_id: receipt.id.clone(),
        });
    }
    let action_hash_ok = receipt.action.verify_hash()?;
    if !action_hash_ok {
        return Err(ComplianceCertificateError::InvalidActionHash {
            receipt_id: receipt.id.clone(),
        });
    }
    let kernel_key_hex = receipt.kernel_key.to_hex();
    if config.trusted_kernel_keys.is_empty() {
        // Operator contract: the trust set must be populated. Emit a
        // one-shot warning so the misconfiguration is visible, then
        // fall through to the standard untrusted-key rejection (an
        // empty trust set contains nothing, so every receipt fails the
        // membership check that follows).
        warn_empty_compliance_trusted_keys_once();
    }
    if !config.trusted_kernel_keys.contains(&kernel_key_hex) {
        return Err(ComplianceCertificateError::UntrustedKernelKey {
            receipt_id: receipt.id.clone(),
            kernel_key: kernel_key_hex,
        });
    }
    if receipt_session_id(receipt) != Some(session_id) {
        return Err(ComplianceCertificateError::SessionMismatch {
            receipt_id: receipt.id.clone(),
            session_id: session_id.to_string(),
        });
    }
    if let Some(expected_tenant_id) = config.expected_tenant_id.as_deref() {
        if receipt.tenant_id.as_deref() != Some(expected_tenant_id) {
            return Err(ComplianceCertificateError::TenantMismatch {
                receipt_id: receipt.id.clone(),
                tenant_id: expected_tenant_id.to_string(),
            });
        }
    }
    if matches!(
        receipt.decision.as_ref(),
        Some(chio_core::receipt::decision::Decision::Allow)
    ) && !receipt.is_allowed()
    {
        return Err(ComplianceCertificateError::NonAuthorizingReceipt {
            receipt_id: receipt.id.clone(),
        });
    }
    Ok(())
}

/// Generate a certificate committing the complete supplied set and exact profile.
/// The caller supplies the set; this API does not claim retained-history coverage.
pub fn generate_compliance_certificate(
    session_id: &str,
    receipts: &[ComplianceReceiptEntry],
    config: &ComplianceConfig,
    keypair: &Keypair,
    clock: &AcpClock,
) -> Result<ComplianceCertificate, ComplianceCertificateError> {
    generate_compliance_certificate_with_coverage(
        session_id,
        receipts,
        config,
        keypair,
        clock,
        ComplianceCoverage::SuppliedReceiptSet,
    )
}

/// Bind a descriptive signed snapshot reference alongside the supplied set.
/// This portable API does not authenticate whole-corpus completeness from metadata.
/// The CLI obtains that guarantee by collecting and comparing the sealed reader result.
pub fn generate_compliance_certificate_with_coverage(
    session_id: &str,
    receipts: &[ComplianceReceiptEntry],
    config: &ComplianceConfig,
    keypair: &Keypair,
    clock: &AcpClock,
    coverage: ComplianceCoverage,
) -> Result<ComplianceCertificate, ComplianceCertificateError> {
    if session_id.len() > 1024 {
        return Err(ComplianceBundleError::CapacityExceeded.into());
    }
    // Preserve the empty-session diagnostic before reading time.
    if receipts.is_empty() {
        return Err(ComplianceCertificateError::EmptySession(
            session_id.to_owned(),
        ));
    }
    let now = clock.seconds()?;
    let summary = compliance_bundle::validate_set(session_id, receipts, config, now, &coverage)?;
    if keypair.public_key() != summary.kernel_key {
        return Err(ComplianceCertificateError::SelfVerification);
    }
    let body = ComplianceCertificateBody {
        schema: COMPLIANCE_CERTIFICATE_SCHEMA.to_owned(),
        session_id: session_id.to_owned(),
        issued_at: now,
        receipt_count: summary.receipt_count,
        first_receipt_at: summary.first_receipt_at,
        last_receipt_at: summary.last_receipt_at,
        all_signatures_valid: true,
        // v2 continuity means the committed selected order, not global adjacency.
        chain_continuous: true,
        scope_compliant: summary.checks.tool_targets == ComplianceCheckStatus::Passed,
        budget_compliant: summary.checks.allowed_mediated_receipt_limit
            == ComplianceCheckStatus::Passed,
        guards_compliant: summary.checks.required_guards == ComplianceCheckStatus::Passed,
        anomalies: Vec::new(),
        kernel_key: summary.kernel_key,
        receipt_set_digest: Some(summary.receipt_set_digest),
        compliance_profile_digest: Some(summary.profile_digest),
        invocation_count: Some(summary.invocation_count),
        checks: Some(summary.checks),
        coverage: Some(coverage),
    };
    compliance_bundle::preflight_body(&body)?;
    let body_bytes = canonical_json_bytes(&body)?;
    let signature = keypair.sign(&body_bytes);
    let certificate = ComplianceCertificate {
        body,
        signer_key: keypair.public_key(),
        signature,
    };
    if !verify_compliance_certificate_at_time(
        &certificate,
        VerificationMode::Lightweight,
        None,
        config,
        now,
    )
    .passed
    {
        return Err(ComplianceCertificateError::SelfVerification);
    }
    Ok(certificate)
}

/// Verify signature/body only or the exact committed v2 receipt set.
pub fn verify_compliance_certificate(
    cert: &ComplianceCertificate,
    mode: VerificationMode,
    receipts: Option<&[ComplianceReceiptEntry]>,
    config: &ComplianceConfig,
) -> CertificateVerificationResult {
    verify_compliance_certificate_with_clock(cert, mode, receipts, config, &AcpClock::default())
}

/// Verify issuance bounds against an explicit trusted authority clock.
pub fn verify_compliance_certificate_with_clock(
    cert: &ComplianceCertificate,
    mode: VerificationMode,
    receipts: Option<&[ComplianceReceiptEntry]>,
    config: &ComplianceConfig,
    clock: &AcpClock,
) -> CertificateVerificationResult {
    match clock.seconds() {
        Ok(now) => verify_compliance_certificate_at_time(cert, mode, receipts, config, now),
        Err(error) => CertificateVerificationResult {
            verification_scope: CertificateVerificationScope::Unverified,
            certificate_signature_valid: false,
            body_consistent: false,
            receipts_reverified: 0,
            receipt_failures: 0,
            passed: false,
            summary: format!("certificate trusted-time verification unavailable: {error}"),
        },
    }
}

fn verify_compliance_certificate_at_time(
    cert: &ComplianceCertificate,
    mode: VerificationMode,
    receipts: Option<&[ComplianceReceiptEntry]>,
    config: &ComplianceConfig,
    now: u64,
) -> CertificateVerificationResult {
    if compliance_bundle::preflight_certificate(cert).is_err() {
        return CertificateVerificationResult {
            verification_scope: CertificateVerificationScope::Unverified,
            certificate_signature_valid: false,
            body_consistent: false,
            receipts_reverified: 0,
            receipt_failures: 0,
            passed: false,
            summary: ComplianceBundleError::CapacityExceeded.reason().into(),
        };
    }
    let body_bytes = match canonical_json_bytes(&cert.body) {
        Ok(bytes) => bytes,
        Err(_) => {
            return CertificateVerificationResult {
                verification_scope: CertificateVerificationScope::Unverified,
                certificate_signature_valid: false,
                body_consistent: false,
                receipts_reverified: 0,
                receipt_failures: 0,
                passed: false,
                summary: "failed to serialize certificate body for verification".into(),
            }
        }
    };
    let sig_valid = cert.signer_key.verify_strict(&body_bytes, &cert.signature);
    let signer_trusted = config
        .trusted_kernel_keys
        .contains(&cert.signer_key.to_hex());
    let signer_matches_body = cert.signer_key == cert.body.kernel_key;
    let legacy = cert.body.schema == COMPLIANCE_CERTIFICATE_SCHEMA_V1;
    let body_ok_excluding_signer_match = certificate_body_consistent(cert, now);
    let body_ok = body_ok_excluding_signer_match && signer_matches_body;
    if mode == VerificationMode::Lightweight {
        let passed = sig_valid && signer_trusted && body_ok;
        return CertificateVerificationResult {
            verification_scope: if passed {
                CertificateVerificationScope::SignatureAndBodyOnly
            } else {
                CertificateVerificationScope::Unverified
            },
            certificate_signature_valid: sig_valid,
            body_consistent: body_ok,
            receipts_reverified: 0,
            receipt_failures: 0,
            passed,
            summary: if passed {
                if legacy {
                    "legacy lightweight signature/body assertions verified; receipt set, history and compliance checks not reverified".into()
                } else {
                    "lightweight signature/body verification passed; receipt set, history and compliance checks not reverified".into()
                }
            } else {
                verification_failure_summary(
                    sig_valid,
                    signer_trusted,
                    body_ok_excluding_signer_match,
                    signer_matches_body,
                    0,
                )
            },
        };
    }
    let Some(entries) = receipts.filter(|entries| !entries.is_empty()) else {
        return CertificateVerificationResult {
            verification_scope: CertificateVerificationScope::Unverified,
            certificate_signature_valid: sig_valid,
            body_consistent: false,
            receipts_reverified: 0,
            receipt_failures: 0,
            passed: false,
            summary: "full-bundle verification requires a nonempty receipt set".into(),
        };
    };
    if legacy || cert.body.coverage.is_none() || entries.len() > 100_000 {
        return CertificateVerificationResult {
            verification_scope: CertificateVerificationScope::Unverified,
            certificate_signature_valid: sig_valid,
            body_consistent: false,
            receipts_reverified: 0,
            receipt_failures: 0,
            passed: false,
            summary: ComplianceBundleError::MissingCommitment.reason().into(),
        };
    }
    let mut report = compliance_bundle::ReceiptVerificationReport::default();
    let validation = cert
        .body
        .coverage
        .as_ref()
        .ok_or(ComplianceBundleError::MissingCommitment)
        .map_err(ComplianceCertificateError::from)
        .and_then(|coverage| {
            compliance_bundle::validate_set_with_report(
                &cert.body.session_id,
                entries,
                config,
                cert.body.issued_at,
                coverage,
                &mut report,
            )
        })
        .and_then(|summary| {
            if cert.body.receipt_count != summary.receipt_count
                || cert.body.invocation_count != Some(summary.invocation_count)
            {
                return Err(ComplianceBundleError::CountMismatch.into());
            }
            if cert.body.receipt_set_digest.as_deref() != Some(summary.receipt_set_digest.as_str())
            {
                return Err(ComplianceBundleError::MissingCommitment.into());
            }
            if cert.body.compliance_profile_digest.as_deref()
                != Some(summary.profile_digest.as_str())
                || cert.body.checks.as_ref() != Some(&summary.checks)
            {
                return Err(ComplianceBundleError::ProfileMismatch.into());
            }
            if cert.body.kernel_key != summary.kernel_key
                || cert.body.first_receipt_at != summary.first_receipt_at
                || cert.body.last_receipt_at != summary.last_receipt_at
            {
                return Err(ComplianceBundleError::TimeMismatch.into());
            }
            Ok(())
        });
    let reverified = report.reverified;
    let failures = report.failures;
    let passed = sig_valid && signer_trusted && body_ok && failures == 0 && validation.is_ok();
    let summary = if passed {
        format!("full committed receipt-set integrity verified ({reverified} receipts); signed snapshot references do not independently verify retained corpus completeness or session closure")
    } else {
        let mut reason = verification_failure_summary(
            sig_valid,
            signer_trusted,
            body_ok_excluding_signer_match,
            signer_matches_body,
            failures,
        );
        if let Err(error) = &validation {
            if let ComplianceCertificateError::Bundle(error) = error {
                reason.push_str("; ");
                reason.push_str(error.reason());
            } else {
                reason.push_str("; configured receipt-set checks failed");
            }
        }
        reason
    };
    CertificateVerificationResult {
        verification_scope: if passed {
            CertificateVerificationScope::CommittedReceiptSet
        } else {
            CertificateVerificationScope::Unverified
        },
        certificate_signature_valid: sig_valid,
        body_consistent: body_ok && validation.is_ok(),
        receipts_reverified: reverified,
        receipt_failures: failures,
        passed,
        summary,
    }
}

fn certificate_body_consistent(cert: &ComplianceCertificate, now: u64) -> bool {
    let body = &cert.body;
    if !body.all_signatures_valid
        || !body.chain_continuous
        || !body.anomalies.is_empty()
        || body.receipt_count == 0
        || body.first_receipt_at > body.last_receipt_at
        || body.last_receipt_at > body.issued_at
        || body.issued_at > now
    {
        return false;
    }
    if body.schema == COMPLIANCE_CERTIFICATE_SCHEMA_V1 {
        return body.scope_compliant && body.budget_compliant && body.guards_compliant;
    }
    if body.schema != COMPLIANCE_CERTIFICATE_SCHEMA
        || !compliance_bundle::valid_digest(body.receipt_set_digest.as_deref())
        || !compliance_bundle::valid_digest(body.compliance_profile_digest.as_deref())
        || body
            .invocation_count
            .is_none_or(|count| count > body.receipt_count)
    {
        return false;
    }
    let (Some(checks), Some(coverage)) = (&body.checks, &body.coverage) else {
        return false;
    };
    body.scope_compliant == (checks.tool_targets == ComplianceCheckStatus::Passed)
        && body.guards_compliant == (checks.required_guards == ComplianceCheckStatus::Passed)
        && body.budget_compliant
            == (checks.allowed_mediated_receipt_limit == ComplianceCheckStatus::Passed)
        && coverage
            .validate(&body.session_id, &[], &body.kernel_key, body.issued_at)
            .is_ok()
}

/// Build a human-readable reason list for a failed certificate verification.
///
/// `body_ok_excluding_signer_match` must reflect ONLY the body conjuncts that
/// are independent of the signer-vs-body comparison (schema, signatures,
/// chain continuity, scope/budget/guards, anomalies). The signer mismatch is
/// reported via its own dedicated reason, so folding it back into a generic
/// "body consistency check failed" entry would produce a redundant message
/// whose root cause is already named on the previous line.
fn verification_failure_summary(
    sig_valid: bool,
    signer_trusted: bool,
    body_ok_excluding_signer_match: bool,
    signer_matches_body: bool,
    receipt_failures: u64,
) -> String {
    let mut reasons = Vec::new();
    if !sig_valid {
        reasons.push("certificate signature invalid".to_string());
    }
    if !signer_trusted {
        reasons.push("certificate signer is not trusted".to_string());
    }
    if !signer_matches_body {
        reasons.push("certificate signer does not match body kernel key".to_string());
    }
    if !body_ok_excluding_signer_match {
        reasons.push("body consistency check failed".to_string());
    }
    if receipt_failures > 0 {
        reasons.push(format!(
            "{receipt_failures} receipt authority check(s) failed"
        ));
    }
    if reasons.is_empty() {
        "verification failed".into()
    } else {
        format!("verification failed: {}", reasons.join(", "))
    }
}
