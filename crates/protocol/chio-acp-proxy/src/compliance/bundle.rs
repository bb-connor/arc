//! Authenticated ACP receipt sets and the exact checks requested by an operator.

use crate::{AcpAuditError, ComplianceCertificateError, ComplianceConfig, ComplianceReceiptEntry};
use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[path = "bundle/coverage.rs"]
mod coverage;
pub use coverage::ComplianceCoverage;
#[path = "bundle/bounds.rs"]
mod bounds;
pub(crate) use bounds::{preflight_body, preflight_certificate};

const MAX_CERTIFICATE_RECEIPTS: usize = 100_000;
const MAX_RECEIPT_BYTES: usize = 1024 * 1024;
const MAX_RECEIPT_SET_BYTES: usize = 128 * 1024 * 1024;

/// An exact tool target, without filesystem or network scope implications.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComplianceToolTarget {
    pub server_id: String,
    pub tool_name: String,
}

/// Whether a configured check was actually applicable and evaluated.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceCheckStatus {
    #[default]
    NotEvaluated,
    NotApplicable,
    Passed,
}

/// Signed check semantics; the limit counts allowed mediated receipts, not spend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComplianceChecks {
    pub tool_targets: ComplianceCheckStatus,
    pub required_guards: ComplianceCheckStatus,
    pub allowed_mediated_receipt_limit: ComplianceCheckStatus,
    pub tenant: ComplianceCheckStatus,
}

/// Explicit operator profile. Trusted signing keys are supplied independently.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComplianceProfile {
    #[serde(default)]
    pub budget_limit: u64,
    #[serde(default)]
    pub required_guards: Vec<String>,
    #[serde(default)]
    pub tool_targets: Vec<ComplianceToolTarget>,
    /// Explicit legacy tool-name prefixes, not resource scopes.
    #[serde(default)]
    pub authorized_tool_prefixes: Vec<String>,
    #[serde(default)]
    pub expected_tenant_id: Option<String>,
}

impl ComplianceProfile {
    pub fn into_config(self, trusted_kernel_keys: BTreeSet<String>) -> ComplianceConfig {
        ComplianceConfig {
            budget_limit: self.budget_limit,
            required_guards: self.required_guards,
            authorized_tool_targets: self.tool_targets,
            authorized_scopes: self.authorized_tool_prefixes,
            expected_tenant_id: self.expected_tenant_id,
            trusted_kernel_keys,
        }
    }
}

/// Input-independent refusal categories for invalid or incomplete certificate data.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("urn:chio:error:attest:receipt-verification-failed")]
pub enum ComplianceBundleError {
    MissingCommitment,
    CountMismatch,
    DuplicateReceipt,
    InvalidSequence,
    TimeMismatch,
    ProfileMismatch,
    InvalidProfile,
    CoverageMismatch,
    CapacityExceeded,
}

impl ComplianceBundleError {
    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::MissingCommitment => "certificate lacks full receipt-set commitments",
            Self::CountMismatch => "receipt or allowed-mediated count differs",
            Self::DuplicateReceipt => "receipt set contains duplicate identities",
            Self::InvalidSequence => "receipt ordering is invalid",
            Self::TimeMismatch => "signed time coverage differs",
            Self::ProfileMismatch => "operator profile differs from the signed profile",
            Self::InvalidProfile => "operator profile contains invalid identifiers or limits",
            Self::CoverageMismatch => "retained snapshot coverage differs",
            Self::CapacityExceeded => "receipt set exceeds certificate bounds",
        }
    }
}

#[derive(Serialize)]
struct ProfileCommitment<'a> {
    schema: &'static str,
    allowed_mediated_receipt_limit: u64,
    required_guards: &'a [String],
    tool_targets: &'a [ComplianceToolTarget],
    tool_name_prefixes: &'a [String],
    expected_tenant_id: Option<&'a str>,
}

pub(crate) fn profile_digest(
    config: &ComplianceConfig,
) -> Result<String, ComplianceCertificateError> {
    let valid_id = |value: &str| !value.is_empty() && value.len() <= 1024 && value.trim() == value;
    if config.required_guards.len() > 128
        || config.authorized_tool_targets.len() > 128
        || config.authorized_scopes.len() > 128
        || config.required_guards.iter().any(|value| !valid_id(value))
        || config
            .authorized_scopes
            .iter()
            .any(|value| !valid_id(value))
        || config
            .authorized_tool_targets
            .iter()
            .any(|target| !valid_id(&target.server_id) || !valid_id(&target.tool_name))
        || config
            .expected_tenant_id
            .as_deref()
            .is_some_and(|value| !valid_id(value))
        || config.required_guards.iter().collect::<BTreeSet<_>>().len()
            != config.required_guards.len()
    {
        return Err(ComplianceBundleError::InvalidProfile.into());
    }
    let bytes = canonical_json_bytes(&ProfileCommitment {
        schema: "chio.acp.compliance-profile.v2",
        allowed_mediated_receipt_limit: config.budget_limit,
        required_guards: &config.required_guards,
        tool_targets: &config.authorized_tool_targets,
        tool_name_prefixes: &config.authorized_scopes,
        expected_tenant_id: config.expected_tenant_id.as_deref(),
    })?;
    Ok(chio_core::hashing::sha256_hex(&bytes))
}

pub(crate) fn valid_digest(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

pub(crate) struct BundleSummary {
    pub receipt_count: u64,
    pub invocation_count: u64,
    pub first_receipt_at: u64,
    pub last_receipt_at: u64,
    pub kernel_key: PublicKey,
    pub receipt_set_digest: String,
    pub profile_digest: String,
    pub checks: ComplianceChecks,
}

#[derive(Default)]
pub(crate) struct ReceiptVerificationReport {
    pub reverified: u64,
    pub failures: u64,
}

pub(crate) fn validate_set(
    session_id: &str,
    entries: &[ComplianceReceiptEntry],
    config: &ComplianceConfig,
    issued_at: u64,
    coverage: &ComplianceCoverage,
) -> Result<BundleSummary, ComplianceCertificateError> {
    validate_set_with_report(
        session_id,
        entries,
        config,
        issued_at,
        coverage,
        &mut ReceiptVerificationReport::default(),
    )
}

pub(crate) fn validate_set_with_report(
    session_id: &str,
    entries: &[ComplianceReceiptEntry],
    config: &ComplianceConfig,
    issued_at: u64,
    coverage: &ComplianceCoverage,
    report: &mut ReceiptVerificationReport,
) -> Result<BundleSummary, ComplianceCertificateError> {
    bounds::preflight_set(session_id, entries, coverage)?;
    let first = entries
        .first()
        .ok_or_else(|| ComplianceCertificateError::EmptySession(session_id.into()))?;
    if entries.len() > MAX_CERTIFICATE_RECEIPTS {
        return Err(ComplianceBundleError::CapacityExceeded.into());
    }
    let receipt_count =
        u64::try_from(entries.len()).map_err(|_| ComplianceBundleError::CapacityExceeded)?;
    let profile_digest = profile_digest(config)?;
    let mut authority_error = None;
    for entry in entries {
        report.reverified = report.reverified.saturating_add(1);
        if let Err(error) = crate::validate_compliance_receipt(session_id, entry, config) {
            report.failures = report.failures.saturating_add(1);
            authority_error.get_or_insert(error);
        }
    }
    if let Some(error) = authority_error {
        return Err(error);
    }
    let has_entry_sequence = first.entry_seq.is_some();
    let mut previous: Option<(u64, u64)> = None;
    let mut receipt_ids = BTreeSet::new();
    let mut source_sequences = BTreeSet::new();
    let mut invocation_count = 0u64;
    let mut total_bytes = 0usize;
    let mut digest = Sha256::new();
    digest.update(b"chio.acp.compliance-receipt-set.v2\0");
    digest.update(receipt_count.to_be_bytes());
    for entry in entries {
        if entry.receipt.kernel_key != first.receipt.kernel_key {
            return Err(ComplianceCertificateError::KernelKeyMismatch {
                receipt_id: entry.receipt.id.clone(),
            });
        }
        if entry.receipt.tenant_id != first.receipt.tenant_id {
            return Err(ComplianceCertificateError::TenantMismatch {
                receipt_id: entry.receipt.id.clone(),
                tenant_id: first.receipt.tenant_id.clone().unwrap_or_default(),
            });
        }
        if !receipt_ids.insert(&entry.receipt.id) || !source_sequences.insert(entry.seq) {
            return Err(ComplianceBundleError::DuplicateReceipt.into());
        }
        if entry.entry_seq.is_some() != has_entry_sequence {
            return Err(ComplianceBundleError::InvalidSequence.into());
        }
        let order = entry.entry_seq.unwrap_or(entry.seq);
        if let Some((prior_order, prior_time)) = previous {
            let minimum = prior_order.checked_add(1).ok_or(AcpAuditError::Clock(
                chio_security_types::clock::ClockError::Overflow,
            ))?;
            if order < minimum {
                return Err(ComplianceCertificateError::ChainDiscontinuity {
                    expected: minimum,
                    found: order,
                });
            }
            if entry.receipt.timestamp < prior_time {
                return Err(ComplianceBundleError::TimeMismatch.into());
            }
        }
        if entry.receipt.timestamp > issued_at {
            return Err(
                AcpAuditError::Clock(chio_security_types::clock::ClockError::NotYetValid).into(),
            );
        }
        previous = Some((order, entry.receipt.timestamp));
        if entry.receipt.is_allowed() {
            invocation_count = invocation_count
                .checked_add(1)
                .ok_or(ComplianceBundleError::CapacityExceeded)?;
            validate_invocation_profile(entry, config)?;
        }
        let bytes = canonical_json_bytes(&entry.receipt)?;
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .ok_or(ComplianceBundleError::CapacityExceeded)?;
        if bytes.len() > MAX_RECEIPT_BYTES || total_bytes > MAX_RECEIPT_SET_BYTES {
            return Err(ComplianceBundleError::CapacityExceeded.into());
        }
        // Domain, count, then source sequence, an entry-sequence presence byte
        // and optional sequence, followed by length-framed canonical receipt
        // bytes. Identity framing does not consume the receipt byte ceiling.
        digest.update(entry.seq.to_be_bytes());
        digest.update([u8::from(entry.entry_seq.is_some())]);
        if let Some(entry_seq) = entry.entry_seq {
            digest.update(entry_seq.to_be_bytes());
        }
        digest.update(
            u64::try_from(bytes.len())
                .map_err(|_| ComplianceBundleError::CapacityExceeded)?
                .to_be_bytes(),
        );
        digest.update(bytes);
    }
    if config.budget_limit > 0 && invocation_count > config.budget_limit {
        return Err(ComplianceCertificateError::BudgetExceeded {
            used: invocation_count,
            limit: config.budget_limit,
        });
    }
    coverage.validate(session_id, entries, &first.receipt.kernel_key, issued_at)?;
    let applicable_status = |configured: bool| {
        if !configured {
            ComplianceCheckStatus::NotEvaluated
        } else if invocation_count == 0 {
            ComplianceCheckStatus::NotApplicable
        } else {
            ComplianceCheckStatus::Passed
        }
    };
    Ok(BundleSummary {
        receipt_count,
        invocation_count,
        first_receipt_at: first.receipt.timestamp,
        last_receipt_at: entries
            .last()
            .map_or(first.receipt.timestamp, |entry| entry.receipt.timestamp),
        kernel_key: first.receipt.kernel_key.clone(),
        receipt_set_digest: format!("{:x}", digest.finalize()),
        profile_digest,
        checks: ComplianceChecks {
            tool_targets: applicable_status(
                !config.authorized_scopes.is_empty() || !config.authorized_tool_targets.is_empty(),
            ),
            required_guards: applicable_status(!config.required_guards.is_empty()),
            allowed_mediated_receipt_limit: if config.budget_limit > 0 {
                ComplianceCheckStatus::Passed
            } else {
                ComplianceCheckStatus::NotEvaluated
            },
            tenant: if config.expected_tenant_id.is_some() {
                ComplianceCheckStatus::Passed
            } else {
                ComplianceCheckStatus::NotEvaluated
            },
        },
    })
}

fn validate_invocation_profile(
    entry: &ComplianceReceiptEntry,
    config: &ComplianceConfig,
) -> Result<(), ComplianceCertificateError> {
    let receipt = &entry.receipt;
    let prefixes_match = config.authorized_scopes.is_empty()
        || config
            .authorized_scopes
            .iter()
            .any(|prefix| receipt.tool_name.starts_with(prefix));
    let targets_match = config.authorized_tool_targets.is_empty()
        || config.authorized_tool_targets.iter().any(|target| {
            target.server_id == receipt.tool_server && target.tool_name == receipt.tool_name
        });
    if !prefixes_match || !targets_match {
        return Err(ComplianceCertificateError::ScopeViolation {
            receipt_id: receipt.id.clone(),
            resource: receipt.tool_name.clone(),
        });
    }
    for guard in &config.required_guards {
        let present = receipt
            .evidence
            .iter()
            .any(|evidence| evidence.guard_name == *guard && evidence.verdict);
        let denied = receipt
            .evidence
            .iter()
            .any(|evidence| evidence.guard_name == *guard && !evidence.verdict);
        if !present || denied {
            return Err(ComplianceCertificateError::GuardBypass {
                guard_name: guard.clone(),
                receipt_id: receipt.id.clone(),
            });
        }
    }
    Ok(())
}
