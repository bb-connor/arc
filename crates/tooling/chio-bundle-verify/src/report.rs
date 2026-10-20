//! The per-receipt column report and its exit class.

use std::path::Path;

use chio_core_types::crypto::PublicKey;
use chio_core_types::root_authority::{ReportColumn, VerifierTrust};
use serde::{Deserialize, Serialize};

use crate::error::{BundleVerifyError, ExitClass};
use crate::verify::{verify_package, EmbeddedHttpReceiptVerifier, VerifiedPackage};

pub const BUNDLE_VERIFY_REPORT_SCHEMA: &str = "chio.bundle-verify-report.v1";

/// How far one column of one receipt is established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    Verified,
    Observed,
    Asserted,
    Unverifiable,
    Rejected,
}

/// One column's class and, when it is not `verified`, why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColumnResult {
    pub class: EvidenceClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ColumnResult {
    fn verified() -> Self {
        Self {
            class: EvidenceClass::Verified,
            reason: None,
        }
    }

    fn unverifiable(reason: &str) -> Self {
        Self {
            class: EvidenceClass::Unverifiable,
            reason: Some(reason.to_string()),
        }
    }
}

/// The five columns of one tool receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptColumns {
    pub identity_root: ColumnResult,
    pub delegation_chain: ColumnResult,
    pub decision: ColumnResult,
    pub content: ColumnResult,
    pub settlement: ColumnResult,
}

impl ReceiptColumns {
    #[must_use]
    pub fn get(&self, column: ReportColumn) -> &ColumnResult {
        match column {
            ReportColumn::IdentityRoot => &self.identity_root,
            ReportColumn::DelegationChain => &self.delegation_chain,
            ReportColumn::Decision => &self.decision,
            ReportColumn::Content => &self.content,
            ReportColumn::Settlement => &self.settlement,
        }
    }
}

/// One tool receipt's row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptReport {
    pub receipt_id: String,
    pub seq: u64,
    pub columns: ReceiptColumns,
}

/// `chio.bundle-verify-report.v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationReport {
    pub schema: String,
    pub envelope_signer: PublicKey,
    pub manifest_sha256: String,
    pub required_columns: Vec<ReportColumn>,
    pub receipts: Vec<ReceiptReport>,
    pub exit_class: i32,
}

impl VerificationReport {
    /// 10 when a required column is not `verified` for some receipt, else 0.
    /// Integrity, parse and trust failures never reach a report.
    #[must_use]
    pub fn exit_class(&self, trust: &VerifierTrust) -> ExitClass {
        let unverified = self.receipts.iter().any(|receipt| {
            trust
                .required_columns
                .iter()
                .any(|column| receipt.columns.get(*column).class != EvidenceClass::Verified)
        });
        if unverified {
            ExitClass::RequiredColumn
        } else {
            ExitClass::Verified
        }
    }
}

const NO_ROOT_AUTHORITY: &str = "the receipt carries no root authority";
const NO_DISCLOSURE: &str = "the bundle carries no content openings";
const NO_SETTLEMENT: &str = "the bundle carries no settlement evidence";

/// Verify a bundle directory and report one evidence class per column.
///
/// Every integrity, parse and trust failure is an error. A `settlement`
/// requirement is refused as unsupported before any file is read.
pub fn verify_bundle(
    dir: &Path,
    trust: &VerifierTrust,
    embedded_http: Option<&dyn EmbeddedHttpReceiptVerifier>,
) -> Result<VerificationReport, BundleVerifyError> {
    if trust.required_columns.contains(&ReportColumn::Settlement) {
        return Err(BundleVerifyError::unsupported(
            "this verifier cannot verify the settlement column",
        ));
    }
    let verified = verify_package(dir, trust, embedded_http)?;
    Ok(report(&verified, trust))
}

/// The report of an already verified package.
#[must_use]
pub fn report(verified: &VerifiedPackage, trust: &VerifierTrust) -> VerificationReport {
    let receipts = verified
        .package
        .bundle
        .tool_receipts
        .iter()
        .map(|record| ReceiptReport {
            receipt_id: record.receipt.id.clone(),
            seq: record.seq,
            columns: ReceiptColumns {
                identity_root: ColumnResult::unverifiable(NO_ROOT_AUTHORITY),
                delegation_chain: ColumnResult::unverifiable(NO_ROOT_AUTHORITY),
                decision: ColumnResult::verified(),
                content: ColumnResult::unverifiable(NO_DISCLOSURE),
                settlement: ColumnResult::unverifiable(NO_SETTLEMENT),
            },
        })
        .collect();
    let mut report = VerificationReport {
        schema: BUNDLE_VERIFY_REPORT_SCHEMA.to_string(),
        envelope_signer: verified.package.envelope.signer_key.clone(),
        manifest_sha256: verified.manifest_sha256.clone(),
        required_columns: trust.required_columns.clone(),
        receipts,
        exit_class: 0,
    };
    report.exit_class = report.exit_class(trust).code();
    report
}
