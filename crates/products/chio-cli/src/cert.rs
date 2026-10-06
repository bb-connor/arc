// CLI handlers for `chio cert` commands.

use std::path::Path;

use chio_acp_proxy::{
    generate_compliance_certificate_with_coverage, verify_compliance_certificate,
    CertificateVerificationScope, ComplianceCertificate, VerificationMode,
};

use crate::CliError;
#[cfg(test)]
use chio_acp_proxy::{generate_compliance_certificate, ComplianceConfig};

mod session_receipts;
use session_receipts::{certificate_entries, load_session_receipts, snapshot_reference};
mod profile;

#[cfg(test)]
#[path = "cert/session_receipts_tests.rs"]
mod session_receipts_tests;

/// `chio cert generate` -- walk the receipt store for a session and produce
/// a signed compliance certificate.
pub fn cmd_cert_generate(
    session_id: &str,
    receipt_db: &Path,
    budget_limit: u64,
    output: Option<&Path>,
    authority_seed_file: Option<&Path>,
    json_output: bool,
) -> Result<(), CliError> {
    cmd_cert_generate_with_profile(CertificateGenerateOptions {
        session_id,
        receipt_db,
        budget_limit,
        output,
        authority_seed_file,
        json_output,
        profile_path: None,
    })
}

pub(crate) struct CertificateGenerateOptions<'a> {
    pub session_id: &'a str,
    pub receipt_db: &'a Path,
    pub budget_limit: u64,
    pub output: Option<&'a Path>,
    pub authority_seed_file: Option<&'a Path>,
    pub json_output: bool,
    pub profile_path: Option<&'a Path>,
}

pub(crate) fn cmd_cert_generate_with_profile(
    options: CertificateGenerateOptions<'_>,
) -> Result<(), CliError> {
    let CertificateGenerateOptions {
        session_id,
        receipt_db,
        budget_limit,
        output,
        authority_seed_file,
        json_output,
        profile_path,
    } = options;
    let default_seed_path = std::path::PathBuf::from(".chio-authority-seed");
    let keypair =
        crate::load_existing_authority_keypair(authority_seed_file.unwrap_or(&default_seed_path))?;
    let config = profile::load_profile(
        profile_path,
        &keypair.public_key(),
        (budget_limit != 0).then_some(budget_limit),
    )?;
    let snapshot = load_session_receipts(
        receipt_db,
        session_id,
        &keypair.public_key(),
        config.expected_tenant_id.as_deref(),
    )?;
    let entries = certificate_entries(&snapshot);
    let cert = generate_compliance_certificate_with_coverage(
        session_id,
        &entries,
        &config,
        &keypair,
        &chio_acp_proxy::AcpClock::default(),
        snapshot_reference(&snapshot),
    )
    .map_err(certificate_generation_error)?;

    let cert_json = serde_json::to_string_pretty(&cert)
        .map_err(|e| CliError::cli_other_error(format!("serialization failed: {e}")))?;

    if let Some(out_path) = output {
        std::fs::write(out_path, &cert_json)
            .map_err(|e| CliError::cli_other_error(format!("failed to write output: {e}")))?;
        if !json_output {
            eprintln!(
                "compliance certificate for session {} written to {}",
                session_id,
                out_path.display()
            );
        }
    }

    if json_output || output.is_none() {
        println!("{cert_json}");
    }

    Ok(())
}

fn certificate_generation_error(error: chio_acp_proxy::ComplianceCertificateError) -> CliError {
    let spec = chio_errors::_generated::error_codes::lookup_error_code(error.code())
        .unwrap_or(&chio_errors::_generated::error_codes::KERNEL_INTERNAL_ERROR);
    CliError::with_source(spec, error)
}

/// `chio cert verify` -- verify a compliance certificate.
pub fn cmd_cert_verify(
    certificate_path: &Path,
    full: bool,
    receipt_db: Option<&Path>,
    trusted_kernel_pubkey: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    cmd_cert_verify_with_profile(CertificateVerifyOptions {
        certificate_path,
        full,
        receipt_db,
        trusted_kernel_pubkey,
        json_output,
        profile_path: None,
    })
}

pub(crate) struct CertificateVerifyOptions<'a> {
    pub certificate_path: &'a Path,
    pub full: bool,
    pub receipt_db: Option<&'a Path>,
    pub trusted_kernel_pubkey: &'a Path,
    pub json_output: bool,
    pub profile_path: Option<&'a Path>,
}

pub(crate) fn cmd_cert_verify_with_profile(
    options: CertificateVerifyOptions<'_>,
) -> Result<(), CliError> {
    let CertificateVerifyOptions {
        certificate_path,
        full,
        receipt_db,
        trusted_kernel_pubkey,
        json_output,
        profile_path,
    } = options;
    let cert: ComplianceCertificate =
        crate::input::text(&crate::input::read_text(certificate_path)?)?;
    let trusted_kernel_key =
        crate::load_trusted_kernel_pubkey(trusted_kernel_pubkey).map_err(|source| {
            CliError::with_public_source(
                &chio_errors::_generated::error_codes::ATTEST_RECEIPT_VERIFICATION_FAILED,
                "trusted certificate kernel key could not be loaded",
                source,
            )
        })?;
    let config = profile::load_profile(profile_path, &trusted_kernel_key, None)?;
    let snapshot = if full {
        let path = receipt_db.ok_or_else(|| {
            CliError::cli_other_error("full-bundle verification requires --receipt-db")
        })?;
        Some(load_session_receipts(
            path,
            &cert.body.session_id,
            &trusted_kernel_key,
            config.expected_tenant_id.as_deref(),
        )?)
    } else {
        None
    };
    let entries = snapshot.as_ref().map(certificate_entries);
    let mode = if full {
        VerificationMode::FullBundle
    } else {
        VerificationMode::Lightweight
    };
    let mut result = verify_compliance_certificate(&cert, mode, entries.as_deref(), &config);
    if let Some(snapshot) = &snapshot {
        if cert.body.coverage.as_ref() != Some(&snapshot_reference(snapshot)) {
            result.passed = false;
            result.body_consistent = false;
            result.verification_scope = CertificateVerificationScope::Unverified;
            result.summary = "signed snapshot reference differs from the exact authenticated retained tool snapshot; collect a fresh certificate".into();
        } else if result.passed {
            result.verification_scope =
                CertificateVerificationScope::AuthenticatedRetainedToolSnapshot;
            result.summary = format!("authenticated retained tool snapshot verified through claim entry {}; session lifetime closure is not asserted", snapshot.coverage().snapshot_end_entry_seq);
        }
    }

    if json_output {
        let result_json = serde_json::to_string_pretty(&result)
            .map_err(|e| CliError::cli_other_error(format!("serialization failed: {e}")))?;
        println!("{result_json}");
    } else if result.passed {
        println!("PASS: {}", result.summary);
    } else {
        println!("FAIL: {}", result.summary);
    }

    if !result.passed {
        return Err(CliError::registry_error(
            &chio_errors::_generated::error_codes::ATTEST_RECEIPT_VERIFICATION_FAILED,
            "certificate verification failed",
        ));
    }

    Ok(())
}

/// `chio cert inspect` -- display certificate contents.
pub fn cmd_cert_inspect(certificate_path: &Path, json_output: bool) -> Result<(), CliError> {
    let cert_text = crate::input::read_text(certificate_path)
        .map_err(|e| CliError::cli_other_error(format!("failed to read certificate: {e}")))?;

    let cert: ComplianceCertificate = crate::input::text(&cert_text)?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&cert.body)
                .map_err(|e| CliError::cli_other_error(format!("serialization failed: {e}")))?
        );
    } else {
        println!("Session ID:     {}", cert.body.session_id);
        println!("Schema:         {}", cert.body.schema);
        println!("Issued at:      {}", cert.body.issued_at);
        println!("Receipt count:  {}", cert.body.receipt_count);
        if let Some(count) = cert.body.invocation_count {
            println!("Allowed mediated receipts: {count} (not dispatch or spend proof)");
        }
        match cert.body.coverage.as_ref() {
            Some(chio_acp_proxy::ComplianceCoverage::SuppliedReceiptSet) => println!("Coverage: supplied receipt set"),
            Some(chio_acp_proxy::ComplianceCoverage::RetainedSnapshotReference { snapshot_end_entry_seq, .. }) => println!("Coverage: signed snapshot reference through claim entry {snapshot_end_entry_seq}; full verification requires the authenticated store"),
            None => println!("Coverage: legacy signed assertion"),
        }
        println!("First receipt:  {}", cert.body.first_receipt_at);
        println!("Last receipt:   {}", cert.body.last_receipt_at);
        println!(
            "Signatures:     {}",
            if cert.body.all_signatures_valid {
                "valid"
            } else {
                "INVALID"
            }
        );
        println!(
            "Chain:          {}",
            if cert.body.chain_continuous {
                "continuous"
            } else {
                "BROKEN"
            }
        );
        println!(
            "Tool targets:   {}",
            check_label(
                cert.body.checks.as_ref().map(|checks| checks.tool_targets),
                cert.body.scope_compliant
            )
        );
        println!(
            "Allowed receipts: {}",
            check_label(
                cert.body
                    .checks
                    .as_ref()
                    .map(|checks| checks.allowed_mediated_receipt_limit),
                cert.body.budget_compliant
            )
        );
        println!(
            "Guards:         {}",
            check_label(
                cert.body
                    .checks
                    .as_ref()
                    .map(|checks| checks.required_guards),
                cert.body.guards_compliant
            )
        );
        if !cert.body.anomalies.is_empty() {
            println!("Anomalies:");
            for a in &cert.body.anomalies {
                println!("  - {a}");
            }
        }
        println!("Signer key:     {}", cert.signer_key.to_hex());
        println!("Kernel key:     {}", cert.body.kernel_key.to_hex());
    }

    Ok(())
}

fn check_label(
    status: Option<chio_acp_proxy::ComplianceCheckStatus>,
    legacy_passed: bool,
) -> &'static str {
    match status {
        Some(chio_acp_proxy::ComplianceCheckStatus::Passed) => "checked and passed",
        Some(chio_acp_proxy::ComplianceCheckStatus::NotEvaluated) => "not evaluated",
        Some(chio_acp_proxy::ComplianceCheckStatus::NotApplicable) => "not applicable",
        None if legacy_passed => "legacy signed assertion (not reverified)",
        None => "legacy check did not pass",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn certificate_diagnostic_reports_missing_evidence_without_signing_failure(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let seed = directory.path().join("seed");
        std::fs::write(&seed, "57".repeat(32))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600))?;
        }
        let native = generate_compliance_certificate(
            "private-session",
            &[],
            &ComplianceConfig::default(),
            &chio_core::Keypair::from_seed(&[87; 32]),
            &chio_acp_proxy::AcpClock::default(),
        )
        .err()
        .ok_or("empty session was certified")?;
        let error = certificate_generation_error(native);
        assert_eq!(
            error.report().code,
            "urn:chio:error:attest:provenance-missing"
        );
        let native = std::error::Error::source(&error)
            .and_then(std::error::Error::source)
            .and_then(|source| source.downcast_ref::<chio_acp_proxy::ComplianceCertificateError>());
        assert!(matches!(
            native,
            Some(chio_acp_proxy::ComplianceCertificateError::EmptySession(_))
        ));
        assert!(!format!("{error} {error:?} {:?}", error.report()).contains("private-session"));
        Ok(())
    }

    #[test]
    fn certificate_inspection_labels_unconfigured_checks_honestly() {
        assert_eq!(
            check_label(
                Some(chio_acp_proxy::ComplianceCheckStatus::NotEvaluated),
                false
            ),
            "not evaluated"
        );
        assert_eq!(
            check_label(
                Some(chio_acp_proxy::ComplianceCheckStatus::NotApplicable),
                false
            ),
            "not applicable"
        );
        assert_eq!(
            check_label(None, true),
            "legacy signed assertion (not reverified)"
        );
    }
}
