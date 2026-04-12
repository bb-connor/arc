use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_control_plane::{evidence_export, CliError};
use arc_core::capability::{ArcScope, CapabilityToken, CapabilityTokenBody, Operation, ToolGrant};
use arc_core::crypto::Keypair;
use arc_core::receipt::{ArcReceipt, ArcReceiptBody, Decision, ToolCallAction};
use arc_core::{canonical_json_bytes, sha256_hex};
use arc_kernel::build_checkpoint;
use arc_mercury_core::{
    MercuryAssuranceArtifactKind, MercuryAssuranceAudience, MercuryAssuranceDisclosureProfile,
    MercuryAssuranceInvestigationPackage, MercuryAssurancePackage, MercuryAssuranceReviewPackage,
    MercuryAssuranceReviewerPopulation, MercuryAssuranceSuiteArtifact,
    MercuryAssuranceSuitePackage, MercuryBroaderDistributionArtifact,
    MercuryBroaderDistributionArtifactKind, MercuryBroaderDistributionMotion,
    MercuryBroaderDistributionPackage, MercuryBroaderDistributionProfile,
    MercuryBroaderDistributionSurface, MercuryBundleManifest, MercuryControlledAdoptionArtifact,
    MercuryControlledAdoptionArtifactKind, MercuryControlledAdoptionCohort,
    MercuryControlledAdoptionPackage, MercuryControlledAdoptionProfile,
    MercuryControlledAdoptionSurface, MercuryDeliveryContinuityArtifact,
    MercuryDeliveryContinuityArtifactKind, MercuryDeliveryContinuityMotion,
    MercuryDeliveryContinuityPackage, MercuryDeliveryContinuityProfile,
    MercuryDeliveryContinuitySurface, MercuryDownstreamArtifact, MercuryDownstreamArtifactRole,
    MercuryDownstreamConsumerProfile, MercuryDownstreamReviewPackage, MercuryDownstreamTransport,
    MercuryEmbeddedArtifactKind, MercuryEmbeddedOemArtifact, MercuryEmbeddedOemPackage,
    MercuryEmbeddedOemProfile, MercuryEmbeddedPartnerSurface, MercuryEmbeddedSdkSurface,
    MercuryGovernanceChangeClass, MercuryGovernanceControlState, MercuryGovernanceDecisionPackage,
    MercuryGovernanceGateState, MercuryGovernanceReviewAudience, MercuryGovernanceReviewPackage,
    MercuryGovernanceWorkflowPath, MercuryInquiryPackage, MercuryPackageKind, MercuryPilotScenario,
    MercuryPilotStep, MercuryPortfolioProgramArtifact, MercuryPortfolioProgramArtifactKind,
    MercuryPortfolioProgramMotion, MercuryPortfolioProgramPackage, MercuryPortfolioProgramProfile,
    MercuryPortfolioProgramSurface, MercuryPortfolioRevenueBoundaryArtifact,
    MercuryPortfolioRevenueBoundaryArtifactKind, MercuryPortfolioRevenueBoundaryMotion,
    MercuryPortfolioRevenueBoundaryPackage, MercuryPortfolioRevenueBoundaryProfile,
    MercuryPortfolioRevenueBoundarySurface, MercuryProgramFamilyArtifact,
    MercuryProgramFamilyArtifactKind, MercuryProgramFamilyMotion, MercuryProgramFamilyPackage,
    MercuryProgramFamilyProfile, MercuryProgramFamilySurface, MercuryProofPackage,
    MercuryPublicationProfile, MercuryReferenceDistributionArtifact,
    MercuryReferenceDistributionArtifactKind, MercuryReferenceDistributionMotion,
    MercuryReferenceDistributionPackage, MercuryReferenceDistributionProfile,
    MercuryReferenceDistributionSurface, MercuryReleaseReadinessArtifact,
    MercuryReleaseReadinessArtifactKind, MercuryReleaseReadinessAudience,
    MercuryReleaseReadinessDeliverySurface, MercuryReleaseReadinessPackage,
    MercuryReleaseReadinessProfile, MercuryRenewalQualificationArtifact,
    MercuryRenewalQualificationArtifactKind, MercuryRenewalQualificationMotion,
    MercuryRenewalQualificationPackage, MercuryRenewalQualificationProfile,
    MercuryRenewalQualificationSurface, MercurySecondAccountExpansionArtifact,
    MercurySecondAccountExpansionArtifactKind, MercurySecondAccountExpansionMotion,
    MercurySecondAccountExpansionPackage, MercurySecondAccountExpansionProfile,
    MercurySecondAccountExpansionSurface, MercurySecondPortfolioProgramArtifact,
    MercurySecondPortfolioProgramArtifactKind, MercurySecondPortfolioProgramMotion,
    MercurySecondPortfolioProgramPackage, MercurySecondPortfolioProgramProfile,
    MercurySecondPortfolioProgramSurface, MercurySelectiveAccountActivationArtifact,
    MercurySelectiveAccountActivationArtifactKind, MercurySelectiveAccountActivationMotion,
    MercurySelectiveAccountActivationPackage, MercurySelectiveAccountActivationProfile,
    MercurySelectiveAccountActivationSurface, MercurySupervisedLiveCapture,
    MercurySupervisedLiveControlState, MercurySupervisedLiveMode, MercuryThirdProgramArtifact,
    MercuryThirdProgramArtifactKind, MercuryThirdProgramMotion, MercuryThirdProgramPackage,
    MercuryThirdProgramProfile, MercuryThirdProgramSurface, MercuryTrustNetworkArtifact,
    MercuryTrustNetworkArtifactKind, MercuryTrustNetworkInteropSurface, MercuryTrustNetworkPackage,
    MercuryTrustNetworkProfile, MercuryTrustNetworkSponsorBoundary, MercuryTrustNetworkTrustAnchor,
    MercuryTrustNetworkWitnessStep, MercuryVerificationReport,
    MERCURY_ASSURANCE_DISCLOSURE_PROFILE_SCHEMA, MERCURY_ASSURANCE_INVESTIGATION_PACKAGE_SCHEMA,
    MERCURY_ASSURANCE_PACKAGE_SCHEMA, MERCURY_ASSURANCE_REVIEW_PACKAGE_SCHEMA,
    MERCURY_ASSURANCE_SUITE_PACKAGE_SCHEMA, MERCURY_BROADER_DISTRIBUTION_PACKAGE_SCHEMA,
    MERCURY_BROADER_DISTRIBUTION_PROFILE_SCHEMA, MERCURY_CONTROLLED_ADOPTION_PACKAGE_SCHEMA,
    MERCURY_CONTROLLED_ADOPTION_PROFILE_SCHEMA, MERCURY_DELIVERY_CONTINUITY_PACKAGE_SCHEMA,
    MERCURY_DELIVERY_CONTINUITY_PROFILE_SCHEMA, MERCURY_DOWNSTREAM_REVIEW_PACKAGE_SCHEMA,
    MERCURY_EMBEDDED_OEM_PACKAGE_SCHEMA, MERCURY_EMBEDDED_OEM_PROFILE_SCHEMA,
    MERCURY_GOVERNANCE_DECISION_PACKAGE_SCHEMA, MERCURY_GOVERNANCE_REVIEW_PACKAGE_SCHEMA,
    MERCURY_INQUIRY_PACKAGE_SCHEMA, MERCURY_PORTFOLIO_PROGRAM_PACKAGE_SCHEMA,
    MERCURY_PORTFOLIO_PROGRAM_PROFILE_SCHEMA, MERCURY_PORTFOLIO_REVENUE_BOUNDARY_PACKAGE_SCHEMA,
    MERCURY_PORTFOLIO_REVENUE_BOUNDARY_PROFILE_SCHEMA, MERCURY_PROGRAM_FAMILY_PACKAGE_SCHEMA,
    MERCURY_PROGRAM_FAMILY_PROFILE_SCHEMA, MERCURY_PROOF_PACKAGE_SCHEMA,
    MERCURY_REFERENCE_DISTRIBUTION_PACKAGE_SCHEMA, MERCURY_REFERENCE_DISTRIBUTION_PROFILE_SCHEMA,
    MERCURY_RELEASE_READINESS_PACKAGE_SCHEMA, MERCURY_RELEASE_READINESS_PROFILE_SCHEMA,
    MERCURY_RENEWAL_QUALIFICATION_PACKAGE_SCHEMA, MERCURY_RENEWAL_QUALIFICATION_PROFILE_SCHEMA,
    MERCURY_SECOND_ACCOUNT_EXPANSION_PACKAGE_SCHEMA,
    MERCURY_SECOND_ACCOUNT_EXPANSION_PROFILE_SCHEMA,
    MERCURY_SECOND_PORTFOLIO_PROGRAM_PACKAGE_SCHEMA,
    MERCURY_SECOND_PORTFOLIO_PROGRAM_PROFILE_SCHEMA,
    MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_PACKAGE_SCHEMA,
    MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_PROFILE_SCHEMA, MERCURY_THIRD_PROGRAM_PACKAGE_SCHEMA,
    MERCURY_THIRD_PROGRAM_PROFILE_SCHEMA, MERCURY_TRUST_NETWORK_PACKAGE_SCHEMA,
    MERCURY_TRUST_NETWORK_PROFILE_SCHEMA,
};
use arc_store_sqlite::SqliteReceiptStore;
use chrono::Utc;
use serde::Serialize;

mod portfolio_program_lane;
mod portfolio_revenue_boundary_lane;
mod program_family_lane;
mod renewal_qualification_lane;
mod second_account_expansion_lane;
mod second_portfolio_program_lane;
mod third_program_lane;

use portfolio_program_lane::export_portfolio_program;
pub use portfolio_program_lane::{
    cmd_mercury_portfolio_program_export, cmd_mercury_portfolio_program_validate,
};
pub use portfolio_revenue_boundary_lane::{
    cmd_mercury_portfolio_revenue_boundary_export, cmd_mercury_portfolio_revenue_boundary_validate,
};
use program_family_lane::export_program_family;
pub use program_family_lane::{
    cmd_mercury_program_family_export, cmd_mercury_program_family_validate,
};
use renewal_qualification_lane::export_renewal_qualification;
pub use renewal_qualification_lane::{
    cmd_mercury_renewal_qualification_export, cmd_mercury_renewal_qualification_validate,
};
use second_account_expansion_lane::export_second_account_expansion;
pub use second_account_expansion_lane::{
    cmd_mercury_second_account_expansion_export, cmd_mercury_second_account_expansion_validate,
};
use second_portfolio_program_lane::export_second_portfolio_program;
pub use second_portfolio_program_lane::{
    cmd_mercury_second_portfolio_program_export, cmd_mercury_second_portfolio_program_validate,
};
use third_program_lane::export_third_program;
pub use third_program_lane::{
    cmd_mercury_third_program_export, cmd_mercury_third_program_validate,
};

const MERCURY_WORKFLOW_BOUNDARY: &str =
    "Controlled release, rollback, and inquiry evidence for AI-assisted execution workflow changes.";
const MERCURY_SUPERVISED_LIVE_DECISION: &str = "proceed";
const MERCURY_DOWNSTREAM_DECISION: &str = "proceed_case_management_only";
const MERCURY_GOVERNANCE_DECISION: &str = "proceed_governance_workbench_only";
const MERCURY_ASSURANCE_DECISION: &str = "proceed_assurance_suite_only";
const MERCURY_EMBEDDED_OEM_DECISION: &str = "proceed_embedded_oem_only";
const MERCURY_TRUST_NETWORK_DECISION: &str = "proceed_trust_network_only";
const MERCURY_RELEASE_READINESS_DECISION: &str = "launch_release_readiness_only";
const MERCURY_CONTROLLED_ADOPTION_DECISION: &str = "scale_controlled_adoption_only";
const MERCURY_REFERENCE_DISTRIBUTION_DECISION: &str = "proceed_reference_distribution_only";
const MERCURY_BROADER_DISTRIBUTION_DECISION: &str = "proceed_broader_distribution_only";
const MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_DECISION: &str =
    "proceed_selective_account_activation_only";
const MERCURY_DELIVERY_CONTINUITY_DECISION: &str = "proceed_delivery_continuity_only";
const MERCURY_RENEWAL_QUALIFICATION_DECISION: &str = "proceed_renewal_qualification_only";
const MERCURY_SECOND_ACCOUNT_EXPANSION_DECISION: &str = "proceed_second_account_expansion_only";
const MERCURY_PORTFOLIO_PROGRAM_DECISION: &str = "proceed_portfolio_program_only";
const MERCURY_SECOND_PORTFOLIO_PROGRAM_DECISION: &str = "proceed_second_portfolio_program_only";
const MERCURY_THIRD_PROGRAM_DECISION: &str = "proceed_third_program_only";
const MERCURY_PROGRAM_FAMILY_DECISION: &str = "proceed_program_family_only";
const MERCURY_PORTFOLIO_REVENUE_BOUNDARY_DECISION: &str = "proceed_portfolio_revenue_boundary_only";
const MERCURY_DOWNSTREAM_DESTINATION_LABEL: &str = "case-management-review-drop";
const MERCURY_DOWNSTREAM_DESTINATION_OWNER: &str = "partner-case-management-owner";
const MERCURY_DOWNSTREAM_SUPPORT_OWNER: &str = "mercury-review-ops";
const MERCURY_GOVERNANCE_WORKFLOW_OWNER: &str = "mercury-workflow-owner";
const MERCURY_GOVERNANCE_CONTROL_TEAM_OWNER: &str = "mercury-control-review";
const MERCURY_ASSURANCE_REVIEWER_OWNER: &str = "mercury-assurance-review";
const MERCURY_ASSURANCE_SUPPORT_OWNER: &str = "mercury-assurance-ops";
const MERCURY_EMBEDDED_PARTNER_OWNER: &str = "partner-review-platform-owner";
const MERCURY_EMBEDDED_SUPPORT_OWNER: &str = "mercury-embedded-ops";
const MERCURY_TRUST_NETWORK_SPONSOR_OWNER: &str = "counterparty-review-network-sponsor";
const MERCURY_TRUST_NETWORK_SUPPORT_OWNER: &str = "mercury-trust-network-ops";
const MERCURY_RELEASE_OWNER: &str = "mercury-release-manager";
const MERCURY_RELEASE_PARTNER_OWNER: &str = "mercury-partner-delivery";
const MERCURY_RELEASE_SUPPORT_OWNER: &str = "mercury-release-ops";
const MERCURY_CUSTOMER_SUCCESS_OWNER: &str = "mercury-customer-success";
const MERCURY_REFERENCE_OWNER: &str = "mercury-reference-program";
const MERCURY_ADOPTION_SUPPORT_OWNER: &str = "mercury-adoption-ops";
const MERCURY_BUYER_APPROVAL_OWNER: &str = "mercury-buyer-reference-approval";
const MERCURY_LANDED_ACCOUNT_SALES_OWNER: &str = "mercury-landed-account-sales";
const MERCURY_QUALIFICATION_OWNER: &str = "mercury-account-qualification";
const MERCURY_DISTRIBUTION_APPROVAL_OWNER: &str = "mercury-broader-distribution-approval";
const MERCURY_BROADER_DISTRIBUTION_OWNER: &str = "mercury-broader-distribution";
const MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_OWNER: &str = "mercury-selective-account-activation";
const MERCURY_ACTIVATION_APPROVAL_OWNER: &str = "mercury-activation-approval";
const MERCURY_CONTROLLED_DELIVERY_OWNER: &str = "mercury-controlled-delivery";
const MERCURY_DELIVERY_CONTINUITY_OWNER: &str = "mercury-delivery-continuity";
const MERCURY_RENEWAL_GATE_OWNER: &str = "mercury-renewal-gate";
const MERCURY_CUSTOMER_EVIDENCE_OWNER: &str = "mercury-customer-evidence";
const MERCURY_RENEWAL_QUALIFICATION_OWNER: &str = "mercury-renewal-qualification";
const MERCURY_OUTCOME_REVIEW_OWNER: &str = "mercury-outcome-review";
const MERCURY_EXPANSION_BOUNDARY_OWNER: &str = "mercury-expansion-boundary";
const MERCURY_SECOND_ACCOUNT_EXPANSION_OWNER: &str = "mercury-second-account-expansion";
const MERCURY_PORTFOLIO_REVIEW_OWNER: &str = "mercury-portfolio-review";
const MERCURY_REUSE_GOVERNANCE_OWNER: &str = "mercury-reuse-governance";
const MERCURY_PORTFOLIO_PROGRAM_OWNER: &str = "mercury-portfolio-program";
const MERCURY_PROGRAM_REVIEW_OWNER: &str = "mercury-program-review";
const MERCURY_REVENUE_OPERATIONS_GUARDRAILS_OWNER: &str = "mercury-revenue-ops-guardrails";
const MERCURY_SECOND_PORTFOLIO_PROGRAM_OWNER: &str = "mercury-second-portfolio-program";
const MERCURY_PORTFOLIO_REUSE_REVIEW_OWNER: &str = "mercury-portfolio-reuse-review";
const MERCURY_REVENUE_BOUNDARY_GUARDRAILS_OWNER: &str = "mercury-revenue-boundary-guardrails";
const MERCURY_THIRD_PROGRAM_OWNER: &str = "mercury-third-program";
const MERCURY_MULTI_PROGRAM_REVIEW_OWNER: &str = "mercury-multi-program-review";
const MERCURY_MULTI_PROGRAM_GUARDRAILS_OWNER: &str = "mercury-multi-program-guardrails";
const MERCURY_PROGRAM_FAMILY_OWNER: &str = "mercury-program-family";
const MERCURY_SHARED_REVIEW_OWNER: &str = "mercury-shared-review";
const MERCURY_PORTFOLIO_CLAIM_DISCIPLINE_OWNER: &str = "mercury-portfolio-claim-discipline";
const MERCURY_PORTFOLIO_REVENUE_BOUNDARY_OWNER: &str = "mercury-portfolio-revenue-boundary";
const MERCURY_COMMERCIAL_REVIEW_OWNER: &str = "mercury-commercial-review";
const MERCURY_CHANNEL_BOUNDARY_OWNER: &str = "mercury-channel-boundary";

fn current_utc_date() -> String {
    Utc::now().format("%Y-%m-%d").to_string()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("{prefix}-{stamp}-{}", std::process::id()))
}

fn read_json_file<T: for<'de> serde::Deserialize<'de>>(path: &Path) -> Result<T, CliError> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn write_json_file<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn ensure_empty_directory(path: &Path) -> Result<(), CliError> {
    if path.exists() {
        if !path.is_dir() {
            return Err(CliError::Other(format!(
                "output path must be a directory: {}",
                path.display()
            )));
        }
        if fs::read_dir(path)?.next().is_some() {
            return Err(CliError::Other(format!(
                "output directory must be empty: {}",
                path.display()
            )));
        }
    } else {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

fn relative_display(root: &Path, path: &Path) -> Result<String, CliError> {
    path.strip_prefix(root)
        .map(|relative| relative.display().to_string())
        .map_err(|error| CliError::Other(error.to_string()))
}

fn copy_file(src: &Path, dst: &Path) -> Result<(), CliError> {
    let parent = dst.parent().ok_or_else(|| {
        CliError::Other(format!(
            "destination path is missing parent directory: {}",
            dst.display()
        ))
    })?;
    fs::create_dir_all(parent)?;
    fs::copy(src, dst)?;
    Ok(())
}

fn load_bundle_manifests(paths: &[PathBuf]) -> Result<Vec<MercuryBundleManifest>, CliError> {
    paths
        .iter()
        .map(|path| {
            let manifest: MercuryBundleManifest = read_json_file(path)?;
            manifest
                .validate()
                .map_err(|error| CliError::Other(error.to_string()))?;
            Ok(manifest)
        })
        .collect()
}

fn write_bundle_manifests(
    dir: &Path,
    manifests: &[MercuryBundleManifest],
) -> Result<Vec<PathBuf>, CliError> {
    if manifests.len() == 1 {
        let path = dir.with_file_name("bundle-manifest.json");
        write_json_file(&path, &manifests[0])?;
        return Ok(vec![path]);
    }

    fs::create_dir_all(dir)?;
    let mut paths = Vec::with_capacity(manifests.len());
    for (index, manifest) in manifests.iter().enumerate() {
        let path = dir.join(format!("{:02}-{}.json", index + 1, manifest.bundle_id));
        write_json_file(&path, manifest)?;
        paths.push(path);
    }
    Ok(paths)
}

fn build_proof_package(
    input: &Path,
    bundle_manifest_paths: &[PathBuf],
) -> Result<MercuryProofPackage, CliError> {
    let verified = evidence_export::load_verified_evidence_package_summary(input)?;
    let bundle_manifests = load_bundle_manifests(bundle_manifest_paths)?;
    MercuryProofPackage::build(
        verified.bundle,
        verified.manifest_hash,
        verified.manifest_schema,
        verified.exported_at,
        unix_now(),
        MercuryPublicationProfile::pilot_default(),
        bundle_manifests,
    )
    .map_err(|error| CliError::Other(error.to_string()))
}

fn build_inquiry_package(
    proof_package: MercuryProofPackage,
    audience: &str,
    redaction_profile: Option<&str>,
    verifier_equivalent: bool,
) -> Result<MercuryInquiryPackage, CliError> {
    let latest = proof_package
        .receipt_records
        .last()
        .ok_or_else(|| CliError::Other("proof package is missing receipt_records".to_string()))?
        .metadata
        .clone();
    let workflow_id = proof_package.workflow_id.clone();
    let proof_package_id = proof_package.package_id.clone();
    let disclosure_policy = latest.disclosure.policy.clone();
    let approval_state = latest.approval_state.state.as_str().to_string();
    let rendered_export = serde_json::json!({
        "workflowId": workflow_id,
        "proofPackageId": proof_package_id,
        "audience": audience,
        "redactionProfile": redaction_profile,
        "verifierEquivalent": verifier_equivalent,
        "receiptIds": proof_package
            .receipt_records
            .iter()
            .map(|record| record.receipt_id.clone())
            .collect::<Vec<_>>(),
        "disclosurePolicy": disclosure_policy,
        "approvalState": approval_state,
    });
    MercuryInquiryPackage::build(
        proof_package,
        unix_now(),
        audience,
        redaction_profile.map(ToOwned::to_owned),
        rendered_export,
        latest.disclosure,
        latest.approval_state,
        verifier_equivalent,
    )
    .map_err(|error| CliError::Other(error.to_string()))
}

fn write_verification_report(
    path: &Path,
    report: &MercuryVerificationReport,
) -> Result<(), CliError> {
    write_json_file(path, report)
}

fn pilot_capability_with_id(
    id: &str,
    subject: &Keypair,
    issuer: &Keypair,
) -> Result<CapabilityToken, CliError> {
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: id.to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ArcScope {
                grants: vec![ToolGrant {
                    server_id: "mercury".to_string(),
                    tool_name: "*".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ArcScope::default()
            },
            issued_at: 100,
            expires_at: 10_000,
            delegation_chain: vec![],
        },
        issuer,
    )
    .map_err(CliError::from)
}

fn pilot_receipt(
    step: &MercuryPilotStep,
    capability_id: &str,
    kernel_keypair: &Keypair,
) -> Result<ArcReceipt, CliError> {
    let action = ToolCallAction::from_parameters(serde_json::json!({
        "workflowId": step.metadata.business_ids.workflow_id,
        "eventId": step.metadata.chronology.event_id,
        "decisionType": step.metadata.decision_context.decision_type.as_str(),
        "stage": serde_json::to_value(step.metadata.chronology.stage)?,
    }))?;
    let metadata = step
        .metadata
        .into_receipt_metadata_value()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let content_hash = sha256_hex(&canonical_json_bytes(&step.metadata)?);
    ArcReceipt::sign(
        ArcReceiptBody {
            id: step.receipt_id.clone(),
            timestamp: step.timestamp,
            capability_id: capability_id.to_string(),
            tool_server: "mercury".to_string(),
            tool_name: step.tool_name.clone(),
            action,
            decision: Decision::Allow,
            content_hash,
            policy_hash: "policy-mercury-pilot-v1".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            kernel_key: kernel_keypair.public_key(),
        },
        kernel_keypair,
    )
    .map_err(CliError::from)
}

fn populate_mercury_receipt_store(
    receipt_db: &Path,
    capability_id: &str,
    steps: &[MercuryPilotStep],
) -> Result<(), CliError> {
    let mut store = SqliteReceiptStore::open(receipt_db)?;
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let kernel_keypair = Keypair::generate();
    let capability = pilot_capability_with_id(capability_id, &subject, &issuer)?;
    store
        .record_capability_snapshot(&capability, None)
        .map_err(|error| CliError::Other(error.to_string()))?;

    let mut start_seq = None;
    let mut end_seq = None;
    for step in steps {
        let receipt = pilot_receipt(step, capability_id, &kernel_keypair)?;
        let seq = store.append_arc_receipt_returning_seq(&receipt)?;
        if start_seq.is_none() {
            start_seq = Some(seq);
        }
        end_seq = Some(seq);
    }

    let start_seq = start_seq
        .ok_or_else(|| CliError::Other("capture did not generate any receipts".to_string()))?;
    let end_seq = end_seq
        .ok_or_else(|| CliError::Other("capture did not generate any receipts".to_string()))?;
    let canonical = store.receipts_canonical_bytes_range(start_seq, end_seq)?;
    let checkpoint = build_checkpoint(
        1,
        start_seq,
        end_seq,
        &canonical
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>(),
        &issuer,
    )?;
    store.store_checkpoint(&checkpoint)?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct PilotInquiryConfig<'a> {
    audience: &'a str,
    redaction_profile: Option<&'a str>,
    verifier_equivalent: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryPilotRunPaths {
    events_file: String,
    receipt_db: String,
    evidence_dir: String,
    bundle_manifest_file: String,
    proof_package_file: String,
    proof_verification_file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inquiry_package_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inquiry_verification_file: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryExportRunPaths {
    input_file: String,
    receipt_db: String,
    evidence_dir: String,
    bundle_manifest_files: Vec<String>,
    proof_package_file: String,
    proof_verification_file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inquiry_package_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    inquiry_verification_file: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryPilotExportSummary {
    scenario_id: String,
    workflow_id: String,
    scenario_file: String,
    primary_receipt_count: usize,
    rollback_receipt_count: usize,
    primary: MercuryPilotRunPaths,
    rollback: MercuryPilotRunPaths,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySupervisedLiveExportSummary {
    capture_id: String,
    workflow_id: String,
    mode: String,
    receipt_count: usize,
    control_state: MercurySupervisedLiveControlState,
    export: MercuryExportRunPaths,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryQualificationDocRefs {
    bridge_file: String,
    operating_model_file: String,
    operations_runbook_file: String,
    qualification_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySupervisedLiveQualificationReport {
    workflow_id: String,
    decision: String,
    same_workflow_boundary: String,
    supervised_live: MercurySupervisedLiveExportSummary,
    pilot: MercuryPilotExportSummary,
    docs: MercuryQualificationDocRefs,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySupervisedLiveReviewerPackage {
    workflow_id: String,
    decision: String,
    qualification_report_file: String,
    supervised_live_dir: String,
    pilot_dir: String,
    supervised_live_proof_package_file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    supervised_live_inquiry_package_file: Option<String>,
    rollback_proof_package_file: String,
    docs: MercuryQualificationDocRefs,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDownstreamReviewDocRefs {
    distribution_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDownstreamConsumerManifest {
    schema: String,
    workflow_id: String,
    consumer_profile: String,
    transport: String,
    acknowledgement_required: bool,
    fail_closed: bool,
    reviewer_package_file: String,
    qualification_report_file: String,
    external_assurance_package_file: String,
    external_inquiry_package_file: String,
    external_inquiry_verification_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDownstreamDeliveryAcknowledgement {
    schema: String,
    workflow_id: String,
    consumer_profile: String,
    destination_label: String,
    status: String,
    acknowledged_at: u64,
    acknowledged_by: String,
    delivered_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDownstreamReviewExportSummary {
    workflow_id: String,
    consumer_profile: String,
    transport: String,
    qualification_dir: String,
    internal_assurance_package_file: String,
    external_assurance_package_file: String,
    downstream_review_package_file: String,
    consumer_manifest_file: String,
    acknowledgement_file: String,
    consumer_drop_dir: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDownstreamReviewDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_consumer_profile: String,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDownstreamReviewValidationReport {
    workflow_id: String,
    decision: String,
    consumer_profile: String,
    same_workflow_boundary: String,
    downstream_review: MercuryDownstreamReviewExportSummary,
    decision_record_file: String,
    docs: MercuryDownstreamReviewDocRefs,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryGovernanceWorkbenchDocRefs {
    workbench_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryGovernanceWorkbenchExportSummary {
    workflow_id: String,
    workflow_path: String,
    workflow_owner: String,
    control_team_owner: String,
    qualification_dir: String,
    control_state: MercuryGovernanceControlState,
    control_state_file: String,
    governance_decision_package_file: String,
    workflow_owner_review_package_file: String,
    control_team_review_package_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryGovernanceWorkbenchDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_workflow_path: String,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryGovernanceWorkbenchValidationReport {
    workflow_id: String,
    decision: String,
    workflow_path: String,
    same_workflow_boundary: String,
    governance_workbench: MercuryGovernanceWorkbenchExportSummary,
    decision_record_file: String,
    docs: MercuryGovernanceWorkbenchDocRefs,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryAssuranceSuiteDocRefs {
    suite_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Copy)]
struct MercuryAssurancePopulationConfig<'a> {
    reviewer_population: MercuryAssuranceReviewerPopulation,
    dir_name: &'a str,
    audience: &'a str,
    redaction_profile: &'a str,
    retained_artifact_policy: &'a str,
    intended_use: &'a str,
    verifier_equivalent: bool,
    investigation_focus: &'a [&'a str],
}

#[derive(Debug, Clone)]
struct MercuryAssuranceInvestigationInputs {
    account_id: Option<String>,
    desk_id: Option<String>,
    strategy_id: Option<String>,
    event_ids: Vec<String>,
    source_record_ids: Vec<String>,
    idempotency_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryAssuranceSuiteExportSummary {
    workflow_id: String,
    reviewer_owner: String,
    support_owner: String,
    reviewer_populations: Vec<String>,
    qualification_dir: String,
    governance_workbench_dir: String,
    governance_decision_package_file: String,
    assurance_suite_package_file: String,
    internal_review_package_file: String,
    auditor_review_package_file: String,
    counterparty_review_package_file: String,
    internal_investigation_package_file: String,
    auditor_investigation_package_file: String,
    counterparty_investigation_package_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryAssuranceSuiteDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_reviewer_populations: Vec<String>,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryAssuranceSuiteValidationReport {
    workflow_id: String,
    decision: String,
    reviewer_owner: String,
    support_owner: String,
    same_workflow_boundary: String,
    assurance_suite: MercuryAssuranceSuiteExportSummary,
    decision_record_file: String,
    docs: MercuryAssuranceSuiteDocRefs,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryEmbeddedOemDocRefs {
    oem_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryEmbeddedPartnerManifest {
    schema: String,
    workflow_id: String,
    partner_surface: String,
    sdk_surface: String,
    reviewer_population: String,
    fail_closed: bool,
    acknowledgement_required: bool,
    profile_file: String,
    assurance_suite_package_file: String,
    governance_decision_package_file: String,
    disclosure_profile_file: String,
    review_package_file: String,
    investigation_package_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
    support_owner: String,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryEmbeddedDeliveryAcknowledgement {
    schema: String,
    workflow_id: String,
    partner_surface: String,
    partner_owner: String,
    status: String,
    acknowledged_at: u64,
    acknowledged_by: String,
    delivered_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryEmbeddedOemExportSummary {
    workflow_id: String,
    partner_surface: String,
    sdk_surface: String,
    reviewer_population: String,
    partner_owner: String,
    support_owner: String,
    assurance_suite_dir: String,
    embedded_oem_profile_file: String,
    embedded_oem_package_file: String,
    partner_sdk_manifest_file: String,
    assurance_suite_package_file: String,
    governance_decision_package_file: String,
    disclosure_profile_file: String,
    review_package_file: String,
    investigation_package_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
    acknowledgement_file: String,
    partner_sdk_bundle_dir: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryEmbeddedOemDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_partner_surface: String,
    selected_sdk_surface: String,
    selected_reviewer_population: String,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryEmbeddedOemValidationReport {
    workflow_id: String,
    decision: String,
    partner_surface: String,
    sdk_surface: String,
    reviewer_population: String,
    partner_owner: String,
    support_owner: String,
    same_workflow_boundary: String,
    embedded_oem: MercuryEmbeddedOemExportSummary,
    decision_record_file: String,
    docs: MercuryEmbeddedOemDocRefs,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryTrustNetworkDocRefs {
    trust_network_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryTrustNetworkInteroperabilityManifest {
    schema: String,
    workflow_id: String,
    sponsor_boundary: String,
    trust_anchor: String,
    interop_surface: String,
    reviewer_population: String,
    fail_closed: bool,
    profile_file: String,
    shared_proof_package_file: String,
    shared_review_package_file: String,
    shared_inquiry_package_file: String,
    shared_inquiry_verification_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
    witness_record_file: String,
    trust_anchor_record_file: String,
    support_owner: String,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryTrustNetworkWitnessRecord {
    schema: String,
    workflow_id: String,
    sponsor_boundary: String,
    trust_anchor: String,
    checkpoint_continuity: String,
    witness_steps: Vec<String>,
    witness_operator: String,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryTrustAnchorRecord {
    schema: String,
    workflow_id: String,
    trust_anchor: String,
    anchor_scope: String,
    verification_material: String,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryTrustNetworkExportSummary {
    workflow_id: String,
    sponsor_boundary: String,
    trust_anchor: String,
    interop_surface: String,
    reviewer_population: String,
    sponsor_owner: String,
    support_owner: String,
    embedded_oem_dir: String,
    trust_network_profile_file: String,
    trust_network_package_file: String,
    interop_manifest_file: String,
    shared_proof_package_file: String,
    shared_review_package_file: String,
    shared_inquiry_package_file: String,
    shared_inquiry_verification_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
    witness_record_file: String,
    trust_anchor_record_file: String,
    share_dir: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryTrustNetworkDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_sponsor_boundary: String,
    selected_trust_anchor: String,
    selected_interop_surface: String,
    selected_reviewer_population: String,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryTrustNetworkValidationReport {
    workflow_id: String,
    decision: String,
    sponsor_boundary: String,
    trust_anchor: String,
    interop_surface: String,
    reviewer_population: String,
    sponsor_owner: String,
    support_owner: String,
    same_workflow_boundary: String,
    trust_network: MercuryTrustNetworkExportSummary,
    decision_record_file: String,
    docs: MercuryTrustNetworkDocRefs,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReleaseReadinessDocRefs {
    release_readiness_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReleaseReadinessPartnerManifest {
    schema: String,
    workflow_id: String,
    delivery_surface: String,
    reviewer_population: String,
    acknowledgement_required: bool,
    fail_closed: bool,
    proof_package_file: String,
    inquiry_package_file: String,
    inquiry_verification_file: String,
    assurance_suite_package_file: String,
    trust_network_package_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
    operator_release_checklist_file: String,
    escalation_manifest_file: String,
    support_handoff_file: String,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReleaseReadinessDeliveryAcknowledgement {
    schema: String,
    workflow_id: String,
    delivery_surface: String,
    partner_owner: String,
    status: String,
    acknowledged_at: u64,
    acknowledged_by: String,
    delivered_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReleaseReadinessOperatorChecklist {
    schema: String,
    workflow_id: String,
    release_owner: String,
    partner_owner: String,
    support_owner: String,
    fail_closed: bool,
    gating_checks: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReleaseReadinessEscalationManifest {
    schema: String,
    workflow_id: String,
    release_owner: String,
    support_owner: String,
    fail_closed: bool,
    escalation_triggers: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReleaseReadinessSupportHandoff {
    schema: String,
    workflow_id: String,
    release_owner: String,
    support_owner: String,
    active_window: String,
    required_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReleaseReadinessExportSummary {
    workflow_id: String,
    audiences: Vec<String>,
    delivery_surface: String,
    release_owner: String,
    partner_owner: String,
    support_owner: String,
    trust_network_dir: String,
    release_readiness_profile_file: String,
    release_readiness_package_file: String,
    partner_delivery_manifest_file: String,
    acknowledgement_file: String,
    operator_release_checklist_file: String,
    escalation_manifest_file: String,
    support_handoff_file: String,
    partner_bundle_dir: String,
    proof_package_file: String,
    inquiry_package_file: String,
    inquiry_verification_file: String,
    assurance_suite_package_file: String,
    trust_network_package_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReleaseReadinessDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_delivery_surface: String,
    selected_audiences: Vec<String>,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReleaseReadinessValidationReport {
    workflow_id: String,
    decision: String,
    audiences: Vec<String>,
    delivery_surface: String,
    release_owner: String,
    partner_owner: String,
    support_owner: String,
    same_workflow_boundary: String,
    release_readiness: MercuryReleaseReadinessExportSummary,
    decision_record_file: String,
    docs: MercuryReleaseReadinessDocRefs,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryControlledAdoptionDocRefs {
    controlled_adoption_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryControlledAdoptionCustomerSuccessChecklist {
    schema: String,
    workflow_id: String,
    customer_success_owner: String,
    reference_owner: String,
    support_owner: String,
    fail_closed: bool,
    readiness_checks: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryControlledAdoptionRenewalManifest {
    schema: String,
    workflow_id: String,
    cohort: String,
    adoption_surface: String,
    success_window: String,
    renewal_signal: String,
    release_readiness_package_file: String,
    trust_network_package_file: String,
    assurance_suite_package_file: String,
    proof_package_file: String,
    inquiry_package_file: String,
    inquiry_verification_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryControlledAdoptionRenewalAcknowledgement {
    schema: String,
    workflow_id: String,
    cohort: String,
    adoption_surface: String,
    customer_success_owner: String,
    status: String,
    acknowledged_at: u64,
    acknowledged_by: String,
    delivered_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryControlledAdoptionReferenceReadinessBrief {
    schema: String,
    workflow_id: String,
    reference_owner: String,
    cohort: String,
    adoption_surface: String,
    approved_claim: String,
    required_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryControlledAdoptionSupportEscalationManifest {
    schema: String,
    workflow_id: String,
    support_owner: String,
    customer_success_owner: String,
    fail_closed: bool,
    escalation_triggers: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryControlledAdoptionExportSummary {
    workflow_id: String,
    cohort: String,
    adoption_surface: String,
    customer_success_owner: String,
    reference_owner: String,
    support_owner: String,
    release_readiness_dir: String,
    controlled_adoption_profile_file: String,
    controlled_adoption_package_file: String,
    customer_success_checklist_file: String,
    renewal_evidence_manifest_file: String,
    renewal_acknowledgement_file: String,
    reference_readiness_brief_file: String,
    support_escalation_manifest_file: String,
    adoption_evidence_dir: String,
    release_readiness_package_file: String,
    trust_network_package_file: String,
    assurance_suite_package_file: String,
    proof_package_file: String,
    inquiry_package_file: String,
    inquiry_verification_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryControlledAdoptionDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_cohort: String,
    selected_adoption_surface: String,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryControlledAdoptionValidationReport {
    workflow_id: String,
    decision: String,
    cohort: String,
    adoption_surface: String,
    customer_success_owner: String,
    reference_owner: String,
    support_owner: String,
    same_workflow_boundary: String,
    controlled_adoption: MercuryControlledAdoptionExportSummary,
    decision_record_file: String,
    docs: MercuryControlledAdoptionDocRefs,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReferenceDistributionDocRefs {
    reference_distribution_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReferenceDistributionAccountMotionFreeze {
    schema: String,
    workflow_id: String,
    expansion_motion: String,
    distribution_surface: String,
    landed_account_target: String,
    approved_buyer_path: Vec<String>,
    non_goals: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReferenceDistributionManifest {
    schema: String,
    workflow_id: String,
    expansion_motion: String,
    distribution_surface: String,
    controlled_adoption_package_file: String,
    renewal_evidence_manifest_file: String,
    renewal_acknowledgement_file: String,
    reference_readiness_brief_file: String,
    release_readiness_package_file: String,
    trust_network_package_file: String,
    assurance_suite_package_file: String,
    proof_package_file: String,
    inquiry_package_file: String,
    inquiry_verification_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReferenceDistributionClaimDisciplineRules {
    schema: String,
    workflow_id: String,
    reference_owner: String,
    buyer_approval_owner: String,
    fail_closed: bool,
    approved_claims: Vec<String>,
    prohibited_claims: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReferenceDistributionBuyerApproval {
    schema: String,
    workflow_id: String,
    buyer_approval_owner: String,
    status: String,
    approved_at: u64,
    approved_by: String,
    approved_claims: Vec<String>,
    required_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReferenceDistributionSalesHandoffBrief {
    schema: String,
    workflow_id: String,
    sales_owner: String,
    reference_owner: String,
    buyer_approval_owner: String,
    expansion_motion: String,
    distribution_surface: String,
    approved_scope: String,
    entry_criteria: Vec<String>,
    escalation_triggers: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReferenceDistributionExportSummary {
    workflow_id: String,
    expansion_motion: String,
    distribution_surface: String,
    reference_owner: String,
    buyer_approval_owner: String,
    sales_owner: String,
    controlled_adoption_dir: String,
    reference_distribution_profile_file: String,
    reference_distribution_package_file: String,
    account_motion_freeze_file: String,
    reference_distribution_manifest_file: String,
    claim_discipline_rules_file: String,
    buyer_reference_approval_file: String,
    sales_handoff_brief_file: String,
    reference_evidence_dir: String,
    controlled_adoption_package_file: String,
    renewal_evidence_manifest_file: String,
    renewal_acknowledgement_file: String,
    reference_readiness_brief_file: String,
    release_readiness_package_file: String,
    trust_network_package_file: String,
    assurance_suite_package_file: String,
    proof_package_file: String,
    inquiry_package_file: String,
    inquiry_verification_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReferenceDistributionDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_expansion_motion: String,
    selected_distribution_surface: String,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryReferenceDistributionValidationReport {
    workflow_id: String,
    decision: String,
    expansion_motion: String,
    distribution_surface: String,
    reference_owner: String,
    buyer_approval_owner: String,
    sales_owner: String,
    same_workflow_boundary: String,
    reference_distribution: MercuryReferenceDistributionExportSummary,
    decision_record_file: String,
    docs: MercuryReferenceDistributionDocRefs,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryBroaderDistributionDocRefs {
    broader_distribution_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryBroaderDistributionTargetAccountFreeze {
    schema: String,
    workflow_id: String,
    distribution_motion: String,
    distribution_surface: String,
    target_account_segment: String,
    qualification_gates: Vec<String>,
    non_goals: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryBroaderDistributionManifest {
    schema: String,
    workflow_id: String,
    distribution_motion: String,
    distribution_surface: String,
    reference_distribution_package_file: String,
    account_motion_freeze_file: String,
    reference_distribution_manifest_file: String,
    reference_claim_discipline_file: String,
    reference_buyer_approval_file: String,
    reference_sales_handoff_file: String,
    controlled_adoption_package_file: String,
    renewal_evidence_manifest_file: String,
    renewal_acknowledgement_file: String,
    reference_readiness_brief_file: String,
    release_readiness_package_file: String,
    trust_network_package_file: String,
    assurance_suite_package_file: String,
    proof_package_file: String,
    inquiry_package_file: String,
    inquiry_verification_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryBroaderDistributionClaimGovernanceRules {
    schema: String,
    workflow_id: String,
    qualification_owner: String,
    approval_owner: String,
    fail_closed: bool,
    approved_claims: Vec<String>,
    prohibited_claims: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryBroaderDistributionSelectiveAccountApproval {
    schema: String,
    workflow_id: String,
    approval_owner: String,
    status: String,
    approved_at: u64,
    approved_by: String,
    approved_claims: Vec<String>,
    required_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryBroaderDistributionHandoffBrief {
    schema: String,
    workflow_id: String,
    distribution_owner: String,
    qualification_owner: String,
    approval_owner: String,
    distribution_motion: String,
    distribution_surface: String,
    approved_scope: String,
    entry_criteria: Vec<String>,
    escalation_triggers: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryBroaderDistributionExportSummary {
    workflow_id: String,
    distribution_motion: String,
    distribution_surface: String,
    qualification_owner: String,
    approval_owner: String,
    distribution_owner: String,
    reference_distribution_dir: String,
    broader_distribution_profile_file: String,
    broader_distribution_package_file: String,
    target_account_freeze_file: String,
    broader_distribution_manifest_file: String,
    claim_governance_rules_file: String,
    selective_account_approval_file: String,
    distribution_handoff_brief_file: String,
    qualification_evidence_dir: String,
    reference_distribution_package_file: String,
    account_motion_freeze_file: String,
    reference_distribution_manifest_file: String,
    reference_claim_discipline_file: String,
    reference_buyer_approval_file: String,
    reference_sales_handoff_file: String,
    controlled_adoption_package_file: String,
    renewal_evidence_manifest_file: String,
    renewal_acknowledgement_file: String,
    reference_readiness_brief_file: String,
    release_readiness_package_file: String,
    trust_network_package_file: String,
    assurance_suite_package_file: String,
    proof_package_file: String,
    inquiry_package_file: String,
    inquiry_verification_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryBroaderDistributionDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_distribution_motion: String,
    selected_distribution_surface: String,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryBroaderDistributionValidationReport {
    workflow_id: String,
    decision: String,
    distribution_motion: String,
    distribution_surface: String,
    qualification_owner: String,
    approval_owner: String,
    distribution_owner: String,
    same_workflow_boundary: String,
    broader_distribution: MercuryBroaderDistributionExportSummary,
    decision_record_file: String,
    docs: MercuryBroaderDistributionDocRefs,
}

impl MercuryPilotRunPaths {
    fn from_export(paths: MercuryExportRunPaths) -> Result<Self, CliError> {
        let bundle_manifest_file =
            paths
                .bundle_manifest_files
                .first()
                .cloned()
                .ok_or_else(|| {
                    CliError::Other("pilot export is missing bundle manifest".to_string())
                })?;
        Ok(Self {
            events_file: paths.input_file,
            receipt_db: paths.receipt_db,
            evidence_dir: paths.evidence_dir,
            bundle_manifest_file,
            proof_package_file: paths.proof_package_file,
            proof_verification_file: paths.proof_verification_file,
            inquiry_package_file: paths.inquiry_package_file,
            inquiry_verification_file: paths.inquiry_verification_file,
        })
    }
}

fn reviewer_doc_refs() -> MercuryQualificationDocRefs {
    MercuryQualificationDocRefs {
        bridge_file: "docs/mercury/SUPERVISED_LIVE_BRIDGE.md".to_string(),
        operating_model_file: "docs/mercury/SUPERVISED_LIVE_OPERATING_MODEL.md".to_string(),
        operations_runbook_file: "docs/mercury/SUPERVISED_LIVE_OPERATIONS_RUNBOOK.md".to_string(),
        qualification_package_file: "docs/mercury/SUPERVISED_LIVE_QUALIFICATION_PACKAGE.md"
            .to_string(),
        decision_record_file: "docs/mercury/SUPERVISED_LIVE_DECISION_RECORD.md".to_string(),
    }
}

fn downstream_review_doc_refs() -> MercuryDownstreamReviewDocRefs {
    MercuryDownstreamReviewDocRefs {
        distribution_file: "docs/mercury/DOWNSTREAM_REVIEW_DISTRIBUTION.md".to_string(),
        operations_file: "docs/mercury/DOWNSTREAM_REVIEW_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/DOWNSTREAM_REVIEW_VALIDATION_PACKAGE.md".to_string(),
        decision_record_file: "docs/mercury/DOWNSTREAM_REVIEW_DECISION_RECORD.md".to_string(),
    }
}

fn governance_workbench_doc_refs() -> MercuryGovernanceWorkbenchDocRefs {
    MercuryGovernanceWorkbenchDocRefs {
        workbench_file: "docs/mercury/GOVERNANCE_WORKBENCH.md".to_string(),
        operations_file: "docs/mercury/GOVERNANCE_WORKBENCH_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/GOVERNANCE_WORKBENCH_VALIDATION_PACKAGE.md"
            .to_string(),
        decision_record_file: "docs/mercury/GOVERNANCE_WORKBENCH_DECISION_RECORD.md".to_string(),
    }
}

fn assurance_suite_doc_refs() -> MercuryAssuranceSuiteDocRefs {
    MercuryAssuranceSuiteDocRefs {
        suite_file: "docs/mercury/ASSURANCE_SUITE.md".to_string(),
        operations_file: "docs/mercury/ASSURANCE_SUITE_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/ASSURANCE_SUITE_VALIDATION_PACKAGE.md".to_string(),
        decision_record_file: "docs/mercury/ASSURANCE_SUITE_DECISION_RECORD.md".to_string(),
    }
}

fn embedded_oem_doc_refs() -> MercuryEmbeddedOemDocRefs {
    MercuryEmbeddedOemDocRefs {
        oem_file: "docs/mercury/EMBEDDED_OEM.md".to_string(),
        operations_file: "docs/mercury/EMBEDDED_OEM_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/EMBEDDED_OEM_VALIDATION_PACKAGE.md".to_string(),
        decision_record_file: "docs/mercury/EMBEDDED_OEM_DECISION_RECORD.md".to_string(),
    }
}

fn trust_network_doc_refs() -> MercuryTrustNetworkDocRefs {
    MercuryTrustNetworkDocRefs {
        trust_network_file: "docs/mercury/TRUST_NETWORK.md".to_string(),
        operations_file: "docs/mercury/TRUST_NETWORK_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/TRUST_NETWORK_VALIDATION_PACKAGE.md".to_string(),
        decision_record_file: "docs/mercury/TRUST_NETWORK_DECISION_RECORD.md".to_string(),
    }
}

fn release_readiness_doc_refs() -> MercuryReleaseReadinessDocRefs {
    MercuryReleaseReadinessDocRefs {
        release_readiness_file: "docs/mercury/RELEASE_READINESS.md".to_string(),
        operations_file: "docs/mercury/RELEASE_READINESS_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/RELEASE_READINESS_VALIDATION_PACKAGE.md".to_string(),
        decision_record_file: "docs/mercury/RELEASE_READINESS_DECISION_RECORD.md".to_string(),
    }
}

fn controlled_adoption_doc_refs() -> MercuryControlledAdoptionDocRefs {
    MercuryControlledAdoptionDocRefs {
        controlled_adoption_file: "docs/mercury/CONTROLLED_ADOPTION.md".to_string(),
        operations_file: "docs/mercury/CONTROLLED_ADOPTION_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/CONTROLLED_ADOPTION_VALIDATION_PACKAGE.md"
            .to_string(),
        decision_record_file: "docs/mercury/CONTROLLED_ADOPTION_DECISION_RECORD.md".to_string(),
    }
}

fn reference_distribution_doc_refs() -> MercuryReferenceDistributionDocRefs {
    MercuryReferenceDistributionDocRefs {
        reference_distribution_file: "docs/mercury/REFERENCE_DISTRIBUTION.md".to_string(),
        operations_file: "docs/mercury/REFERENCE_DISTRIBUTION_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/REFERENCE_DISTRIBUTION_VALIDATION_PACKAGE.md"
            .to_string(),
        decision_record_file: "docs/mercury/REFERENCE_DISTRIBUTION_DECISION_RECORD.md".to_string(),
    }
}

fn broader_distribution_doc_refs() -> MercuryBroaderDistributionDocRefs {
    MercuryBroaderDistributionDocRefs {
        broader_distribution_file: "docs/mercury/BROADER_DISTRIBUTION.md".to_string(),
        operations_file: "docs/mercury/BROADER_DISTRIBUTION_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/BROADER_DISTRIBUTION_VALIDATION_PACKAGE.md"
            .to_string(),
        decision_record_file: "docs/mercury/BROADER_DISTRIBUTION_DECISION_RECORD.md".to_string(),
    }
}

fn assurance_suite_population_configs() -> [MercuryAssurancePopulationConfig<'static>; 3] {
    [
        MercuryAssurancePopulationConfig {
            reviewer_population: MercuryAssuranceReviewerPopulation::InternalReview,
            dir_name: "internal-review",
            audience: "internal-review",
            redaction_profile: "internal-review-default",
            retained_artifact_policy: "retain-all-qualified-review-artifacts",
            intended_use:
                "Internal review over the same qualified workflow evidence without lossy redaction.",
            verifier_equivalent: true,
            investigation_focus: &[
                "release approval continuity",
                "rollback readiness and supervisory coverage",
            ],
        },
        MercuryAssurancePopulationConfig {
            reviewer_population: MercuryAssuranceReviewerPopulation::AuditorReview,
            dir_name: "auditor-review",
            audience: "auditor-review",
            redaction_profile: "auditor-review-default",
            retained_artifact_policy: "retain-qualified-audit-artifacts-and-source-links",
            intended_use:
                "Auditor review over the same governed workflow with retained provenance and checkpoint continuity.",
            verifier_equivalent: true,
            investigation_focus: &[
                "checkpoint and retained-artifact continuity",
                "control-state and exception routing evidence",
            ],
        },
        MercuryAssurancePopulationConfig {
            reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview,
            dir_name: "counterparty-review",
            audience: "counterparty-review",
            redaction_profile: "counterparty-review-default",
            retained_artifact_policy: "retain-bounded-redacted-review-artifacts",
            intended_use:
                "Counterparty review over a bounded redacted export without widening into a generic portal.",
            verifier_equivalent: false,
            investigation_focus: &[
                "bounded disclosure and inquiry continuity",
                "release and rollback reconstruction from redacted evidence",
            ],
        },
    ]
}

fn build_assurance_package(
    workflow_id: &str,
    audience: MercuryAssuranceAudience,
    disclosure_profile: &str,
    proof_package_file: &str,
    inquiry_package_file: &str,
    reviewer_package_file: &str,
    qualification_report_file: &str,
    verifier_equivalent: bool,
) -> Result<MercuryAssurancePackage, CliError> {
    let package = MercuryAssurancePackage {
        schema: MERCURY_ASSURANCE_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "assurance-{}-{}-{}",
            audience.as_str(),
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        audience,
        disclosure_profile: disclosure_profile.to_string(),
        proof_package_file: proof_package_file.to_string(),
        inquiry_package_file: inquiry_package_file.to_string(),
        reviewer_package_file: reviewer_package_file.to_string(),
        qualification_report_file: qualification_report_file.to_string(),
        verifier_equivalent,
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(package)
}

fn build_governance_review_package(
    workflow_id: &str,
    audience: MercuryGovernanceReviewAudience,
    disclosure_profile: &str,
    proof_package_file: &str,
    inquiry_package_file: &str,
    reviewer_package_file: &str,
    qualification_report_file: &str,
    decision_package_file: &str,
    verifier_equivalent: bool,
) -> Result<MercuryGovernanceReviewPackage, CliError> {
    let package = MercuryGovernanceReviewPackage {
        schema: MERCURY_GOVERNANCE_REVIEW_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "governance-review-{}-{}-{}",
            audience.as_str(),
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        audience,
        disclosure_profile: disclosure_profile.to_string(),
        proof_package_file: proof_package_file.to_string(),
        inquiry_package_file: inquiry_package_file.to_string(),
        reviewer_package_file: reviewer_package_file.to_string(),
        qualification_report_file: qualification_report_file.to_string(),
        decision_package_file: decision_package_file.to_string(),
        verifier_equivalent,
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(package)
}

fn build_assurance_disclosure_profile(
    workflow_id: &str,
    config: MercuryAssurancePopulationConfig<'_>,
) -> Result<MercuryAssuranceDisclosureProfile, CliError> {
    let profile = MercuryAssuranceDisclosureProfile {
        schema: MERCURY_ASSURANCE_DISCLOSURE_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "assurance-{}-{}-{}",
            config.reviewer_population.as_str(),
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        reviewer_population: config.reviewer_population,
        redaction_profile: config.redaction_profile.to_string(),
        verifier_equivalent: config.verifier_equivalent,
        retained_artifact_policy: config.retained_artifact_policy.to_string(),
        intended_use: config.intended_use.to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}

fn build_assurance_review_package(
    workflow_id: &str,
    reviewer_population: MercuryAssuranceReviewerPopulation,
    disclosure_profile_file: &str,
    proof_package_file: &str,
    inquiry_package_file: &str,
    inquiry_verification_file: &str,
    reviewer_package_file: &str,
    qualification_report_file: &str,
    governance_decision_package_file: &str,
    verifier_equivalent: bool,
) -> Result<MercuryAssuranceReviewPackage, CliError> {
    let package = MercuryAssuranceReviewPackage {
        schema: MERCURY_ASSURANCE_REVIEW_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "assurance-review-{}-{}-{}",
            reviewer_population.as_str(),
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        reviewer_population,
        disclosure_profile_file: disclosure_profile_file.to_string(),
        proof_package_file: proof_package_file.to_string(),
        inquiry_package_file: inquiry_package_file.to_string(),
        inquiry_verification_file: inquiry_verification_file.to_string(),
        reviewer_package_file: reviewer_package_file.to_string(),
        qualification_report_file: qualification_report_file.to_string(),
        governance_decision_package_file: governance_decision_package_file.to_string(),
        verifier_equivalent,
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(package)
}

fn collect_assurance_investigation_inputs(
    proof_package: &MercuryProofPackage,
) -> MercuryAssuranceInvestigationInputs {
    let event_ids = proof_package
        .receipt_records
        .iter()
        .map(|record| record.metadata.chronology.event_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let source_record_ids = proof_package
        .receipt_records
        .iter()
        .filter_map(|record| record.metadata.provenance.source_record_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let idempotency_keys = proof_package
        .receipt_records
        .iter()
        .filter_map(|record| record.metadata.chronology.idempotency_key.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    MercuryAssuranceInvestigationInputs {
        account_id: proof_package.account_id.clone(),
        desk_id: proof_package.desk_id.clone(),
        strategy_id: proof_package.strategy_id.clone(),
        event_ids,
        source_record_ids,
        idempotency_keys,
    }
}

fn build_assurance_investigation_package(
    workflow_id: &str,
    reviewer_population: MercuryAssuranceReviewerPopulation,
    assurance_review_package_file: &str,
    investigation_inputs: &MercuryAssuranceInvestigationInputs,
    investigation_focus: &[&str],
) -> Result<MercuryAssuranceInvestigationPackage, CliError> {
    let package = MercuryAssuranceInvestigationPackage {
        schema: MERCURY_ASSURANCE_INVESTIGATION_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "assurance-investigation-{}-{}-{}",
            reviewer_population.as_str(),
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        reviewer_population,
        assurance_review_package_file: assurance_review_package_file.to_string(),
        account_id: investigation_inputs.account_id.clone(),
        desk_id: investigation_inputs.desk_id.clone(),
        strategy_id: investigation_inputs.strategy_id.clone(),
        investigation_focus: investigation_focus
            .iter()
            .map(ToString::to_string)
            .collect(),
        event_ids: investigation_inputs.event_ids.clone(),
        source_record_ids: investigation_inputs.source_record_ids.clone(),
        idempotency_keys: investigation_inputs.idempotency_keys.clone(),
        fail_closed: true,
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(package)
}

fn build_embedded_oem_profile(workflow_id: &str) -> Result<MercuryEmbeddedOemProfile, CliError> {
    let profile = MercuryEmbeddedOemProfile {
        schema: MERCURY_EMBEDDED_OEM_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "embedded-oem-reviewer-workbench-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        partner_surface: MercuryEmbeddedPartnerSurface::ReviewerWorkbenchEmbed,
        sdk_surface: MercuryEmbeddedSdkSurface::SignedArtifactBundle,
        reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview,
        retained_artifact_policy: "retain-bounded-redacted-review-artifacts".to_string(),
        intended_use: "Embed a bounded counterparty-review Mercury evidence bundle inside one partner reviewer workbench without widening into a generic SDK platform."
            .to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}

fn build_trust_network_profile(workflow_id: &str) -> Result<MercuryTrustNetworkProfile, CliError> {
    let profile = MercuryTrustNetworkProfile {
        schema: MERCURY_TRUST_NETWORK_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "trust-network-counterparty-review-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        sponsor_boundary: MercuryTrustNetworkSponsorBoundary::CounterpartyReviewExchange,
        trust_anchor: MercuryTrustNetworkTrustAnchor::ArcCheckpointWitnessChain,
        interop_surface: MercuryTrustNetworkInteropSurface::ProofInquiryBundleExchange,
        reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview,
        witness_steps: vec![
            MercuryTrustNetworkWitnessStep::CheckpointPublication,
            MercuryTrustNetworkWitnessStep::IndependentWitnessRecord,
            MercuryTrustNetworkWitnessStep::CounterpartyResolution,
        ],
        retained_artifact_policy:
            "retain-shared-proof-and-counterparty-review-exchange-artifacts".to_string(),
        intended_use: "Share one bounded counterparty-review proof and inquiry bundle across one checkpoint-backed witness chain without widening Mercury into a generic trust broker."
            .to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}

fn build_release_readiness_profile(
    workflow_id: &str,
) -> Result<MercuryReleaseReadinessProfile, CliError> {
    let profile = MercuryReleaseReadinessProfile {
        schema: MERCURY_RELEASE_READINESS_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "release-readiness-signed-partner-review-bundle-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        audiences: vec![
            MercuryReleaseReadinessAudience::Reviewer,
            MercuryReleaseReadinessAudience::Partner,
            MercuryReleaseReadinessAudience::Operator,
        ],
        delivery_surface: MercuryReleaseReadinessDeliverySurface::SignedPartnerReviewBundle,
        retained_artifact_policy:
            "retain-bounded-release-review-and-partner-delivery-artifacts".to_string(),
        intended_use: "Launch one bounded Mercury release-readiness lane for reviewer, partner, and operator audiences over the validated trust-network bundle without widening Mercury into a new product line."
            .to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}

fn build_controlled_adoption_profile(
    workflow_id: &str,
) -> Result<MercuryControlledAdoptionProfile, CliError> {
    let profile = MercuryControlledAdoptionProfile {
        schema: MERCURY_CONTROLLED_ADOPTION_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "controlled-adoption-design-partner-renewal-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        cohort: MercuryControlledAdoptionCohort::DesignPartnerRenewal,
        adoption_surface: MercuryControlledAdoptionSurface::RenewalReferenceBundle,
        success_window: "first-90-days-post-launch".to_string(),
        retained_artifact_policy:
            "retain-bounded-adoption-renewal-and-reference-artifacts".to_string(),
        intended_use: "Qualify one bounded Mercury controlled-adoption lane for renewal and reference evidence over the validated release-readiness package without widening Mercury into new product surfaces or polluting ARC generic crates."
            .to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}

fn build_reference_distribution_profile(
    workflow_id: &str,
) -> Result<MercuryReferenceDistributionProfile, CliError> {
    let profile = MercuryReferenceDistributionProfile {
        schema: MERCURY_REFERENCE_DISTRIBUTION_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "reference-distribution-landed-account-expansion-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        expansion_motion: MercuryReferenceDistributionMotion::LandedAccountExpansion,
        distribution_surface: MercuryReferenceDistributionSurface::ApprovedReferenceBundle,
        claim_discipline: "approved-reference-evidence-only".to_string(),
        retained_artifact_policy:
            "retain-bounded-reference-distribution-and-landed-account-expansion-artifacts"
                .to_string(),
        intended_use: "Qualify one bounded Mercury reference-distribution lane for landed-account expansion over the validated controlled-adoption package without widening into generic sales tooling, merged shells, or ARC commercial surfaces."
            .to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}

fn build_broader_distribution_profile(
    workflow_id: &str,
) -> Result<MercuryBroaderDistributionProfile, CliError> {
    let profile = MercuryBroaderDistributionProfile {
        schema: MERCURY_BROADER_DISTRIBUTION_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "broader-distribution-selective-account-qualification-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        distribution_motion: MercuryBroaderDistributionMotion::SelectiveAccountQualification,
        distribution_surface: MercuryBroaderDistributionSurface::GovernedDistributionBundle,
        claim_governance: "governed-broader-distribution-evidence-only".to_string(),
        retained_artifact_policy:
            "retain-bounded-broader-distribution-and-selective-account-qualification-artifacts"
                .to_string(),
        intended_use: "Qualify one bounded Mercury broader-distribution lane for selective account qualification over the validated reference-distribution package without widening into generic sales tooling, CRM workflows, merged shells, or ARC commercial surfaces."
            .to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}

fn export_assurance_suite(output: &Path) -> Result<MercuryAssuranceSuiteExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let governance_dir = output.join("governance-workbench");
    let governance_summary = export_governance_workbench(&governance_dir)?;
    let proof_package_path =
        governance_dir.join("qualification/supervised-live/proof-package.json");
    let proof_package: MercuryProofPackage = read_json_file(&proof_package_path)?;
    proof_package
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;

    let reviewer_package_path = governance_dir.join("qualification/reviewer-package.json");
    let qualification_report_path = governance_dir.join("qualification/qualification-report.json");
    let governance_decision_package_path = governance_dir.join("governance-decision-package.json");
    let investigation_inputs = collect_assurance_investigation_inputs(&proof_package);

    let populations_dir = output.join("reviewer-populations");
    fs::create_dir_all(&populations_dir)?;

    let mut reviewer_populations = Vec::new();
    let mut artifacts = Vec::new();
    let mut internal_review_package_file = String::new();
    let mut auditor_review_package_file = String::new();
    let mut counterparty_review_package_file = String::new();
    let mut internal_investigation_package_file = String::new();
    let mut auditor_investigation_package_file = String::new();
    let mut counterparty_investigation_package_file = String::new();

    for config in assurance_suite_population_configs() {
        let population_dir = populations_dir.join(config.dir_name);
        fs::create_dir_all(&population_dir)?;

        let disclosure_profile =
            build_assurance_disclosure_profile(&governance_summary.workflow_id, config)?;
        let disclosure_profile_path = population_dir.join("disclosure-profile.json");
        write_json_file(&disclosure_profile_path, &disclosure_profile)?;

        let inquiry_package = build_inquiry_package(
            proof_package.clone(),
            config.audience,
            Some(config.redaction_profile),
            config.verifier_equivalent,
        )?;
        let inquiry_report = inquiry_package
            .verify(unix_now())
            .map_err(|error| CliError::Other(error.to_string()))?;
        let inquiry_package_path = population_dir.join("inquiry-package.json");
        let inquiry_verification_path = population_dir.join("inquiry-verification.json");
        write_json_file(&inquiry_package_path, &inquiry_package)?;
        write_verification_report(&inquiry_verification_path, &inquiry_report)?;

        let review_package = build_assurance_review_package(
            &governance_summary.workflow_id,
            config.reviewer_population,
            &relative_display(output, &disclosure_profile_path)?,
            &relative_display(output, &proof_package_path)?,
            &relative_display(output, &inquiry_package_path)?,
            &relative_display(output, &inquiry_verification_path)?,
            &relative_display(output, &reviewer_package_path)?,
            &relative_display(output, &qualification_report_path)?,
            &relative_display(output, &governance_decision_package_path)?,
            config.verifier_equivalent,
        )?;
        let review_package_path = population_dir.join("review-package.json");
        write_json_file(&review_package_path, &review_package)?;

        let investigation_package = build_assurance_investigation_package(
            &governance_summary.workflow_id,
            config.reviewer_population,
            &relative_display(output, &review_package_path)?,
            &investigation_inputs,
            config.investigation_focus,
        )?;
        let investigation_package_path = population_dir.join("investigation-package.json");
        write_json_file(&investigation_package_path, &investigation_package)?;

        reviewer_populations.push(config.reviewer_population.as_str().to_string());
        artifacts.push(MercuryAssuranceSuiteArtifact {
            reviewer_population: config.reviewer_population,
            artifact_kind: MercuryAssuranceArtifactKind::DisclosureProfile,
            relative_path: relative_display(output, &disclosure_profile_path)?,
        });
        artifacts.push(MercuryAssuranceSuiteArtifact {
            reviewer_population: config.reviewer_population,
            artifact_kind: MercuryAssuranceArtifactKind::ReviewPackage,
            relative_path: relative_display(output, &review_package_path)?,
        });
        artifacts.push(MercuryAssuranceSuiteArtifact {
            reviewer_population: config.reviewer_population,
            artifact_kind: MercuryAssuranceArtifactKind::InvestigationPackage,
            relative_path: relative_display(output, &investigation_package_path)?,
        });

        match config.reviewer_population {
            MercuryAssuranceReviewerPopulation::InternalReview => {
                internal_review_package_file = review_package_path.display().to_string();
                internal_investigation_package_file =
                    investigation_package_path.display().to_string();
            }
            MercuryAssuranceReviewerPopulation::AuditorReview => {
                auditor_review_package_file = review_package_path.display().to_string();
                auditor_investigation_package_file =
                    investigation_package_path.display().to_string();
            }
            MercuryAssuranceReviewerPopulation::CounterpartyReview => {
                counterparty_review_package_file = review_package_path.display().to_string();
                counterparty_investigation_package_file =
                    investigation_package_path.display().to_string();
            }
        }
    }

    let assurance_suite_package = MercuryAssuranceSuitePackage {
        schema: MERCURY_ASSURANCE_SUITE_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "assurance-suite-{}-{}",
            governance_summary.workflow_id,
            current_utc_date()
        ),
        workflow_id: governance_summary.workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        reviewer_owner: MERCURY_ASSURANCE_REVIEWER_OWNER.to_string(),
        support_owner: MERCURY_ASSURANCE_SUPPORT_OWNER.to_string(),
        fail_closed: true,
        governance_decision_package_file: relative_display(
            output,
            &governance_decision_package_path,
        )?,
        reviewer_populations: vec![
            MercuryAssuranceReviewerPopulation::InternalReview,
            MercuryAssuranceReviewerPopulation::AuditorReview,
            MercuryAssuranceReviewerPopulation::CounterpartyReview,
        ],
        artifacts,
    };
    assurance_suite_package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let assurance_suite_package_path = output.join("assurance-suite-package.json");
    write_json_file(&assurance_suite_package_path, &assurance_suite_package)?;

    let summary = MercuryAssuranceSuiteExportSummary {
        workflow_id: governance_summary.workflow_id,
        reviewer_owner: MERCURY_ASSURANCE_REVIEWER_OWNER.to_string(),
        support_owner: MERCURY_ASSURANCE_SUPPORT_OWNER.to_string(),
        reviewer_populations,
        qualification_dir: governance_summary.qualification_dir,
        governance_workbench_dir: governance_dir.display().to_string(),
        governance_decision_package_file: governance_summary.governance_decision_package_file,
        assurance_suite_package_file: assurance_suite_package_path.display().to_string(),
        internal_review_package_file,
        auditor_review_package_file,
        counterparty_review_package_file,
        internal_investigation_package_file,
        auditor_investigation_package_file,
        counterparty_investigation_package_file,
    };
    write_json_file(&output.join("assurance-suite-summary.json"), &summary)?;

    Ok(summary)
}

fn export_embedded_oem(output: &Path) -> Result<MercuryEmbeddedOemExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let assurance_dir = output.join("assurance-suite");
    let assurance_summary = export_assurance_suite(&assurance_dir)?;
    let workflow_id = assurance_summary.workflow_id.clone();

    let profile = build_embedded_oem_profile(&workflow_id)?;
    let profile_path = output.join("embedded-oem-profile.json");
    write_json_file(&profile_path, &profile)?;

    let partner_bundle_dir = output.join("partner-sdk-bundle");
    fs::create_dir_all(&partner_bundle_dir)?;

    let assurance_suite_package_src = assurance_dir.join("assurance-suite-package.json");
    let governance_decision_package_src =
        assurance_dir.join("governance-workbench/governance-decision-package.json");
    let disclosure_profile_src =
        assurance_dir.join("reviewer-populations/counterparty-review/disclosure-profile.json");
    let review_package_src =
        assurance_dir.join("reviewer-populations/counterparty-review/review-package.json");
    let investigation_package_src =
        assurance_dir.join("reviewer-populations/counterparty-review/investigation-package.json");
    let reviewer_package_src =
        assurance_dir.join("governance-workbench/qualification/reviewer-package.json");
    let qualification_report_src =
        assurance_dir.join("governance-workbench/qualification/qualification-report.json");

    let assurance_suite_package_path = partner_bundle_dir.join("assurance-suite-package.json");
    let governance_decision_package_path =
        partner_bundle_dir.join("governance-decision-package.json");
    let disclosure_profile_path = partner_bundle_dir.join("disclosure-profile.json");
    let review_package_path = partner_bundle_dir.join("review-package.json");
    let investigation_package_path = partner_bundle_dir.join("investigation-package.json");
    let reviewer_package_path = partner_bundle_dir.join("reviewer-package.json");
    let qualification_report_path = partner_bundle_dir.join("qualification-report.json");

    copy_file(&assurance_suite_package_src, &assurance_suite_package_path)?;
    copy_file(
        &governance_decision_package_src,
        &governance_decision_package_path,
    )?;
    copy_file(&disclosure_profile_src, &disclosure_profile_path)?;
    copy_file(&review_package_src, &review_package_path)?;
    copy_file(&investigation_package_src, &investigation_package_path)?;
    copy_file(&reviewer_package_src, &reviewer_package_path)?;
    copy_file(&qualification_report_src, &qualification_report_path)?;

    let acknowledgement = MercuryEmbeddedDeliveryAcknowledgement {
        schema: "arc.mercury.embedded_delivery_acknowledgement.v1".to_string(),
        workflow_id: workflow_id.clone(),
        partner_surface: MercuryEmbeddedPartnerSurface::ReviewerWorkbenchEmbed
            .as_str()
            .to_string(),
        partner_owner: MERCURY_EMBEDDED_PARTNER_OWNER.to_string(),
        status: "acknowledged".to_string(),
        acknowledged_at: unix_now(),
        acknowledged_by: "partner-review-platform-drop".to_string(),
        delivered_files: vec![
            "assurance-suite-package.json".to_string(),
            "governance-decision-package.json".to_string(),
            "disclosure-profile.json".to_string(),
            "review-package.json".to_string(),
            "investigation-package.json".to_string(),
            "reviewer-package.json".to_string(),
            "qualification-report.json".to_string(),
        ],
        note: "The embedded OEM bundle is limited to one reviewer-workbench surface, one signed artifact bundle, and one counterparty-review population. Any missing or inconsistent artifact must fail closed."
            .to_string(),
    };
    let acknowledgement_path = partner_bundle_dir.join("delivery-acknowledgement.json");
    write_json_file(&acknowledgement_path, &acknowledgement)?;

    let sdk_manifest = MercuryEmbeddedPartnerManifest {
        schema: "arc.mercury.embedded_partner_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        partner_surface: MercuryEmbeddedPartnerSurface::ReviewerWorkbenchEmbed
            .as_str()
            .to_string(),
        sdk_surface: MercuryEmbeddedSdkSurface::SignedArtifactBundle
            .as_str()
            .to_string(),
        reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview
            .as_str()
            .to_string(),
        fail_closed: true,
        acknowledgement_required: true,
        profile_file: relative_display(output, &profile_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        governance_decision_package_file: relative_display(
            output,
            &governance_decision_package_path,
        )?,
        disclosure_profile_file: relative_display(output, &disclosure_profile_path)?,
        review_package_file: relative_display(output, &review_package_path)?,
        investigation_package_file: relative_display(output, &investigation_package_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        support_owner: MERCURY_EMBEDDED_SUPPORT_OWNER.to_string(),
        note: "This manifest is the bounded embedded OEM surface. It packages one counterparty-review Mercury bundle for one partner reviewer workbench and does not imply a generic SDK or multi-partner OEM platform."
            .to_string(),
    };
    let sdk_manifest_path = output.join("partner-sdk-manifest.json");
    write_json_file(&sdk_manifest_path, &sdk_manifest)?;

    let package = MercuryEmbeddedOemPackage {
        schema: MERCURY_EMBEDDED_OEM_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "embedded-oem-reviewer-workbench-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        partner_surface: MercuryEmbeddedPartnerSurface::ReviewerWorkbenchEmbed,
        sdk_surface: MercuryEmbeddedSdkSurface::SignedArtifactBundle,
        reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview,
        partner_owner: MERCURY_EMBEDDED_PARTNER_OWNER.to_string(),
        support_owner: MERCURY_EMBEDDED_SUPPORT_OWNER.to_string(),
        acknowledgement_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        sdk_manifest_file: relative_display(output, &sdk_manifest_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        governance_decision_package_file: relative_display(
            output,
            &governance_decision_package_path,
        )?,
        artifacts: vec![
            MercuryEmbeddedOemArtifact {
                artifact_kind: MercuryEmbeddedArtifactKind::DisclosureProfile,
                relative_path: relative_display(output, &disclosure_profile_path)?,
            },
            MercuryEmbeddedOemArtifact {
                artifact_kind: MercuryEmbeddedArtifactKind::ReviewPackage,
                relative_path: relative_display(output, &review_package_path)?,
            },
            MercuryEmbeddedOemArtifact {
                artifact_kind: MercuryEmbeddedArtifactKind::InvestigationPackage,
                relative_path: relative_display(output, &investigation_package_path)?,
            },
            MercuryEmbeddedOemArtifact {
                artifact_kind: MercuryEmbeddedArtifactKind::ReviewerPackage,
                relative_path: relative_display(output, &reviewer_package_path)?,
            },
            MercuryEmbeddedOemArtifact {
                artifact_kind: MercuryEmbeddedArtifactKind::QualificationReport,
                relative_path: relative_display(output, &qualification_report_path)?,
            },
            MercuryEmbeddedOemArtifact {
                artifact_kind: MercuryEmbeddedArtifactKind::DeliveryAcknowledgement,
                relative_path: relative_display(output, &acknowledgement_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("embedded-oem-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercuryEmbeddedOemExportSummary {
        workflow_id,
        partner_surface: MercuryEmbeddedPartnerSurface::ReviewerWorkbenchEmbed
            .as_str()
            .to_string(),
        sdk_surface: MercuryEmbeddedSdkSurface::SignedArtifactBundle
            .as_str()
            .to_string(),
        reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview
            .as_str()
            .to_string(),
        partner_owner: MERCURY_EMBEDDED_PARTNER_OWNER.to_string(),
        support_owner: MERCURY_EMBEDDED_SUPPORT_OWNER.to_string(),
        assurance_suite_dir: assurance_dir.display().to_string(),
        embedded_oem_profile_file: profile_path.display().to_string(),
        embedded_oem_package_file: package_path.display().to_string(),
        partner_sdk_manifest_file: sdk_manifest_path.display().to_string(),
        assurance_suite_package_file: assurance_suite_package_path.display().to_string(),
        governance_decision_package_file: governance_decision_package_path.display().to_string(),
        disclosure_profile_file: disclosure_profile_path.display().to_string(),
        review_package_file: review_package_path.display().to_string(),
        investigation_package_file: investigation_package_path.display().to_string(),
        reviewer_package_file: reviewer_package_path.display().to_string(),
        qualification_report_file: qualification_report_path.display().to_string(),
        acknowledgement_file: acknowledgement_path.display().to_string(),
        partner_sdk_bundle_dir: partner_bundle_dir.display().to_string(),
    };
    write_json_file(&output.join("embedded-oem-summary.json"), &summary)?;

    Ok(summary)
}

fn export_trust_network(output: &Path) -> Result<MercuryTrustNetworkExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let embedded_oem_dir = output.join("embedded-oem");
    let embedded_summary = export_embedded_oem(&embedded_oem_dir)?;
    let workflow_id = embedded_summary.workflow_id.clone();

    let profile = build_trust_network_profile(&workflow_id)?;
    let profile_path = output.join("trust-network-profile.json");
    write_json_file(&profile_path, &profile)?;

    let share_dir = output.join("trust-network-share");
    fs::create_dir_all(&share_dir)?;

    let shared_proof_package_src = embedded_oem_dir.join(
        "assurance-suite/governance-workbench/qualification/supervised-live/proof-package.json",
    );
    let shared_review_package_src = embedded_oem_dir.join("partner-sdk-bundle/review-package.json");
    let reviewer_package_src = embedded_oem_dir.join("partner-sdk-bundle/reviewer-package.json");
    let qualification_report_src =
        embedded_oem_dir.join("partner-sdk-bundle/qualification-report.json");

    let witness_record_path = share_dir.join("witness-record.json");
    let trust_anchor_record_path = share_dir.join("trust-anchor-record.json");
    let shared_proof_package_path = share_dir.join("shared-proof-package.json");
    let shared_review_package_path = share_dir.join("review-package.json");
    let reviewer_package_path = share_dir.join("reviewer-package.json");
    let qualification_report_path = share_dir.join("qualification-report.json");

    let witness_record = MercuryTrustNetworkWitnessRecord {
        schema: "arc.mercury.trust_network_witness_record.v1".to_string(),
        workflow_id: workflow_id.clone(),
        sponsor_boundary: MercuryTrustNetworkSponsorBoundary::CounterpartyReviewExchange
            .as_str()
            .to_string(),
        trust_anchor: MercuryTrustNetworkTrustAnchor::ArcCheckpointWitnessChain
            .as_str()
            .to_string(),
        checkpoint_continuity: "append_only".to_string(),
        witness_steps: profile
            .witness_steps
            .iter()
            .map(|step| step.as_str().to_string())
            .collect(),
        witness_operator: MERCURY_TRUST_NETWORK_SPONSOR_OWNER.to_string(),
        note: "The trust-network lane remains bounded to one counterparty-review exchange sponsor, one checkpoint-backed witness chain, and one fail-closed interoperability path."
            .to_string(),
    };
    write_json_file(&witness_record_path, &witness_record)?;

    let trust_anchor_record = MercuryTrustAnchorRecord {
        schema: "arc.mercury.trust_anchor_record.v1".to_string(),
        workflow_id: workflow_id.clone(),
        trust_anchor: MercuryTrustNetworkTrustAnchor::ArcCheckpointWitnessChain
            .as_str()
            .to_string(),
        anchor_scope:
            "arc checkpoint signatures plus one bounded trust-network witness chain".to_string(),
        verification_material:
            "shared-proof-package publicationProfile binds witness and trust-anchor references."
                .to_string(),
        note: "This trust anchor is limited to one counterparty-review trust-network lane and does not imply a generic ecosystem trust service."
            .to_string(),
    };
    write_json_file(&trust_anchor_record_path, &trust_anchor_record)?;

    let mut shared_proof_package: MercuryProofPackage = read_json_file(&shared_proof_package_src)?;
    shared_proof_package.publication_profile.witness_record =
        Some(relative_display(output, &witness_record_path)?);
    shared_proof_package.publication_profile.trust_anchor =
        Some(relative_display(output, &trust_anchor_record_path)?);
    shared_proof_package
        .publication_profile
        .freshness_window_secs = Some(86_400);
    shared_proof_package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    write_json_file(&shared_proof_package_path, &shared_proof_package)?;

    let shared_inquiry_package = build_inquiry_package(
        shared_proof_package.clone(),
        "trust-network-review",
        Some("shared-proof-exchange"),
        false,
    )?;
    let shared_inquiry_report = shared_inquiry_package
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;
    let shared_inquiry_package_path = share_dir.join("inquiry-package.json");
    let shared_inquiry_verification_path = share_dir.join("inquiry-verification.json");
    write_json_file(&shared_inquiry_package_path, &shared_inquiry_package)?;
    write_verification_report(&shared_inquiry_verification_path, &shared_inquiry_report)?;

    copy_file(&shared_review_package_src, &shared_review_package_path)?;
    copy_file(&reviewer_package_src, &reviewer_package_path)?;
    copy_file(&qualification_report_src, &qualification_report_path)?;

    let interop_manifest = MercuryTrustNetworkInteroperabilityManifest {
        schema: "arc.mercury.trust_network_interop_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        sponsor_boundary: MercuryTrustNetworkSponsorBoundary::CounterpartyReviewExchange
            .as_str()
            .to_string(),
        trust_anchor: MercuryTrustNetworkTrustAnchor::ArcCheckpointWitnessChain
            .as_str()
            .to_string(),
        interop_surface: MercuryTrustNetworkInteropSurface::ProofInquiryBundleExchange
            .as_str()
            .to_string(),
        reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview
            .as_str()
            .to_string(),
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        shared_proof_package_file: relative_display(output, &shared_proof_package_path)?,
        shared_review_package_file: relative_display(output, &shared_review_package_path)?,
        shared_inquiry_package_file: relative_display(output, &shared_inquiry_package_path)?,
        shared_inquiry_verification_file: relative_display(
            output,
            &shared_inquiry_verification_path,
        )?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        witness_record_file: relative_display(output, &witness_record_path)?,
        trust_anchor_record_file: relative_display(output, &trust_anchor_record_path)?,
        support_owner: MERCURY_TRUST_NETWORK_SUPPORT_OWNER.to_string(),
        note: "This manifest is the bounded trust-network exchange surface. It shares one counterparty-review proof and inquiry bundle over one checkpoint-backed witness chain and does not imply a generic trust broker or multi-network service."
            .to_string(),
    };
    let interop_manifest_path = output.join("trust-network-interoperability-manifest.json");
    write_json_file(&interop_manifest_path, &interop_manifest)?;

    let package = MercuryTrustNetworkPackage {
        schema: MERCURY_TRUST_NETWORK_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "trust-network-counterparty-review-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        sponsor_boundary: MercuryTrustNetworkSponsorBoundary::CounterpartyReviewExchange,
        trust_anchor: MercuryTrustNetworkTrustAnchor::ArcCheckpointWitnessChain,
        interop_surface: MercuryTrustNetworkInteropSurface::ProofInquiryBundleExchange,
        reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview,
        sponsor_owner: MERCURY_TRUST_NETWORK_SPONSOR_OWNER.to_string(),
        support_owner: MERCURY_TRUST_NETWORK_SUPPORT_OWNER.to_string(),
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        embedded_oem_package_file: relative_display(
            output,
            &embedded_oem_dir.join("embedded-oem-package.json"),
        )?,
        embedded_partner_manifest_file: relative_display(
            output,
            &embedded_oem_dir.join("partner-sdk-manifest.json"),
        )?,
        artifacts: vec![
            MercuryTrustNetworkArtifact {
                artifact_kind: MercuryTrustNetworkArtifactKind::SharedProofPackage,
                relative_path: relative_display(output, &shared_proof_package_path)?,
            },
            MercuryTrustNetworkArtifact {
                artifact_kind: MercuryTrustNetworkArtifactKind::SharedReviewPackage,
                relative_path: relative_display(output, &shared_review_package_path)?,
            },
            MercuryTrustNetworkArtifact {
                artifact_kind: MercuryTrustNetworkArtifactKind::SharedInquiryPackage,
                relative_path: relative_display(output, &shared_inquiry_package_path)?,
            },
            MercuryTrustNetworkArtifact {
                artifact_kind: MercuryTrustNetworkArtifactKind::InquiryVerification,
                relative_path: relative_display(output, &shared_inquiry_verification_path)?,
            },
            MercuryTrustNetworkArtifact {
                artifact_kind: MercuryTrustNetworkArtifactKind::InteroperabilityManifest,
                relative_path: relative_display(output, &interop_manifest_path)?,
            },
            MercuryTrustNetworkArtifact {
                artifact_kind: MercuryTrustNetworkArtifactKind::WitnessRecord,
                relative_path: relative_display(output, &witness_record_path)?,
            },
            MercuryTrustNetworkArtifact {
                artifact_kind: MercuryTrustNetworkArtifactKind::TrustAnchorRecord,
                relative_path: relative_display(output, &trust_anchor_record_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("trust-network-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercuryTrustNetworkExportSummary {
        workflow_id,
        sponsor_boundary: MercuryTrustNetworkSponsorBoundary::CounterpartyReviewExchange
            .as_str()
            .to_string(),
        trust_anchor: MercuryTrustNetworkTrustAnchor::ArcCheckpointWitnessChain
            .as_str()
            .to_string(),
        interop_surface: MercuryTrustNetworkInteropSurface::ProofInquiryBundleExchange
            .as_str()
            .to_string(),
        reviewer_population: MercuryAssuranceReviewerPopulation::CounterpartyReview
            .as_str()
            .to_string(),
        sponsor_owner: MERCURY_TRUST_NETWORK_SPONSOR_OWNER.to_string(),
        support_owner: MERCURY_TRUST_NETWORK_SUPPORT_OWNER.to_string(),
        embedded_oem_dir: embedded_oem_dir.display().to_string(),
        trust_network_profile_file: profile_path.display().to_string(),
        trust_network_package_file: package_path.display().to_string(),
        interop_manifest_file: interop_manifest_path.display().to_string(),
        shared_proof_package_file: shared_proof_package_path.display().to_string(),
        shared_review_package_file: shared_review_package_path.display().to_string(),
        shared_inquiry_package_file: shared_inquiry_package_path.display().to_string(),
        shared_inquiry_verification_file: shared_inquiry_verification_path.display().to_string(),
        reviewer_package_file: reviewer_package_path.display().to_string(),
        qualification_report_file: qualification_report_path.display().to_string(),
        witness_record_file: witness_record_path.display().to_string(),
        trust_anchor_record_file: trust_anchor_record_path.display().to_string(),
        share_dir: share_dir.display().to_string(),
    };
    write_json_file(&output.join("trust-network-summary.json"), &summary)?;

    Ok(summary)
}

fn export_release_readiness(
    output: &Path,
) -> Result<MercuryReleaseReadinessExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let trust_network_dir = output.join("trust-network");
    let trust_network = export_trust_network(&trust_network_dir)?;
    let workflow_id = trust_network.workflow_id.clone();

    let profile = build_release_readiness_profile(&workflow_id)?;
    let profile_path = output.join("release-readiness-profile.json");
    write_json_file(&profile_path, &profile)?;

    let partner_bundle_dir = output.join("partner-delivery");
    fs::create_dir_all(&partner_bundle_dir)?;

    let proof_package_path = partner_bundle_dir.join("proof-package.json");
    let inquiry_package_path = partner_bundle_dir.join("inquiry-package.json");
    let inquiry_verification_path = partner_bundle_dir.join("inquiry-verification.json");
    let assurance_suite_package_path = partner_bundle_dir.join("assurance-suite-package.json");
    let trust_network_package_path = partner_bundle_dir.join("trust-network-package.json");
    let reviewer_package_path = partner_bundle_dir.join("reviewer-package.json");
    let qualification_report_path = partner_bundle_dir.join("qualification-report.json");

    copy_file(
        &trust_network_dir.join("trust-network-share/shared-proof-package.json"),
        &proof_package_path,
    )?;
    copy_file(
        &trust_network_dir.join("trust-network-share/inquiry-package.json"),
        &inquiry_package_path,
    )?;
    copy_file(
        &trust_network_dir.join("trust-network-share/inquiry-verification.json"),
        &inquiry_verification_path,
    )?;
    copy_file(
        &trust_network_dir.join("embedded-oem/assurance-suite/assurance-suite-package.json"),
        &assurance_suite_package_path,
    )?;
    copy_file(
        &trust_network_dir.join("trust-network-package.json"),
        &trust_network_package_path,
    )?;
    copy_file(
        &trust_network_dir.join("trust-network-share/reviewer-package.json"),
        &reviewer_package_path,
    )?;
    copy_file(
        &trust_network_dir.join("trust-network-share/qualification-report.json"),
        &qualification_report_path,
    )?;

    let operator_release_checklist = MercuryReleaseReadinessOperatorChecklist {
        schema: "arc.mercury.release_readiness_operator_checklist.v1".to_string(),
        workflow_id: workflow_id.clone(),
        release_owner: MERCURY_RELEASE_OWNER.to_string(),
        partner_owner: MERCURY_RELEASE_PARTNER_OWNER.to_string(),
        support_owner: MERCURY_RELEASE_SUPPORT_OWNER.to_string(),
        fail_closed: true,
        gating_checks: vec![
            "confirm release-readiness profile matches reviewer, partner, and operator audiences"
                .to_string(),
            "confirm partner-delivery bundle contains proof, inquiry, assurance, trust-network, reviewer, and qualification artifacts"
                .to_string(),
            "confirm the same workflow sentence remains unchanged across all exported artifacts"
                .to_string(),
            "confirm operator escalation and support handoff files are present before launch"
                .to_string(),
        ],
        note: "The operator checklist is limited to one bounded Mercury release-readiness lane and does not authorize a generic ARC release console."
            .to_string(),
    };
    let operator_release_checklist_path = output.join("operator-release-checklist.json");
    write_json_file(
        &operator_release_checklist_path,
        &operator_release_checklist,
    )?;

    let escalation_manifest = MercuryReleaseReadinessEscalationManifest {
        schema: "arc.mercury.release_readiness_escalation_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        release_owner: MERCURY_RELEASE_OWNER.to_string(),
        support_owner: MERCURY_RELEASE_SUPPORT_OWNER.to_string(),
        fail_closed: true,
        escalation_triggers: vec![
            "partner-delivery manifest mismatch".to_string(),
            "missing proof, inquiry, assurance, or trust-network file".to_string(),
            "reviewer package and qualification report cannot be matched to the same workflow"
                .to_string(),
            "operator checklist is incomplete at launch time".to_string(),
        ],
        note: "Escalation remains product-owned inside Mercury and must not be shifted into ARC generic crates."
            .to_string(),
    };
    let escalation_manifest_path = output.join("escalation-manifest.json");
    write_json_file(&escalation_manifest_path, &escalation_manifest)?;

    let support_handoff = MercuryReleaseReadinessSupportHandoff {
        schema: "arc.mercury.release_readiness_support_handoff.v1".to_string(),
        workflow_id: workflow_id.clone(),
        release_owner: MERCURY_RELEASE_OWNER.to_string(),
        support_owner: MERCURY_RELEASE_SUPPORT_OWNER.to_string(),
        active_window: "launch + initial controlled adoption window".to_string(),
        required_files: vec![
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &assurance_suite_package_path)?,
            relative_display(output, &trust_network_package_path)?,
            relative_display(output, &reviewer_package_path)?,
            relative_display(output, &qualification_report_path)?,
        ],
        note: "This handoff is bounded to one Mercury launch lane and one support-owner path."
            .to_string(),
    };
    let support_handoff_path = output.join("support-handoff.json");
    write_json_file(&support_handoff_path, &support_handoff)?;

    let partner_manifest = MercuryReleaseReadinessPartnerManifest {
        schema: "arc.mercury.release_readiness_partner_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        delivery_surface: MercuryReleaseReadinessDeliverySurface::SignedPartnerReviewBundle
            .as_str()
            .to_string(),
        reviewer_population: trust_network.reviewer_population.clone(),
        acknowledgement_required: true,
        fail_closed: true,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        inquiry_verification_file: relative_display(output, &inquiry_verification_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        operator_release_checklist_file: relative_display(output, &operator_release_checklist_path)?,
        escalation_manifest_file: relative_display(output, &escalation_manifest_path)?,
        support_handoff_file: relative_display(output, &support_handoff_path)?,
        note: "This manifest delivers one bounded Mercury package to one partner path while preserving the same proof, inquiry, assurance, and trust-network truth chain."
            .to_string(),
    };
    let partner_manifest_path = output.join("partner-delivery-manifest.json");
    write_json_file(&partner_manifest_path, &partner_manifest)?;

    let acknowledgement = MercuryReleaseReadinessDeliveryAcknowledgement {
        schema: "arc.mercury.release_readiness_delivery_acknowledgement.v1".to_string(),
        workflow_id: workflow_id.clone(),
        delivery_surface: MercuryReleaseReadinessDeliverySurface::SignedPartnerReviewBundle
            .as_str()
            .to_string(),
        partner_owner: MERCURY_RELEASE_PARTNER_OWNER.to_string(),
        status: "acknowledged".to_string(),
        acknowledged_at: unix_now(),
        acknowledged_by: MERCURY_RELEASE_PARTNER_OWNER.to_string(),
        delivered_files: vec![
            relative_display(output, &partner_manifest_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &assurance_suite_package_path)?,
            relative_display(output, &trust_network_package_path)?,
            relative_display(output, &reviewer_package_path)?,
            relative_display(output, &qualification_report_path)?,
        ],
        note: "Acknowledgement is required before this bounded release-readiness lane may be treated as launched."
            .to_string(),
    };
    let acknowledgement_path = output.join("delivery-acknowledgement.json");
    write_json_file(&acknowledgement_path, &acknowledgement)?;

    let package = MercuryReleaseReadinessPackage {
        schema: MERCURY_RELEASE_READINESS_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "release-readiness-signed-partner-review-bundle-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        audiences: profile.audiences.clone(),
        delivery_surface: MercuryReleaseReadinessDeliverySurface::SignedPartnerReviewBundle,
        release_owner: MERCURY_RELEASE_OWNER.to_string(),
        partner_owner: MERCURY_RELEASE_PARTNER_OWNER.to_string(),
        support_owner: MERCURY_RELEASE_SUPPORT_OWNER.to_string(),
        acknowledgement_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        artifacts: vec![
            MercuryReleaseReadinessArtifact {
                artifact_kind: MercuryReleaseReadinessArtifactKind::PartnerDeliveryManifest,
                relative_path: relative_display(output, &partner_manifest_path)?,
            },
            MercuryReleaseReadinessArtifact {
                artifact_kind: MercuryReleaseReadinessArtifactKind::DeliveryAcknowledgement,
                relative_path: relative_display(output, &acknowledgement_path)?,
            },
            MercuryReleaseReadinessArtifact {
                artifact_kind: MercuryReleaseReadinessArtifactKind::OperatorReleaseChecklist,
                relative_path: relative_display(output, &operator_release_checklist_path)?,
            },
            MercuryReleaseReadinessArtifact {
                artifact_kind: MercuryReleaseReadinessArtifactKind::EscalationManifest,
                relative_path: relative_display(output, &escalation_manifest_path)?,
            },
            MercuryReleaseReadinessArtifact {
                artifact_kind: MercuryReleaseReadinessArtifactKind::SupportHandoff,
                relative_path: relative_display(output, &support_handoff_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("release-readiness-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercuryReleaseReadinessExportSummary {
        workflow_id,
        audiences: profile
            .audiences
            .iter()
            .map(|audience| audience.as_str().to_string())
            .collect(),
        delivery_surface: MercuryReleaseReadinessDeliverySurface::SignedPartnerReviewBundle
            .as_str()
            .to_string(),
        release_owner: MERCURY_RELEASE_OWNER.to_string(),
        partner_owner: MERCURY_RELEASE_PARTNER_OWNER.to_string(),
        support_owner: MERCURY_RELEASE_SUPPORT_OWNER.to_string(),
        trust_network_dir: trust_network_dir.display().to_string(),
        release_readiness_profile_file: profile_path.display().to_string(),
        release_readiness_package_file: package_path.display().to_string(),
        partner_delivery_manifest_file: partner_manifest_path.display().to_string(),
        acknowledgement_file: acknowledgement_path.display().to_string(),
        operator_release_checklist_file: operator_release_checklist_path.display().to_string(),
        escalation_manifest_file: escalation_manifest_path.display().to_string(),
        support_handoff_file: support_handoff_path.display().to_string(),
        partner_bundle_dir: partner_bundle_dir.display().to_string(),
        proof_package_file: proof_package_path.display().to_string(),
        inquiry_package_file: inquiry_package_path.display().to_string(),
        inquiry_verification_file: inquiry_verification_path.display().to_string(),
        assurance_suite_package_file: assurance_suite_package_path.display().to_string(),
        trust_network_package_file: trust_network_package_path.display().to_string(),
        reviewer_package_file: reviewer_package_path.display().to_string(),
        qualification_report_file: qualification_report_path.display().to_string(),
    };
    write_json_file(&output.join("release-readiness-summary.json"), &summary)?;

    Ok(summary)
}

fn export_controlled_adoption(
    output: &Path,
) -> Result<MercuryControlledAdoptionExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let release_readiness_dir = output.join("release-readiness");
    let release_readiness = export_release_readiness(&release_readiness_dir)?;
    let workflow_id = release_readiness.workflow_id.clone();

    let profile = build_controlled_adoption_profile(&workflow_id)?;
    let profile_path = output.join("controlled-adoption-profile.json");
    write_json_file(&profile_path, &profile)?;

    let adoption_evidence_dir = output.join("adoption-evidence");
    fs::create_dir_all(&adoption_evidence_dir)?;

    let release_readiness_package_path =
        adoption_evidence_dir.join("release-readiness-package.json");
    let trust_network_package_path = adoption_evidence_dir.join("trust-network-package.json");
    let assurance_suite_package_path = adoption_evidence_dir.join("assurance-suite-package.json");
    let proof_package_path = adoption_evidence_dir.join("proof-package.json");
    let inquiry_package_path = adoption_evidence_dir.join("inquiry-package.json");
    let inquiry_verification_path = adoption_evidence_dir.join("inquiry-verification.json");
    let reviewer_package_path = adoption_evidence_dir.join("reviewer-package.json");
    let qualification_report_path = adoption_evidence_dir.join("qualification-report.json");

    copy_file(
        &release_readiness_dir.join("release-readiness-package.json"),
        &release_readiness_package_path,
    )?;
    copy_file(
        &release_readiness_dir.join("partner-delivery/trust-network-package.json"),
        &trust_network_package_path,
    )?;
    copy_file(
        &release_readiness_dir.join("partner-delivery/assurance-suite-package.json"),
        &assurance_suite_package_path,
    )?;
    copy_file(
        &release_readiness_dir.join("partner-delivery/proof-package.json"),
        &proof_package_path,
    )?;
    copy_file(
        &release_readiness_dir.join("partner-delivery/inquiry-package.json"),
        &inquiry_package_path,
    )?;
    copy_file(
        &release_readiness_dir.join("partner-delivery/inquiry-verification.json"),
        &inquiry_verification_path,
    )?;
    copy_file(
        &release_readiness_dir.join("partner-delivery/reviewer-package.json"),
        &reviewer_package_path,
    )?;
    copy_file(
        &release_readiness_dir.join("partner-delivery/qualification-report.json"),
        &qualification_report_path,
    )?;

    let customer_success_checklist = MercuryControlledAdoptionCustomerSuccessChecklist {
        schema: "arc.mercury.controlled_adoption_customer_success_checklist.v1".to_string(),
        workflow_id: workflow_id.clone(),
        customer_success_owner: MERCURY_CUSTOMER_SUCCESS_OWNER.to_string(),
        reference_owner: MERCURY_REFERENCE_OWNER.to_string(),
        support_owner: MERCURY_ADOPTION_SUPPORT_OWNER.to_string(),
        fail_closed: true,
        readiness_checks: vec![
            "confirm the adoption cohort remains design-partner renewal only".to_string(),
            "confirm renewal evidence points back to the same release-readiness package and Mercury workflow".to_string(),
            "confirm reference-readiness materials use only the bounded approved claim".to_string(),
            "confirm customer-success and support escalation files exist before any renewal or reference motion".to_string(),
        ],
        note: "This checklist governs one Mercury post-launch adoption lane only and does not authorize generic ARC renewal tooling or broader Mercury delivery surfaces."
            .to_string(),
    };
    let customer_success_checklist_path = output.join("customer-success-checklist.json");
    write_json_file(
        &customer_success_checklist_path,
        &customer_success_checklist,
    )?;

    let renewal_manifest = MercuryControlledAdoptionRenewalManifest {
        schema: "arc.mercury.controlled_adoption_renewal_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        cohort: MercuryControlledAdoptionCohort::DesignPartnerRenewal
            .as_str()
            .to_string(),
        adoption_surface: MercuryControlledAdoptionSurface::RenewalReferenceBundle
            .as_str()
            .to_string(),
        success_window: profile.success_window.clone(),
        renewal_signal: "design partner confirms continued Mercury use with proof-backed renewal and reference review".to_string(),
        release_readiness_package_file: relative_display(output, &release_readiness_package_path)?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        inquiry_verification_file: relative_display(output, &inquiry_verification_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        note: "This manifest freezes one bounded renewal-evidence lane on top of the validated Mercury release-readiness stack and does not imply a generic customer-success platform."
            .to_string(),
    };
    let renewal_manifest_path = output.join("renewal-evidence-manifest.json");
    write_json_file(&renewal_manifest_path, &renewal_manifest)?;

    let renewal_acknowledgement = MercuryControlledAdoptionRenewalAcknowledgement {
        schema: "arc.mercury.controlled_adoption_renewal_acknowledgement.v1".to_string(),
        workflow_id: workflow_id.clone(),
        cohort: MercuryControlledAdoptionCohort::DesignPartnerRenewal
            .as_str()
            .to_string(),
        adoption_surface: MercuryControlledAdoptionSurface::RenewalReferenceBundle
            .as_str()
            .to_string(),
        customer_success_owner: MERCURY_CUSTOMER_SUCCESS_OWNER.to_string(),
        status: "acknowledged".to_string(),
        acknowledged_at: unix_now(),
        acknowledged_by: MERCURY_CUSTOMER_SUCCESS_OWNER.to_string(),
        delivered_files: vec![
            relative_display(output, &renewal_manifest_path)?,
            relative_display(output, &release_readiness_package_path)?,
            relative_display(output, &trust_network_package_path)?,
            relative_display(output, &assurance_suite_package_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &reviewer_package_path)?,
            relative_display(output, &qualification_report_path)?,
        ],
        note: "Acknowledgement is required before the bounded renewal and reference lane may be treated as ready for scaled Mercury adoption."
            .to_string(),
    };
    let renewal_acknowledgement_path = output.join("renewal-acknowledgement.json");
    write_json_file(&renewal_acknowledgement_path, &renewal_acknowledgement)?;

    let reference_readiness_brief = MercuryControlledAdoptionReferenceReadinessBrief {
        schema: "arc.mercury.controlled_adoption_reference_readiness_brief.v1".to_string(),
        workflow_id: workflow_id.clone(),
        reference_owner: MERCURY_REFERENCE_OWNER.to_string(),
        cohort: MercuryControlledAdoptionCohort::DesignPartnerRenewal
            .as_str()
            .to_string(),
        adoption_surface: MercuryControlledAdoptionSurface::RenewalReferenceBundle
            .as_str()
            .to_string(),
        approved_claim: "Mercury can support one bounded controlled-adoption lane for renewal and reference readiness over the validated release-readiness evidence stack."
            .to_string(),
        required_files: vec![
            relative_display(output, &renewal_manifest_path)?,
            relative_display(output, &renewal_acknowledgement_path)?,
            relative_display(output, &release_readiness_package_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
        ],
        note: "Reference material remains bounded to one approved claim and one design-partner renewal cohort. Broader marketing claims require a later milestone."
            .to_string(),
    };
    let reference_readiness_brief_path = output.join("reference-readiness-brief.json");
    write_json_file(&reference_readiness_brief_path, &reference_readiness_brief)?;

    let support_escalation_manifest = MercuryControlledAdoptionSupportEscalationManifest {
        schema: "arc.mercury.controlled_adoption_support_escalation_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        support_owner: MERCURY_ADOPTION_SUPPORT_OWNER.to_string(),
        customer_success_owner: MERCURY_CUSTOMER_SUCCESS_OWNER.to_string(),
        fail_closed: true,
        escalation_triggers: vec![
            "renewal evidence no longer maps to the same release-readiness package".to_string(),
            "reference-readiness brief uses an unapproved claim or missing artifact".to_string(),
            "proof, inquiry, assurance, or trust-network adoption evidence is missing".to_string(),
            "customer-success acknowledgement is missing before renewal or reference use".to_string(),
        ],
        note: "Escalation remains Mercury-owned for one bounded controlled-adoption lane and must not migrate into ARC generic release or support surfaces."
            .to_string(),
    };
    let support_escalation_manifest_path = output.join("support-escalation-manifest.json");
    write_json_file(
        &support_escalation_manifest_path,
        &support_escalation_manifest,
    )?;

    let package = MercuryControlledAdoptionPackage {
        schema: MERCURY_CONTROLLED_ADOPTION_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "controlled-adoption-design-partner-renewal-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        cohort: MercuryControlledAdoptionCohort::DesignPartnerRenewal,
        adoption_surface: MercuryControlledAdoptionSurface::RenewalReferenceBundle,
        customer_success_owner: MERCURY_CUSTOMER_SUCCESS_OWNER.to_string(),
        reference_owner: MERCURY_REFERENCE_OWNER.to_string(),
        support_owner: MERCURY_ADOPTION_SUPPORT_OWNER.to_string(),
        acknowledgement_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        release_readiness_package_file: relative_display(output, &release_readiness_package_path)?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        artifacts: vec![
            MercuryControlledAdoptionArtifact {
                artifact_kind: MercuryControlledAdoptionArtifactKind::CustomerSuccessChecklist,
                relative_path: relative_display(output, &customer_success_checklist_path)?,
            },
            MercuryControlledAdoptionArtifact {
                artifact_kind: MercuryControlledAdoptionArtifactKind::RenewalEvidenceManifest,
                relative_path: relative_display(output, &renewal_manifest_path)?,
            },
            MercuryControlledAdoptionArtifact {
                artifact_kind: MercuryControlledAdoptionArtifactKind::RenewalAcknowledgement,
                relative_path: relative_display(output, &renewal_acknowledgement_path)?,
            },
            MercuryControlledAdoptionArtifact {
                artifact_kind: MercuryControlledAdoptionArtifactKind::ReferenceReadinessBrief,
                relative_path: relative_display(output, &reference_readiness_brief_path)?,
            },
            MercuryControlledAdoptionArtifact {
                artifact_kind: MercuryControlledAdoptionArtifactKind::SupportEscalationManifest,
                relative_path: relative_display(output, &support_escalation_manifest_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("controlled-adoption-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercuryControlledAdoptionExportSummary {
        workflow_id,
        cohort: MercuryControlledAdoptionCohort::DesignPartnerRenewal
            .as_str()
            .to_string(),
        adoption_surface: MercuryControlledAdoptionSurface::RenewalReferenceBundle
            .as_str()
            .to_string(),
        customer_success_owner: MERCURY_CUSTOMER_SUCCESS_OWNER.to_string(),
        reference_owner: MERCURY_REFERENCE_OWNER.to_string(),
        support_owner: MERCURY_ADOPTION_SUPPORT_OWNER.to_string(),
        release_readiness_dir: release_readiness_dir.display().to_string(),
        controlled_adoption_profile_file: profile_path.display().to_string(),
        controlled_adoption_package_file: package_path.display().to_string(),
        customer_success_checklist_file: customer_success_checklist_path.display().to_string(),
        renewal_evidence_manifest_file: renewal_manifest_path.display().to_string(),
        renewal_acknowledgement_file: renewal_acknowledgement_path.display().to_string(),
        reference_readiness_brief_file: reference_readiness_brief_path.display().to_string(),
        support_escalation_manifest_file: support_escalation_manifest_path.display().to_string(),
        adoption_evidence_dir: adoption_evidence_dir.display().to_string(),
        release_readiness_package_file: release_readiness_package_path.display().to_string(),
        trust_network_package_file: trust_network_package_path.display().to_string(),
        assurance_suite_package_file: assurance_suite_package_path.display().to_string(),
        proof_package_file: proof_package_path.display().to_string(),
        inquiry_package_file: inquiry_package_path.display().to_string(),
        inquiry_verification_file: inquiry_verification_path.display().to_string(),
        reviewer_package_file: reviewer_package_path.display().to_string(),
        qualification_report_file: qualification_report_path.display().to_string(),
    };
    write_json_file(&output.join("controlled-adoption-summary.json"), &summary)?;

    let _ = release_readiness;

    Ok(summary)
}

fn export_reference_distribution(
    output: &Path,
) -> Result<MercuryReferenceDistributionExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let controlled_adoption_dir = output.join("controlled-adoption");
    let controlled_adoption = export_controlled_adoption(&controlled_adoption_dir)?;
    let workflow_id = controlled_adoption.workflow_id.clone();

    let profile = build_reference_distribution_profile(&workflow_id)?;
    let profile_path = output.join("reference-distribution-profile.json");
    write_json_file(&profile_path, &profile)?;

    let reference_evidence_dir = output.join("reference-evidence");
    fs::create_dir_all(&reference_evidence_dir)?;

    let controlled_adoption_package_path =
        reference_evidence_dir.join("controlled-adoption-package.json");
    let renewal_evidence_manifest_path =
        reference_evidence_dir.join("renewal-evidence-manifest.json");
    let renewal_acknowledgement_path = reference_evidence_dir.join("renewal-acknowledgement.json");
    let reference_readiness_brief_path =
        reference_evidence_dir.join("reference-readiness-brief.json");
    let release_readiness_package_path =
        reference_evidence_dir.join("release-readiness-package.json");
    let trust_network_package_path = reference_evidence_dir.join("trust-network-package.json");
    let assurance_suite_package_path = reference_evidence_dir.join("assurance-suite-package.json");
    let proof_package_path = reference_evidence_dir.join("proof-package.json");
    let inquiry_package_path = reference_evidence_dir.join("inquiry-package.json");
    let inquiry_verification_path = reference_evidence_dir.join("inquiry-verification.json");
    let reviewer_package_path = reference_evidence_dir.join("reviewer-package.json");
    let qualification_report_path = reference_evidence_dir.join("qualification-report.json");

    copy_file(
        Path::new(&controlled_adoption.controlled_adoption_package_file),
        &controlled_adoption_package_path,
    )?;
    copy_file(
        Path::new(&controlled_adoption.renewal_evidence_manifest_file),
        &renewal_evidence_manifest_path,
    )?;
    copy_file(
        Path::new(&controlled_adoption.renewal_acknowledgement_file),
        &renewal_acknowledgement_path,
    )?;
    copy_file(
        Path::new(&controlled_adoption.reference_readiness_brief_file),
        &reference_readiness_brief_path,
    )?;
    copy_file(
        Path::new(&controlled_adoption.release_readiness_package_file),
        &release_readiness_package_path,
    )?;
    copy_file(
        Path::new(&controlled_adoption.trust_network_package_file),
        &trust_network_package_path,
    )?;
    copy_file(
        Path::new(&controlled_adoption.assurance_suite_package_file),
        &assurance_suite_package_path,
    )?;
    copy_file(
        Path::new(&controlled_adoption.proof_package_file),
        &proof_package_path,
    )?;
    copy_file(
        Path::new(&controlled_adoption.inquiry_package_file),
        &inquiry_package_path,
    )?;
    copy_file(
        Path::new(&controlled_adoption.inquiry_verification_file),
        &inquiry_verification_path,
    )?;
    copy_file(
        Path::new(&controlled_adoption.reviewer_package_file),
        &reviewer_package_path,
    )?;
    copy_file(
        Path::new(&controlled_adoption.qualification_report_file),
        &qualification_report_path,
    )?;

    let approved_claim = "Mercury can support one bounded landed-account expansion motion using one approved reference bundle rooted in the validated controlled-adoption, release-readiness, trust-network, assurance, proof, and inquiry stack.".to_string();

    let account_motion_freeze = MercuryReferenceDistributionAccountMotionFreeze {
        schema: "arc.mercury.reference_distribution_account_motion_freeze.v1".to_string(),
        workflow_id: workflow_id.clone(),
        expansion_motion: MercuryReferenceDistributionMotion::LandedAccountExpansion
            .as_str()
            .to_string(),
        distribution_surface: MercuryReferenceDistributionSurface::ApprovedReferenceBundle
            .as_str()
            .to_string(),
        landed_account_target:
            "one landed account already carrying design-partner renewal evidence".to_string(),
        approved_buyer_path: vec![
            "workflow engineering lead".to_string(),
            "head of trading platform or control-program sponsor".to_string(),
            "economic buyer reviewing one bounded reference bundle".to_string(),
        ],
        non_goals: vec![
            "generic sales tooling or CRM workflows".to_string(),
            "merged Mercury and ARC-Wall commercial packaging".to_string(),
            "additional landed-account motions or broader product-family claims".to_string(),
        ],
        note: "This freeze keeps the next Mercury step bounded to one landed-account expansion motion over the existing controlled-adoption package."
            .to_string(),
    };
    let account_motion_freeze_path = output.join("account-motion-freeze.json");
    write_json_file(&account_motion_freeze_path, &account_motion_freeze)?;

    let reference_distribution_manifest = MercuryReferenceDistributionManifest {
        schema: "arc.mercury.reference_distribution_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        expansion_motion: MercuryReferenceDistributionMotion::LandedAccountExpansion
            .as_str()
            .to_string(),
        distribution_surface: MercuryReferenceDistributionSurface::ApprovedReferenceBundle
            .as_str()
            .to_string(),
        controlled_adoption_package_file: relative_display(output, &controlled_adoption_package_path)?,
        renewal_evidence_manifest_file: relative_display(output, &renewal_evidence_manifest_path)?,
        renewal_acknowledgement_file: relative_display(output, &renewal_acknowledgement_path)?,
        reference_readiness_brief_file: relative_display(output, &reference_readiness_brief_path)?,
        release_readiness_package_file: relative_display(output, &release_readiness_package_path)?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        inquiry_verification_file: relative_display(output, &inquiry_verification_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        note: "This manifest freezes one approved reference bundle over the existing Mercury truth chain and does not imply generic commercial packaging."
            .to_string(),
    };
    let reference_distribution_manifest_path = output.join("reference-distribution-manifest.json");
    write_json_file(
        &reference_distribution_manifest_path,
        &reference_distribution_manifest,
    )?;

    let claim_discipline_rules = MercuryReferenceDistributionClaimDisciplineRules {
        schema: "arc.mercury.reference_distribution_claim_discipline_rules.v1".to_string(),
        workflow_id: workflow_id.clone(),
        reference_owner: MERCURY_REFERENCE_OWNER.to_string(),
        buyer_approval_owner: MERCURY_BUYER_APPROVAL_OWNER.to_string(),
        fail_closed: true,
        approved_claims: vec![
            approved_claim.clone(),
            "The reference bundle remains bounded to one landed-account motion and one approved evidence chain.".to_string(),
        ],
        prohibited_claims: vec![
            "Mercury is now a generic sales platform".to_string(),
            "ARC provides a commercial expansion console".to_string(),
            "the bundle proves broad best-execution or universal rollout readiness".to_string(),
        ],
        note: "Claim discipline stays Mercury-owned and fail-closed for one approved reference-backed expansion path."
            .to_string(),
    };
    let claim_discipline_rules_path = output.join("claim-discipline-rules.json");
    write_json_file(&claim_discipline_rules_path, &claim_discipline_rules)?;

    let buyer_reference_approval = MercuryReferenceDistributionBuyerApproval {
        schema: "arc.mercury.reference_distribution_buyer_reference_approval.v1".to_string(),
        workflow_id: workflow_id.clone(),
        buyer_approval_owner: MERCURY_BUYER_APPROVAL_OWNER.to_string(),
        status: "approved".to_string(),
        approved_at: unix_now(),
        approved_by: MERCURY_BUYER_APPROVAL_OWNER.to_string(),
        approved_claims: claim_discipline_rules.approved_claims.clone(),
        required_files: vec![
            relative_display(output, &account_motion_freeze_path)?,
            relative_display(output, &reference_distribution_manifest_path)?,
            relative_display(output, &claim_discipline_rules_path)?,
            relative_display(output, &renewal_acknowledgement_path)?,
            relative_display(output, &reference_readiness_brief_path)?,
            relative_display(output, &controlled_adoption_package_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
        ],
        note: "Buyer-reference approval is required before the bounded landed-account motion can use the approved reference bundle."
            .to_string(),
    };
    let buyer_reference_approval_path = output.join("buyer-reference-approval.json");
    write_json_file(&buyer_reference_approval_path, &buyer_reference_approval)?;

    let sales_handoff_brief = MercuryReferenceDistributionSalesHandoffBrief {
        schema: "arc.mercury.reference_distribution_sales_handoff_brief.v1".to_string(),
        workflow_id: workflow_id.clone(),
        sales_owner: MERCURY_LANDED_ACCOUNT_SALES_OWNER.to_string(),
        reference_owner: MERCURY_REFERENCE_OWNER.to_string(),
        buyer_approval_owner: MERCURY_BUYER_APPROVAL_OWNER.to_string(),
        expansion_motion: MercuryReferenceDistributionMotion::LandedAccountExpansion
            .as_str()
            .to_string(),
        distribution_surface: MercuryReferenceDistributionSurface::ApprovedReferenceBundle
            .as_str()
            .to_string(),
        approved_scope: "one approved reference-backed landed-account expansion motion only"
            .to_string(),
        entry_criteria: vec![
            "controlled-adoption package is present and internally consistent".to_string(),
            "renewal acknowledgement and reference-readiness brief are current".to_string(),
            "buyer-reference approval is present before handoff".to_string(),
        ],
        escalation_triggers: vec![
            "approved claim drifts from the bundle contents".to_string(),
            "required files are missing or no longer map to the same workflow".to_string(),
            "the motion broadens beyond one landed account or one reference bundle".to_string(),
        ],
        note: "The handoff brief exists to move one approved Mercury reference bundle into one landed-account motion, not to define a generic sales system."
            .to_string(),
    };
    let sales_handoff_brief_path = output.join("sales-handoff-brief.json");
    write_json_file(&sales_handoff_brief_path, &sales_handoff_brief)?;

    let package = MercuryReferenceDistributionPackage {
        schema: MERCURY_REFERENCE_DISTRIBUTION_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "reference-distribution-landed-account-expansion-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        expansion_motion: MercuryReferenceDistributionMotion::LandedAccountExpansion,
        distribution_surface: MercuryReferenceDistributionSurface::ApprovedReferenceBundle,
        reference_owner: MERCURY_REFERENCE_OWNER.to_string(),
        buyer_approval_owner: MERCURY_BUYER_APPROVAL_OWNER.to_string(),
        sales_owner: MERCURY_LANDED_ACCOUNT_SALES_OWNER.to_string(),
        approval_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        controlled_adoption_package_file: relative_display(
            output,
            &controlled_adoption_package_path,
        )?,
        renewal_evidence_manifest_file: relative_display(output, &renewal_evidence_manifest_path)?,
        renewal_acknowledgement_file: relative_display(output, &renewal_acknowledgement_path)?,
        reference_readiness_brief_file: relative_display(output, &reference_readiness_brief_path)?,
        release_readiness_package_file: relative_display(output, &release_readiness_package_path)?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        inquiry_verification_file: relative_display(output, &inquiry_verification_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        artifacts: vec![
            MercuryReferenceDistributionArtifact {
                artifact_kind: MercuryReferenceDistributionArtifactKind::AccountMotionFreeze,
                relative_path: relative_display(output, &account_motion_freeze_path)?,
            },
            MercuryReferenceDistributionArtifact {
                artifact_kind:
                    MercuryReferenceDistributionArtifactKind::ReferenceDistributionManifest,
                relative_path: relative_display(output, &reference_distribution_manifest_path)?,
            },
            MercuryReferenceDistributionArtifact {
                artifact_kind: MercuryReferenceDistributionArtifactKind::ClaimDisciplineRules,
                relative_path: relative_display(output, &claim_discipline_rules_path)?,
            },
            MercuryReferenceDistributionArtifact {
                artifact_kind: MercuryReferenceDistributionArtifactKind::BuyerReferenceApproval,
                relative_path: relative_display(output, &buyer_reference_approval_path)?,
            },
            MercuryReferenceDistributionArtifact {
                artifact_kind: MercuryReferenceDistributionArtifactKind::SalesHandoffBrief,
                relative_path: relative_display(output, &sales_handoff_brief_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("reference-distribution-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercuryReferenceDistributionExportSummary {
        workflow_id,
        expansion_motion: MercuryReferenceDistributionMotion::LandedAccountExpansion
            .as_str()
            .to_string(),
        distribution_surface: MercuryReferenceDistributionSurface::ApprovedReferenceBundle
            .as_str()
            .to_string(),
        reference_owner: MERCURY_REFERENCE_OWNER.to_string(),
        buyer_approval_owner: MERCURY_BUYER_APPROVAL_OWNER.to_string(),
        sales_owner: MERCURY_LANDED_ACCOUNT_SALES_OWNER.to_string(),
        controlled_adoption_dir: controlled_adoption_dir.display().to_string(),
        reference_distribution_profile_file: profile_path.display().to_string(),
        reference_distribution_package_file: package_path.display().to_string(),
        account_motion_freeze_file: account_motion_freeze_path.display().to_string(),
        reference_distribution_manifest_file: reference_distribution_manifest_path
            .display()
            .to_string(),
        claim_discipline_rules_file: claim_discipline_rules_path.display().to_string(),
        buyer_reference_approval_file: buyer_reference_approval_path.display().to_string(),
        sales_handoff_brief_file: sales_handoff_brief_path.display().to_string(),
        reference_evidence_dir: reference_evidence_dir.display().to_string(),
        controlled_adoption_package_file: controlled_adoption_package_path.display().to_string(),
        renewal_evidence_manifest_file: renewal_evidence_manifest_path.display().to_string(),
        renewal_acknowledgement_file: renewal_acknowledgement_path.display().to_string(),
        reference_readiness_brief_file: reference_readiness_brief_path.display().to_string(),
        release_readiness_package_file: release_readiness_package_path.display().to_string(),
        trust_network_package_file: trust_network_package_path.display().to_string(),
        assurance_suite_package_file: assurance_suite_package_path.display().to_string(),
        proof_package_file: proof_package_path.display().to_string(),
        inquiry_package_file: inquiry_package_path.display().to_string(),
        inquiry_verification_file: inquiry_verification_path.display().to_string(),
        reviewer_package_file: reviewer_package_path.display().to_string(),
        qualification_report_file: qualification_report_path.display().to_string(),
    };
    write_json_file(
        &output.join("reference-distribution-summary.json"),
        &summary,
    )?;

    let _ = controlled_adoption;

    Ok(summary)
}

fn export_broader_distribution(
    output: &Path,
) -> Result<MercuryBroaderDistributionExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let reference_distribution_dir = output.join("reference-distribution");
    let reference_distribution = export_reference_distribution(&reference_distribution_dir)?;
    let workflow_id = reference_distribution.workflow_id.clone();

    let profile = build_broader_distribution_profile(&workflow_id)?;
    let profile_path = output.join("broader-distribution-profile.json");
    write_json_file(&profile_path, &profile)?;

    let qualification_evidence_dir = output.join("qualification-evidence");
    fs::create_dir_all(&qualification_evidence_dir)?;

    let reference_distribution_package_path =
        qualification_evidence_dir.join("reference-distribution-package.json");
    let account_motion_freeze_path = qualification_evidence_dir.join("account-motion-freeze.json");
    let reference_distribution_manifest_path =
        qualification_evidence_dir.join("reference-distribution-manifest.json");
    let reference_claim_discipline_path =
        qualification_evidence_dir.join("reference-claim-discipline-rules.json");
    let reference_buyer_approval_path =
        qualification_evidence_dir.join("reference-buyer-approval.json");
    let reference_sales_handoff_path =
        qualification_evidence_dir.join("reference-sales-handoff-brief.json");
    let controlled_adoption_package_path =
        qualification_evidence_dir.join("controlled-adoption-package.json");
    let renewal_evidence_manifest_path =
        qualification_evidence_dir.join("renewal-evidence-manifest.json");
    let renewal_acknowledgement_path =
        qualification_evidence_dir.join("renewal-acknowledgement.json");
    let reference_readiness_brief_path =
        qualification_evidence_dir.join("reference-readiness-brief.json");
    let release_readiness_package_path =
        qualification_evidence_dir.join("release-readiness-package.json");
    let trust_network_package_path = qualification_evidence_dir.join("trust-network-package.json");
    let assurance_suite_package_path =
        qualification_evidence_dir.join("assurance-suite-package.json");
    let proof_package_path = qualification_evidence_dir.join("proof-package.json");
    let inquiry_package_path = qualification_evidence_dir.join("inquiry-package.json");
    let inquiry_verification_path = qualification_evidence_dir.join("inquiry-verification.json");
    let reviewer_package_path = qualification_evidence_dir.join("reviewer-package.json");
    let qualification_report_path = qualification_evidence_dir.join("qualification-report.json");

    copy_file(
        Path::new(&reference_distribution.reference_distribution_package_file),
        &reference_distribution_package_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.account_motion_freeze_file),
        &account_motion_freeze_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.reference_distribution_manifest_file),
        &reference_distribution_manifest_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.claim_discipline_rules_file),
        &reference_claim_discipline_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.buyer_reference_approval_file),
        &reference_buyer_approval_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.sales_handoff_brief_file),
        &reference_sales_handoff_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.controlled_adoption_package_file),
        &controlled_adoption_package_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.renewal_evidence_manifest_file),
        &renewal_evidence_manifest_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.renewal_acknowledgement_file),
        &renewal_acknowledgement_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.reference_readiness_brief_file),
        &reference_readiness_brief_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.release_readiness_package_file),
        &release_readiness_package_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.trust_network_package_file),
        &trust_network_package_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.assurance_suite_package_file),
        &assurance_suite_package_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.proof_package_file),
        &proof_package_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.inquiry_package_file),
        &inquiry_package_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.inquiry_verification_file),
        &inquiry_verification_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.reviewer_package_file),
        &reviewer_package_path,
    )?;
    copy_file(
        Path::new(&reference_distribution.qualification_report_file),
        &qualification_report_path,
    )?;

    let approved_claim = "Mercury can support one bounded broader-distribution readiness motion using one governed distribution bundle for selective account qualification rooted in the validated reference-distribution, controlled-adoption, release-readiness, trust-network, assurance, proof, and inquiry stack.".to_string();

    let target_account_freeze = MercuryBroaderDistributionTargetAccountFreeze {
        schema: "arc.mercury.broader_distribution_target_account_freeze.v1".to_string(),
        workflow_id: workflow_id.clone(),
        distribution_motion: MercuryBroaderDistributionMotion::SelectiveAccountQualification
            .as_str()
            .to_string(),
        distribution_surface: MercuryBroaderDistributionSurface::GovernedDistributionBundle
            .as_str()
            .to_string(),
        target_account_segment:
            "one adjacent account matching the validated reference-backed workflow pattern"
                .to_string(),
        qualification_gates: vec![
            "same workflow boundary as the reference-distribution package".to_string(),
            "selective-account review stays within one governed bundle".to_string(),
            "claim-governance approval is present before handoff".to_string(),
        ],
        non_goals: vec![
            "generic sales tooling or CRM workflows".to_string(),
            "multi-segment channel programs or partner marketplaces".to_string(),
            "merged Mercury and ARC-Wall commercial packaging".to_string(),
        ],
        note: "This freeze keeps the next Mercury step bounded to one selective account-qualification motion over the existing reference-distribution package."
            .to_string(),
    };
    let target_account_freeze_path = output.join("target-account-freeze.json");
    write_json_file(&target_account_freeze_path, &target_account_freeze)?;

    let broader_distribution_manifest = MercuryBroaderDistributionManifest {
        schema: "arc.mercury.broader_distribution_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        distribution_motion: MercuryBroaderDistributionMotion::SelectiveAccountQualification
            .as_str()
            .to_string(),
        distribution_surface: MercuryBroaderDistributionSurface::GovernedDistributionBundle
            .as_str()
            .to_string(),
        reference_distribution_package_file: relative_display(
            output,
            &reference_distribution_package_path,
        )?,
        account_motion_freeze_file: relative_display(output, &account_motion_freeze_path)?,
        reference_distribution_manifest_file: relative_display(
            output,
            &reference_distribution_manifest_path,
        )?,
        reference_claim_discipline_file: relative_display(
            output,
            &reference_claim_discipline_path,
        )?,
        reference_buyer_approval_file: relative_display(output, &reference_buyer_approval_path)?,
        reference_sales_handoff_file: relative_display(output, &reference_sales_handoff_path)?,
        controlled_adoption_package_file: relative_display(
            output,
            &controlled_adoption_package_path,
        )?,
        renewal_evidence_manifest_file: relative_display(output, &renewal_evidence_manifest_path)?,
        renewal_acknowledgement_file: relative_display(output, &renewal_acknowledgement_path)?,
        reference_readiness_brief_file: relative_display(output, &reference_readiness_brief_path)?,
        release_readiness_package_file: relative_display(output, &release_readiness_package_path)?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        inquiry_verification_file: relative_display(output, &inquiry_verification_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        note: "This manifest freezes one governed broader-distribution bundle over the existing Mercury truth chain and does not imply generic commercial tooling."
            .to_string(),
    };
    let broader_distribution_manifest_path = output.join("broader-distribution-manifest.json");
    write_json_file(
        &broader_distribution_manifest_path,
        &broader_distribution_manifest,
    )?;

    let claim_governance_rules = MercuryBroaderDistributionClaimGovernanceRules {
        schema: "arc.mercury.broader_distribution_claim_governance_rules.v1".to_string(),
        workflow_id: workflow_id.clone(),
        qualification_owner: MERCURY_QUALIFICATION_OWNER.to_string(),
        approval_owner: MERCURY_DISTRIBUTION_APPROVAL_OWNER.to_string(),
        fail_closed: true,
        approved_claims: vec![
            approved_claim.clone(),
            "The broader-distribution bundle remains bounded to one selective account-qualification motion and one governed distribution surface.".to_string(),
        ],
        prohibited_claims: vec![
            "Mercury is now a generic sales or channel platform".to_string(),
            "ARC provides a commercial broader-distribution console".to_string(),
            "the bundle proves universal rollout readiness or broad business performance".to_string(),
        ],
        note: "Claim governance stays Mercury-owned and fail-closed for one governed broader-distribution path."
            .to_string(),
    };
    let claim_governance_rules_path = output.join("claim-governance-rules.json");
    write_json_file(&claim_governance_rules_path, &claim_governance_rules)?;

    let selective_account_approval = MercuryBroaderDistributionSelectiveAccountApproval {
        schema: "arc.mercury.broader_distribution_selective_account_approval.v1".to_string(),
        workflow_id: workflow_id.clone(),
        approval_owner: MERCURY_DISTRIBUTION_APPROVAL_OWNER.to_string(),
        status: "approved".to_string(),
        approved_at: unix_now(),
        approved_by: MERCURY_DISTRIBUTION_APPROVAL_OWNER.to_string(),
        approved_claims: claim_governance_rules.approved_claims.clone(),
        required_files: vec![
            relative_display(output, &target_account_freeze_path)?,
            relative_display(output, &broader_distribution_manifest_path)?,
            relative_display(output, &claim_governance_rules_path)?,
            relative_display(output, &reference_distribution_package_path)?,
            relative_display(output, &reference_buyer_approval_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &reviewer_package_path)?,
        ],
        note: "Selective-account approval is required before the governed broader-distribution bundle can be handed off."
            .to_string(),
    };
    let selective_account_approval_path = output.join("selective-account-approval.json");
    write_json_file(
        &selective_account_approval_path,
        &selective_account_approval,
    )?;

    let distribution_handoff_brief = MercuryBroaderDistributionHandoffBrief {
        schema: "arc.mercury.broader_distribution_handoff_brief.v1".to_string(),
        workflow_id: workflow_id.clone(),
        distribution_owner: MERCURY_BROADER_DISTRIBUTION_OWNER.to_string(),
        qualification_owner: MERCURY_QUALIFICATION_OWNER.to_string(),
        approval_owner: MERCURY_DISTRIBUTION_APPROVAL_OWNER.to_string(),
        distribution_motion: MercuryBroaderDistributionMotion::SelectiveAccountQualification
            .as_str()
            .to_string(),
        distribution_surface: MercuryBroaderDistributionSurface::GovernedDistributionBundle
            .as_str()
            .to_string(),
        approved_scope: "one governed broader-distribution bundle for one selective account-qualification motion only"
            .to_string(),
        entry_criteria: vec![
            "reference-distribution package is present and internally consistent".to_string(),
            "claim-governance rules and selective-account approval are current".to_string(),
            "the target account remains within the frozen workflow boundary".to_string(),
        ],
        escalation_triggers: vec![
            "approved claim drifts from the governed bundle contents".to_string(),
            "required files are missing or no longer map to the same workflow".to_string(),
            "the motion broadens beyond one selective account or one governed bundle".to_string(),
        ],
        note: "The handoff brief exists to move one governed Mercury bundle into one selective account-qualification motion, not to define a generic commercial system."
            .to_string(),
    };
    let distribution_handoff_brief_path = output.join("distribution-handoff-brief.json");
    write_json_file(
        &distribution_handoff_brief_path,
        &distribution_handoff_brief,
    )?;

    let package = MercuryBroaderDistributionPackage {
        schema: MERCURY_BROADER_DISTRIBUTION_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "broader-distribution-selective-account-qualification-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        distribution_motion: MercuryBroaderDistributionMotion::SelectiveAccountQualification,
        distribution_surface: MercuryBroaderDistributionSurface::GovernedDistributionBundle,
        qualification_owner: MERCURY_QUALIFICATION_OWNER.to_string(),
        approval_owner: MERCURY_DISTRIBUTION_APPROVAL_OWNER.to_string(),
        distribution_owner: MERCURY_BROADER_DISTRIBUTION_OWNER.to_string(),
        approval_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        reference_distribution_package_file: relative_display(
            output,
            &reference_distribution_package_path,
        )?,
        account_motion_freeze_file: relative_display(output, &account_motion_freeze_path)?,
        reference_distribution_manifest_file: relative_display(
            output,
            &reference_distribution_manifest_path,
        )?,
        reference_claim_discipline_file: relative_display(
            output,
            &reference_claim_discipline_path,
        )?,
        reference_buyer_approval_file: relative_display(output, &reference_buyer_approval_path)?,
        reference_sales_handoff_file: relative_display(output, &reference_sales_handoff_path)?,
        controlled_adoption_package_file: relative_display(
            output,
            &controlled_adoption_package_path,
        )?,
        renewal_evidence_manifest_file: relative_display(output, &renewal_evidence_manifest_path)?,
        renewal_acknowledgement_file: relative_display(output, &renewal_acknowledgement_path)?,
        reference_readiness_brief_file: relative_display(output, &reference_readiness_brief_path)?,
        release_readiness_package_file: relative_display(output, &release_readiness_package_path)?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        inquiry_verification_file: relative_display(output, &inquiry_verification_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        artifacts: vec![
            MercuryBroaderDistributionArtifact {
                artifact_kind: MercuryBroaderDistributionArtifactKind::TargetAccountFreeze,
                relative_path: relative_display(output, &target_account_freeze_path)?,
            },
            MercuryBroaderDistributionArtifact {
                artifact_kind: MercuryBroaderDistributionArtifactKind::BroaderDistributionManifest,
                relative_path: relative_display(output, &broader_distribution_manifest_path)?,
            },
            MercuryBroaderDistributionArtifact {
                artifact_kind: MercuryBroaderDistributionArtifactKind::ClaimGovernanceRules,
                relative_path: relative_display(output, &claim_governance_rules_path)?,
            },
            MercuryBroaderDistributionArtifact {
                artifact_kind: MercuryBroaderDistributionArtifactKind::SelectiveAccountApproval,
                relative_path: relative_display(output, &selective_account_approval_path)?,
            },
            MercuryBroaderDistributionArtifact {
                artifact_kind: MercuryBroaderDistributionArtifactKind::DistributionHandoffBrief,
                relative_path: relative_display(output, &distribution_handoff_brief_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("broader-distribution-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercuryBroaderDistributionExportSummary {
        workflow_id,
        distribution_motion: MercuryBroaderDistributionMotion::SelectiveAccountQualification
            .as_str()
            .to_string(),
        distribution_surface: MercuryBroaderDistributionSurface::GovernedDistributionBundle
            .as_str()
            .to_string(),
        qualification_owner: MERCURY_QUALIFICATION_OWNER.to_string(),
        approval_owner: MERCURY_DISTRIBUTION_APPROVAL_OWNER.to_string(),
        distribution_owner: MERCURY_BROADER_DISTRIBUTION_OWNER.to_string(),
        reference_distribution_dir: reference_distribution_dir.display().to_string(),
        broader_distribution_profile_file: profile_path.display().to_string(),
        broader_distribution_package_file: package_path.display().to_string(),
        target_account_freeze_file: target_account_freeze_path.display().to_string(),
        broader_distribution_manifest_file: broader_distribution_manifest_path
            .display()
            .to_string(),
        claim_governance_rules_file: claim_governance_rules_path.display().to_string(),
        selective_account_approval_file: selective_account_approval_path.display().to_string(),
        distribution_handoff_brief_file: distribution_handoff_brief_path.display().to_string(),
        qualification_evidence_dir: qualification_evidence_dir.display().to_string(),
        reference_distribution_package_file: reference_distribution_package_path
            .display()
            .to_string(),
        account_motion_freeze_file: account_motion_freeze_path.display().to_string(),
        reference_distribution_manifest_file: reference_distribution_manifest_path
            .display()
            .to_string(),
        reference_claim_discipline_file: reference_claim_discipline_path.display().to_string(),
        reference_buyer_approval_file: reference_buyer_approval_path.display().to_string(),
        reference_sales_handoff_file: reference_sales_handoff_path.display().to_string(),
        controlled_adoption_package_file: controlled_adoption_package_path.display().to_string(),
        renewal_evidence_manifest_file: renewal_evidence_manifest_path.display().to_string(),
        renewal_acknowledgement_file: renewal_acknowledgement_path.display().to_string(),
        reference_readiness_brief_file: reference_readiness_brief_path.display().to_string(),
        release_readiness_package_file: release_readiness_package_path.display().to_string(),
        trust_network_package_file: trust_network_package_path.display().to_string(),
        assurance_suite_package_file: assurance_suite_package_path.display().to_string(),
        proof_package_file: proof_package_path.display().to_string(),
        inquiry_package_file: inquiry_package_path.display().to_string(),
        inquiry_verification_file: inquiry_verification_path.display().to_string(),
        reviewer_package_file: reviewer_package_path.display().to_string(),
        qualification_report_file: qualification_report_path.display().to_string(),
    };
    write_json_file(&output.join("broader-distribution-summary.json"), &summary)?;

    let _ = reference_distribution;

    Ok(summary)
}

fn export_supervised_live_qualification(
    output: &Path,
) -> Result<
    (
        MercurySupervisedLiveQualificationReport,
        MercurySupervisedLiveReviewerPackage,
    ),
    CliError,
> {
    ensure_empty_directory(output)?;

    let supervised_live_dir = output.join("supervised-live");
    let pilot_dir = output.join("pilot");
    let supervised_live = export_supervised_live_capture(
        &supervised_live_dir,
        MercurySupervisedLiveCapture::sample(MercurySupervisedLiveMode::Live),
    )?;
    let pilot = export_pilot_scenario(&pilot_dir, MercuryPilotScenario::gold_release_control())?;
    let docs = reviewer_doc_refs();

    let qualification_report = MercurySupervisedLiveQualificationReport {
        workflow_id: supervised_live.workflow_id.clone(),
        decision: MERCURY_SUPERVISED_LIVE_DECISION.to_string(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        supervised_live: supervised_live.clone(),
        pilot: pilot.clone(),
        docs: docs.clone(),
    };
    let qualification_report_file = output.join("qualification-report.json");
    write_json_file(&qualification_report_file, &qualification_report)?;

    let reviewer_package = MercurySupervisedLiveReviewerPackage {
        workflow_id: supervised_live.workflow_id.clone(),
        decision: MERCURY_SUPERVISED_LIVE_DECISION.to_string(),
        qualification_report_file: qualification_report_file.display().to_string(),
        supervised_live_dir: supervised_live_dir.display().to_string(),
        pilot_dir: pilot_dir.display().to_string(),
        supervised_live_proof_package_file: supervised_live.export.proof_package_file.clone(),
        supervised_live_inquiry_package_file: supervised_live.export.inquiry_package_file.clone(),
        rollback_proof_package_file: pilot.rollback.proof_package_file.clone(),
        docs,
    };
    write_json_file(&output.join("reviewer-package.json"), &reviewer_package)?;

    Ok((qualification_report, reviewer_package))
}

fn export_downstream_review(
    output: &Path,
) -> Result<MercuryDownstreamReviewExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let qualification_dir = output.join("qualification");
    let (qualification_report, reviewer_package) =
        export_supervised_live_qualification(&qualification_dir)?;
    let proof_package_path = qualification_dir.join("supervised-live/proof-package.json");
    let proof_package: MercuryProofPackage = read_json_file(&proof_package_path)?;
    proof_package
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;

    let reviewer_package_path = qualification_dir.join("reviewer-package.json");
    let qualification_report_path = qualification_dir.join("qualification-report.json");

    let assurance_dir = output.join("assurance");
    let internal_dir = assurance_dir.join("internal-review");
    let external_dir = assurance_dir.join("external-review");
    fs::create_dir_all(&internal_dir)?;
    fs::create_dir_all(&external_dir)?;

    let internal_inquiry = build_inquiry_package(
        proof_package.clone(),
        "internal-review",
        Some("internal-review-default"),
        false,
    )?;
    let internal_inquiry_report = internal_inquiry
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;
    let internal_inquiry_path = internal_dir.join("inquiry-package.json");
    let internal_inquiry_report_path = internal_dir.join("inquiry-verification.json");
    write_json_file(&internal_inquiry_path, &internal_inquiry)?;
    write_verification_report(&internal_inquiry_report_path, &internal_inquiry_report)?;

    let internal_assurance = build_assurance_package(
        &qualification_report.workflow_id,
        MercuryAssuranceAudience::InternalReview,
        "internal-review-default",
        &relative_display(output, &proof_package_path)?,
        &relative_display(output, &internal_inquiry_path)?,
        &relative_display(output, &reviewer_package_path)?,
        &relative_display(output, &qualification_report_path)?,
        internal_inquiry_report.verifier_equivalent,
    )?;
    let internal_assurance_path = internal_dir.join("assurance-package.json");
    write_json_file(&internal_assurance_path, &internal_assurance)?;

    let external_inquiry = build_inquiry_package(
        proof_package,
        "external-review",
        Some("external-review-default"),
        false,
    )?;
    let external_inquiry_report = external_inquiry
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;
    let external_inquiry_path = external_dir.join("inquiry-package.json");
    let external_inquiry_report_path = external_dir.join("inquiry-verification.json");
    write_json_file(&external_inquiry_path, &external_inquiry)?;
    write_verification_report(&external_inquiry_report_path, &external_inquiry_report)?;

    let external_assurance = build_assurance_package(
        &qualification_report.workflow_id,
        MercuryAssuranceAudience::ExternalReview,
        "external-review-default",
        &relative_display(output, &proof_package_path)?,
        &relative_display(output, &external_inquiry_path)?,
        &relative_display(output, &reviewer_package_path)?,
        &relative_display(output, &qualification_report_path)?,
        external_inquiry_report.verifier_equivalent,
    )?;
    let external_assurance_path = external_dir.join("assurance-package.json");
    write_json_file(&external_assurance_path, &external_assurance)?;

    let consumer_drop_dir = output.join("consumer-drop");
    fs::create_dir_all(&consumer_drop_dir)?;
    let consumer_reviewer_package_path = consumer_drop_dir.join("reviewer-package.json");
    let consumer_qualification_report_path = consumer_drop_dir.join("qualification-report.json");
    let consumer_external_assurance_path =
        consumer_drop_dir.join("external-assurance-package.json");
    let consumer_external_inquiry_path = consumer_drop_dir.join("external-inquiry-package.json");
    let consumer_external_inquiry_verification_path =
        consumer_drop_dir.join("external-inquiry-verification.json");
    copy_file(&reviewer_package_path, &consumer_reviewer_package_path)?;
    copy_file(
        &qualification_report_path,
        &consumer_qualification_report_path,
    )?;
    copy_file(&external_assurance_path, &consumer_external_assurance_path)?;
    copy_file(&external_inquiry_path, &consumer_external_inquiry_path)?;
    copy_file(
        &external_inquiry_report_path,
        &consumer_external_inquiry_verification_path,
    )?;

    let consumer_manifest = MercuryDownstreamConsumerManifest {
        schema: "arc.mercury.consumer_manifest.v1".to_string(),
        workflow_id: qualification_report.workflow_id.clone(),
        consumer_profile: MercuryDownstreamConsumerProfile::CaseManagementReview
            .as_str()
            .to_string(),
        transport: MercuryDownstreamTransport::FileDrop.as_str().to_string(),
        acknowledgement_required: true,
        fail_closed: true,
        reviewer_package_file: "reviewer-package.json".to_string(),
        qualification_report_file: "qualification-report.json".to_string(),
        external_assurance_package_file: "external-assurance-package.json".to_string(),
        external_inquiry_package_file: "external-inquiry-package.json".to_string(),
        external_inquiry_verification_file: "external-inquiry-verification.json".to_string(),
    };
    let consumer_manifest_path = consumer_drop_dir.join("consumer-manifest.json");
    write_json_file(&consumer_manifest_path, &consumer_manifest)?;

    let acknowledgement = MercuryDownstreamDeliveryAcknowledgement {
        schema: "arc.mercury.delivery_acknowledgement.v1".to_string(),
        workflow_id: qualification_report.workflow_id.clone(),
        consumer_profile: MercuryDownstreamConsumerProfile::CaseManagementReview
            .as_str()
            .to_string(),
        destination_label: MERCURY_DOWNSTREAM_DESTINATION_LABEL.to_string(),
        status: "acknowledged".to_string(),
        acknowledged_at: unix_now(),
        acknowledged_by: "mercury-file-drop".to_string(),
        delivered_files: vec![
            "consumer-manifest.json".to_string(),
            "external-assurance-package.json".to_string(),
            "external-inquiry-package.json".to_string(),
            "external-inquiry-verification.json".to_string(),
            "qualification-report.json".to_string(),
            "reviewer-package.json".to_string(),
        ],
        note: "The bounded case-management review package has been staged in the file-drop intake. Any delivery failure must fail closed and no broader consumer path is implied."
            .to_string(),
    };
    let acknowledgement_path = consumer_drop_dir.join("delivery-acknowledgement.json");
    write_json_file(&acknowledgement_path, &acknowledgement)?;

    let downstream_package = MercuryDownstreamReviewPackage {
        schema: MERCURY_DOWNSTREAM_REVIEW_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "downstream-review-case-management-{}-{}",
            qualification_report.workflow_id,
            current_utc_date()
        ),
        workflow_id: qualification_report.workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        consumer_profile: MercuryDownstreamConsumerProfile::CaseManagementReview,
        transport: MercuryDownstreamTransport::FileDrop,
        destination_label: MERCURY_DOWNSTREAM_DESTINATION_LABEL.to_string(),
        destination_owner: MERCURY_DOWNSTREAM_DESTINATION_OWNER.to_string(),
        support_owner: MERCURY_DOWNSTREAM_SUPPORT_OWNER.to_string(),
        acknowledgement_required: true,
        fail_closed: true,
        artifacts: vec![
            MercuryDownstreamArtifact {
                role: MercuryDownstreamArtifactRole::InternalAssurancePackage,
                relative_path: relative_display(output, &internal_assurance_path)?,
                disclosure_profile: "internal-review-default".to_string(),
            },
            MercuryDownstreamArtifact {
                role: MercuryDownstreamArtifactRole::ExternalAssurancePackage,
                relative_path: relative_display(output, &external_assurance_path)?,
                disclosure_profile: "external-review-default".to_string(),
            },
            MercuryDownstreamArtifact {
                role: MercuryDownstreamArtifactRole::ReviewerPackage,
                relative_path: relative_display(output, &reviewer_package_path)?,
                disclosure_profile: "review-package".to_string(),
            },
            MercuryDownstreamArtifact {
                role: MercuryDownstreamArtifactRole::QualificationReport,
                relative_path: relative_display(output, &qualification_report_path)?,
                disclosure_profile: "review-package".to_string(),
            },
            MercuryDownstreamArtifact {
                role: MercuryDownstreamArtifactRole::ExternalInquiryPackage,
                relative_path: relative_display(output, &external_inquiry_path)?,
                disclosure_profile: "external-review-default".to_string(),
            },
            MercuryDownstreamArtifact {
                role: MercuryDownstreamArtifactRole::ExternalInquiryVerification,
                relative_path: relative_display(output, &external_inquiry_report_path)?,
                disclosure_profile: "external-review-default".to_string(),
            },
            MercuryDownstreamArtifact {
                role: MercuryDownstreamArtifactRole::ConsumerManifest,
                relative_path: relative_display(output, &consumer_manifest_path)?,
                disclosure_profile: "case-management-intake".to_string(),
            },
            MercuryDownstreamArtifact {
                role: MercuryDownstreamArtifactRole::DeliveryAcknowledgement,
                relative_path: relative_display(output, &acknowledgement_path)?,
                disclosure_profile: "case-management-intake".to_string(),
            },
        ],
    };
    downstream_package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let downstream_package_path = output.join("downstream-review-package.json");
    write_json_file(&downstream_package_path, &downstream_package)?;

    let summary = MercuryDownstreamReviewExportSummary {
        workflow_id: qualification_report.workflow_id,
        consumer_profile: MercuryDownstreamConsumerProfile::CaseManagementReview
            .as_str()
            .to_string(),
        transport: MercuryDownstreamTransport::FileDrop.as_str().to_string(),
        qualification_dir: qualification_dir.display().to_string(),
        internal_assurance_package_file: internal_assurance_path.display().to_string(),
        external_assurance_package_file: external_assurance_path.display().to_string(),
        downstream_review_package_file: downstream_package_path.display().to_string(),
        consumer_manifest_file: consumer_manifest_path.display().to_string(),
        acknowledgement_file: acknowledgement_path.display().to_string(),
        consumer_drop_dir: consumer_drop_dir.display().to_string(),
    };
    write_json_file(&output.join("downstream-review-summary.json"), &summary)?;

    let _ = reviewer_package;

    Ok(summary)
}

fn export_governance_workbench(
    output: &Path,
) -> Result<MercuryGovernanceWorkbenchExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let qualification_dir = output.join("qualification");
    let (qualification_report, reviewer_package) =
        export_supervised_live_qualification(&qualification_dir)?;
    let proof_package_path = qualification_dir.join("supervised-live/proof-package.json");
    let proof_package: MercuryProofPackage = read_json_file(&proof_package_path)?;
    proof_package
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;

    let reviewer_package_path = qualification_dir.join("reviewer-package.json");
    let qualification_report_path = qualification_dir.join("qualification-report.json");
    let decision_package_path = output.join("governance-decision-package.json");

    let review_dir = output.join("governance-reviews");
    let workflow_owner_dir = review_dir.join("workflow-owner");
    let control_team_dir = review_dir.join("control-team");
    fs::create_dir_all(&workflow_owner_dir)?;
    fs::create_dir_all(&control_team_dir)?;

    let workflow_owner_inquiry = build_inquiry_package(
        proof_package.clone(),
        "workflow-owner",
        Some("workflow-owner-default"),
        false,
    )?;
    let workflow_owner_inquiry_report = workflow_owner_inquiry
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;
    let workflow_owner_inquiry_path = workflow_owner_dir.join("inquiry-package.json");
    let workflow_owner_inquiry_report_path = workflow_owner_dir.join("inquiry-verification.json");
    write_json_file(&workflow_owner_inquiry_path, &workflow_owner_inquiry)?;
    write_verification_report(
        &workflow_owner_inquiry_report_path,
        &workflow_owner_inquiry_report,
    )?;

    let control_team_inquiry = build_inquiry_package(
        proof_package,
        "control-team",
        Some("control-team-default"),
        false,
    )?;
    let control_team_inquiry_report = control_team_inquiry
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;
    let control_team_inquiry_path = control_team_dir.join("inquiry-package.json");
    let control_team_inquiry_report_path = control_team_dir.join("inquiry-verification.json");
    write_json_file(&control_team_inquiry_path, &control_team_inquiry)?;
    write_verification_report(
        &control_team_inquiry_report_path,
        &control_team_inquiry_report,
    )?;

    let control_state = MercuryGovernanceControlState {
        approval_gate: MercuryGovernanceGateState::Approved,
        release_gate: MercuryGovernanceGateState::Approved,
        rollback_gate: MercuryGovernanceGateState::Ready,
        exception_gate: MercuryGovernanceGateState::Routed,
        escalation_owner: MERCURY_GOVERNANCE_CONTROL_TEAM_OWNER.to_string(),
    };
    let control_state_path = output.join("governance-control-state.json");
    write_json_file(&control_state_path, &control_state)?;

    let workflow_owner_review = build_governance_review_package(
        &qualification_report.workflow_id,
        MercuryGovernanceReviewAudience::WorkflowOwner,
        "workflow-owner-default",
        &relative_display(output, &proof_package_path)?,
        &relative_display(output, &workflow_owner_inquiry_path)?,
        &relative_display(output, &reviewer_package_path)?,
        &relative_display(output, &qualification_report_path)?,
        &relative_display(output, &decision_package_path)?,
        workflow_owner_inquiry_report.verifier_equivalent,
    )?;
    let workflow_owner_review_path = workflow_owner_dir.join("review-package.json");
    write_json_file(&workflow_owner_review_path, &workflow_owner_review)?;

    let control_team_review = build_governance_review_package(
        &qualification_report.workflow_id,
        MercuryGovernanceReviewAudience::ControlTeam,
        "control-team-default",
        &relative_display(output, &proof_package_path)?,
        &relative_display(output, &control_team_inquiry_path)?,
        &relative_display(output, &reviewer_package_path)?,
        &relative_display(output, &qualification_report_path)?,
        &relative_display(output, &decision_package_path)?,
        control_team_inquiry_report.verifier_equivalent,
    )?;
    let control_team_review_path = control_team_dir.join("review-package.json");
    write_json_file(&control_team_review_path, &control_team_review)?;

    let decision_package = MercuryGovernanceDecisionPackage {
        schema: MERCURY_GOVERNANCE_DECISION_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "governance-change-review-release-control-{}-{}",
            qualification_report.workflow_id,
            current_utc_date()
        ),
        workflow_id: qualification_report.workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        workflow_path: MercuryGovernanceWorkflowPath::ChangeReviewReleaseControl,
        change_classes: vec![
            MercuryGovernanceChangeClass::Model,
            MercuryGovernanceChangeClass::Prompt,
            MercuryGovernanceChangeClass::Policy,
            MercuryGovernanceChangeClass::Parameter,
            MercuryGovernanceChangeClass::Release,
        ],
        workflow_owner: MERCURY_GOVERNANCE_WORKFLOW_OWNER.to_string(),
        control_team_owner: MERCURY_GOVERNANCE_CONTROL_TEAM_OWNER.to_string(),
        fail_closed: true,
        control_state: control_state.clone(),
        workflow_owner_review_package_file: relative_display(output, &workflow_owner_review_path)?,
        control_team_review_package_file: relative_display(output, &control_team_review_path)?,
    };
    decision_package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    write_json_file(&decision_package_path, &decision_package)?;

    let summary = MercuryGovernanceWorkbenchExportSummary {
        workflow_id: qualification_report.workflow_id,
        workflow_path: MercuryGovernanceWorkflowPath::ChangeReviewReleaseControl
            .as_str()
            .to_string(),
        workflow_owner: MERCURY_GOVERNANCE_WORKFLOW_OWNER.to_string(),
        control_team_owner: MERCURY_GOVERNANCE_CONTROL_TEAM_OWNER.to_string(),
        qualification_dir: qualification_dir.display().to_string(),
        control_state,
        control_state_file: control_state_path.display().to_string(),
        governance_decision_package_file: decision_package_path.display().to_string(),
        workflow_owner_review_package_file: workflow_owner_review_path.display().to_string(),
        control_team_review_package_file: control_team_review_path.display().to_string(),
    };
    write_json_file(&output.join("governance-workbench-summary.json"), &summary)?;

    let _ = reviewer_package;

    Ok(summary)
}

fn export_mercury_run(
    run_dir: &Path,
    input_name: &str,
    input_value: &impl Serialize,
    capability_id: &str,
    steps: &[MercuryPilotStep],
    bundle_manifests: &[MercuryBundleManifest],
    inquiry: Option<PilotInquiryConfig<'_>>,
) -> Result<MercuryExportRunPaths, CliError> {
    fs::create_dir_all(run_dir)?;

    let input_file = run_dir.join(input_name);
    let receipt_db = run_dir.join("receipts.sqlite3");
    let evidence_dir = run_dir.join("evidence");
    let bundle_manifest_dir = run_dir.join("bundle-manifests");
    let proof_package_file = run_dir.join("proof-package.json");
    let proof_verification_file = run_dir.join("proof-verification.json");
    let inquiry_package_file = run_dir.join("inquiry-package.json");
    let inquiry_verification_file = run_dir.join("inquiry-verification.json");

    write_json_file(&input_file, input_value)?;
    let bundle_manifest_paths = write_bundle_manifests(&bundle_manifest_dir, bundle_manifests)?;
    populate_mercury_receipt_store(&receipt_db, capability_id, steps)?;
    evidence_export::cmd_evidence_export(
        &evidence_dir,
        None,
        None,
        None,
        None,
        None,
        None,
        true,
        Some(&receipt_db),
        None,
        None,
    )?;

    let proof_package = build_proof_package(&evidence_dir, &bundle_manifest_paths)?;
    let proof_report = proof_package
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;
    write_json_file(&proof_package_file, &proof_package)?;
    write_verification_report(&proof_verification_file, &proof_report)?;

    let (inquiry_package_file, inquiry_verification_file) = if let Some(config) = inquiry {
        let inquiry_package = build_inquiry_package(
            proof_package,
            config.audience,
            config.redaction_profile,
            config.verifier_equivalent,
        )?;
        let inquiry_report = inquiry_package
            .verify(unix_now())
            .map_err(|error| CliError::Other(error.to_string()))?;
        write_json_file(&inquiry_package_file, &inquiry_package)?;
        write_verification_report(&inquiry_verification_file, &inquiry_report)?;
        (
            Some(inquiry_package_file.display().to_string()),
            Some(inquiry_verification_file.display().to_string()),
        )
    } else {
        (None, None)
    };

    Ok(MercuryExportRunPaths {
        input_file: input_file.display().to_string(),
        receipt_db: receipt_db.display().to_string(),
        evidence_dir: evidence_dir.display().to_string(),
        bundle_manifest_files: bundle_manifest_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        proof_package_file: proof_package_file.display().to_string(),
        proof_verification_file: proof_verification_file.display().to_string(),
        inquiry_package_file,
        inquiry_verification_file,
    })
}

fn export_pilot_scenario(
    output: &Path,
    scenario: MercuryPilotScenario,
) -> Result<MercuryPilotExportSummary, CliError> {
    scenario
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let scenario_file = output.join("scenario.json");
    write_json_file(&scenario_file, &scenario)?;

    let primary = MercuryPilotRunPaths::from_export(export_mercury_run(
        &output.join("primary"),
        "events.json",
        &scenario.primary_path,
        "cap-mercury-pilot-primary",
        &scenario.primary_path,
        std::slice::from_ref(&scenario.primary_bundle_manifest),
        Some(PilotInquiryConfig {
            audience: "design-partner",
            redaction_profile: Some("design-partner-default"),
            verifier_equivalent: false,
        }),
    )?)?;
    let rollback = MercuryPilotRunPaths::from_export(export_mercury_run(
        &output.join("rollback"),
        "events.json",
        &scenario.rollback_variant,
        "cap-mercury-pilot-rollback",
        &scenario.rollback_variant,
        std::slice::from_ref(&scenario.rollback_bundle_manifest),
        None,
    )?)?;

    let summary = MercuryPilotExportSummary {
        scenario_id: scenario.scenario_id,
        workflow_id: scenario.workflow_id,
        scenario_file: scenario_file.display().to_string(),
        primary_receipt_count: scenario.primary_path.len(),
        rollback_receipt_count: scenario.rollback_variant.len(),
        primary,
        rollback,
    };
    write_json_file(&output.join("pilot-summary.json"), &summary)?;
    Ok(summary)
}

fn export_supervised_live_capture(
    output: &Path,
    capture: MercurySupervisedLiveCapture,
) -> Result<MercurySupervisedLiveExportSummary, CliError> {
    capture
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    capture
        .ensure_export_ready()
        .map_err(|error| CliError::Other(error.to_string()))?;

    let inquiry = capture.inquiry.as_ref().map(|config| PilotInquiryConfig {
        audience: config.audience.as_str(),
        redaction_profile: config.redaction_profile.as_deref(),
        verifier_equivalent: config.verifier_equivalent,
    });
    let export = export_mercury_run(
        output,
        "capture.json",
        &capture,
        &format!("cap-{}", capture.capture_id),
        &capture.steps,
        &capture.bundle_manifests,
        inquiry,
    )?;

    let summary = MercurySupervisedLiveExportSummary {
        capture_id: capture.capture_id,
        workflow_id: capture.workflow_id,
        mode: capture.mode.as_str().to_string(),
        receipt_count: capture.steps.len(),
        control_state: capture.control_state,
        export,
    };
    write_json_file(&output.join("supervised-live-summary.json"), &summary)?;
    Ok(summary)
}

pub fn cmd_mercury_proof_export(
    input: &Path,
    output: &Path,
    bundle_manifest_paths: &[PathBuf],
    json_output: bool,
) -> Result<(), CliError> {
    let package = build_proof_package(input, bundle_manifest_paths)?;
    package
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;
    write_json_file(output, &package)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&package)?);
    } else {
        println!("mercury proof package exported");
        println!("output:              {}", output.display());
        println!("package_id:          {}", package.package_id);
        println!("workflow_id:         {}", package.workflow_id);
        println!("receipt_count:       {}", package.receipt_records.len());
        println!("bundle_manifests:    {}", package.bundle_manifests.len());
    }

    Ok(())
}

pub fn cmd_mercury_inquiry_export(
    input: &Path,
    output: &Path,
    audience: &str,
    redaction_profile: Option<&str>,
    verifier_equivalent: bool,
    json_output: bool,
) -> Result<(), CliError> {
    let proof_package: MercuryProofPackage = read_json_file(input)?;
    proof_package
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package = build_inquiry_package(
        proof_package,
        audience,
        redaction_profile,
        verifier_equivalent,
    )?;
    package
        .verify(unix_now())
        .map_err(|error| CliError::Other(error.to_string()))?;
    write_json_file(output, &package)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&package)?);
    } else {
        println!("mercury inquiry package exported");
        println!("output:              {}", output.display());
        println!("inquiry_id:          {}", package.inquiry_id);
        println!("workflow_id:         {}", package.proof_package.workflow_id);
        println!("audience:            {}", package.audience);
        println!("verifier_equivalent: {}", package.verifier_equivalent);
    }

    Ok(())
}

pub fn cmd_mercury_verify(input: &Path, json_output: bool, explain: bool) -> Result<(), CliError> {
    let value: serde_json::Value = read_json_file(input)?;
    let schema = value
        .get("schema")
        .and_then(|schema| schema.as_str())
        .ok_or_else(|| CliError::Other("mercury package is missing schema".to_string()))?;
    let report = match schema {
        MERCURY_PROOF_PACKAGE_SCHEMA => {
            let package: MercuryProofPackage = serde_json::from_value(value)?;
            package
                .verify(unix_now())
                .map_err(|error| CliError::Other(error.to_string()))?
        }
        MERCURY_INQUIRY_PACKAGE_SCHEMA => {
            let package: MercuryInquiryPackage = serde_json::from_value(value)?;
            package
                .verify(unix_now())
                .map_err(|error| CliError::Other(error.to_string()))?
        }
        _ => {
            return Err(CliError::Other(format!(
                "unsupported mercury package schema: {schema}"
            )))
        }
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        let package_kind = match report.package_kind {
            MercuryPackageKind::Proof => "proof",
            MercuryPackageKind::Inquiry => "inquiry",
        };
        println!("mercury {package_kind} package verified");
        println!("package_id:          {}", report.package_id);
        println!("workflow_id:         {}", report.workflow_id);
        println!("receipt_count:       {}", report.receipt_count);
        println!("verifier_equivalent: {}", report.verifier_equivalent);
        if explain {
            println!("steps:");
            for step in &report.steps {
                println!("  - {}: {}", step.name, step.detail);
            }
        }
    }

    Ok(())
}

pub fn cmd_mercury_pilot_export(output: &Path, json_output: bool) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let summary = export_pilot_scenario(output, MercuryPilotScenario::gold_release_control())?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury pilot corpus exported");
        println!("output:              {}", output.display());
        println!("scenario_id:         {}", summary.scenario_id);
        println!("workflow_id:         {}", summary.workflow_id);
        println!("primary_receipts:    {}", summary.primary_receipt_count);
        println!("rollback_receipts:   {}", summary.rollback_receipt_count);
        println!(
            "primary_proof:       {}",
            summary.primary.proof_package_file
        );
        if let Some(inquiry_package_file) = summary.primary.inquiry_package_file.as_deref() {
            println!("primary_inquiry:     {}", inquiry_package_file);
        }
        println!(
            "rollback_proof:      {}",
            summary.rollback.proof_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_supervised_live_export(
    input: &Path,
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let capture: MercurySupervisedLiveCapture = read_json_file(input)?;
    let summary = export_supervised_live_capture(output, capture)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury supervised-live capture exported");
        println!("output:              {}", output.display());
        println!("capture_id:          {}", summary.capture_id);
        println!("workflow_id:         {}", summary.workflow_id);
        println!("mode:                {}", summary.mode);
        println!("receipt_count:       {}", summary.receipt_count);
        println!(
            "coverage_state:      {}",
            summary.control_state.coverage_state.as_str()
        );
        println!(
            "release_gate:        {}",
            summary.control_state.release_gate.state.as_str()
        );
        println!(
            "rollback_gate:       {}",
            summary.control_state.rollback_gate.state.as_str()
        );
        println!("proof_package:       {}", summary.export.proof_package_file);
        if let Some(inquiry_package_file) = summary.export.inquiry_package_file.as_deref() {
            println!("inquiry_package:     {}", inquiry_package_file);
        }
    }

    Ok(())
}

pub fn cmd_mercury_supervised_live_qualify(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let (_, reviewer_package) = export_supervised_live_qualification(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&reviewer_package)?);
    } else {
        println!("mercury supervised-live qualification package exported");
        println!("output:                     {}", output.display());
        println!(
            "workflow_id:                {}",
            reviewer_package.workflow_id
        );
        println!("decision:                   {}", reviewer_package.decision);
        println!(
            "qualification_report:       {}",
            reviewer_package.qualification_report_file
        );
        println!(
            "reviewer_package:           {}",
            output.join("reviewer-package.json").display()
        );
        println!(
            "supervised_live_proof:      {}",
            reviewer_package.supervised_live_proof_package_file
        );
        println!(
            "rollback_proof:             {}",
            reviewer_package.rollback_proof_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_downstream_review_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_downstream_review(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury downstream-review package exported");
        println!("output:                     {}", output.display());
        println!("workflow_id:                {}", summary.workflow_id);
        println!("consumer_profile:           {}", summary.consumer_profile);
        println!("transport:                  {}", summary.transport);
        println!(
            "internal_assurance:         {}",
            summary.internal_assurance_package_file
        );
        println!(
            "external_assurance:         {}",
            summary.external_assurance_package_file
        );
        println!(
            "downstream_review_package:  {}",
            summary.downstream_review_package_file
        );
        println!(
            "consumer_manifest:          {}",
            summary.consumer_manifest_file
        );
        println!(
            "acknowledgement:            {}",
            summary.acknowledgement_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_downstream_review_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let downstream_review_dir = output.join("downstream-review");
    let summary = export_downstream_review(&downstream_review_dir)?;
    let docs = downstream_review_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryDownstreamReviewDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_DOWNSTREAM_DECISION.to_string(),
        selected_consumer_profile: summary.consumer_profile.clone(),
        approved_scope:
            "Proceed with the bounded case-management review consumer path only."
                .to_string(),
        deferred_scope: vec![
            "additional archive connectors".to_string(),
            "surveillance connectors".to_string(),
            "governance workbench breadth".to_string(),
            "OMS/EMS or FIX coupling".to_string(),
            "OEM packaging and trust-network work".to_string(),
        ],
        rationale: "The downstream review package now strengthens buyer review flows without widening MERCURY into multi-consumer sprawl or deep runtime coupling."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryDownstreamReviewValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_DOWNSTREAM_DECISION.to_string(),
        consumer_profile: summary.consumer_profile.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        downstream_review: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury downstream-review validation package exported");
        println!("output:                     {}", output.display());
        println!("workflow_id:                {}", report.workflow_id);
        println!("decision:                   {}", report.decision);
        println!("consumer_profile:           {}", report.consumer_profile);
        println!(
            "validation_report:          {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:            {}",
            decision_record_file.display()
        );
        println!(
            "downstream_review_package:  {}",
            report.downstream_review.downstream_review_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_governance_workbench_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_governance_workbench(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury governance-workbench package exported");
        println!("output:                     {}", output.display());
        println!("workflow_id:                {}", summary.workflow_id);
        println!("workflow_path:              {}", summary.workflow_path);
        println!("workflow_owner:             {}", summary.workflow_owner);
        println!("control_team_owner:         {}", summary.control_team_owner);
        println!(
            "governance_decision:        {}",
            summary.governance_decision_package_file
        );
        println!(
            "workflow_owner_review:      {}",
            summary.workflow_owner_review_package_file
        );
        println!(
            "control_team_review:        {}",
            summary.control_team_review_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_governance_workbench_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let governance_dir = output.join("governance-workbench");
    let summary = export_governance_workbench(&governance_dir)?;
    let docs = governance_workbench_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryGovernanceWorkbenchDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_GOVERNANCE_DECISION.to_string(),
        selected_workflow_path: summary.workflow_path.clone(),
        approved_scope:
            "Proceed with the bounded governance workbench change-review path only."
                .to_string(),
        deferred_scope: vec![
            "additional governance workflow breadth".to_string(),
            "additional downstream consumer connectors".to_string(),
            "OMS/EMS or FIX coupling".to_string(),
            "OEM packaging and trust-network work".to_string(),
            "generic workflow orchestration".to_string(),
        ],
        rationale: "The governance workbench package now deepens buyer review and control workflows without widening MERCURY into generic orchestration, connector sprawl, or deep runtime coupling."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryGovernanceWorkbenchValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_GOVERNANCE_DECISION.to_string(),
        workflow_path: summary.workflow_path.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        governance_workbench: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury governance-workbench validation package exported");
        println!("output:                     {}", output.display());
        println!("workflow_id:                {}", report.workflow_id);
        println!("decision:                   {}", report.decision);
        println!("workflow_path:              {}", report.workflow_path);
        println!(
            "validation_report:          {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:            {}",
            decision_record_file.display()
        );
        println!(
            "governance_decision:        {}",
            report.governance_workbench.governance_decision_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_assurance_suite_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_assurance_suite(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury assurance-suite package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", summary.workflow_id);
        println!("reviewer_owner:                {}", summary.reviewer_owner);
        println!("support_owner:                 {}", summary.support_owner);
        println!(
            "assurance_suite_package:       {}",
            summary.assurance_suite_package_file
        );
        println!(
            "internal_review_package:       {}",
            summary.internal_review_package_file
        );
        println!(
            "auditor_review_package:        {}",
            summary.auditor_review_package_file
        );
        println!(
            "counterparty_review_package:   {}",
            summary.counterparty_review_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_assurance_suite_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let assurance_dir = output.join("assurance-suite");
    let summary = export_assurance_suite(&assurance_dir)?;
    let docs = assurance_suite_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryAssuranceSuiteDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_ASSURANCE_DECISION.to_string(),
        selected_reviewer_populations: summary.reviewer_populations.clone(),
        approved_scope:
            "Proceed with the bounded assurance-suite reviewer populations only."
                .to_string(),
        deferred_scope: vec![
            "additional reviewer populations".to_string(),
            "generic review portal or case-management product breadth".to_string(),
            "additional downstream or governance workflow lanes".to_string(),
            "OMS/EMS or FIX coupling".to_string(),
            "OEM packaging and trust-network work".to_string(),
        ],
        rationale: "The assurance suite now packages internal, auditor, and counterparty review over the same Mercury proof chain without widening Mercury into a generic portal, connector sprawl, or embedded platform."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryAssuranceSuiteValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_ASSURANCE_DECISION.to_string(),
        reviewer_owner: summary.reviewer_owner.clone(),
        support_owner: summary.support_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        assurance_suite: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury assurance-suite validation package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", report.workflow_id);
        println!("decision:                      {}", report.decision);
        println!("reviewer_owner:                {}", report.reviewer_owner);
        println!("support_owner:                 {}", report.support_owner);
        println!(
            "validation_report:             {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:               {}",
            decision_record_file.display()
        );
        println!(
            "assurance_suite_package:       {}",
            report.assurance_suite.assurance_suite_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_embedded_oem_export(output: &Path, json_output: bool) -> Result<(), CliError> {
    let summary = export_embedded_oem(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury embedded-oem package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", summary.workflow_id);
        println!("partner_surface:               {}", summary.partner_surface);
        println!("sdk_surface:                   {}", summary.sdk_surface);
        println!(
            "reviewer_population:           {}",
            summary.reviewer_population
        );
        println!("partner_owner:                 {}", summary.partner_owner);
        println!("support_owner:                 {}", summary.support_owner);
        println!(
            "embedded_oem_package:          {}",
            summary.embedded_oem_package_file
        );
        println!(
            "partner_sdk_manifest:          {}",
            summary.partner_sdk_manifest_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_embedded_oem_validate(output: &Path, json_output: bool) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let embedded_oem_dir = output.join("embedded-oem");
    let summary = export_embedded_oem(&embedded_oem_dir)?;
    let docs = embedded_oem_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryEmbeddedOemDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_EMBEDDED_OEM_DECISION.to_string(),
        selected_partner_surface: summary.partner_surface.clone(),
        selected_sdk_surface: summary.sdk_surface.clone(),
        selected_reviewer_population: summary.reviewer_population.clone(),
        approved_scope:
            "Proceed with the bounded reviewer-workbench embedded OEM path only."
                .to_string(),
        deferred_scope: vec![
            "additional partner surfaces".to_string(),
            "multi-partner OEM breadth".to_string(),
            "generic SDK platform or multi-language client breadth".to_string(),
            "trust-network services".to_string(),
            "ARC-Wall and companion-product work".to_string(),
        ],
        rationale: "The embedded OEM bundle now packages one counterparty-review Mercury surface for one partner workbench without widening Mercury into a generic SDK platform, multi-partner OEM program, or separate trust service."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryEmbeddedOemValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_EMBEDDED_OEM_DECISION.to_string(),
        partner_surface: summary.partner_surface.clone(),
        sdk_surface: summary.sdk_surface.clone(),
        reviewer_population: summary.reviewer_population.clone(),
        partner_owner: summary.partner_owner.clone(),
        support_owner: summary.support_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        embedded_oem: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury embedded-oem validation package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", report.workflow_id);
        println!("decision:                      {}", report.decision);
        println!("partner_surface:               {}", report.partner_surface);
        println!("sdk_surface:                   {}", report.sdk_surface);
        println!(
            "reviewer_population:           {}",
            report.reviewer_population
        );
        println!(
            "validation_report:             {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:               {}",
            decision_record_file.display()
        );
        println!(
            "embedded_oem_package:          {}",
            report.embedded_oem.embedded_oem_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_trust_network_export(output: &Path, json_output: bool) -> Result<(), CliError> {
    let summary = export_trust_network(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury trust-network package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", summary.workflow_id);
        println!(
            "sponsor_boundary:              {}",
            summary.sponsor_boundary
        );
        println!("trust_anchor:                  {}", summary.trust_anchor);
        println!("interop_surface:               {}", summary.interop_surface);
        println!(
            "reviewer_population:           {}",
            summary.reviewer_population
        );
        println!(
            "trust_network_package:         {}",
            summary.trust_network_package_file
        );
        println!(
            "interop_manifest:              {}",
            summary.interop_manifest_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_trust_network_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let trust_network_dir = output.join("trust-network");
    let summary = export_trust_network(&trust_network_dir)?;
    let docs = trust_network_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryTrustNetworkDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_TRUST_NETWORK_DECISION.to_string(),
        selected_sponsor_boundary: summary.sponsor_boundary.clone(),
        selected_trust_anchor: summary.trust_anchor.clone(),
        selected_interop_surface: summary.interop_surface.clone(),
        selected_reviewer_population: summary.reviewer_population.clone(),
        approved_scope:
            "Proceed with the bounded counterparty-review trust-network path only."
                .to_string(),
        deferred_scope: vec![
            "additional trust-network sponsor boundaries".to_string(),
            "multi-network witness or trust-broker services".to_string(),
            "generic ecosystem interoperability infrastructure".to_string(),
            "ARC-Wall companion-product work".to_string(),
            "multi-product platform hardening".to_string(),
        ],
        rationale: "The trust-network lane now shares one bounded counterparty-review proof and inquiry bundle over one checkpoint-backed witness chain without widening Mercury into a generic trust broker, ecosystem network, or companion-product platform."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryTrustNetworkValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_TRUST_NETWORK_DECISION.to_string(),
        sponsor_boundary: summary.sponsor_boundary.clone(),
        trust_anchor: summary.trust_anchor.clone(),
        interop_surface: summary.interop_surface.clone(),
        reviewer_population: summary.reviewer_population.clone(),
        sponsor_owner: summary.sponsor_owner.clone(),
        support_owner: summary.support_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        trust_network: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury trust-network validation package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", report.workflow_id);
        println!("decision:                      {}", report.decision);
        println!("sponsor_boundary:              {}", report.sponsor_boundary);
        println!("trust_anchor:                  {}", report.trust_anchor);
        println!("interop_surface:               {}", report.interop_surface);
        println!(
            "reviewer_population:           {}",
            report.reviewer_population
        );
        println!(
            "validation_report:             {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:               {}",
            decision_record_file.display()
        );
        println!(
            "trust_network_package:         {}",
            report.trust_network.trust_network_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_release_readiness_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_release_readiness(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury release-readiness package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", summary.workflow_id);
        println!(
            "delivery_surface:              {}",
            summary.delivery_surface
        );
        println!(
            "audiences:                     {}",
            summary.audiences.join(", ")
        );
        println!("release_owner:                 {}", summary.release_owner);
        println!("partner_owner:                 {}", summary.partner_owner);
        println!("support_owner:                 {}", summary.support_owner);
        println!(
            "release_readiness_package:     {}",
            summary.release_readiness_package_file
        );
        println!(
            "partner_delivery_manifest:     {}",
            summary.partner_delivery_manifest_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_release_readiness_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let release_readiness_dir = output.join("release-readiness");
    let summary = export_release_readiness(&release_readiness_dir)?;
    let docs = release_readiness_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryReleaseReadinessDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_RELEASE_READINESS_DECISION.to_string(),
        selected_delivery_surface: summary.delivery_surface.clone(),
        selected_audiences: summary.audiences.clone(),
        approved_scope: "Launch one bounded Mercury release-readiness lane only.".to_string(),
        deferred_scope: vec![
            "additional partner-delivery surfaces".to_string(),
            "generic ARC release console or merged shell".to_string(),
            "new Mercury product-line claims".to_string(),
            "additional trust-network sponsor breadth".to_string(),
            "ARC-Wall or cross-product packaging unification".to_string(),
        ],
        rationale: "The release-readiness lane now packages one Mercury reviewer, partner, and operator path over the validated proof, inquiry, assurance, and trust-network stack without widening ARC or creating a new product line."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryReleaseReadinessValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_RELEASE_READINESS_DECISION.to_string(),
        audiences: summary.audiences.clone(),
        delivery_surface: summary.delivery_surface.clone(),
        release_owner: summary.release_owner.clone(),
        partner_owner: summary.partner_owner.clone(),
        support_owner: summary.support_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        release_readiness: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury release-readiness validation package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", report.workflow_id);
        println!("decision:                      {}", report.decision);
        println!("delivery_surface:              {}", report.delivery_surface);
        println!(
            "audiences:                     {}",
            report.audiences.join(", ")
        );
        println!("release_owner:                 {}", report.release_owner);
        println!("partner_owner:                 {}", report.partner_owner);
        println!("support_owner:                 {}", report.support_owner);
        println!(
            "validation_report:             {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:               {}",
            decision_record_file.display()
        );
        println!(
            "release_readiness_package:     {}",
            report.release_readiness.release_readiness_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_controlled_adoption_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_controlled_adoption(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury controlled-adoption package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", summary.workflow_id);
        println!("cohort:                        {}", summary.cohort);
        println!(
            "adoption_surface:              {}",
            summary.adoption_surface
        );
        println!(
            "customer_success_owner:        {}",
            summary.customer_success_owner
        );
        println!("reference_owner:               {}", summary.reference_owner);
        println!("support_owner:                 {}", summary.support_owner);
        println!(
            "controlled_adoption_package:   {}",
            summary.controlled_adoption_package_file
        );
        println!(
            "renewal_evidence_manifest:     {}",
            summary.renewal_evidence_manifest_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_controlled_adoption_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let controlled_adoption_dir = output.join("controlled-adoption");
    let summary = export_controlled_adoption(&controlled_adoption_dir)?;
    let docs = controlled_adoption_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryControlledAdoptionDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_CONTROLLED_ADOPTION_DECISION.to_string(),
        selected_cohort: summary.cohort.clone(),
        selected_adoption_surface: summary.adoption_surface.clone(),
        approved_scope: "Scale one bounded Mercury controlled-adoption lane only.".to_string(),
        deferred_scope: vec![
            "additional adoption cohorts".to_string(),
            "broader Mercury product lines or delivery surfaces".to_string(),
            "generic ARC renewal tooling or release consoles".to_string(),
            "merged Mercury and ARC-Wall packaging".to_string(),
            "new cross-product runtime coupling".to_string(),
        ],
        rationale: "The controlled-adoption lane now packages one design-partner renewal and reference path over the validated Mercury release-readiness stack without widening Mercury into a new product surface or polluting ARC generic crates."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryControlledAdoptionValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_CONTROLLED_ADOPTION_DECISION.to_string(),
        cohort: summary.cohort.clone(),
        adoption_surface: summary.adoption_surface.clone(),
        customer_success_owner: summary.customer_success_owner.clone(),
        reference_owner: summary.reference_owner.clone(),
        support_owner: summary.support_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        controlled_adoption: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury controlled-adoption validation package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", report.workflow_id);
        println!("decision:                      {}", report.decision);
        println!("cohort:                        {}", report.cohort);
        println!("adoption_surface:              {}", report.adoption_surface);
        println!(
            "customer_success_owner:        {}",
            report.customer_success_owner
        );
        println!("reference_owner:               {}", report.reference_owner);
        println!("support_owner:                 {}", report.support_owner);
        println!(
            "validation_report:             {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:               {}",
            decision_record_file.display()
        );
        println!(
            "controlled_adoption_package:   {}",
            report.controlled_adoption.controlled_adoption_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_reference_distribution_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_reference_distribution(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury reference-distribution package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", summary.workflow_id);
        println!(
            "expansion_motion:              {}",
            summary.expansion_motion
        );
        println!(
            "distribution_surface:          {}",
            summary.distribution_surface
        );
        println!("reference_owner:               {}", summary.reference_owner);
        println!(
            "buyer_approval_owner:          {}",
            summary.buyer_approval_owner
        );
        println!("sales_owner:                   {}", summary.sales_owner);
        println!(
            "reference_distribution_package: {}",
            summary.reference_distribution_package_file
        );
        println!(
            "buyer_reference_approval:      {}",
            summary.buyer_reference_approval_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_reference_distribution_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let reference_distribution_dir = output.join("reference-distribution");
    let summary = export_reference_distribution(&reference_distribution_dir)?;
    let docs = reference_distribution_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryReferenceDistributionDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_REFERENCE_DISTRIBUTION_DECISION.to_string(),
        selected_expansion_motion: summary.expansion_motion.clone(),
        selected_distribution_surface: summary.distribution_surface.clone(),
        approved_scope:
            "Proceed with one bounded Mercury reference-distribution lane only.".to_string(),
        deferred_scope: vec![
            "additional landed-account motions".to_string(),
            "generic sales tooling, CRM workflows, or commercial consoles".to_string(),
            "merged Mercury and ARC-Wall commercial packaging".to_string(),
            "ARC-side commercial control surfaces".to_string(),
            "broader product-family or universal rollout claims".to_string(),
        ],
        rationale: "The reference-distribution lane now packages one approved landed-account expansion motion over the validated controlled-adoption stack without widening Mercury into a generic sales platform or polluting ARC's generic substrate."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("expansion-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryReferenceDistributionValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_REFERENCE_DISTRIBUTION_DECISION.to_string(),
        expansion_motion: summary.expansion_motion.clone(),
        distribution_surface: summary.distribution_surface.clone(),
        reference_owner: summary.reference_owner.clone(),
        buyer_approval_owner: summary.buyer_approval_owner.clone(),
        sales_owner: summary.sales_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        reference_distribution: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury reference-distribution validation package exported");
        println!("output:                        {}", output.display());
        println!("workflow_id:                   {}", report.workflow_id);
        println!("decision:                      {}", report.decision);
        println!("expansion_motion:              {}", report.expansion_motion);
        println!(
            "distribution_surface:          {}",
            report.distribution_surface
        );
        println!("reference_owner:               {}", report.reference_owner);
        println!(
            "buyer_approval_owner:          {}",
            report.buyer_approval_owner
        );
        println!("sales_owner:                   {}", report.sales_owner);
        println!(
            "validation_report:             {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:               {}",
            decision_record_file.display()
        );
        println!(
            "reference_distribution_package: {}",
            report
                .reference_distribution
                .reference_distribution_package_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_broader_distribution_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_broader_distribution(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury broader-distribution package exported");
        println!("output:                         {}", output.display());
        println!("workflow_id:                    {}", summary.workflow_id);
        println!(
            "distribution_motion:            {}",
            summary.distribution_motion
        );
        println!(
            "distribution_surface:           {}",
            summary.distribution_surface
        );
        println!(
            "qualification_owner:            {}",
            summary.qualification_owner
        );
        println!("approval_owner:                 {}", summary.approval_owner);
        println!(
            "distribution_owner:             {}",
            summary.distribution_owner
        );
        println!(
            "broader_distribution_package:   {}",
            summary.broader_distribution_package_file
        );
        println!(
            "selective_account_approval:     {}",
            summary.selective_account_approval_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_broader_distribution_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let broader_distribution_dir = output.join("broader-distribution");
    let summary = export_broader_distribution(&broader_distribution_dir)?;
    let docs = broader_distribution_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryBroaderDistributionDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_BROADER_DISTRIBUTION_DECISION.to_string(),
        selected_distribution_motion: summary.distribution_motion.clone(),
        selected_distribution_surface: summary.distribution_surface.clone(),
        approved_scope:
            "Proceed with one bounded Mercury broader-distribution lane only.".to_string(),
        deferred_scope: vec![
            "additional broader-distribution motions or surfaces".to_string(),
            "generic sales tooling, CRM workflows, or commercial consoles".to_string(),
            "multi-segment channel programs or partner marketplaces".to_string(),
            "merged Mercury and ARC-Wall commercial packaging".to_string(),
            "ARC-side commercial control surfaces".to_string(),
        ],
        rationale: "The broader-distribution lane now packages one governed selective-account qualification motion over the validated reference-distribution stack without widening Mercury into a generic commercial platform or polluting ARC's generic substrate."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("broader-distribution-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryBroaderDistributionValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_BROADER_DISTRIBUTION_DECISION.to_string(),
        distribution_motion: summary.distribution_motion.clone(),
        distribution_surface: summary.distribution_surface.clone(),
        qualification_owner: summary.qualification_owner.clone(),
        approval_owner: summary.approval_owner.clone(),
        distribution_owner: summary.distribution_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        broader_distribution: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury broader-distribution validation package exported");
        println!("output:                         {}", output.display());
        println!("workflow_id:                    {}", report.workflow_id);
        println!("decision:                       {}", report.decision);
        println!(
            "distribution_motion:            {}",
            report.distribution_motion
        );
        println!(
            "distribution_surface:           {}",
            report.distribution_surface
        );
        println!(
            "qualification_owner:            {}",
            report.qualification_owner
        );
        println!("approval_owner:                 {}", report.approval_owner);
        println!(
            "distribution_owner:             {}",
            report.distribution_owner
        );
        println!(
            "validation_report:              {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:                {}",
            decision_record_file.display()
        );
        println!(
            "broader_distribution_package:   {}",
            report
                .broader_distribution
                .broader_distribution_package_file
        );
    }

    Ok(())
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySelectiveAccountActivationDocRefs {
    selective_account_activation_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySelectiveAccountActivationScopeFreeze {
    schema: String,
    workflow_id: String,
    activation_motion: String,
    delivery_surface: String,
    target_account_label: String,
    entry_gates: Vec<String>,
    non_goals: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySelectiveAccountActivationManifest {
    schema: String,
    workflow_id: String,
    activation_motion: String,
    delivery_surface: String,
    broader_distribution_package_file: String,
    target_account_freeze_file: String,
    broader_distribution_manifest_file: String,
    claim_governance_rules_file: String,
    selective_account_approval_file: String,
    distribution_handoff_brief_file: String,
    reference_distribution_package_file: String,
    controlled_adoption_package_file: String,
    release_readiness_package_file: String,
    trust_network_package_file: String,
    assurance_suite_package_file: String,
    proof_package_file: String,
    inquiry_package_file: String,
    inquiry_verification_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySelectiveAccountActivationClaimContainmentRules {
    schema: String,
    workflow_id: String,
    activation_owner: String,
    approval_owner: String,
    fail_closed: bool,
    approved_claims: Vec<String>,
    prohibited_claims: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySelectiveAccountActivationApprovalRefresh {
    schema: String,
    workflow_id: String,
    approval_owner: String,
    status: String,
    refreshed_at: u64,
    refreshed_by: String,
    approved_claims: Vec<String>,
    required_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySelectiveAccountActivationCustomerHandoffBrief {
    schema: String,
    workflow_id: String,
    delivery_owner: String,
    activation_owner: String,
    approval_owner: String,
    activation_motion: String,
    delivery_surface: String,
    approved_scope: String,
    entry_criteria: Vec<String>,
    escalation_triggers: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySelectiveAccountActivationExportSummary {
    workflow_id: String,
    activation_motion: String,
    delivery_surface: String,
    activation_owner: String,
    approval_owner: String,
    delivery_owner: String,
    broader_distribution_dir: String,
    selective_account_activation_profile_file: String,
    selective_account_activation_package_file: String,
    activation_scope_freeze_file: String,
    selective_account_activation_manifest_file: String,
    claim_containment_rules_file: String,
    activation_approval_refresh_file: String,
    customer_handoff_brief_file: String,
    activation_evidence_dir: String,
    broader_distribution_package_file: String,
    target_account_freeze_file: String,
    broader_distribution_manifest_file: String,
    claim_governance_rules_file: String,
    selective_account_approval_file: String,
    distribution_handoff_brief_file: String,
    reference_distribution_package_file: String,
    controlled_adoption_package_file: String,
    release_readiness_package_file: String,
    trust_network_package_file: String,
    assurance_suite_package_file: String,
    proof_package_file: String,
    inquiry_package_file: String,
    inquiry_verification_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySelectiveAccountActivationDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_activation_motion: String,
    selected_delivery_surface: String,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercurySelectiveAccountActivationValidationReport {
    workflow_id: String,
    decision: String,
    activation_motion: String,
    delivery_surface: String,
    activation_owner: String,
    approval_owner: String,
    delivery_owner: String,
    same_workflow_boundary: String,
    selective_account_activation: MercurySelectiveAccountActivationExportSummary,
    decision_record_file: String,
    docs: MercurySelectiveAccountActivationDocRefs,
}

fn selective_account_activation_doc_refs() -> MercurySelectiveAccountActivationDocRefs {
    MercurySelectiveAccountActivationDocRefs {
        selective_account_activation_file: "docs/mercury/SELECTIVE_ACCOUNT_ACTIVATION.md"
            .to_string(),
        operations_file: "docs/mercury/SELECTIVE_ACCOUNT_ACTIVATION_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/SELECTIVE_ACCOUNT_ACTIVATION_VALIDATION_PACKAGE.md"
            .to_string(),
        decision_record_file: "docs/mercury/SELECTIVE_ACCOUNT_ACTIVATION_DECISION_RECORD.md"
            .to_string(),
    }
}

fn build_selective_account_activation_profile(
    workflow_id: &str,
) -> Result<MercurySelectiveAccountActivationProfile, CliError> {
    let profile = MercurySelectiveAccountActivationProfile {
        schema: MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "selective-account-activation-controlled-delivery-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        activation_motion: MercurySelectiveAccountActivationMotion::SelectiveAccountActivation,
        delivery_surface: MercurySelectiveAccountActivationSurface::ControlledDeliveryBundle,
        claim_containment: "controlled-delivery-evidence-only".to_string(),
        retained_artifact_policy:
            "retain-bounded-selective-account-activation-and-controlled-delivery-artifacts"
                .to_string(),
        intended_use: "Activate one bounded Mercury selective-account lane over the validated broader-distribution package without widening into generic onboarding tooling, CRM workflows, channel marketplaces, merged shells, or ARC commercial surfaces."
            .to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}

fn export_selective_account_activation(
    output: &Path,
) -> Result<MercurySelectiveAccountActivationExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let broader_distribution_dir = output.join("broader-distribution");
    let broader_distribution = export_broader_distribution(&broader_distribution_dir)?;
    let workflow_id = broader_distribution.workflow_id.clone();

    let profile = build_selective_account_activation_profile(&workflow_id)?;
    let profile_path = output.join("selective-account-activation-profile.json");
    write_json_file(&profile_path, &profile)?;

    let activation_evidence_dir = output.join("activation-evidence");
    fs::create_dir_all(&activation_evidence_dir)?;

    let broader_distribution_package_path =
        activation_evidence_dir.join("broader-distribution-package.json");
    let target_account_freeze_path = activation_evidence_dir.join("target-account-freeze.json");
    let broader_distribution_manifest_path =
        activation_evidence_dir.join("broader-distribution-manifest.json");
    let claim_governance_rules_path = activation_evidence_dir.join("claim-governance-rules.json");
    let selective_account_approval_path =
        activation_evidence_dir.join("selective-account-approval.json");
    let distribution_handoff_brief_path =
        activation_evidence_dir.join("distribution-handoff-brief.json");
    let reference_distribution_package_path =
        activation_evidence_dir.join("reference-distribution-package.json");
    let controlled_adoption_package_path =
        activation_evidence_dir.join("controlled-adoption-package.json");
    let release_readiness_package_path =
        activation_evidence_dir.join("release-readiness-package.json");
    let trust_network_package_path = activation_evidence_dir.join("trust-network-package.json");
    let assurance_suite_package_path = activation_evidence_dir.join("assurance-suite-package.json");
    let proof_package_path = activation_evidence_dir.join("proof-package.json");
    let inquiry_package_path = activation_evidence_dir.join("inquiry-package.json");
    let inquiry_verification_path = activation_evidence_dir.join("inquiry-verification.json");
    let reviewer_package_path = activation_evidence_dir.join("reviewer-package.json");
    let qualification_report_path = activation_evidence_dir.join("qualification-report.json");

    copy_file(
        Path::new(&broader_distribution.broader_distribution_package_file),
        &broader_distribution_package_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.target_account_freeze_file),
        &target_account_freeze_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.broader_distribution_manifest_file),
        &broader_distribution_manifest_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.claim_governance_rules_file),
        &claim_governance_rules_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.selective_account_approval_file),
        &selective_account_approval_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.distribution_handoff_brief_file),
        &distribution_handoff_brief_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.reference_distribution_package_file),
        &reference_distribution_package_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.controlled_adoption_package_file),
        &controlled_adoption_package_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.release_readiness_package_file),
        &release_readiness_package_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.trust_network_package_file),
        &trust_network_package_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.assurance_suite_package_file),
        &assurance_suite_package_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.proof_package_file),
        &proof_package_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.inquiry_package_file),
        &inquiry_package_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.inquiry_verification_file),
        &inquiry_verification_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.reviewer_package_file),
        &reviewer_package_path,
    )?;
    copy_file(
        Path::new(&broader_distribution.qualification_report_file),
        &qualification_report_path,
    )?;

    let approved_claim = "Mercury can activate one previously qualified account using one controlled delivery bundle rooted in the validated broader-distribution, reference-distribution, controlled-adoption, release-readiness, trust-network, assurance, proof, and inquiry stack."
        .to_string();

    let activation_scope_freeze = MercurySelectiveAccountActivationScopeFreeze {
        schema: "arc.mercury.selective_account_activation_scope_freeze.v1".to_string(),
        workflow_id: workflow_id.clone(),
        activation_motion: MercurySelectiveAccountActivationMotion::SelectiveAccountActivation
            .as_str()
            .to_string(),
        delivery_surface: MercurySelectiveAccountActivationSurface::ControlledDeliveryBundle
            .as_str()
            .to_string(),
        target_account_label:
            "one previously qualified account accepted through the broader-distribution lane"
                .to_string(),
        entry_gates: vec![
            "broader-distribution approval remains current for the same workflow".to_string(),
            "delivery stays within one controlled bundle and one product-owned handoff".to_string(),
            "claim containment and approval refresh are present before activation".to_string(),
        ],
        non_goals: vec![
            "generic onboarding tooling or success automation".to_string(),
            "CRM workflows or channel marketplace routing".to_string(),
            "ARC-side commercial control surfaces or merged shells".to_string(),
        ],
        note: "This freeze keeps the next Mercury step bounded to one selective-account activation motion over the existing broader-distribution package."
            .to_string(),
    };
    let activation_scope_freeze_path = output.join("activation-scope-freeze.json");
    write_json_file(&activation_scope_freeze_path, &activation_scope_freeze)?;

    let activation_manifest = MercurySelectiveAccountActivationManifest {
        schema: "arc.mercury.selective_account_activation_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        activation_motion: MercurySelectiveAccountActivationMotion::SelectiveAccountActivation
            .as_str()
            .to_string(),
        delivery_surface: MercurySelectiveAccountActivationSurface::ControlledDeliveryBundle
            .as_str()
            .to_string(),
        broader_distribution_package_file: relative_display(
            output,
            &broader_distribution_package_path,
        )?,
        target_account_freeze_file: relative_display(output, &target_account_freeze_path)?,
        broader_distribution_manifest_file: relative_display(
            output,
            &broader_distribution_manifest_path,
        )?,
        claim_governance_rules_file: relative_display(output, &claim_governance_rules_path)?,
        selective_account_approval_file: relative_display(output, &selective_account_approval_path)?,
        distribution_handoff_brief_file: relative_display(output, &distribution_handoff_brief_path)?,
        reference_distribution_package_file: relative_display(
            output,
            &reference_distribution_package_path,
        )?,
        controlled_adoption_package_file: relative_display(
            output,
            &controlled_adoption_package_path,
        )?,
        release_readiness_package_file: relative_display(
            output,
            &release_readiness_package_path,
        )?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        inquiry_verification_file: relative_display(output, &inquiry_verification_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        note: "This manifest freezes one controlled-delivery bundle over the existing Mercury truth chain and does not imply a generic onboarding or channel system."
            .to_string(),
    };
    let activation_manifest_path = output.join("selective-account-activation-manifest.json");
    write_json_file(&activation_manifest_path, &activation_manifest)?;

    let claim_containment_rules = MercurySelectiveAccountActivationClaimContainmentRules {
        schema: "arc.mercury.selective_account_activation_claim_containment_rules.v1".to_string(),
        workflow_id: workflow_id.clone(),
        activation_owner: MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_OWNER.to_string(),
        approval_owner: MERCURY_ACTIVATION_APPROVAL_OWNER.to_string(),
        fail_closed: true,
        approved_claims: vec![
            approved_claim.clone(),
            "The selective-account activation bundle remains bounded to one activation motion and one controlled delivery surface."
                .to_string(),
        ],
        prohibited_claims: vec![
            "Mercury now provides a generic onboarding or CRM platform".to_string(),
            "ARC exposes a commercial activation console".to_string(),
            "the bundle proves universal rollout readiness or broad business performance"
                .to_string(),
        ],
        note: "Claim containment stays Mercury-owned and fail-closed for one selective-account activation path."
            .to_string(),
    };
    let claim_containment_rules_path = output.join("claim-containment-rules.json");
    write_json_file(&claim_containment_rules_path, &claim_containment_rules)?;

    let activation_approval_refresh = MercurySelectiveAccountActivationApprovalRefresh {
        schema: "arc.mercury.selective_account_activation_approval_refresh.v1".to_string(),
        workflow_id: workflow_id.clone(),
        approval_owner: MERCURY_ACTIVATION_APPROVAL_OWNER.to_string(),
        status: "refreshed".to_string(),
        refreshed_at: unix_now(),
        refreshed_by: MERCURY_ACTIVATION_APPROVAL_OWNER.to_string(),
        approved_claims: claim_containment_rules.approved_claims.clone(),
        required_files: vec![
            relative_display(output, &activation_scope_freeze_path)?,
            relative_display(output, &activation_manifest_path)?,
            relative_display(output, &claim_containment_rules_path)?,
            relative_display(output, &broader_distribution_package_path)?,
            relative_display(output, &selective_account_approval_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &reviewer_package_path)?,
        ],
        note: "Approval refresh is required before controlled delivery can proceed for the bounded selective-account activation bundle."
            .to_string(),
    };
    let activation_approval_refresh_path = output.join("activation-approval-refresh.json");
    write_json_file(
        &activation_approval_refresh_path,
        &activation_approval_refresh,
    )?;

    let customer_handoff_brief = MercurySelectiveAccountActivationCustomerHandoffBrief {
        schema: "arc.mercury.selective_account_activation_customer_handoff_brief.v1".to_string(),
        workflow_id: workflow_id.clone(),
        delivery_owner: MERCURY_CONTROLLED_DELIVERY_OWNER.to_string(),
        activation_owner: MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_OWNER.to_string(),
        approval_owner: MERCURY_ACTIVATION_APPROVAL_OWNER.to_string(),
        activation_motion: MercurySelectiveAccountActivationMotion::SelectiveAccountActivation
            .as_str()
            .to_string(),
        delivery_surface: MercurySelectiveAccountActivationSurface::ControlledDeliveryBundle
            .as_str()
            .to_string(),
        approved_scope: "one controlled-delivery bundle for one previously qualified account only"
            .to_string(),
        entry_criteria: vec![
            "broader-distribution package and approval remain internally consistent".to_string(),
            "claim-containment rules and approval refresh are current".to_string(),
            "customer handoff stays within one product-owned delivery motion".to_string(),
        ],
        escalation_triggers: vec![
            "approved claim drifts from the delivery bundle contents".to_string(),
            "required files are missing or no longer map to the same workflow".to_string(),
            "the motion widens beyond one account or one controlled delivery bundle".to_string(),
        ],
        note: "The customer handoff brief exists to move one governed Mercury bundle into one controlled delivery motion, not to define a generic onboarding or account-management system."
            .to_string(),
    };
    let customer_handoff_brief_path = output.join("customer-handoff-brief.json");
    write_json_file(&customer_handoff_brief_path, &customer_handoff_brief)?;

    let package = MercurySelectiveAccountActivationPackage {
        schema: MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "selective-account-activation-controlled-delivery-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        activation_motion: MercurySelectiveAccountActivationMotion::SelectiveAccountActivation,
        delivery_surface: MercurySelectiveAccountActivationSurface::ControlledDeliveryBundle,
        activation_owner: MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_OWNER.to_string(),
        approval_owner: MERCURY_ACTIVATION_APPROVAL_OWNER.to_string(),
        delivery_owner: MERCURY_CONTROLLED_DELIVERY_OWNER.to_string(),
        approval_refresh_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        broader_distribution_package_file: relative_display(
            output,
            &broader_distribution_package_path,
        )?,
        target_account_freeze_file: relative_display(output, &target_account_freeze_path)?,
        broader_distribution_manifest_file: relative_display(
            output,
            &broader_distribution_manifest_path,
        )?,
        claim_governance_rules_file: relative_display(output, &claim_governance_rules_path)?,
        selective_account_approval_file: relative_display(
            output,
            &selective_account_approval_path,
        )?,
        distribution_handoff_brief_file: relative_display(
            output,
            &distribution_handoff_brief_path,
        )?,
        reference_distribution_package_file: relative_display(
            output,
            &reference_distribution_package_path,
        )?,
        controlled_adoption_package_file: relative_display(
            output,
            &controlled_adoption_package_path,
        )?,
        release_readiness_package_file: relative_display(output, &release_readiness_package_path)?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        inquiry_verification_file: relative_display(output, &inquiry_verification_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        artifacts: vec![
            MercurySelectiveAccountActivationArtifact {
                artifact_kind: MercurySelectiveAccountActivationArtifactKind::ActivationScopeFreeze,
                relative_path: relative_display(output, &activation_scope_freeze_path)?,
            },
            MercurySelectiveAccountActivationArtifact {
                artifact_kind: MercurySelectiveAccountActivationArtifactKind::ActivationManifest,
                relative_path: relative_display(output, &activation_manifest_path)?,
            },
            MercurySelectiveAccountActivationArtifact {
                artifact_kind: MercurySelectiveAccountActivationArtifactKind::ClaimContainmentRules,
                relative_path: relative_display(output, &claim_containment_rules_path)?,
            },
            MercurySelectiveAccountActivationArtifact {
                artifact_kind:
                    MercurySelectiveAccountActivationArtifactKind::ActivationApprovalRefresh,
                relative_path: relative_display(output, &activation_approval_refresh_path)?,
            },
            MercurySelectiveAccountActivationArtifact {
                artifact_kind: MercurySelectiveAccountActivationArtifactKind::CustomerHandoffBrief,
                relative_path: relative_display(output, &customer_handoff_brief_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("selective-account-activation-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercurySelectiveAccountActivationExportSummary {
        workflow_id,
        activation_motion: MercurySelectiveAccountActivationMotion::SelectiveAccountActivation
            .as_str()
            .to_string(),
        delivery_surface: MercurySelectiveAccountActivationSurface::ControlledDeliveryBundle
            .as_str()
            .to_string(),
        activation_owner: MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_OWNER.to_string(),
        approval_owner: MERCURY_ACTIVATION_APPROVAL_OWNER.to_string(),
        delivery_owner: MERCURY_CONTROLLED_DELIVERY_OWNER.to_string(),
        broader_distribution_dir: broader_distribution_dir.display().to_string(),
        selective_account_activation_profile_file: profile_path.display().to_string(),
        selective_account_activation_package_file: package_path.display().to_string(),
        activation_scope_freeze_file: activation_scope_freeze_path.display().to_string(),
        selective_account_activation_manifest_file: activation_manifest_path.display().to_string(),
        claim_containment_rules_file: claim_containment_rules_path.display().to_string(),
        activation_approval_refresh_file: activation_approval_refresh_path.display().to_string(),
        customer_handoff_brief_file: customer_handoff_brief_path.display().to_string(),
        activation_evidence_dir: activation_evidence_dir.display().to_string(),
        broader_distribution_package_file: broader_distribution_package_path.display().to_string(),
        target_account_freeze_file: target_account_freeze_path.display().to_string(),
        broader_distribution_manifest_file: broader_distribution_manifest_path
            .display()
            .to_string(),
        claim_governance_rules_file: claim_governance_rules_path.display().to_string(),
        selective_account_approval_file: selective_account_approval_path.display().to_string(),
        distribution_handoff_brief_file: distribution_handoff_brief_path.display().to_string(),
        reference_distribution_package_file: reference_distribution_package_path
            .display()
            .to_string(),
        controlled_adoption_package_file: controlled_adoption_package_path.display().to_string(),
        release_readiness_package_file: release_readiness_package_path.display().to_string(),
        trust_network_package_file: trust_network_package_path.display().to_string(),
        assurance_suite_package_file: assurance_suite_package_path.display().to_string(),
        proof_package_file: proof_package_path.display().to_string(),
        inquiry_package_file: inquiry_package_path.display().to_string(),
        inquiry_verification_file: inquiry_verification_path.display().to_string(),
        reviewer_package_file: reviewer_package_path.display().to_string(),
        qualification_report_file: qualification_report_path.display().to_string(),
    };
    write_json_file(
        &output.join("selective-account-activation-summary.json"),
        &summary,
    )?;

    Ok(summary)
}

pub fn cmd_mercury_selective_account_activation_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_selective_account_activation(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury selective-account-activation package exported");
        println!("output:                             {}", output.display());
        println!(
            "workflow_id:                        {}",
            summary.workflow_id
        );
        println!(
            "activation_motion:                  {}",
            summary.activation_motion
        );
        println!(
            "delivery_surface:                   {}",
            summary.delivery_surface
        );
        println!(
            "activation_owner:                   {}",
            summary.activation_owner
        );
        println!(
            "approval_owner:                     {}",
            summary.approval_owner
        );
        println!(
            "delivery_owner:                     {}",
            summary.delivery_owner
        );
        println!(
            "selective_account_activation_package: {}",
            summary.selective_account_activation_package_file
        );
        println!(
            "activation_approval_refresh:        {}",
            summary.activation_approval_refresh_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_selective_account_activation_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let selective_account_activation_dir = output.join("selective-account-activation");
    let summary = export_selective_account_activation(&selective_account_activation_dir)?;
    let docs = selective_account_activation_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercurySelectiveAccountActivationDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_DECISION.to_string(),
        selected_activation_motion: summary.activation_motion.clone(),
        selected_delivery_surface: summary.delivery_surface.clone(),
        approved_scope:
            "Proceed with one bounded Mercury selective-account activation lane only."
                .to_string(),
        deferred_scope: vec![
            "additional selective-account activation motions or surfaces".to_string(),
            "generic onboarding tooling, CRM workflows, or commercial consoles".to_string(),
            "channel marketplaces or multi-segment activation programs".to_string(),
            "merged Mercury and ARC-Wall commercial packaging".to_string(),
            "ARC-side commercial control surfaces".to_string(),
        ],
        rationale: "The selective-account activation lane now packages one controlled delivery motion over the validated broader-distribution stack without widening Mercury into a generic onboarding platform or polluting ARC's generic substrate."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("selective-account-activation-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercurySelectiveAccountActivationValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_SELECTIVE_ACCOUNT_ACTIVATION_DECISION.to_string(),
        activation_motion: summary.activation_motion.clone(),
        delivery_surface: summary.delivery_surface.clone(),
        activation_owner: summary.activation_owner.clone(),
        approval_owner: summary.approval_owner.clone(),
        delivery_owner: summary.delivery_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        selective_account_activation: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury selective-account-activation validation package exported");
        println!("output:                             {}", output.display());
        println!("workflow_id:                        {}", report.workflow_id);
        println!("decision:                           {}", report.decision);
        println!(
            "activation_motion:                  {}",
            report.activation_motion
        );
        println!(
            "delivery_surface:                   {}",
            report.delivery_surface
        );
        println!(
            "activation_owner:                   {}",
            report.activation_owner
        );
        println!(
            "approval_owner:                     {}",
            report.approval_owner
        );
        println!(
            "delivery_owner:                     {}",
            report.delivery_owner
        );
        println!(
            "validation_report:                  {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:                    {}",
            decision_record_file.display()
        );
        println!(
            "selective_account_activation_package: {}",
            report
                .selective_account_activation
                .selective_account_activation_package_file
        );
    }

    Ok(())
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDeliveryContinuityDocRefs {
    delivery_continuity_file: String,
    operations_file: String,
    validation_package_file: String,
    decision_record_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDeliveryContinuityAccountBoundaryFreeze {
    schema: String,
    workflow_id: String,
    continuity_motion: String,
    continuity_surface: String,
    account_boundary_label: String,
    entry_gates: Vec<String>,
    non_goals: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDeliveryContinuityManifest {
    schema: String,
    workflow_id: String,
    continuity_motion: String,
    continuity_surface: String,
    selective_account_activation_package_file: String,
    activation_scope_freeze_file: String,
    selective_account_activation_manifest_file: String,
    claim_containment_rules_file: String,
    activation_approval_refresh_file: String,
    customer_handoff_brief_file: String,
    broader_distribution_package_file: String,
    broader_distribution_manifest_file: String,
    target_account_freeze_file: String,
    claim_governance_rules_file: String,
    selective_account_approval_file: String,
    reference_distribution_package_file: String,
    controlled_adoption_package_file: String,
    release_readiness_package_file: String,
    trust_network_package_file: String,
    assurance_suite_package_file: String,
    proof_package_file: String,
    inquiry_package_file: String,
    inquiry_verification_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDeliveryContinuityOutcomeEvidenceSummary {
    schema: String,
    workflow_id: String,
    continuity_owner: String,
    renewal_owner: String,
    evidence_owner: String,
    continuity_motion: String,
    continuity_surface: String,
    supported_claims: Vec<String>,
    evidence_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDeliveryContinuityRenewalGate {
    schema: String,
    workflow_id: String,
    renewal_owner: String,
    status: String,
    reviewed_at: u64,
    reviewed_by: String,
    approved_claims: Vec<String>,
    required_files: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDeliveryContinuityDeliveryEscalationBrief {
    schema: String,
    workflow_id: String,
    continuity_owner: String,
    evidence_owner: String,
    renewal_owner: String,
    continuity_motion: String,
    continuity_surface: String,
    service_boundary: String,
    escalation_triggers: Vec<String>,
    immediate_actions: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDeliveryContinuityCustomerEvidenceHandoff {
    schema: String,
    workflow_id: String,
    evidence_owner: String,
    continuity_owner: String,
    renewal_owner: String,
    continuity_motion: String,
    continuity_surface: String,
    approved_scope: String,
    required_evidence: Vec<String>,
    deferred_requests: Vec<String>,
    note: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDeliveryContinuityExportSummary {
    workflow_id: String,
    continuity_motion: String,
    continuity_surface: String,
    continuity_owner: String,
    renewal_owner: String,
    evidence_owner: String,
    selective_account_activation_dir: String,
    delivery_continuity_profile_file: String,
    delivery_continuity_package_file: String,
    account_boundary_freeze_file: String,
    delivery_continuity_manifest_file: String,
    outcome_evidence_summary_file: String,
    renewal_gate_file: String,
    delivery_escalation_brief_file: String,
    customer_evidence_handoff_file: String,
    continuity_evidence_dir: String,
    selective_account_activation_package_file: String,
    activation_scope_freeze_file: String,
    selective_account_activation_manifest_file: String,
    claim_containment_rules_file: String,
    activation_approval_refresh_file: String,
    customer_handoff_brief_file: String,
    broader_distribution_package_file: String,
    broader_distribution_manifest_file: String,
    target_account_freeze_file: String,
    claim_governance_rules_file: String,
    selective_account_approval_file: String,
    reference_distribution_package_file: String,
    controlled_adoption_package_file: String,
    release_readiness_package_file: String,
    trust_network_package_file: String,
    assurance_suite_package_file: String,
    proof_package_file: String,
    inquiry_package_file: String,
    inquiry_verification_file: String,
    reviewer_package_file: String,
    qualification_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDeliveryContinuityDecisionRecord {
    workflow_id: String,
    decision: String,
    selected_continuity_motion: String,
    selected_continuity_surface: String,
    approved_scope: String,
    deferred_scope: Vec<String>,
    rationale: String,
    validation_report_file: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MercuryDeliveryContinuityValidationReport {
    workflow_id: String,
    decision: String,
    continuity_motion: String,
    continuity_surface: String,
    continuity_owner: String,
    renewal_owner: String,
    evidence_owner: String,
    same_workflow_boundary: String,
    delivery_continuity: MercuryDeliveryContinuityExportSummary,
    decision_record_file: String,
    docs: MercuryDeliveryContinuityDocRefs,
}

fn delivery_continuity_doc_refs() -> MercuryDeliveryContinuityDocRefs {
    MercuryDeliveryContinuityDocRefs {
        delivery_continuity_file: "docs/mercury/DELIVERY_CONTINUITY.md".to_string(),
        operations_file: "docs/mercury/DELIVERY_CONTINUITY_OPERATIONS.md".to_string(),
        validation_package_file: "docs/mercury/DELIVERY_CONTINUITY_VALIDATION_PACKAGE.md"
            .to_string(),
        decision_record_file: "docs/mercury/DELIVERY_CONTINUITY_DECISION_RECORD.md".to_string(),
    }
}

fn build_delivery_continuity_profile(
    workflow_id: &str,
) -> Result<MercuryDeliveryContinuityProfile, CliError> {
    let profile = MercuryDeliveryContinuityProfile {
        schema: MERCURY_DELIVERY_CONTINUITY_PROFILE_SCHEMA.to_string(),
        profile_id: format!(
            "delivery-continuity-outcome-evidence-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.to_string(),
        continuity_motion: MercuryDeliveryContinuityMotion::ControlledDeliveryContinuity,
        continuity_surface: MercuryDeliveryContinuitySurface::OutcomeEvidenceBundle,
        renewal_gate: "evidence_backed_renewal_only".to_string(),
        retained_artifact_policy:
            "retain-bounded-delivery-continuity-and-renewal-gate-artifacts".to_string(),
        intended_use: "Maintain one previously activated Mercury account inside one bounded controlled-delivery continuity lane with one renewal gate over the validated selective-account-activation package, without widening into generic onboarding tooling, CRM workflows, support desks, channel marketplaces, or ARC commercial surfaces."
            .to_string(),
        fail_closed: true,
    };
    profile
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    Ok(profile)
}

fn export_delivery_continuity(
    output: &Path,
) -> Result<MercuryDeliveryContinuityExportSummary, CliError> {
    ensure_empty_directory(output)?;

    let selective_account_activation_dir = output.join("selective-account-activation");
    let selective_account_activation =
        export_selective_account_activation(&selective_account_activation_dir)?;
    let workflow_id = selective_account_activation.workflow_id.clone();

    let profile = build_delivery_continuity_profile(&workflow_id)?;
    let profile_path = output.join("delivery-continuity-profile.json");
    write_json_file(&profile_path, &profile)?;

    let continuity_evidence_dir = output.join("continuity-evidence");
    fs::create_dir_all(&continuity_evidence_dir)?;

    let selective_account_activation_package_path =
        continuity_evidence_dir.join("selective-account-activation-package.json");
    let activation_scope_freeze_path = continuity_evidence_dir.join("activation-scope-freeze.json");
    let selective_account_activation_manifest_path =
        continuity_evidence_dir.join("selective-account-activation-manifest.json");
    let claim_containment_rules_path = continuity_evidence_dir.join("claim-containment-rules.json");
    let activation_approval_refresh_path =
        continuity_evidence_dir.join("activation-approval-refresh.json");
    let customer_handoff_brief_path = continuity_evidence_dir.join("customer-handoff-brief.json");
    let broader_distribution_package_path =
        continuity_evidence_dir.join("broader-distribution-package.json");
    let broader_distribution_manifest_path =
        continuity_evidence_dir.join("broader-distribution-manifest.json");
    let target_account_freeze_path = continuity_evidence_dir.join("target-account-freeze.json");
    let claim_governance_rules_path = continuity_evidence_dir.join("claim-governance-rules.json");
    let selective_account_approval_path =
        continuity_evidence_dir.join("selective-account-approval.json");
    let reference_distribution_package_path =
        continuity_evidence_dir.join("reference-distribution-package.json");
    let controlled_adoption_package_path =
        continuity_evidence_dir.join("controlled-adoption-package.json");
    let release_readiness_package_path =
        continuity_evidence_dir.join("release-readiness-package.json");
    let trust_network_package_path = continuity_evidence_dir.join("trust-network-package.json");
    let assurance_suite_package_path = continuity_evidence_dir.join("assurance-suite-package.json");
    let proof_package_path = continuity_evidence_dir.join("proof-package.json");
    let inquiry_package_path = continuity_evidence_dir.join("inquiry-package.json");
    let inquiry_verification_path = continuity_evidence_dir.join("inquiry-verification.json");
    let reviewer_package_path = continuity_evidence_dir.join("reviewer-package.json");
    let qualification_report_path = continuity_evidence_dir.join("qualification-report.json");

    copy_file(
        Path::new(&selective_account_activation.selective_account_activation_package_file),
        &selective_account_activation_package_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.activation_scope_freeze_file),
        &activation_scope_freeze_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.selective_account_activation_manifest_file),
        &selective_account_activation_manifest_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.claim_containment_rules_file),
        &claim_containment_rules_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.activation_approval_refresh_file),
        &activation_approval_refresh_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.customer_handoff_brief_file),
        &customer_handoff_brief_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.broader_distribution_package_file),
        &broader_distribution_package_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.broader_distribution_manifest_file),
        &broader_distribution_manifest_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.target_account_freeze_file),
        &target_account_freeze_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.claim_governance_rules_file),
        &claim_governance_rules_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.selective_account_approval_file),
        &selective_account_approval_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.reference_distribution_package_file),
        &reference_distribution_package_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.controlled_adoption_package_file),
        &controlled_adoption_package_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.release_readiness_package_file),
        &release_readiness_package_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.trust_network_package_file),
        &trust_network_package_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.assurance_suite_package_file),
        &assurance_suite_package_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.proof_package_file),
        &proof_package_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.inquiry_package_file),
        &inquiry_package_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.inquiry_verification_file),
        &inquiry_verification_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.reviewer_package_file),
        &reviewer_package_path,
    )?;
    copy_file(
        Path::new(&selective_account_activation.qualification_report_file),
        &qualification_report_path,
    )?;

    let approved_claim = "Mercury can maintain one previously activated account inside one controlled-delivery continuity lane and carry one evidence-backed renewal gate over the validated selective-account-activation, broader-distribution, reference-distribution, controlled-adoption, release-readiness, trust-network, assurance, proof, and inquiry chain."
        .to_string();

    let account_boundary_freeze = MercuryDeliveryContinuityAccountBoundaryFreeze {
        schema: "arc.mercury.delivery_continuity_account_boundary_freeze.v1".to_string(),
        workflow_id: workflow_id.clone(),
        continuity_motion: MercuryDeliveryContinuityMotion::ControlledDeliveryContinuity
            .as_str()
            .to_string(),
        continuity_surface: MercuryDeliveryContinuitySurface::OutcomeEvidenceBundle
            .as_str()
            .to_string(),
        account_boundary_label:
            "one already activated account operating inside one previously validated selective-account-activation lane".to_string(),
        entry_gates: vec![
            "selective-account-activation package and approval refresh remain current for the same workflow".to_string(),
            "delivery continuity stays within one activated account and one outcome-evidence bundle".to_string(),
            "renewal gate, escalation brief, and customer-evidence handoff are present before continuity claims are reused".to_string(),
        ],
        non_goals: vec![
            "generic onboarding tooling or CRM workflows".to_string(),
            "support desks, customer success platforms, or channel marketplaces".to_string(),
            "ARC-side commercial control surfaces or merged product shells".to_string(),
        ],
        note: "This freeze keeps the next Mercury step bounded to one controlled-delivery continuity motion over one already activated account."
            .to_string(),
    };
    let account_boundary_freeze_path = output.join("account-boundary-freeze.json");
    write_json_file(&account_boundary_freeze_path, &account_boundary_freeze)?;

    let delivery_continuity_manifest = MercuryDeliveryContinuityManifest {
        schema: "arc.mercury.delivery_continuity_manifest.v1".to_string(),
        workflow_id: workflow_id.clone(),
        continuity_motion: MercuryDeliveryContinuityMotion::ControlledDeliveryContinuity
            .as_str()
            .to_string(),
        continuity_surface: MercuryDeliveryContinuitySurface::OutcomeEvidenceBundle
            .as_str()
            .to_string(),
        selective_account_activation_package_file: relative_display(
            output,
            &selective_account_activation_package_path,
        )?,
        activation_scope_freeze_file: relative_display(output, &activation_scope_freeze_path)?,
        selective_account_activation_manifest_file: relative_display(
            output,
            &selective_account_activation_manifest_path,
        )?,
        claim_containment_rules_file: relative_display(output, &claim_containment_rules_path)?,
        activation_approval_refresh_file: relative_display(
            output,
            &activation_approval_refresh_path,
        )?,
        customer_handoff_brief_file: relative_display(output, &customer_handoff_brief_path)?,
        broader_distribution_package_file: relative_display(
            output,
            &broader_distribution_package_path,
        )?,
        broader_distribution_manifest_file: relative_display(
            output,
            &broader_distribution_manifest_path,
        )?,
        target_account_freeze_file: relative_display(output, &target_account_freeze_path)?,
        claim_governance_rules_file: relative_display(output, &claim_governance_rules_path)?,
        selective_account_approval_file: relative_display(
            output,
            &selective_account_approval_path,
        )?,
        reference_distribution_package_file: relative_display(
            output,
            &reference_distribution_package_path,
        )?,
        controlled_adoption_package_file: relative_display(
            output,
            &controlled_adoption_package_path,
        )?,
        release_readiness_package_file: relative_display(
            output,
            &release_readiness_package_path,
        )?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        inquiry_verification_file: relative_display(output, &inquiry_verification_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        note: "This manifest freezes one outcome-evidence bundle over the existing Mercury truth chain and does not imply a generic onboarding, support, or customer platform."
            .to_string(),
    };
    let delivery_continuity_manifest_path = output.join("delivery-continuity-manifest.json");
    write_json_file(
        &delivery_continuity_manifest_path,
        &delivery_continuity_manifest,
    )?;

    let outcome_evidence_summary = MercuryDeliveryContinuityOutcomeEvidenceSummary {
        schema: "arc.mercury.delivery_continuity_outcome_evidence_summary.v1".to_string(),
        workflow_id: workflow_id.clone(),
        continuity_owner: MERCURY_DELIVERY_CONTINUITY_OWNER.to_string(),
        renewal_owner: MERCURY_RENEWAL_GATE_OWNER.to_string(),
        evidence_owner: MERCURY_CUSTOMER_EVIDENCE_OWNER.to_string(),
        continuity_motion: MercuryDeliveryContinuityMotion::ControlledDeliveryContinuity
            .as_str()
            .to_string(),
        continuity_surface: MercuryDeliveryContinuitySurface::OutcomeEvidenceBundle
            .as_str()
            .to_string(),
        supported_claims: vec![
            approved_claim.clone(),
            "The continuity bundle remains bounded to one continuity motion, one renewal gate, and one outcome-evidence surface."
                .to_string(),
        ],
        evidence_files: vec![
            relative_display(output, &selective_account_activation_package_path)?,
            relative_display(output, &activation_approval_refresh_path)?,
            relative_display(output, &broader_distribution_package_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &reviewer_package_path)?,
            relative_display(output, &qualification_report_path)?,
        ],
        note: "Outcome evidence remains Mercury-owned and evidence-backed for one already activated account only."
            .to_string(),
    };
    let outcome_evidence_summary_path = output.join("outcome-evidence-summary.json");
    write_json_file(&outcome_evidence_summary_path, &outcome_evidence_summary)?;

    let renewal_gate = MercuryDeliveryContinuityRenewalGate {
        schema: "arc.mercury.delivery_continuity_renewal_gate.v1".to_string(),
        workflow_id: workflow_id.clone(),
        renewal_owner: MERCURY_RENEWAL_GATE_OWNER.to_string(),
        status: "ready".to_string(),
        reviewed_at: unix_now(),
        reviewed_by: MERCURY_RENEWAL_GATE_OWNER.to_string(),
        approved_claims: outcome_evidence_summary.supported_claims.clone(),
        required_files: vec![
            relative_display(output, &account_boundary_freeze_path)?,
            relative_display(output, &delivery_continuity_manifest_path)?,
            relative_display(output, &outcome_evidence_summary_path)?,
            relative_display(output, &selective_account_activation_package_path)?,
            relative_display(output, &activation_approval_refresh_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
            relative_display(output, &reviewer_package_path)?,
        ],
        note: "The renewal gate must be refreshed before Mercury can reuse controlled-delivery continuity claims for the same activated account."
            .to_string(),
    };
    let renewal_gate_path = output.join("renewal-gate.json");
    write_json_file(&renewal_gate_path, &renewal_gate)?;

    let delivery_escalation_brief = MercuryDeliveryContinuityDeliveryEscalationBrief {
        schema: "arc.mercury.delivery_continuity_delivery_escalation_brief.v1".to_string(),
        workflow_id: workflow_id.clone(),
        continuity_owner: MERCURY_DELIVERY_CONTINUITY_OWNER.to_string(),
        evidence_owner: MERCURY_CUSTOMER_EVIDENCE_OWNER.to_string(),
        renewal_owner: MERCURY_RENEWAL_GATE_OWNER.to_string(),
        continuity_motion: MercuryDeliveryContinuityMotion::ControlledDeliveryContinuity
            .as_str()
            .to_string(),
        continuity_surface: MercuryDeliveryContinuitySurface::OutcomeEvidenceBundle
            .as_str()
            .to_string(),
        service_boundary: "one already activated account in one controlled-delivery continuity lane only".to_string(),
        escalation_triggers: vec![
            "continuity claims drift beyond the outcome-evidence bundle".to_string(),
            "renewal-gate state is stale, missing, or no longer maps to the same workflow".to_string(),
            "requested support expands into generic onboarding, CRM, or multi-account delivery".to_string(),
        ],
        immediate_actions: vec![
            "pause reuse of the continuity bundle".to_string(),
            "regenerate the export from the canonical selective-account-activation lane".to_string(),
            "require a fresh renewal-gate review before any further customer-facing use".to_string(),
        ],
        note: "Delivery escalation exists to keep the lane bounded and evidence-backed, not to create a generic support desk."
            .to_string(),
    };
    let delivery_escalation_brief_path = output.join("delivery-escalation-brief.json");
    write_json_file(&delivery_escalation_brief_path, &delivery_escalation_brief)?;

    let customer_evidence_handoff = MercuryDeliveryContinuityCustomerEvidenceHandoff {
        schema: "arc.mercury.delivery_continuity_customer_evidence_handoff.v1".to_string(),
        workflow_id: workflow_id.clone(),
        evidence_owner: MERCURY_CUSTOMER_EVIDENCE_OWNER.to_string(),
        continuity_owner: MERCURY_DELIVERY_CONTINUITY_OWNER.to_string(),
        renewal_owner: MERCURY_RENEWAL_GATE_OWNER.to_string(),
        continuity_motion: MercuryDeliveryContinuityMotion::ControlledDeliveryContinuity
            .as_str()
            .to_string(),
        continuity_surface: MercuryDeliveryContinuitySurface::OutcomeEvidenceBundle
            .as_str()
            .to_string(),
        approved_scope:
            "one outcome-evidence bundle for one already activated account only".to_string(),
        required_evidence: vec![
            relative_display(output, &delivery_continuity_manifest_path)?,
            relative_display(output, &outcome_evidence_summary_path)?,
            relative_display(output, &renewal_gate_path)?,
            relative_display(output, &delivery_escalation_brief_path)?,
            relative_display(output, &proof_package_path)?,
            relative_display(output, &inquiry_package_path)?,
        ],
        deferred_requests: vec![
            "generic onboarding requests".to_string(),
            "broad customer-success or support programs".to_string(),
            "multi-account expansions or channel-marketplace asks".to_string(),
        ],
        note: "Customer evidence handoff stays product-owned and bounded to one continuity motion over one activated account."
            .to_string(),
    };
    let customer_evidence_handoff_path = output.join("customer-evidence-handoff.json");
    write_json_file(&customer_evidence_handoff_path, &customer_evidence_handoff)?;

    let package = MercuryDeliveryContinuityPackage {
        schema: MERCURY_DELIVERY_CONTINUITY_PACKAGE_SCHEMA.to_string(),
        package_id: format!(
            "delivery-continuity-outcome-evidence-{}-{}",
            workflow_id,
            current_utc_date()
        ),
        workflow_id: workflow_id.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        continuity_motion: MercuryDeliveryContinuityMotion::ControlledDeliveryContinuity,
        continuity_surface: MercuryDeliveryContinuitySurface::OutcomeEvidenceBundle,
        continuity_owner: MERCURY_DELIVERY_CONTINUITY_OWNER.to_string(),
        renewal_owner: MERCURY_RENEWAL_GATE_OWNER.to_string(),
        evidence_owner: MERCURY_CUSTOMER_EVIDENCE_OWNER.to_string(),
        renewal_gate_required: true,
        fail_closed: true,
        profile_file: relative_display(output, &profile_path)?,
        selective_account_activation_package_file: relative_display(
            output,
            &selective_account_activation_package_path,
        )?,
        activation_scope_freeze_file: relative_display(output, &activation_scope_freeze_path)?,
        selective_account_activation_manifest_file: relative_display(
            output,
            &selective_account_activation_manifest_path,
        )?,
        claim_containment_rules_file: relative_display(output, &claim_containment_rules_path)?,
        activation_approval_refresh_file: relative_display(
            output,
            &activation_approval_refresh_path,
        )?,
        customer_handoff_brief_file: relative_display(output, &customer_handoff_brief_path)?,
        broader_distribution_package_file: relative_display(
            output,
            &broader_distribution_package_path,
        )?,
        broader_distribution_manifest_file: relative_display(
            output,
            &broader_distribution_manifest_path,
        )?,
        target_account_freeze_file: relative_display(output, &target_account_freeze_path)?,
        claim_governance_rules_file: relative_display(output, &claim_governance_rules_path)?,
        selective_account_approval_file: relative_display(
            output,
            &selective_account_approval_path,
        )?,
        reference_distribution_package_file: relative_display(
            output,
            &reference_distribution_package_path,
        )?,
        controlled_adoption_package_file: relative_display(
            output,
            &controlled_adoption_package_path,
        )?,
        release_readiness_package_file: relative_display(output, &release_readiness_package_path)?,
        trust_network_package_file: relative_display(output, &trust_network_package_path)?,
        assurance_suite_package_file: relative_display(output, &assurance_suite_package_path)?,
        proof_package_file: relative_display(output, &proof_package_path)?,
        inquiry_package_file: relative_display(output, &inquiry_package_path)?,
        inquiry_verification_file: relative_display(output, &inquiry_verification_path)?,
        reviewer_package_file: relative_display(output, &reviewer_package_path)?,
        qualification_report_file: relative_display(output, &qualification_report_path)?,
        artifacts: vec![
            MercuryDeliveryContinuityArtifact {
                artifact_kind: MercuryDeliveryContinuityArtifactKind::AccountBoundaryFreeze,
                relative_path: relative_display(output, &account_boundary_freeze_path)?,
            },
            MercuryDeliveryContinuityArtifact {
                artifact_kind: MercuryDeliveryContinuityArtifactKind::DeliveryContinuityManifest,
                relative_path: relative_display(output, &delivery_continuity_manifest_path)?,
            },
            MercuryDeliveryContinuityArtifact {
                artifact_kind: MercuryDeliveryContinuityArtifactKind::OutcomeEvidenceSummary,
                relative_path: relative_display(output, &outcome_evidence_summary_path)?,
            },
            MercuryDeliveryContinuityArtifact {
                artifact_kind: MercuryDeliveryContinuityArtifactKind::RenewalGateRecord,
                relative_path: relative_display(output, &renewal_gate_path)?,
            },
            MercuryDeliveryContinuityArtifact {
                artifact_kind: MercuryDeliveryContinuityArtifactKind::DeliveryEscalationBrief,
                relative_path: relative_display(output, &delivery_escalation_brief_path)?,
            },
            MercuryDeliveryContinuityArtifact {
                artifact_kind: MercuryDeliveryContinuityArtifactKind::CustomerEvidenceHandoff,
                relative_path: relative_display(output, &customer_evidence_handoff_path)?,
            },
        ],
    };
    package
        .validate()
        .map_err(|error| CliError::Other(error.to_string()))?;
    let package_path = output.join("delivery-continuity-package.json");
    write_json_file(&package_path, &package)?;

    let summary = MercuryDeliveryContinuityExportSummary {
        workflow_id,
        continuity_motion: MercuryDeliveryContinuityMotion::ControlledDeliveryContinuity
            .as_str()
            .to_string(),
        continuity_surface: MercuryDeliveryContinuitySurface::OutcomeEvidenceBundle
            .as_str()
            .to_string(),
        continuity_owner: MERCURY_DELIVERY_CONTINUITY_OWNER.to_string(),
        renewal_owner: MERCURY_RENEWAL_GATE_OWNER.to_string(),
        evidence_owner: MERCURY_CUSTOMER_EVIDENCE_OWNER.to_string(),
        selective_account_activation_dir: selective_account_activation_dir.display().to_string(),
        delivery_continuity_profile_file: profile_path.display().to_string(),
        delivery_continuity_package_file: package_path.display().to_string(),
        account_boundary_freeze_file: account_boundary_freeze_path.display().to_string(),
        delivery_continuity_manifest_file: delivery_continuity_manifest_path.display().to_string(),
        outcome_evidence_summary_file: outcome_evidence_summary_path.display().to_string(),
        renewal_gate_file: renewal_gate_path.display().to_string(),
        delivery_escalation_brief_file: delivery_escalation_brief_path.display().to_string(),
        customer_evidence_handoff_file: customer_evidence_handoff_path.display().to_string(),
        continuity_evidence_dir: continuity_evidence_dir.display().to_string(),
        selective_account_activation_package_file: selective_account_activation_package_path
            .display()
            .to_string(),
        activation_scope_freeze_file: activation_scope_freeze_path.display().to_string(),
        selective_account_activation_manifest_file: selective_account_activation_manifest_path
            .display()
            .to_string(),
        claim_containment_rules_file: claim_containment_rules_path.display().to_string(),
        activation_approval_refresh_file: activation_approval_refresh_path.display().to_string(),
        customer_handoff_brief_file: customer_handoff_brief_path.display().to_string(),
        broader_distribution_package_file: broader_distribution_package_path.display().to_string(),
        broader_distribution_manifest_file: broader_distribution_manifest_path
            .display()
            .to_string(),
        target_account_freeze_file: target_account_freeze_path.display().to_string(),
        claim_governance_rules_file: claim_governance_rules_path.display().to_string(),
        selective_account_approval_file: selective_account_approval_path.display().to_string(),
        reference_distribution_package_file: reference_distribution_package_path
            .display()
            .to_string(),
        controlled_adoption_package_file: controlled_adoption_package_path.display().to_string(),
        release_readiness_package_file: release_readiness_package_path.display().to_string(),
        trust_network_package_file: trust_network_package_path.display().to_string(),
        assurance_suite_package_file: assurance_suite_package_path.display().to_string(),
        proof_package_file: proof_package_path.display().to_string(),
        inquiry_package_file: inquiry_package_path.display().to_string(),
        inquiry_verification_file: inquiry_verification_path.display().to_string(),
        reviewer_package_file: reviewer_package_path.display().to_string(),
        qualification_report_file: qualification_report_path.display().to_string(),
    };
    write_json_file(&output.join("delivery-continuity-summary.json"), &summary)?;

    Ok(summary)
}

pub fn cmd_mercury_delivery_continuity_export(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let summary = export_delivery_continuity(output)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("mercury delivery-continuity package exported");
        println!("output:                             {}", output.display());
        println!(
            "workflow_id:                        {}",
            summary.workflow_id
        );
        println!(
            "continuity_motion:                  {}",
            summary.continuity_motion
        );
        println!(
            "continuity_surface:                 {}",
            summary.continuity_surface
        );
        println!(
            "continuity_owner:                   {}",
            summary.continuity_owner
        );
        println!(
            "renewal_owner:                      {}",
            summary.renewal_owner
        );
        println!(
            "evidence_owner:                     {}",
            summary.evidence_owner
        );
        println!(
            "delivery_continuity_package:        {}",
            summary.delivery_continuity_package_file
        );
        println!(
            "renewal_gate:                       {}",
            summary.renewal_gate_file
        );
    }

    Ok(())
}

pub fn cmd_mercury_delivery_continuity_validate(
    output: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    ensure_empty_directory(output)?;

    let delivery_continuity_dir = output.join("delivery-continuity");
    let summary = export_delivery_continuity(&delivery_continuity_dir)?;
    let docs = delivery_continuity_doc_refs();
    let validation_report_file = output.join("validation-report.json");
    let decision_record = MercuryDeliveryContinuityDecisionRecord {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_DELIVERY_CONTINUITY_DECISION.to_string(),
        selected_continuity_motion: summary.continuity_motion.clone(),
        selected_continuity_surface: summary.continuity_surface.clone(),
        approved_scope:
            "Proceed with one bounded Mercury controlled-delivery continuity lane only."
                .to_string(),
        deferred_scope: vec![
            "additional continuity motions or delivery surfaces".to_string(),
            "generic onboarding tooling, CRM workflows, or support desks".to_string(),
            "channel marketplaces, multi-account continuity programs, or merged shells"
                .to_string(),
            "ARC-side commercial control surfaces".to_string(),
        ],
        rationale: "The controlled-delivery continuity lane now packages one outcome-evidence bundle and one renewal gate over the validated selective-account-activation chain without widening Mercury into a generic customer platform or polluting ARC's generic substrate."
            .to_string(),
        validation_report_file: validation_report_file.display().to_string(),
    };
    let decision_record_file = output.join("delivery-continuity-decision.json");
    write_json_file(&decision_record_file, &decision_record)?;

    let report = MercuryDeliveryContinuityValidationReport {
        workflow_id: summary.workflow_id.clone(),
        decision: MERCURY_DELIVERY_CONTINUITY_DECISION.to_string(),
        continuity_motion: summary.continuity_motion.clone(),
        continuity_surface: summary.continuity_surface.clone(),
        continuity_owner: summary.continuity_owner.clone(),
        renewal_owner: summary.renewal_owner.clone(),
        evidence_owner: summary.evidence_owner.clone(),
        same_workflow_boundary: MERCURY_WORKFLOW_BOUNDARY.to_string(),
        delivery_continuity: summary,
        decision_record_file: decision_record_file.display().to_string(),
        docs,
    };
    write_json_file(&validation_report_file, &report)?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("mercury delivery-continuity validation package exported");
        println!("output:                             {}", output.display());
        println!("workflow_id:                        {}", report.workflow_id);
        println!("decision:                           {}", report.decision);
        println!(
            "continuity_motion:                  {}",
            report.continuity_motion
        );
        println!(
            "continuity_surface:                 {}",
            report.continuity_surface
        );
        println!(
            "continuity_owner:                   {}",
            report.continuity_owner
        );
        println!(
            "renewal_owner:                      {}",
            report.renewal_owner
        );
        println!(
            "evidence_owner:                     {}",
            report.evidence_owner
        );
        println!(
            "validation_report:                  {}",
            validation_report_file.display()
        );
        println!(
            "decision_record:                    {}",
            decision_record_file.display()
        );
        println!(
            "delivery_continuity_package:        {}",
            report.delivery_continuity.delivery_continuity_package_file
        );
    }

    Ok(())
}
