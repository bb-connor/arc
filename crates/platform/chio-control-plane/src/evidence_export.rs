use std::cmp::{max, min};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use chio_bundle_verify::federation::merge_read_boundary;
use chio_bundle_verify::package::{write_package, PackageContents, PolicyAttachment};
use chio_bundle_verify::verify::{
    verify_package, verify_transparency, EmbeddedHttpError, EmbeddedHttpReceiptVerifier,
    VerifiedPackage,
};
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::checkpoint::CheckpointTransparencySummary;
use chio_core::receipt::evidence::{
    EvidenceChildReceiptScope, EvidenceDisclosureNotice, EvidenceExportBundle, EvidenceExportQuery,
    EvidenceImportPackage, EvidenceReceiptSemanticSummary, EvidenceTransparencyClaims,
    EvidenceUncheckpointedReceipt, FederationPolicyBody, FederationPolicyDocument,
    PolicyAttachmentMetadata, ReceiptReadBoundary, FEDERATED_EVIDENCE_SHARE_SCHEMA,
    FEDERATION_POLICY_SCHEMA,
};
use chio_core::{canonical_json_bytes, sha256_hex};
use chio_core_types::root_authority::VerifierTrust;
use chio_kernel_core::evidence_verify::build_evidence_transparency_claims;
use chio_store_sqlite::SqliteReceiptStore;

use crate::policy::load_policy;
use crate::{load_or_create_authority_keypair, CliError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct RemoteEvidenceExportRequest {
    #[serde(default)]
    pub query: EvidenceExportQuery,
    #[serde(default)]
    pub require_proofs: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_policy: Option<FederationPolicyDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteEvidenceExportResponse {
    pub bundle: EvidenceExportBundle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency: Option<CheckpointTransparencySummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation_policy: Option<FederationPolicyDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoteEvidenceImportRequest {
    pub package: EvidenceImportPackage,
    /// Explicit administrative trust input, independent of package contents.
    pub trust: VerifierTrust,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteEvidenceImportResponse {
    pub share: chio_kernel::FederatedEvidenceShareSummary,
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedEvidenceExport {
    pub query: EvidenceExportQuery,
    pub require_proofs: bool,
    pub federation_policy: Option<FederationPolicyDocument>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceVerificationResult {
    schema: String,
    verified_at: u64,
    tool_receipts: u64,
    child_receipts: u64,
    checkpoints: u64,
    checkpoint_publications: u64,
    checkpoint_witnesses: u64,
    checkpoint_consistency_proofs: u64,
    checkpoint_equivocations: u64,
    capability_lineage: u64,
    inclusion_proofs: u64,
    uncheckpointed_receipts: u64,
    receipt_semantics: EvidenceReceiptSemanticSummary,
    verified_files: u64,
    child_receipt_scope: EvidenceChildReceiptScope,
    claim_boundary: EvidenceTransparencyClaims,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    disclosure_notice: Option<EvidenceDisclosureNotice>,
    required_columns: Vec<chio_core_types::root_authority::ReportColumn>,
    columns: Vec<chio_bundle_verify::ReceiptReport>,
}

fn unix_now() -> Result<u64, chio_security_types::clock::ClockError> {
    use chio_security_types::clock::{Clock, SystemClock};
    SystemClock.unix_millis().map(|now| now.as_secs())
}

fn ensure_clean_output_dir(path: &Path) -> Result<(), CliError> {
    if path.exists() {
        if !path.is_dir() {
            return Err(CliError::cli_other_error(format!(
                "evidence export output path must be a directory: {}",
                path.display()
            )));
        }
        let mut entries = fs::read_dir(path).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to inspect evidence export output directory {}: {error}",
                path.display()
            ))
        })?;
        match entries.next() {
            Some(Ok(_)) => {
                return Err(CliError::cli_other_error(format!(
                    "evidence export output directory must be empty: {}",
                    path.display()
                )));
            }
            Some(Err(error)) => {
                return Err(CliError::cli_io_error(format!(
                    "failed to inspect evidence export output directory {}: {error}",
                    path.display()
                )));
            }
            None => {}
        }
    } else {
        fs::create_dir_all(path).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to create evidence export output directory {}: {error}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

fn render_readme(
    bundle: &EvidenceExportBundle,
    transparency: &CheckpointTransparencySummary,
    claim_boundary: &EvidenceTransparencyClaims,
    disclosure_notice: Option<&EvidenceDisclosureNotice>,
) -> String {
    let trust_anchor = claim_boundary.trust_anchor.as_deref().unwrap_or("none");
    let child_scope = match bundle.child_receipt_scope {
        EvidenceChildReceiptScope::FullQueryWindow => {
            "Child receipts include the full export query window."
        }
        EvidenceChildReceiptScope::TimeWindowContextOnly => {
            "Child receipts are included only as time-window context; capability and agent filters do not apply to them yet."
        }
        EvidenceChildReceiptScope::OmittedNoJoinPath => {
            "Child receipts are omitted because the export was capability/agent scoped without a truthful child-receipt join path."
        }
    };
    let disclosure_block = match disclosure_notice {
        Some(notice) => format!(
            "\nCross-tenant disclosure notice\n{}\nDisclosed checkpoint body fields: {}\nDisclosed publication record fields: {}\nNarrowed metadata: {}\nProtocol reference: {}\n",
            notice.summary,
            notice.disclosed_checkpoint_body_fields.join(", "),
            notice.disclosed_publication_fields.join(", "),
            notice.narrowed_metadata.join("; "),
            notice.protocol_reference,
        ),
        None => String::new(),
    };

    format!(
        "\
Chio evidence export

This directory is a local SQLite export assembled by `chio evidence export`.
export-envelope.json authenticates the manifest and complete decoded payload.
Verify with an independently obtained kernel public key:
  chio evidence verify --input <directory> --trust <trust-file>
The chio.verifier-trust.v1 file pins every trusted receipt/checkpoint and package signer.
Without its checkpoint_trust_anchor, publication metadata is only a transparency preview.
It contains signed receipts, checkpoints, inclusion proofs, capability lineage,
and retention metadata for offline review.

Audit claims in this package are limited to local receipt verification,
signed checkpoint continuity, and inclusion-proof coverage.
Publication state: {}
Trust anchor: {}
Transparency log identity and append-only growth remain preview-only unless
the verifier independently trusts the exact signed publication anchor binding.

Tool receipts: {}
Child receipts: {}
Checkpoints: {}
Inclusion proofs: {}
Uncheckpointed receipts: {}
Checkpoint publications: {}
Checkpoint witnesses: {}
Checkpoint consistency proofs: {}
Checkpoint equivocations: {}
Transparency preview logs: {}

{}
{}",
        claim_boundary.publication_state.as_str(),
        trust_anchor,
        bundle.tool_receipts.len(),
        bundle.child_receipts.len(),
        bundle.checkpoints.len(),
        bundle.inclusion_proofs.len(),
        bundle.uncheckpointed_receipts.len(),
        transparency.publications.len(),
        transparency.witnesses.len(),
        transparency.consistency_proofs.len(),
        transparency.equivocations.len(),
        claim_boundary.transparency_preview.len(),
        child_scope,
        disclosure_block,
    )
}

fn policy_source_relative_path(policy_file: &Path) -> String {
    let extension = policy_file
        .extension()
        .and_then(|extension| extension.to_str())
        .filter(|extension| !extension.is_empty())
        .unwrap_or("txt");
    format!("policy/source.{extension}")
}

fn policy_metadata(
    policy_file: &Path,
    source_path: &str,
    source_bytes: u64,
) -> Result<PolicyAttachmentMetadata, CliError> {
    let loaded = load_policy(policy_file)?;
    Ok(PolicyAttachmentMetadata {
        format: loaded.format_name().to_string(),
        source_hash: loaded.identity.source_hash,
        runtime_hash: loaded.identity.runtime_hash,
        source_path: source_path.to_string(),
        source_bytes,
    })
}

fn read_federation_policy(path: &Path) -> Result<FederationPolicyDocument, CliError> {
    let policy: FederationPolicyDocument =
        chio_core::canonical::UntrustedJsonText::from_wire(&fs::read(path)?, 64 * 1024 * 1024)
            .and_then(|input| input.decode_signed())?;
    verify_federation_policy(&policy)?;
    Ok(policy)
}

pub(crate) fn render_missing_proofs_error(records: &[EvidenceUncheckpointedReceipt]) -> CliError {
    let sample = records
        .iter()
        .take(5)
        .map(|record| format!("{}@{}", record.receipt_id, record.seq))
        .collect::<Vec<_>>()
        .join(", ");
    CliError::attest_error(format!(
        "evidence export requires checkpoint coverage, but {} receipt(s) are uncheckpointed: {}",
        records.len(),
        sample
    ))
}

pub(crate) fn verify_federation_policy(policy: &FederationPolicyDocument) -> Result<(), CliError> {
    Ok(chio_bundle_verify::federation::verify_federation_policy(
        policy,
    )?)
}

pub(crate) fn merge_export_query(
    policy_query: &EvidenceExportQuery,
    cli_query: &EvidenceExportQuery,
) -> Result<EvidenceExportQuery, CliError> {
    let capability_id = merge_exact_scope(
        policy_query.capability_id.as_deref(),
        cli_query.capability_id.as_deref(),
        "capability_id",
    )?;
    let agent_subject = merge_exact_scope(
        policy_query.agent_subject.as_deref(),
        cli_query.agent_subject.as_deref(),
        "agent_subject",
    )?;
    let tenant = merge_exact_scope(
        policy_query.tenant.as_deref(),
        cli_query.tenant.as_deref(),
        "tenant",
    )?;
    let read_boundary = merge_read_boundary(
        policy_query.read_boundary.as_ref(),
        cli_query.read_boundary.as_ref(),
    )
    .map_err(CliError::from)?;
    let since = match (policy_query.since, cli_query.since) {
        (Some(policy), Some(cli)) => Some(max(policy, cli)),
        (Some(policy), None) => Some(policy),
        (None, Some(cli)) => Some(cli),
        (None, None) => None,
    };
    let until = match (policy_query.until, cli_query.until) {
        (Some(policy), Some(cli)) => Some(min(policy, cli)),
        (Some(policy), None) => Some(policy),
        (None, Some(cli)) => Some(cli),
        (None, None) => None,
    };
    if let (Some(since), Some(until)) = (since, until) {
        if since > until {
            return Err(CliError::attest_error(
                "federation policy scope and requested export window do not overlap".to_string(),
            ));
        }
    }
    let mut merged = EvidenceExportQuery {
        capability_id,
        agent_subject,
        since,
        until,
        tenant,
        read_boundary,
    };
    if let Some(ReceiptReadBoundary::TenantScoped { tenant }) = &merged.read_boundary {
        if merged
            .tenant
            .as_deref()
            .is_some_and(|query_tenant| query_tenant != tenant)
        {
            return Err(CliError::attest_error(
                "evidence package read boundary tenant conflicts with query tenant".to_string(),
            ));
        }
        merged.tenant = Some(tenant.clone());
    }
    Ok(merged)
}

fn merge_exact_scope(
    policy_value: Option<&str>,
    cli_value: Option<&str>,
    field: &str,
) -> Result<Option<String>, CliError> {
    match (policy_value, cli_value) {
        (Some(policy), Some(cli)) if policy != cli => Err(CliError::attest_error(format!(
            "requested export {field} falls outside the signed federation policy"
        ))),
        (Some(policy), _) => Ok(Some(policy.to_string())),
        (None, Some(cli)) => Ok(Some(cli.to_string())),
        (None, None) => Ok(None),
    }
}

pub(crate) fn prepare_evidence_export(
    query: EvidenceExportQuery,
    require_proofs: bool,
    federation_policy: Option<FederationPolicyDocument>,
) -> Result<PreparedEvidenceExport, CliError> {
    if let Some(policy) = &federation_policy {
        verify_federation_policy(policy)?;
    }
    let query = if let Some(policy) = &federation_policy {
        merge_export_query(&policy.body.query, &query)?
    } else {
        query
    };
    query
        .validate_read_boundary()
        .map_err(|error| CliError::attest_error(error.to_string()))?;
    let require_proofs = require_proofs
        || federation_policy
            .as_ref()
            .is_some_and(|policy| policy.body.require_proofs);
    Ok(PreparedEvidenceExport {
        query,
        require_proofs,
        federation_policy,
    })
}

pub(crate) fn validate_evidence_bundle_requirements(
    bundle: &EvidenceExportBundle,
    require_proofs: bool,
) -> Result<(), CliError> {
    if require_proofs && !bundle.uncheckpointed_receipts.is_empty() {
        return Err(render_missing_proofs_error(&bundle.uncheckpointed_receipts));
    }
    Ok(())
}

pub struct EvidenceFederationPolicyCreateArgs<'a> {
    pub output: &'a Path,
    pub signing_seed_file: &'a Path,
    pub issuer: &'a str,
    pub partner: &'a str,
    pub capability_id: Option<&'a str>,
    pub agent_subject: Option<&'a str>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub tenant: Option<&'a str>,
    pub admin_all: bool,
    pub expires_at: u64,
    pub require_proofs: bool,
    pub purpose: Option<&'a str>,
    pub json_output: bool,
}

#[allow(
    clippy::print_stdout,
    reason = "This CLI command emits its requested report to standard output."
)]
pub fn cmd_evidence_federation_policy_create(
    args: EvidenceFederationPolicyCreateArgs<'_>,
) -> Result<(), CliError> {
    let clock_now = unix_now()?;
    let keypair = load_or_create_authority_keypair(args.signing_seed_file)?;
    let created_at = clock_now;
    if created_at > args.expires_at {
        return Err(CliError::attest_error(
            "--expires-at must be greater than or equal to the current Unix timestamp".to_string(),
        ));
    }
    if let (Some(since), Some(until)) = (args.since, args.until) {
        if since > until {
            return Err(CliError::attest_error(
                "federation policy since must be less than or equal to until".to_string(),
            ));
        }
    }
    if args.admin_all && args.tenant.is_some() {
        return Err(CliError::attest_error(
            "use either --tenant or --admin-all for a federation policy, not both".to_string(),
        ));
    }
    let read_boundary = if args.admin_all {
        Some(ReceiptReadBoundary::AdminAll)
    } else if let Some(tenant) = args.tenant {
        Some(ReceiptReadBoundary::tenant_scoped(tenant))
    } else {
        return Err(CliError::attest_error(
            "federation policy requires either --tenant or --admin-all".to_string(),
        ));
    };

    let body = FederationPolicyBody {
        schema: FEDERATION_POLICY_SCHEMA.to_string(),
        issuer: args.issuer.to_string(),
        partner: args.partner.to_string(),
        signer_public_key: keypair.public_key(),
        created_at,
        expires_at: args.expires_at,
        query: EvidenceExportQuery {
            capability_id: args.capability_id.map(ToOwned::to_owned),
            agent_subject: args.agent_subject.map(ToOwned::to_owned),
            since: args.since,
            until: args.until,
            tenant: args.tenant.map(ToOwned::to_owned),
            read_boundary,
        },
        require_proofs: args.require_proofs,
        purpose: args.purpose.map(ToOwned::to_owned),
    };
    let (signature, _) = keypair.sign_canonical(&body)?;
    let policy = FederationPolicyDocument { body, signature };
    verify_federation_policy(&policy)?;
    fs::write(args.output, serde_json::to_vec_pretty(&policy)?)?;

    if args.json_output {
        println!("{}", serde_json::to_string_pretty(&policy)?);
    } else {
        println!("federation policy created");
        println!("output:              {}", args.output.display());
        println!("issuer:              {}", policy.body.issuer);
        println!("partner:             {}", policy.body.partner);
        println!(
            "signer_public_key:   {}",
            policy.body.signer_public_key.to_hex()
        );
        println!("require_proofs:      {}", policy.body.require_proofs);
    }

    Ok(())
}

pub fn cmd_evidence_export(
    output: &Path,
    capability_id: Option<&str>,
    agent_subject: Option<&str>,
    since: Option<u64>,
    until: Option<u64>,
    tenant: Option<&str>,
    admin_all: bool,
    policy_file: Option<&Path>,
    federation_policy_file: Option<&Path>,
    require_proofs: bool,
    receipt_db: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
    signing_key: &chio_core::Keypair,
) -> Result<(), CliError> {
    if admin_all && tenant.is_some() {
        return Err(CliError::attest_error(
            "use either --tenant or --admin-all for evidence export, not both".to_string(),
        ));
    }
    let read_boundary = if admin_all {
        Some(ReceiptReadBoundary::AdminAll)
    } else {
        tenant.map(ReceiptReadBoundary::tenant_scoped)
    };
    let prepared = prepare_evidence_export(
        EvidenceExportQuery {
            capability_id: capability_id.map(ToOwned::to_owned),
            agent_subject: agent_subject.map(ToOwned::to_owned),
            since,
            until,
            tenant: tenant.map(ToOwned::to_owned),
            read_boundary,
        },
        require_proofs,
        federation_policy_file
            .map(read_federation_policy)
            .transpose()?,
    )?;

    let response = match (receipt_db, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::attest_error(
                "use either --receipt-db or --control-url for evidence export, not both"
                    .to_string(),
            ));
        }
        (Some(receipt_db), None) => {
            let store = SqliteReceiptStore::open(receipt_db)?;
            let (bundle, transparency) =
                store.build_evidence_export_bundle_with_transparency(&prepared.query)?;
            validate_evidence_bundle_requirements(&bundle, prepared.require_proofs)?;
            RemoteEvidenceExportResponse {
                bundle,
                transparency: Some(transparency),
                federation_policy: prepared.federation_policy,
            }
        }
        (None, Some(control_url)) => {
            let token = super::require_control_token(control_token)?;
            let client =
                crate::trust_control::service_runtime::client::build_client(control_url, token)?;
            client.export_evidence(&RemoteEvidenceExportRequest {
                query: prepared.query,
                require_proofs: prepared.require_proofs,
                federation_policy: prepared.federation_policy,
            })?
        }
        (None, None) => {
            return Err(CliError::attest_error(
                "evidence export requires either --receipt-db <path> or --control-url <url>"
                    .to_string(),
            ));
        }
    };

    write_evidence_package(
        output,
        response.bundle,
        response.transparency,
        policy_file,
        response.federation_policy.as_ref(),
        signing_key,
    )
}

/// Verifies the HTTP receipts tool receipts embed, for the package verifier.
#[derive(Debug, Clone, Copy, Default)]
pub struct HttpReceiptProjection;

impl EmbeddedHttpReceiptVerifier for HttpReceiptProjection {
    fn verify_projection(
        &self,
        embedded: &serde_json::Value,
        receipt: &ChioReceipt,
    ) -> Result<bool, EmbeddedHttpError> {
        let http: chio_http_core::HttpReceipt = serde_json::from_value(embedded.clone())
            .map_err(|error| EmbeddedHttpError::Decode(error.to_string()))?;
        http.verify_chio_receipt_projection(receipt)
            .map_err(|error| EmbeddedHttpError::Projection(error.to_string()))
    }
}

/// Verify an exported package directory with the verifier-owned `trust`.
pub fn load_verified_evidence_package(
    input: &Path,
    trust: &VerifierTrust,
) -> Result<VerifiedPackage, CliError> {
    Ok(verify_package(input, trust, Some(&HttpReceiptProjection))?)
}

/// Decode a remote import request. `value` comes from the route's
/// `SignedJson` extractor, which read the original bounded bytes through
/// `decode_signed` and refused duplicate keys at every depth. The trust section loads
/// through `VerifierTrust::load` exactly as a trust file does, and the whole
/// request must reserialize to its input, so no member is dropped.
pub(crate) fn decode_remote_import_request(
    value: serde_json::Value,
) -> Result<RemoteEvidenceImportRequest, CliError> {
    use chio_bundle_verify::BundleVerifyError;

    let trust_value = value.get("trust").ok_or_else(|| {
        BundleVerifyError::trust_invalid("evidence import request carries no trust file")
    })?;
    let trust_bytes = serde_json::to_vec(trust_value)?;
    VerifierTrust::load(&trust_bytes)
        .map_err(|error| BundleVerifyError::trust_invalid(error.to_string()))?;
    let request = chio_security_types::strict_serde::lossless(
        value,
        serde_json::from_value::<RemoteEvidenceImportRequest>,
        |typed: &RemoteEvidenceImportRequest| serde_json::to_value(typed),
    )
    .map_err(|error| {
        BundleVerifyError::schema(format!(
            "evidence import request does not match its schema: {error}"
        ))
    })?;
    Ok(request)
}

/// Verify a decoded package with the verifier-owned `trust`.
pub(crate) fn verify_import_package(
    package: &EvidenceImportPackage,
    trust: &VerifierTrust,
) -> Result<(), CliError> {
    chio_bundle_verify::verify_decoded_package(package, trust, Some(&HttpReceiptProjection))?;
    Ok(())
}

#[allow(
    clippy::print_stdout,
    reason = "This CLI command emits its requested report to standard output."
)]
pub fn cmd_evidence_import(
    input: &Path,
    receipt_db: Option<&Path>,
    control_url: Option<&str>,
    control_token: Option<&str>,
    json_output: bool,
    trust: &VerifierTrust,
) -> Result<(), CliError> {
    let package = load_verified_evidence_package(input, trust)?.package;
    let share_import = build_federated_share_import(&package)?;

    let share = match (receipt_db, control_url) {
        (Some(_), Some(_)) => {
            return Err(CliError::attest_error(
                "use either --receipt-db or --control-url for evidence import, not both"
                    .to_string(),
            ));
        }
        (Some(receipt_db), None) => {
            let store = SqliteReceiptStore::open(receipt_db)?;
            store.import_federated_evidence_share(&share_import)?
        }
        (None, Some(control_url)) => {
            let token = super::require_control_token(control_token)?;
            let client =
                crate::trust_control::service_runtime::client::build_client(control_url, token)?;
            client
                .import_evidence(&RemoteEvidenceImportRequest {
                    package,
                    trust: trust.clone(),
                })?
                .share
        }
        (None, None) => {
            return Err(CliError::attest_error(
                "evidence import requires either --receipt-db <path> or --control-url <url>"
                    .to_string(),
            ));
        }
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&share)?);
    } else {
        println!("federated evidence share imported");
        println!("share_id:            {}", share.share_id);
        println!("issuer:              {}", share.issuer);
        println!("partner:             {}", share.partner);
        println!("signer_public_key:   {}", share.signer_public_key);
        println!("tool_receipts:       {}", share.tool_receipts);
        println!("capability_lineage:  {}", share.capability_lineage);
    }

    Ok(())
}

#[allow(
    clippy::print_stdout,
    reason = "This CLI command emits its requested report to standard output."
)]
pub fn cmd_evidence_verify(
    input: &Path,
    trust: &VerifierTrust,
    json_output: bool,
) -> Result<(), CliError> {
    let clock_now = unix_now()?;
    let verified = load_verified_evidence_package(input, trust)?;
    let report = chio_bundle_verify::report(&verified, trust);
    let required_columns = report.exit_class(trust);
    let manifest = verified.package.manifest;
    let transparency = verified.transparency;
    let claim_boundary = verified.claims;

    let result = EvidenceVerificationResult {
        schema: manifest.schema,
        verified_at: clock_now,
        tool_receipts: manifest.counts.tool_receipts,
        child_receipts: manifest.counts.child_receipts,
        checkpoints: manifest.counts.checkpoints,
        checkpoint_publications: crate::integer::count(transparency.publications.len()),
        checkpoint_witnesses: crate::integer::count(transparency.witnesses.len()),
        checkpoint_consistency_proofs: crate::integer::count(transparency.consistency_proofs.len()),
        checkpoint_equivocations: crate::integer::count(transparency.equivocations.len()),
        capability_lineage: manifest.counts.capability_lineage,
        inclusion_proofs: manifest.counts.inclusion_proofs,
        uncheckpointed_receipts: manifest.counts.uncheckpointed_receipts,
        receipt_semantics: manifest.receipt_semantics,
        verified_files: crate::integer::count(manifest.files.len()),
        child_receipt_scope: manifest.child_receipt_scope,
        claim_boundary,
        disclosure_notice: manifest.disclosure_notice,
        required_columns: report.required_columns.clone(),
        columns: report.receipts,
    };

    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("evidence package verified");
        println!("tool_receipts:          {}", result.tool_receipts);
        println!("child_receipts:         {}", result.child_receipts);
        println!("checkpoints:            {}", result.checkpoints);
        println!(
            "checkpoint_publications: {}",
            result.checkpoint_publications
        );
        println!("checkpoint_witnesses:   {}", result.checkpoint_witnesses);
        println!(
            "checkpoint_consistency_proofs: {}",
            result.checkpoint_consistency_proofs
        );
        println!(
            "checkpoint_equivocations: {}",
            result.checkpoint_equivocations
        );
        println!("capability_lineage:     {}", result.capability_lineage);
        println!("inclusion_proofs:       {}", result.inclusion_proofs);
        println!(
            "uncheckpointed_receipts: {}",
            result.uncheckpointed_receipts
        );
        println!(
            "authorized_receipts:     {}",
            result.receipt_semantics.authorized
        );
        println!(
            "trace_observations:      {}",
            result.receipt_semantics.trace_observations
        );
        println!(
            "advisory_evaluations:    {}",
            result.receipt_semantics.advisory_evaluations
        );
        println!("verified_files:         {}", result.verified_files);
        println!("child_receipt_scope:    {:?}", result.child_receipt_scope);
        println!(
            "transparency_preview_logs: {}",
            result.claim_boundary.transparency_preview.len()
        );
        println!(
            "publication_state:      {}",
            result.claim_boundary.publication_state.as_str()
        );
        if let Some(trust_anchor) = result.claim_boundary.trust_anchor.as_deref() {
            println!("trust_anchor:          {}", trust_anchor);
        }
        if let Some(notice) = result.disclosure_notice.as_ref() {
            println!(
                "disclosure_notice:      tenant-scoped export discloses {} signed-checkpoint and {} derived-publication aggregate fields (see README.txt and {})",
                notice.disclosed_checkpoint_body_fields.len(),
                notice.disclosed_publication_fields.len(),
                notice.protocol_reference,
            );
        }
    }

    if required_columns != chio_bundle_verify::ExitClass::Verified {
        return Err(chio_bundle_verify::BundleVerifyError::required_column(
            "a column the trust file requires is not verified for every receipt",
        )
        .into());
    }
    Ok(())
}

/// The federated share an import records: the verified receipts and lineage
/// under the package's signed federation policy.
pub(crate) fn build_federated_share_import(
    package: &EvidenceImportPackage,
) -> Result<chio_kernel::FederatedEvidenceShareImport, CliError> {
    let federation_policy = package.federation_policy.as_ref().ok_or_else(|| {
        CliError::attest_error(
            "evidence import requires a signed attached federation policy so remote receipt sharing stays bilateral and explicit".to_string(),
        )
    })?;
    let share_descriptor = serde_json::json!({
        "schema": FEDERATED_EVIDENCE_SHARE_SCHEMA,
        "manifest": &package.manifest,
        "federationPolicy": federation_policy,
    });
    let share_id = format!(
        "share-{}",
        sha256_hex(&canonical_json_bytes(&share_descriptor)?)
    );
    let manifest_hash = sha256_hex(&canonical_json_bytes(&package.manifest)?);
    Ok(chio_kernel::FederatedEvidenceShareImport {
        share_id,
        manifest_hash,
        exported_at: package.manifest.exported_at,
        issuer: federation_policy.body.issuer.clone(),
        partner: federation_policy.body.partner.clone(),
        signer_public_key: federation_policy.body.signer_public_key.to_hex(),
        require_proofs: federation_policy.body.require_proofs,
        query_json: serde_json::to_string(&package.bundle.query)?,
        tool_receipts: package
            .bundle
            .tool_receipts
            .iter()
            .map(|record| chio_kernel::StoredToolReceipt {
                seq: record.seq,
                receipt: record.receipt.clone(),
            })
            .collect(),
        capability_lineage: package.bundle.capability_lineage.clone(),
    })
}

/// Verify the transparency records of an export, then write and sign the
/// package into the empty directory `output`.
fn write_evidence_package(
    output: &Path,
    bundle: EvidenceExportBundle,
    transparency: Option<CheckpointTransparencySummary>,
    policy_file: Option<&Path>,
    federation_policy: Option<&FederationPolicyDocument>,
    signing_key: &chio_core::Keypair,
) -> Result<(), CliError> {
    let exported_at = unix_now()?;
    ensure_clean_output_dir(output)?;
    let transparency = verify_transparency(&bundle.checkpoints, transparency.as_ref())?;
    let claim_boundary = build_evidence_transparency_claims(&bundle, &transparency, None);
    let disclosure_notice = EvidenceDisclosureNotice::for_query(&bundle.query);
    let readme = render_readme(
        &bundle,
        &transparency,
        &claim_boundary,
        disclosure_notice.as_ref(),
    );
    let policy_source = policy_file.map(fs::read).transpose()?;
    let policy = match (policy_file, policy_source.as_deref()) {
        (Some(policy_file), Some(source)) => {
            let source_path = policy_source_relative_path(policy_file);
            Some(PolicyAttachment {
                metadata: policy_metadata(
                    policy_file,
                    &source_path,
                    crate::integer::count(source.len()),
                )?,
                source,
            })
        }
        _ => None,
    };
    write_package(
        output,
        PackageContents {
            bundle: &bundle,
            transparency: &transparency,
            claim_boundary,
            readme: &readme,
            policy,
            federation_policy,
            exported_at,
        },
        signing_key,
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "evidence_export/tests.rs"]
mod tests;
