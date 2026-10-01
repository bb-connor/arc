use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use chio_core::receipt::body::ChioReceipt;
use chio_core::{canonical_json_bytes, sha256_hex, PublicKey, Signature, SigningAlgorithm};
use chio_core_types::canonical_json_bytes_from_str;
use chio_manifest::{
    migrate_legacy_manifest_v1, verify_manifest, DeclassificationPurpose, NativeSyscallProfile,
    NetworkDestination, SignedManifest, ToolManifest, TOOL_MANIFEST_SCHEMA,
};
use chio_security_types::InformationLabel;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::CliError;

pub(crate) const SHADOW_MIGRATION_INPUT_SCHEMA: &str =
    "chio.active-defense.shadow-migration-input.v1";
const SHADOW_MIGRATION_REPORT_SCHEMA: &str = "chio.active-defense.shadow-migration-report.v1";
pub(crate) const BACKFILL_EVIDENCE_SCHEMA: &str = "chio.active-defense.backfill-evidence.v1";
pub(crate) const BACKFILL_METADATA_KEY: &str = "active_defense_backfill_v1";
const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
enum ShadowMigrationError {
    #[error("invalid active-defense migration input: {0}")]
    Invalid(String),
    #[error("active-defense migration I/O failed: {0}")]
    Io(String),
}

type MigrationResult<T> = Result<T, ShadowMigrationError>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ShadowMigrationInput {
    pub(crate) schema: String,
    pub(crate) manifest_public_keys: Vec<RegisteredPublicKey>,
    pub(crate) receipt_public_keys: Vec<RegisteredPublicKey>,
    pub(crate) manifests: Vec<ManifestRegistration>,
    pub(crate) backfill_targets: Vec<BackfillTarget>,
    pub(crate) backfill_receipts: Vec<RegisteredBackfillReceipt>,
    pub(crate) shadow_observations: Vec<ShadowObservation>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegisteredPublicKey {
    pub(crate) key_id: String,
    pub(crate) public_key: PublicKey,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManifestEnvelope {
    pub(crate) manifest: serde_json::Value,
    pub(crate) signature: Signature,
    pub(crate) signer_key: PublicKey,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManifestRegistration {
    pub(crate) registry_id: String,
    pub(crate) registered_key_id: String,
    pub(crate) signed_envelope: ManifestEnvelope,
    pub(crate) legacy_permission_amendment: Option<LegacyPermissionAmendment>,
    pub(crate) tools: Vec<ToolDeploymentInventory>,
    pub(crate) server_runtime: ServerRuntimeInventory,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LegacyPermissionAmendment {
    pub(crate) native_syscall_profile: NativeSyscallProfile,
    pub(crate) network_destinations: Vec<NetworkDestination>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ToolDeploymentInventory {
    pub(crate) tool_name: String,
    pub(crate) runtime_egress: bool,
    pub(crate) policy_clearances: Vec<InformationLabel>,
    pub(crate) policy_declassification_purposes: Vec<DeclassificationPurpose>,
    pub(crate) adapters: Vec<AdapterInventory>,
    pub(crate) direct_credential_grants: Vec<DirectCredentialGrant>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdapterInventory {
    pub(crate) adapter_id: String,
    pub(crate) preserves_exact_flow_declaration: bool,
    pub(crate) preserves_authenticated_extensions: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DirectCredentialGrant {
    EnvironmentVariable { name: String },
    File { path: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ServerRuntimeInventory {
    Managed,
    Native {
        selected_for_cage: bool,
        operator_ceiling: NativeCageCeiling,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeCageCeiling {
    pub(crate) read_paths: Vec<String>,
    pub(crate) write_paths: Vec<String>,
    pub(crate) network_destinations: Vec<NetworkDestination>,
    pub(crate) environment_variables: Vec<String>,
    pub(crate) native_syscall_profile: NativeSyscallProfile,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackfillTarget {
    pub(crate) tenant_id: String,
    pub(crate) principal_id: String,
    pub(crate) lineage_id: String,
    pub(crate) session_id: String,
    pub(crate) isolation_epoch_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegisteredBackfillReceipt {
    pub(crate) registered_key_id: String,
    pub(crate) receipt: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackfillEvidence {
    pub(crate) schema: String,
    pub(crate) manifest_registry_id: String,
    pub(crate) manifest_digest: String,
    pub(crate) tenant_id: String,
    pub(crate) principal_id: String,
    pub(crate) lineage_id: String,
    pub(crate) session_id: String,
    pub(crate) isolation_epoch_id: String,
    pub(crate) principal_label: InformationLabel,
    pub(crate) lineage_label: InformationLabel,
    pub(crate) session_label: InformationLabel,
    pub(crate) context_generation: u64,
    pub(crate) legacy_session_closed: bool,
}

impl BackfillEvidence {
    fn target(&self) -> BackfillTarget {
        BackfillTarget {
            tenant_id: self.tenant_id.clone(),
            principal_id: self.principal_id.clone(),
            lineage_id: self.lineage_id.clone(),
            session_id: self.session_id.clone(),
            isolation_epoch_id: self.isolation_epoch_id.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ShadowMetric {
    UnknownLabels,
    StoreErrors,
    LateEvents,
    StateEvictions,
    DecoyTouches,
    LineageTruncation,
    ProposedEffects,
    RollbackSimulation,
    FalsePositiveReview,
}

impl ShadowMetric {
    pub(crate) const ALL: [Self; 9] = [
        Self::UnknownLabels,
        Self::StoreErrors,
        Self::LateEvents,
        Self::StateEvictions,
        Self::DecoyTouches,
        Self::LineageTruncation,
        Self::ProposedEffects,
        Self::RollbackSimulation,
        Self::FalsePositiveReview,
    ];

    const fn metric_name(self) -> &'static str {
        match self {
            Self::UnknownLabels => "chio_active_defense_shadow_unknown_labels_total",
            Self::StoreErrors => "chio_active_defense_shadow_store_errors_total",
            Self::LateEvents => "chio_active_defense_shadow_late_events_total",
            Self::StateEvictions => "chio_active_defense_shadow_state_evictions_total",
            Self::DecoyTouches => "chio_active_defense_shadow_decoy_touches_total",
            Self::LineageTruncation => "chio_active_defense_shadow_lineage_truncation_total",
            Self::ProposedEffects => "chio_active_defense_shadow_proposed_effects_total",
            Self::RollbackSimulation => "chio_active_defense_shadow_rollback_simulation_total",
            Self::FalsePositiveReview => "chio_active_defense_shadow_false_positive_review_total",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ShadowObservation {
    pub(crate) metric: ShadowMetric,
    pub(crate) count: u64,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ManifestOutcome {
    VerifiedV2,
    VerifiedV1ConvertedToUnsignedV2,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ShadowMigrationReport {
    schema: &'static str,
    input_digest: String,
    pub(crate) manifests: Vec<ManifestInventoryReport>,
    pub(crate) unsigned_v2_artifacts: Vec<UnsignedV2Artifact>,
    pub(crate) egress_clearance_findings: Vec<EgressClearanceFinding>,
    pub(crate) unknown_output_declarations: Vec<ToolReference>,
    pub(crate) invalid_purpose_sets: Vec<InvalidPurposeFinding>,
    pub(crate) unsupported_adapters: Vec<UnsupportedAdapterFinding>,
    pub(crate) direct_credential_grants: Vec<DirectCredentialFinding>,
    pub(crate) native_cage_inventory: Vec<NativeCageInventoryReport>,
    pub(crate) verified_receipts: Vec<VerifiedReceiptReport>,
    pub(crate) backfill: BackfillReport,
    pub(crate) shadow_metrics: Vec<ShadowMetricReport>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManifestInventoryReport {
    registry_id: String,
    server_id: String,
    source_schema: String,
    registered_key_id: String,
    signer_public_key: String,
    canonical_manifest_digest: String,
    signed_envelope_digest: String,
    pub(crate) outcome: ManifestOutcome,
    operator_resigning_required: bool,
    unsigned_v2_digest: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnsignedV2Artifact {
    registry_id: String,
    source_manifest_digest: String,
    canonical_v2_digest: String,
    pub(crate) operator_resigning_required: bool,
    pub(crate) manifest: ToolManifest,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub(crate) struct ToolReference {
    registry_id: String,
    server_id: String,
    tool_name: String,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum EgressClearanceReason {
    MissingPolicyClearance,
    TopPolicyClearance,
}

#[derive(Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub(crate) struct EgressClearanceFinding {
    registry_id: String,
    server_id: String,
    tool_name: String,
    manifest_egress: bool,
    runtime_egress: bool,
    reason: EgressClearanceReason,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum InvalidPurposeReason {
    DuplicatePolicyPurpose,
    ManifestPurposeNotAuthorizedByPolicy,
    PolicyPurposeWithoutManifestDeclaration,
}

#[derive(Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub(crate) struct InvalidPurposeFinding {
    registry_id: String,
    server_id: String,
    tool_name: String,
    purpose: String,
    reason: InvalidPurposeReason,
}

#[derive(Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnsupportedAdapterFinding {
    registry_id: String,
    server_id: String,
    tool_name: String,
    adapter_id: String,
    preserves_exact_flow_declaration: bool,
    preserves_authenticated_extensions: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectCredentialFinding {
    registry_id: String,
    server_id: String,
    tool_name: String,
    grant: DirectCredentialGrant,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeCageInventoryReport {
    registry_id: String,
    server_id: String,
    pub(crate) selected_for_cage: bool,
    operator_ceiling: NativeCageCeiling,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VerifiedReceiptReport {
    receipt_id: String,
    registered_key_id: String,
    signer_public_key: String,
    canonical_receipt_digest: String,
    manifest_registry_id: String,
    manifest_digest: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BackfillReport {
    verified_evidence_receipts: usize,
    pub(crate) principal_records_from_verified_evidence: usize,
    pub(crate) principal_records_assigned_top: usize,
    lineage_records_from_verified_evidence: usize,
    lineage_records_assigned_top: usize,
    session_records_from_verified_evidence: usize,
    pub(crate) session_records_assigned_top: usize,
    pub(crate) principals: Vec<PrincipalBackfillRecord>,
    lineages: Vec<LineageBackfillRecord>,
    pub(crate) sessions: Vec<SessionBackfillRecord>,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrincipalBackfillRecord {
    tenant_id: String,
    principal_id: String,
    pub(crate) label: InformationLabel,
    context_generation: u64,
    evidence_receipt_ids: Vec<String>,
    pub(crate) assigned_top_due_to_missing_evidence: bool,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct LineageBackfillRecord {
    tenant_id: String,
    lineage_id: String,
    label: InformationLabel,
    context_generation: u64,
    evidence_receipt_ids: Vec<String>,
    assigned_top_due_to_missing_evidence: bool,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionBackfillRecord {
    tenant_id: String,
    principal_id: String,
    lineage_id: String,
    session_id: String,
    isolation_epoch_id: String,
    label: InformationLabel,
    context_generation: u64,
    evidence_receipt_ids: Vec<String>,
    assigned_top_due_to_missing_evidence: bool,
    pub(crate) legacy_session_closed: bool,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ShadowMetricReport {
    metric: ShadowMetric,
    metric_name: &'static str,
    pub(crate) count: u64,
}

#[derive(Debug)]
struct VerifiedManifest {
    registration: ManifestRegistration,
    manifest: ToolManifest,
    source_schema: String,
    source_manifest_digest: String,
    signed_envelope_digest: String,
    signed_v2: bool,
    unsigned_v2_digest: Option<String>,
}

#[derive(Debug)]
struct VerifiedBackfillEvidence {
    registered_key_id: String,
    receipt_id: String,
    signer_public_key: String,
    canonical_receipt_digest: String,
    evidence: BackfillEvidence,
}

pub(crate) fn cmd_shadow_migrate(input_path: &Path, output_path: &Path) -> Result<(), CliError> {
    let report = load_and_build_report(input_path)
        .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    let bytes = canonical_json_bytes(&report).map_err(|error| {
        CliError::cli_other_error(format!("failed to encode active-defense report: {error}"))
    })?;
    write_atomic(output_path, &bytes).map_err(|error| CliError::cli_io_error(error.to_string()))
}

fn load_and_build_report(path: &Path) -> MigrationResult<ShadowMigrationReport> {
    let metadata = fs::metadata(path).map_err(|error| {
        ShadowMigrationError::Io(format!("failed to inspect {}: {error}", path.display()))
    })?;
    if metadata.len() > MAX_INPUT_BYTES {
        return Err(ShadowMigrationError::Invalid(format!(
            "{} exceeds the {} byte input ceiling",
            path.display(),
            MAX_INPUT_BYTES
        )));
    }
    let bytes = fs::read(path).map_err(|error| {
        ShadowMigrationError::Io(format!("failed to read {}: {error}", path.display()))
    })?;
    let input = parse_shadow_migration_input(&bytes)?;
    build_shadow_migration_report(input)
}

fn parse_shadow_migration_input(bytes: &[u8]) -> MigrationResult<ShadowMigrationInput> {
    let text = std::str::from_utf8(bytes).map_err(|error| {
        ShadowMigrationError::Invalid(format!("input is not UTF-8 JSON: {error}"))
    })?;
    let canonical = canonical_json_bytes_from_str(text).map_err(|error| {
        ShadowMigrationError::Invalid(format!("input is not strict canonicalizable JSON: {error}"))
    })?;
    serde_json::from_slice(&canonical).map_err(|error| {
        ShadowMigrationError::Invalid(format!("input does not match the closed schema: {error}"))
    })
}

fn build_shadow_migration_report(
    input: ShadowMigrationInput,
) -> MigrationResult<ShadowMigrationReport> {
    if input.schema != SHADOW_MIGRATION_INPUT_SCHEMA {
        return Err(ShadowMigrationError::Invalid(format!(
            "unsupported schema {}",
            input.schema
        )));
    }
    if input.manifests.is_empty() {
        return Err(ShadowMigrationError::Invalid(
            "manifest registry inventory is empty".to_string(),
        ));
    }

    let input_digest = digest(&input, "migration input")?;
    let manifest_keys = validate_key_registry(&input.manifest_public_keys, "manifest")?;
    let receipt_keys = validate_key_registry(&input.receipt_public_keys, "receipt")?;

    let mut verified_manifests = Vec::with_capacity(input.manifests.len());
    let mut seen_registry_ids = BTreeSet::new();
    let mut seen_server_ids = BTreeSet::new();
    for registration in input.manifests {
        validate_identifier("manifest registry id", &registration.registry_id)?;
        if !seen_registry_ids.insert(registration.registry_id.clone()) {
            return Err(ShadowMigrationError::Invalid(format!(
                "duplicate manifest registry id {}",
                registration.registry_id
            )));
        }
        let registered_key = manifest_keys
            .get(&registration.registered_key_id)
            .ok_or_else(|| {
                ShadowMigrationError::Invalid(format!(
                    "manifest {} references unknown key {}",
                    registration.registry_id, registration.registered_key_id
                ))
            })?;
        let verified = verify_registered_manifest(registration, registered_key)?;
        if !seen_server_ids.insert(verified.manifest.server_id.clone()) {
            return Err(ShadowMigrationError::Invalid(format!(
                "duplicate registered server id {}",
                verified.manifest.server_id
            )));
        }
        verified_manifests.push(verified);
    }
    verified_manifests.sort_by(|left, right| {
        left.registration
            .registry_id
            .cmp(&right.registration.registry_id)
    });

    let targets = validate_backfill_targets(input.backfill_targets)?;
    let verified_receipt_evidence = verify_backfill_receipts(
        input.backfill_receipts,
        &receipt_keys,
        &verified_manifests,
        &targets,
    )?;
    let shadow_metrics = aggregate_shadow_metrics(input.shadow_observations)?;

    let mut manifests = Vec::new();
    let mut unsigned_v2_artifacts = Vec::new();
    let mut egress_clearance_findings = Vec::new();
    let mut unknown_output_declarations = Vec::new();
    let mut invalid_purpose_sets = Vec::new();
    let mut unsupported_adapters = Vec::new();
    let mut direct_credential_grants = Vec::new();
    let mut native_cage_inventory = Vec::new();

    for verified in &verified_manifests {
        inventory_manifest(
            verified,
            ManifestInventoryFindings {
                egress: &mut egress_clearance_findings,
                unknown_outputs: &mut unknown_output_declarations,
                invalid_purposes: &mut invalid_purpose_sets,
                unsupported_adapters: &mut unsupported_adapters,
                credential_grants: &mut direct_credential_grants,
                cage_inventory: &mut native_cage_inventory,
            },
        )?;
        let outcome = if verified.signed_v2 {
            ManifestOutcome::VerifiedV2
        } else {
            ManifestOutcome::VerifiedV1ConvertedToUnsignedV2
        };
        manifests.push(ManifestInventoryReport {
            registry_id: verified.registration.registry_id.clone(),
            server_id: verified.manifest.server_id.clone(),
            source_schema: verified.source_schema.clone(),
            registered_key_id: verified.registration.registered_key_id.clone(),
            signer_public_key: verified.registration.signed_envelope.signer_key.to_hex(),
            canonical_manifest_digest: verified.source_manifest_digest.clone(),
            signed_envelope_digest: verified.signed_envelope_digest.clone(),
            outcome,
            operator_resigning_required: !verified.signed_v2,
            unsigned_v2_digest: verified.unsigned_v2_digest.clone(),
        });
        if let Some(canonical_v2_digest) = &verified.unsigned_v2_digest {
            unsigned_v2_artifacts.push(UnsignedV2Artifact {
                registry_id: verified.registration.registry_id.clone(),
                source_manifest_digest: verified.source_manifest_digest.clone(),
                canonical_v2_digest: canonical_v2_digest.clone(),
                operator_resigning_required: true,
                manifest: verified.manifest.clone(),
            });
        }
    }

    egress_clearance_findings.sort();
    unknown_output_declarations.sort();
    invalid_purpose_sets.sort();
    unsupported_adapters.sort();
    direct_credential_grants.sort();
    native_cage_inventory.sort_by(|left, right| {
        (&left.registry_id, &left.server_id).cmp(&(&right.registry_id, &right.server_id))
    });

    let verified_receipts = verified_receipt_evidence
        .iter()
        .map(|verified| VerifiedReceiptReport {
            receipt_id: verified.receipt_id.clone(),
            registered_key_id: verified.registered_key_id.clone(),
            signer_public_key: verified.signer_public_key.clone(),
            canonical_receipt_digest: verified.canonical_receipt_digest.clone(),
            manifest_registry_id: verified.evidence.manifest_registry_id.clone(),
            manifest_digest: verified.evidence.manifest_digest.clone(),
        })
        .collect();
    let backfill = build_backfill_report(&targets, &verified_receipt_evidence)?;

    Ok(ShadowMigrationReport {
        schema: SHADOW_MIGRATION_REPORT_SCHEMA,
        input_digest,
        manifests,
        unsigned_v2_artifacts,
        egress_clearance_findings,
        unknown_output_declarations,
        invalid_purpose_sets,
        unsupported_adapters,
        direct_credential_grants,
        native_cage_inventory,
        verified_receipts,
        backfill,
        shadow_metrics,
    })
}

fn validate_key_registry(
    keys: &[RegisteredPublicKey],
    label: &str,
) -> MigrationResult<BTreeMap<String, PublicKey>> {
    let mut by_id = BTreeMap::new();
    let mut by_key = BTreeSet::new();
    for registered in keys {
        validate_identifier(&format!("{label} key id"), &registered.key_id)?;
        if registered.public_key.algorithm() != SigningAlgorithm::Ed25519 {
            return Err(ShadowMigrationError::Invalid(format!(
                "{label} key {} is not Ed25519",
                registered.key_id
            )));
        }
        if by_id
            .insert(registered.key_id.clone(), registered.public_key.clone())
            .is_some()
        {
            return Err(ShadowMigrationError::Invalid(format!(
                "duplicate {label} key id {}",
                registered.key_id
            )));
        }
        if !by_key.insert(registered.public_key.to_hex()) {
            return Err(ShadowMigrationError::Invalid(format!(
                "duplicate {label} public key {}",
                registered.public_key.to_hex()
            )));
        }
    }
    Ok(by_id)
}

fn verify_registered_manifest(
    registration: ManifestRegistration,
    registered_key: &PublicKey,
) -> MigrationResult<VerifiedManifest> {
    if registration.signed_envelope.signer_key != *registered_key {
        return Err(ShadowMigrationError::Invalid(format!(
            "manifest {} signer does not match registered key {}",
            registration.registry_id, registration.registered_key_id
        )));
    }
    if registration.signed_envelope.signature.algorithm() != SigningAlgorithm::Ed25519 {
        return Err(ShadowMigrationError::Invalid(format!(
            "manifest {} signature is not Ed25519",
            registration.registry_id
        )));
    }
    let valid = registered_key
        .verify_canonical(
            &registration.signed_envelope.manifest,
            &registration.signed_envelope.signature,
        )
        .map_err(|error| {
            ShadowMigrationError::Invalid(format!(
                "manifest {} signature verification failed: {error}",
                registration.registry_id
            ))
        })?;
    if !valid {
        return Err(ShadowMigrationError::Invalid(format!(
            "manifest {} signature is invalid",
            registration.registry_id
        )));
    }

    let source_schema = registration
        .signed_envelope
        .manifest
        .as_object()
        .and_then(|object| object.get("schema"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ShadowMigrationError::Invalid(format!(
                "manifest {} has no string schema",
                registration.registry_id
            ))
        })?
        .to_string();
    let source_manifest_digest = digest(
        &registration.signed_envelope.manifest,
        "signed manifest body",
    )?;
    let signed_envelope_digest = digest(&registration.signed_envelope, "manifest envelope")?;

    let (manifest, signed_v2, unsigned_v2_digest) = match source_schema.as_str() {
        TOOL_MANIFEST_SCHEMA => {
            if registration.legacy_permission_amendment.is_some() {
                return Err(ShadowMigrationError::Invalid(format!(
                    "v2 manifest {} supplies a legacy permission amendment",
                    registration.registry_id
                )));
            }
            let manifest: ToolManifest =
                strict_typed_value(&registration.signed_envelope.manifest, "v2 manifest body")?;
            let signed = SignedManifest {
                manifest: manifest.clone(),
                signature: registration.signed_envelope.signature.clone(),
                signer_key: registration.signed_envelope.signer_key.clone(),
            };
            verify_manifest(&signed, registered_key).map_err(|error| {
                ShadowMigrationError::Invalid(format!(
                    "v2 manifest {} failed verification: {error}",
                    registration.registry_id
                ))
            })?;
            (manifest, true, None)
        }
        "chio.manifest.v1" => {
            let canonical =
                canonical_json_bytes(&registration.signed_envelope.manifest).map_err(|error| {
                    ShadowMigrationError::Invalid(format!(
                        "v1 manifest {} canonicalization failed: {error}",
                        registration.registry_id
                    ))
                })?;
            let embedded_key = registration
                .signed_envelope
                .manifest
                .as_object()
                .and_then(|object| object.get("public_key"))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    ShadowMigrationError::Invalid(format!(
                        "v1 manifest {} has no embedded public key",
                        registration.registry_id
                    ))
                })?;
            if embedded_key != registered_key.to_hex() {
                return Err(ShadowMigrationError::Invalid(format!(
                    "v1 manifest {} embedded key does not match its registered signer",
                    registration.registry_id
                )));
            }
            let migration = migrate_legacy_manifest_v1(&canonical).map_err(|error| {
                ShadowMigrationError::Invalid(format!(
                    "v1 manifest {} cannot migrate: {error}",
                    registration.registry_id
                ))
            })?;
            let manifest = if migration.requires_permission_amendment() {
                let amendment = registration
                    .legacy_permission_amendment
                    .as_ref()
                    .ok_or_else(|| {
                        ShadowMigrationError::Invalid(format!(
                            "v1 manifest {} requires explicit destination ports and a native syscall profile",
                            registration.registry_id
                        ))
                    })?;
                migration
                    .amend_permissions(
                        amendment.native_syscall_profile,
                        amendment.network_destinations.clone(),
                    )
                    .map_err(|error| {
                        ShadowMigrationError::Invalid(format!(
                            "v1 manifest {} permission amendment is invalid: {error}",
                            registration.registry_id
                        ))
                    })?
            } else {
                if registration.legacy_permission_amendment.is_some() {
                    return Err(ShadowMigrationError::Invalid(format!(
                        "v1 manifest {} supplies an unnecessary permission amendment",
                        registration.registry_id
                    )));
                }
                migration.into_manifest().map_err(|error| {
                    ShadowMigrationError::Invalid(format!(
                        "v1 manifest {} conversion failed: {error}",
                        registration.registry_id
                    ))
                })?
            };
            if manifest.public_key != registered_key.to_hex() {
                return Err(ShadowMigrationError::Invalid(format!(
                    "converted manifest {} changed its embedded signer",
                    registration.registry_id
                )));
            }
            let unsigned_digest = digest(&manifest, "unsigned v2 manifest")?;
            (manifest, false, Some(unsigned_digest))
        }
        _ => {
            return Err(ShadowMigrationError::Invalid(format!(
                "manifest {} uses unsupported schema {}",
                registration.registry_id, source_schema
            )));
        }
    };

    validate_deployment_inventory(&registration, &manifest)?;
    validate_server_runtime(&registration.server_runtime)?;

    Ok(VerifiedManifest {
        registration,
        manifest,
        source_schema,
        source_manifest_digest,
        signed_envelope_digest,
        signed_v2,
        unsigned_v2_digest,
    })
}

fn validate_deployment_inventory(
    registration: &ManifestRegistration,
    manifest: &ToolManifest,
) -> MigrationResult<()> {
    let manifest_tools = manifest
        .tools
        .iter()
        .map(|tool| tool.name.clone())
        .collect::<BTreeSet<_>>();
    let mut deployment_tools = BTreeSet::new();
    for deployment in &registration.tools {
        validate_identifier("deployment tool name", &deployment.tool_name)?;
        if !deployment_tools.insert(deployment.tool_name.clone()) {
            return Err(ShadowMigrationError::Invalid(format!(
                "manifest {} repeats deployment inventory for tool {}",
                registration.registry_id, deployment.tool_name
            )));
        }
        let mut adapter_ids = BTreeSet::new();
        for adapter in &deployment.adapters {
            validate_identifier("adapter id", &adapter.adapter_id)?;
            if !adapter_ids.insert(adapter.adapter_id.clone()) {
                return Err(ShadowMigrationError::Invalid(format!(
                    "manifest {} tool {} repeats adapter {}",
                    registration.registry_id, deployment.tool_name, adapter.adapter_id
                )));
            }
        }
        let mut grants = BTreeSet::new();
        for grant in &deployment.direct_credential_grants {
            validate_credential_grant(grant)?;
            if !grants.insert(grant.clone()) {
                return Err(ShadowMigrationError::Invalid(format!(
                    "manifest {} tool {} repeats a direct credential grant",
                    registration.registry_id, deployment.tool_name
                )));
            }
        }
    }
    if manifest_tools != deployment_tools {
        return Err(ShadowMigrationError::Invalid(format!(
            "manifest {} deployment inventory does not cover exactly its signed tool set",
            registration.registry_id
        )));
    }
    Ok(())
}

fn validate_credential_grant(grant: &DirectCredentialGrant) -> MigrationResult<()> {
    match grant {
        DirectCredentialGrant::EnvironmentVariable { name } => {
            validate_identifier("credential environment variable", name)?;
            let mut bytes = name.bytes();
            let valid_start = bytes.next().is_some_and(|byte| {
                byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_lowercase()
            });
            let valid_rest = bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric());
            if !valid_start || !valid_rest {
                return Err(ShadowMigrationError::Invalid(format!(
                    "credential environment variable {name} is invalid"
                )));
            }
        }
        DirectCredentialGrant::File { path } => validate_path("credential file", path)?,
    }
    Ok(())
}

fn validate_server_runtime(runtime: &ServerRuntimeInventory) -> MigrationResult<()> {
    let ServerRuntimeInventory::Native {
        operator_ceiling, ..
    } = runtime
    else {
        return Ok(());
    };
    validate_distinct_paths("cage read path", &operator_ceiling.read_paths)?;
    validate_distinct_paths("cage write path", &operator_ceiling.write_paths)?;
    let mut destinations = BTreeSet::new();
    for destination in &operator_ceiling.network_destinations {
        let key = (destination.host().as_str().to_string(), destination.port());
        if !destinations.insert(key.clone()) {
            return Err(ShadowMigrationError::Invalid(format!(
                "duplicate cage network destination {}:{}",
                key.0, key.1
            )));
        }
    }
    let mut environment_variables = BTreeSet::new();
    for name in &operator_ceiling.environment_variables {
        validate_identifier("cage environment variable", name)?;
        if !environment_variables.insert(name.clone()) {
            return Err(ShadowMigrationError::Invalid(format!(
                "duplicate cage environment variable {name}"
            )));
        }
    }
    Ok(())
}

fn validate_distinct_paths(label: &str, paths: &[String]) -> MigrationResult<()> {
    let mut seen = BTreeSet::new();
    for path in paths {
        validate_path(label, path)?;
        if !seen.insert(path.clone()) {
            return Err(ShadowMigrationError::Invalid(format!(
                "duplicate {label} {path}"
            )));
        }
    }
    Ok(())
}

fn validate_path(label: &str, path: &str) -> MigrationResult<()> {
    if path.is_empty()
        || path.trim() != path
        || path.chars().any(char::is_control)
        || !Path::new(path).is_absolute()
    {
        return Err(ShadowMigrationError::Invalid(format!(
            "{label} must be a canonical absolute path: {path}"
        )));
    }
    Ok(())
}

struct ManifestInventoryFindings<'findings> {
    egress: &'findings mut Vec<EgressClearanceFinding>,
    unknown_outputs: &'findings mut Vec<ToolReference>,
    invalid_purposes: &'findings mut Vec<InvalidPurposeFinding>,
    unsupported_adapters: &'findings mut Vec<UnsupportedAdapterFinding>,
    credential_grants: &'findings mut Vec<DirectCredentialFinding>,
    cage_inventory: &'findings mut Vec<NativeCageInventoryReport>,
}

fn inventory_manifest(
    verified: &VerifiedManifest,
    findings: ManifestInventoryFindings<'_>,
) -> MigrationResult<()> {
    let ManifestInventoryFindings {
        egress,
        unknown_outputs,
        invalid_purposes,
        unsupported_adapters,
        credential_grants,
        cage_inventory,
    } = findings;
    let deployments = verified
        .registration
        .tools
        .iter()
        .map(|deployment| (deployment.tool_name.as_str(), deployment))
        .collect::<BTreeMap<_, _>>();
    for tool in &verified.manifest.tools {
        let deployment = deployments.get(tool.name.as_str()).ok_or_else(|| {
            ShadowMigrationError::Invalid(format!(
                "manifest {} lost deployment inventory for {}",
                verified.registration.registry_id, tool.name
            ))
        })?;
        let reference = ToolReference {
            registry_id: verified.registration.registry_id.clone(),
            server_id: verified.manifest.server_id.clone(),
            tool_name: tool.name.clone(),
        };
        let manifest_egress = tool.flow.as_ref().is_some_and(|flow| flow.egress);
        if manifest_egress || deployment.runtime_egress {
            if deployment.policy_clearances.is_empty() {
                egress.push(EgressClearanceFinding {
                    registry_id: reference.registry_id.clone(),
                    server_id: reference.server_id.clone(),
                    tool_name: reference.tool_name.clone(),
                    manifest_egress,
                    runtime_egress: deployment.runtime_egress,
                    reason: EgressClearanceReason::MissingPolicyClearance,
                });
            } else if deployment
                .policy_clearances
                .contains(&InformationLabel::Top)
            {
                egress.push(EgressClearanceFinding {
                    registry_id: reference.registry_id.clone(),
                    server_id: reference.server_id.clone(),
                    tool_name: reference.tool_name.clone(),
                    manifest_egress,
                    runtime_egress: deployment.runtime_egress,
                    reason: EgressClearanceReason::TopPolicyClearance,
                });
            }
        }
        if tool
            .flow
            .as_ref()
            .and_then(|flow| flow.output_label.as_ref())
            .is_none()
        {
            unknown_outputs.push(reference.clone());
        }
        inventory_purposes(verified, tool, deployment, invalid_purposes);
        for adapter in &deployment.adapters {
            if !adapter.preserves_exact_flow_declaration
                || !adapter.preserves_authenticated_extensions
            {
                unsupported_adapters.push(UnsupportedAdapterFinding {
                    registry_id: reference.registry_id.clone(),
                    server_id: reference.server_id.clone(),
                    tool_name: reference.tool_name.clone(),
                    adapter_id: adapter.adapter_id.clone(),
                    preserves_exact_flow_declaration: adapter.preserves_exact_flow_declaration,
                    preserves_authenticated_extensions: adapter.preserves_authenticated_extensions,
                });
            }
        }
        for grant in &deployment.direct_credential_grants {
            credential_grants.push(DirectCredentialFinding {
                registry_id: reference.registry_id.clone(),
                server_id: reference.server_id.clone(),
                tool_name: reference.tool_name.clone(),
                grant: grant.clone(),
            });
        }
    }
    if let ServerRuntimeInventory::Native {
        selected_for_cage,
        operator_ceiling,
    } = &verified.registration.server_runtime
    {
        let mut operator_ceiling = operator_ceiling.clone();
        operator_ceiling.read_paths.sort();
        operator_ceiling.write_paths.sort();
        operator_ceiling
            .network_destinations
            .sort_by(|left, right| {
                (left.host().as_str(), left.port()).cmp(&(right.host().as_str(), right.port()))
            });
        operator_ceiling.environment_variables.sort();
        cage_inventory.push(NativeCageInventoryReport {
            registry_id: verified.registration.registry_id.clone(),
            server_id: verified.manifest.server_id.clone(),
            selected_for_cage: *selected_for_cage,
            operator_ceiling,
        });
    }
    Ok(())
}

fn inventory_purposes(
    verified: &VerifiedManifest,
    tool: &chio_manifest::ToolDefinition,
    deployment: &ToolDeploymentInventory,
    findings: &mut Vec<InvalidPurposeFinding>,
) {
    let mut policy_purposes = BTreeSet::new();
    for purpose in &deployment.policy_declassification_purposes {
        if !policy_purposes.insert(purpose.as_str().to_string()) {
            findings.push(InvalidPurposeFinding {
                registry_id: verified.registration.registry_id.clone(),
                server_id: verified.manifest.server_id.clone(),
                tool_name: tool.name.clone(),
                purpose: purpose.as_str().to_string(),
                reason: InvalidPurposeReason::DuplicatePolicyPurpose,
            });
        }
    }
    let manifest_purposes = tool
        .flow
        .as_ref()
        .map(|flow| {
            flow.declassification_purposes
                .iter()
                .map(|purpose| purpose.as_str().to_string())
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    for purpose in manifest_purposes.difference(&policy_purposes) {
        findings.push(InvalidPurposeFinding {
            registry_id: verified.registration.registry_id.clone(),
            server_id: verified.manifest.server_id.clone(),
            tool_name: tool.name.clone(),
            purpose: purpose.clone(),
            reason: InvalidPurposeReason::ManifestPurposeNotAuthorizedByPolicy,
        });
    }
    if tool.flow.is_none() {
        for purpose in policy_purposes {
            findings.push(InvalidPurposeFinding {
                registry_id: verified.registration.registry_id.clone(),
                server_id: verified.manifest.server_id.clone(),
                tool_name: tool.name.clone(),
                purpose,
                reason: InvalidPurposeReason::PolicyPurposeWithoutManifestDeclaration,
            });
        }
    }
}

fn validate_backfill_targets(
    targets: Vec<BackfillTarget>,
) -> MigrationResult<BTreeSet<BackfillTarget>> {
    let mut validated = BTreeSet::new();
    for target in targets {
        validate_identifier("backfill tenant id", &target.tenant_id)?;
        validate_identifier("backfill principal id", &target.principal_id)?;
        validate_identifier("backfill lineage id", &target.lineage_id)?;
        validate_identifier("backfill session id", &target.session_id)?;
        validate_identifier("backfill isolation epoch id", &target.isolation_epoch_id)?;
        if !validated.insert(target.clone()) {
            return Err(ShadowMigrationError::Invalid(format!(
                "duplicate backfill target {}:{}:{}:{}:{}",
                target.tenant_id,
                target.principal_id,
                target.lineage_id,
                target.session_id,
                target.isolation_epoch_id
            )));
        }
    }
    Ok(validated)
}

fn verify_backfill_receipts(
    receipts: Vec<RegisteredBackfillReceipt>,
    receipt_keys: &BTreeMap<String, PublicKey>,
    manifests: &[VerifiedManifest],
    targets: &BTreeSet<BackfillTarget>,
) -> MigrationResult<Vec<VerifiedBackfillEvidence>> {
    let manifest_by_id = manifests
        .iter()
        .map(|manifest| (manifest.registration.registry_id.as_str(), manifest))
        .collect::<BTreeMap<_, _>>();
    let mut verified = Vec::with_capacity(receipts.len());
    let mut seen_receipt_ids = BTreeSet::new();
    for registered in receipts {
        let registered_key = receipt_keys
            .get(&registered.registered_key_id)
            .ok_or_else(|| {
                ShadowMigrationError::Invalid(format!(
                    "backfill receipt references unknown key {}",
                    registered.registered_key_id
                ))
            })?;
        let receipt: ChioReceipt = strict_typed_value(&registered.receipt, "backfill receipt")?;
        if receipt.kernel_key != *registered_key {
            return Err(ShadowMigrationError::Invalid(format!(
                "receipt {} signer does not match registered key {}",
                receipt.id, registered.registered_key_id
            )));
        }
        let signature_valid = receipt.verify_signature().map_err(|error| {
            ShadowMigrationError::Invalid(format!(
                "receipt {} signature verification failed: {error}",
                receipt.id
            ))
        })?;
        if !signature_valid {
            return Err(ShadowMigrationError::Invalid(format!(
                "receipt {} signature is invalid",
                receipt.id
            )));
        }
        if !receipt.action.verify_hash().map_err(|error| {
            ShadowMigrationError::Invalid(format!(
                "receipt {} parameter hash verification failed: {error}",
                receipt.id
            ))
        })? {
            return Err(ShadowMigrationError::Invalid(format!(
                "receipt {} parameter hash is invalid",
                receipt.id
            )));
        }
        if !seen_receipt_ids.insert(receipt.id.clone()) {
            return Err(ShadowMigrationError::Invalid(format!(
                "duplicate backfill receipt {}",
                receipt.id
            )));
        }
        let evidence_value = receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get(BACKFILL_METADATA_KEY))
            .ok_or_else(|| {
                ShadowMigrationError::Invalid(format!(
                    "receipt {} has no signed backfill evidence",
                    receipt.id
                ))
            })?;
        let evidence: BackfillEvidence =
            strict_typed_value(evidence_value, "signed backfill evidence")?;
        if evidence.schema != BACKFILL_EVIDENCE_SCHEMA {
            return Err(ShadowMigrationError::Invalid(format!(
                "receipt {} has unsupported backfill evidence schema {}",
                receipt.id, evidence.schema
            )));
        }
        validate_backfill_evidence_identifiers(&evidence)?;
        if receipt.tenant_id.as_deref() != Some(evidence.tenant_id.as_str()) {
            return Err(ShadowMigrationError::Invalid(format!(
                "receipt {} tenant does not match signed backfill evidence",
                receipt.id
            )));
        }
        if !targets.contains(&evidence.target()) {
            return Err(ShadowMigrationError::Invalid(format!(
                "receipt {} references an unregistered backfill target",
                receipt.id
            )));
        }
        let source_manifest = manifest_by_id
            .get(evidence.manifest_registry_id.as_str())
            .ok_or_else(|| {
                ShadowMigrationError::Invalid(format!(
                    "receipt {} references unknown manifest {}",
                    receipt.id, evidence.manifest_registry_id
                ))
            })?;
        if !source_manifest.signed_v2 {
            return Err(ShadowMigrationError::Invalid(format!(
                "receipt {} references an unsigned migrated v2 manifest",
                receipt.id
            )));
        }
        if evidence.manifest_digest != source_manifest.source_manifest_digest {
            return Err(ShadowMigrationError::Invalid(format!(
                "receipt {} manifest digest does not match the verified registry entry",
                receipt.id
            )));
        }
        if receipt.tool_server != source_manifest.manifest.server_id
            || !source_manifest
                .manifest
                .tools
                .iter()
                .any(|tool| tool.name == receipt.tool_name)
        {
            return Err(ShadowMigrationError::Invalid(format!(
                "receipt {} tool identity is absent from its verified v2 manifest",
                receipt.id
            )));
        }
        let canonical_receipt_digest = digest(&receipt, "backfill receipt")?;
        verified.push(VerifiedBackfillEvidence {
            registered_key_id: registered.registered_key_id,
            receipt_id: receipt.id,
            signer_public_key: registered_key.to_hex(),
            canonical_receipt_digest,
            evidence,
        });
    }
    verified.sort_by(|left, right| left.receipt_id.cmp(&right.receipt_id));
    Ok(verified)
}

fn validate_backfill_evidence_identifiers(evidence: &BackfillEvidence) -> MigrationResult<()> {
    validate_identifier(
        "backfill manifest registry id",
        &evidence.manifest_registry_id,
    )?;
    validate_digest("backfill manifest digest", &evidence.manifest_digest)?;
    validate_identifier("backfill tenant id", &evidence.tenant_id)?;
    validate_identifier("backfill principal id", &evidence.principal_id)?;
    validate_identifier("backfill lineage id", &evidence.lineage_id)?;
    validate_identifier("backfill session id", &evidence.session_id)?;
    validate_identifier("backfill isolation epoch id", &evidence.isolation_epoch_id)
}

fn build_backfill_report(
    targets: &BTreeSet<BackfillTarget>,
    evidence: &[VerifiedBackfillEvidence],
) -> MigrationResult<BackfillReport> {
    let mut by_target: BTreeMap<BackfillTarget, Vec<&VerifiedBackfillEvidence>> = targets
        .iter()
        .cloned()
        .map(|target| (target, Vec::new()))
        .collect();
    for item in evidence {
        let target = item.evidence.target();
        let entries = by_target.get_mut(&target).ok_or_else(|| {
            ShadowMigrationError::Invalid("verified evidence lost its backfill target".to_string())
        })?;
        entries.push(item);
    }

    let mut principal_groups: BTreeMap<(String, String), Vec<&BackfillTarget>> = BTreeMap::new();
    let mut lineage_groups: BTreeMap<(String, String), Vec<&BackfillTarget>> = BTreeMap::new();
    for target in targets {
        principal_groups
            .entry((target.tenant_id.clone(), target.principal_id.clone()))
            .or_default()
            .push(target);
        lineage_groups
            .entry((target.tenant_id.clone(), target.lineage_id.clone()))
            .or_default()
            .push(target);
    }

    let mut principals = Vec::with_capacity(principal_groups.len());
    for ((tenant_id, principal_id), group_targets) in principal_groups {
        let missing = group_targets
            .iter()
            .any(|target| by_target.get(*target).is_none_or(Vec::is_empty));
        let group_evidence = group_targets
            .iter()
            .filter_map(|target| by_target.get(*target))
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        let label = if missing {
            InformationLabel::Top
        } else {
            join_labels(
                group_evidence
                    .iter()
                    .map(|item| &item.evidence.principal_label),
            )?
        };
        principals.push(PrincipalBackfillRecord {
            tenant_id,
            principal_id,
            label,
            context_generation: max_context_generation(&group_evidence),
            evidence_receipt_ids: evidence_ids(&group_evidence),
            assigned_top_due_to_missing_evidence: missing,
        });
    }

    let mut lineages = Vec::with_capacity(lineage_groups.len());
    for ((tenant_id, lineage_id), group_targets) in lineage_groups {
        let missing = group_targets
            .iter()
            .any(|target| by_target.get(*target).is_none_or(Vec::is_empty));
        let group_evidence = group_targets
            .iter()
            .filter_map(|target| by_target.get(*target))
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        let label = if missing {
            InformationLabel::Top
        } else {
            join_labels(
                group_evidence
                    .iter()
                    .map(|item| &item.evidence.lineage_label),
            )?
        };
        lineages.push(LineageBackfillRecord {
            tenant_id,
            lineage_id,
            label,
            context_generation: max_context_generation(&group_evidence),
            evidence_receipt_ids: evidence_ids(&group_evidence),
            assigned_top_due_to_missing_evidence: missing,
        });
    }

    let mut sessions = Vec::with_capacity(targets.len());
    for target in targets {
        let target_evidence = by_target.get(target).ok_or_else(|| {
            ShadowMigrationError::Invalid("backfill target inventory changed".to_string())
        })?;
        let missing = target_evidence.is_empty();
        let label = if missing {
            InformationLabel::Top
        } else {
            join_labels(
                target_evidence
                    .iter()
                    .map(|item| &item.evidence.session_label),
            )?
        };
        sessions.push(SessionBackfillRecord {
            tenant_id: target.tenant_id.clone(),
            principal_id: target.principal_id.clone(),
            lineage_id: target.lineage_id.clone(),
            session_id: target.session_id.clone(),
            isolation_epoch_id: target.isolation_epoch_id.clone(),
            label,
            context_generation: max_context_generation(target_evidence),
            evidence_receipt_ids: evidence_ids(target_evidence),
            assigned_top_due_to_missing_evidence: missing,
            legacy_session_closed: target_evidence
                .iter()
                .any(|item| item.evidence.legacy_session_closed),
        });
    }

    let principal_records_assigned_top = principals
        .iter()
        .filter(|record| record.assigned_top_due_to_missing_evidence)
        .count();
    let lineage_records_assigned_top = lineages
        .iter()
        .filter(|record| record.assigned_top_due_to_missing_evidence)
        .count();
    let session_records_assigned_top = sessions
        .iter()
        .filter(|record| record.assigned_top_due_to_missing_evidence)
        .count();
    Ok(BackfillReport {
        verified_evidence_receipts: evidence.len(),
        principal_records_from_verified_evidence: principals.len() - principal_records_assigned_top,
        principal_records_assigned_top,
        lineage_records_from_verified_evidence: lineages.len() - lineage_records_assigned_top,
        lineage_records_assigned_top,
        session_records_from_verified_evidence: sessions.len() - session_records_assigned_top,
        session_records_assigned_top,
        principals,
        lineages,
        sessions,
    })
}

fn join_labels<'a>(
    labels: impl IntoIterator<Item = &'a InformationLabel>,
) -> MigrationResult<InformationLabel> {
    let mut joined = InformationLabel::bottom();
    for label in labels {
        joined = joined.join_restrictions(label).map_err(|error| {
            ShadowMigrationError::Invalid(format!("backfill label join failed: {error}"))
        })?;
    }
    Ok(joined)
}

fn max_context_generation(evidence: &[&VerifiedBackfillEvidence]) -> u64 {
    evidence
        .iter()
        .map(|item| item.evidence.context_generation)
        .max()
        .unwrap_or(0)
}

fn evidence_ids(evidence: &[&VerifiedBackfillEvidence]) -> Vec<String> {
    let mut ids = evidence
        .iter()
        .map(|item| item.receipt_id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

fn aggregate_shadow_metrics(
    observations: Vec<ShadowObservation>,
) -> MigrationResult<Vec<ShadowMetricReport>> {
    let mut counts = BTreeMap::new();
    for observation in observations {
        let current = counts.entry(observation.metric).or_insert(0_u64);
        *current = current.checked_add(observation.count).ok_or_else(|| {
            ShadowMigrationError::Invalid(format!(
                "shadow metric {} count overflow",
                observation.metric.metric_name()
            ))
        })?;
    }
    Ok(ShadowMetric::ALL
        .into_iter()
        .map(|metric| ShadowMetricReport {
            metric,
            metric_name: metric.metric_name(),
            count: counts.get(&metric).copied().unwrap_or(0),
        })
        .collect())
}

fn strict_typed_value<T>(value: &serde_json::Value, label: &str) -> MigrationResult<T>
where
    T: DeserializeOwned + Serialize,
{
    let typed = serde_json::from_value::<T>(value.clone())
        .map_err(|error| ShadowMigrationError::Invalid(format!("{label} is invalid: {error}")))?;
    let source = canonical_json_bytes(value).map_err(|error| {
        ShadowMigrationError::Invalid(format!("{label} canonicalization failed: {error}"))
    })?;
    let typed_bytes = canonical_json_bytes(&typed).map_err(|error| {
        ShadowMigrationError::Invalid(format!("typed {label} canonicalization failed: {error}"))
    })?;
    if source != typed_bytes {
        return Err(ShadowMigrationError::Invalid(format!(
            "{label} contains unknown, explicit-default, or noncanonical fields"
        )));
    }
    Ok(typed)
}

fn digest<T: Serialize>(value: &T, label: &str) -> MigrationResult<String> {
    let canonical = canonical_json_bytes(value).map_err(|error| {
        ShadowMigrationError::Invalid(format!("{label} canonicalization failed: {error}"))
    })?;
    Ok(sha256_hex(&canonical))
}

fn validate_digest(label: &str, value: &str) -> MigrationResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ShadowMigrationError::Invalid(format!(
            "{label} is not a lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

fn validate_identifier(label: &str, value: &str) -> MigrationResult<()> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ShadowMigrationError::Invalid(format!(
            "{label} is not a bounded canonical identifier"
        )));
    }
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> MigrationResult<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.is_dir() {
        return Err(ShadowMigrationError::Io(format!(
            "output directory {} does not exist",
            parent.display()
        )));
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            ShadowMigrationError::Io(format!(
                "output path {} has no UTF-8 file name",
                path.display()
            ))
        })?;
    let mut last_error = None;
    for attempt in 0_u16..=1024 {
        let temporary = parent.join(format!(".{file_name}.chio-atomic.{attempt}",));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(mut file) => {
                let result = (|| -> std::io::Result<()> {
                    file.write_all(bytes)?;
                    file.sync_all()?;
                    fs::rename(&temporary, path)?;
                    FileSync::sync_directory(parent)?;
                    Ok(())
                })();
                if let Err(error) = result {
                    let _ = fs::remove_file(&temporary);
                    return Err(ShadowMigrationError::Io(format!(
                        "failed to atomically write {}: {error}",
                        path.display()
                    )));
                }
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_error = Some(error);
            }
            Err(error) => {
                return Err(ShadowMigrationError::Io(format!(
                    "failed to create an atomic output beside {}: {error}",
                    path.display()
                )));
            }
        }
    }
    Err(ShadowMigrationError::Io(format!(
        "failed to allocate an atomic output beside {}: {}",
        path.display(),
        last_error
            .map(|error| error.to_string())
            .unwrap_or_else(|| "temporary name space exhausted".to_string())
    )))
}

struct FileSync;

impl FileSync {
    #[cfg(unix)]
    fn sync_directory(path: &Path) -> std::io::Result<()> {
        fs::File::open(path)?.sync_all()
    }

    #[cfg(not(unix))]
    fn sync_directory(_path: &Path) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "active_defense_migration_tests.rs"]
mod tests;
