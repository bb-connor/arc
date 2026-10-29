//! Offline verification of an evidence package against a verifier-owned
//! trust file.
//!
//! Every key the verifier accepts comes from the trust file. Nothing in the
//! package selects a key, an algorithm or a schema, and no check reads a
//! clock.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::PublicKey;
use chio_core_types::hashing::sha256_hex;
use chio_core_types::receipt::body::{chio_receipt_id, ChioReceipt};
use chio_core_types::receipt::checkpoint::{
    is_supported_checkpoint_schema, CheckpointTransparencySummary, KernelCheckpoint,
    ReceiptInclusionProof,
};
use chio_core_types::receipt::crypto_floor::ReceiptCryptoFloor;
use chio_core_types::receipt::evidence::{
    CapabilitySnapshot, EvidenceChildReceiptRecord, EvidenceChildReceiptScope,
    EvidenceDisclosureNotice, EvidenceExportBundle, EvidenceExportManifest, EvidenceExportQuery,
    EvidenceImportPackage, EvidencePackageEnvelope, EvidenceReceiptSemanticSummary,
    EvidenceToolReceiptRecord, EvidenceTransparencyClaims, FederationPolicyDocument,
    PolicyAttachmentMetadata, ReceiptReadBoundary, EVIDENCE_EXPORT_COMMITMENT_SCHEMA,
    EVIDENCE_EXPORT_MANIFEST_SCHEMA,
};
use chio_core_types::receipt::kinds::{BoundaryClass, ReceiptKind};
use chio_core_types::root_authority::VerifierTrust;
use chio_kernel_core::evidence_verify::{
    build_evidence_transparency_claims, checkpoint_body_sha256, validate_checkpoint_transparency,
    verify_checkpoint_signature, verify_checkpoint_transparency_records, CheckpointError,
    VerifiedCheckpoint,
};

use crate::error::BundleVerifyError;
use crate::federation::{ensure_query_within_federation_policy, verify_federation_policy};
use crate::package::{
    manifest_sha256, payload_sha256, verify_inventory, CAPABILITY_LINEAGE_FILE, CHECKPOINTS_FILE,
    CHILD_RECEIPTS_FILE, CONSISTENCY_PROOFS_FILE, ENVELOPE_FILE, EQUIVOCATIONS_FILE,
    FEDERATION_POLICY_FILE, INCLUSION_PROOFS_FILE, MANIFEST_FILE, POLICY_METADATA_FILE,
    PUBLICATIONS_FILE, QUERY_FILE, RECEIPTS_FILE, RETENTION_FILE, UNCHECKPOINTED_FILE,
    WITNESSES_FILE,
};
use crate::read::{read_bytes, read_json, read_ndjson};

/// Metadata key of an HTTP receipt embedded in a tool receipt.
pub const EMBEDDED_HTTP_RECEIPT_KEY: &str = "chio_http_receipt_v1";

/// Why an embedded HTTP receipt is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmbeddedHttpError {
    /// The embedded value does not decode as an HTTP receipt.
    Decode(String),
    /// The HTTP receipt's projection check could not run.
    Projection(String),
}

/// Checks that an embedded HTTP receipt is signed and projects exactly onto
/// the tool receipt carrying it.
pub trait EmbeddedHttpReceiptVerifier {
    fn verify_projection(
        &self,
        embedded: &serde_json::Value,
        receipt: &ChioReceipt,
    ) -> Result<bool, EmbeddedHttpError>;
}

/// A package whose every signature, digest and cross-reference verified.
#[derive(Debug, Clone)]
pub struct VerifiedPackage {
    pub package: EvidenceImportPackage,
    /// Transparency records checked against the signed checkpoints, with
    /// valid trust-anchor bindings kept.
    pub transparency: CheckpointTransparencySummary,
    pub claims: EvidenceTransparencyClaims,
    pub manifest_sha256: String,
}

fn load_trust(trust: &VerifierTrust) -> Result<(), BundleVerifyError> {
    trust
        .validate()
        .map_err(|error| BundleVerifyError::trust_invalid(error.to_string()))
}

fn require_kernel_signer(trust: &VerifierTrust, key: &PublicKey) -> Result<(), BundleVerifyError> {
    if !trust.is_kernel_key(key) {
        return Err(BundleVerifyError::trust_missing(
            "evidence signer is outside the trusted kernel key set",
        ));
    }
    Ok(())
}

/// Read a package directory and verify it. Receipts that embed an HTTP
/// receipt refuse as unsupported unless `embedded_http` is supplied.
pub fn verify_package(
    dir: &Path,
    trust: &VerifierTrust,
    embedded_http: Option<&dyn EmbeddedHttpReceiptVerifier>,
) -> Result<VerifiedPackage, BundleVerifyError> {
    load_trust(trust)?;
    let package = read_package(dir)?;
    let (transparency, claims) = verify_decoded_package(&package, trust, embedded_http)?;
    let manifest_sha256 = manifest_sha256(&package.manifest)?;
    Ok(VerifiedPackage {
        package,
        transparency,
        claims,
        manifest_sha256,
    })
}

/// Read every file of a package directory. Checks the inventory, each file's
/// digest and length and the policy attachment; signatures and trust are
/// [`verify_decoded_package`]'s.
pub fn read_package(dir: &Path) -> Result<EvidenceImportPackage, BundleVerifyError> {
    match std::fs::metadata(dir) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {
            return Err(BundleVerifyError::io(format!(
                "evidence package path must be a directory: {}",
                dir.display()
            )))
        }
        Err(error) => {
            return Err(BundleVerifyError::io(format!(
                "evidence package directory cannot be read: {}: {error}",
                dir.display()
            )))
        }
    }
    let envelope: EvidencePackageEnvelope = match read_bytes(dir, ENVELOPE_FILE) {
        Ok(bytes) => crate::read::decode_strict(ENVELOPE_FILE, "EvidencePackageEnvelope", &bytes)?,
        Err(error) => {
            return Err(BundleVerifyError::envelope(format!(
                "invalid or missing evidence export envelope: {error}"
            )))
        }
    };
    let manifest: EvidenceExportManifest = read_json(dir, MANIFEST_FILE, "EvidenceExportManifest")?;
    verify_inventory(&manifest)?;
    verify_manifest_file_hashes(dir, &manifest)?;
    verify_policy_attachment(dir, &manifest)?;
    let bundle = EvidenceExportBundle {
        query: read_json(dir, QUERY_FILE, "EvidenceExportQuery")?,
        tool_receipts: read_ndjson(dir, RECEIPTS_FILE, "EvidenceToolReceiptRecord")?,
        child_receipts: read_ndjson(dir, CHILD_RECEIPTS_FILE, "EvidenceChildReceiptRecord")?,
        child_receipt_scope: manifest.child_receipt_scope,
        checkpoints: read_ndjson(dir, CHECKPOINTS_FILE, "KernelCheckpoint")?,
        capability_lineage: read_ndjson(dir, CAPABILITY_LINEAGE_FILE, "CapabilitySnapshot")?,
        inclusion_proofs: read_ndjson(dir, INCLUSION_PROOFS_FILE, "ReceiptInclusionProof")?,
        uncheckpointed_receipts: read_ndjson(
            dir,
            UNCHECKPOINTED_FILE,
            "EvidenceUncheckpointedReceipt",
        )?,
        retention: read_json(dir, RETENTION_FILE, "EvidenceRetentionMetadata")?,
    };
    let transparency = Some(CheckpointTransparencySummary {
        publications: read_ndjson(dir, PUBLICATIONS_FILE, "CheckpointPublication")?,
        witnesses: read_ndjson(dir, WITNESSES_FILE, "CheckpointWitness")?,
        consistency_proofs: read_ndjson(
            dir,
            CONSISTENCY_PROOFS_FILE,
            "CheckpointConsistencyProof",
        )?,
        equivocations: read_ndjson(dir, EQUIVOCATIONS_FILE, "CheckpointEquivocation")?,
    });
    let federation_policy = if manifest.federation_policy.is_some() {
        Some(read_json::<FederationPolicyDocument>(
            dir,
            FEDERATION_POLICY_FILE,
            "FederationPolicyDocument",
        )?)
    } else {
        None
    };
    Ok(EvidenceImportPackage {
        envelope,
        manifest,
        bundle,
        transparency,
        federation_policy,
    })
}

fn verify_manifest_file_hashes(
    dir: &Path,
    manifest: &EvidenceExportManifest,
) -> Result<(), BundleVerifyError> {
    let mut seen = BTreeSet::new();
    for file in &manifest.files {
        if !seen.insert(file.path.as_str()) {
            return Err(BundleVerifyError::file(format!(
                "duplicate file entry in evidence manifest: {}",
                file.path
            )));
        }
        let bytes = read_bytes(dir, &file.path)?;
        if sha256_hex(&bytes) != file.sha256 {
            return Err(BundleVerifyError::file(format!(
                "evidence package file hash mismatch for {}",
                file.path
            )));
        }
        if u64::try_from(bytes.len()).ok() != Some(file.bytes) {
            return Err(BundleVerifyError::file(format!(
                "evidence package byte length mismatch for {}",
                file.path
            )));
        }
    }
    Ok(())
}

fn verify_policy_attachment(
    dir: &Path,
    manifest: &EvidenceExportManifest,
) -> Result<(), BundleVerifyError> {
    let Some(expected_policy) = &manifest.policy else {
        return Ok(());
    };
    let metadata: PolicyAttachmentMetadata =
        read_json(dir, POLICY_METADATA_FILE, "PolicyAttachmentMetadata")?;
    if &metadata != expected_policy {
        return Err(BundleVerifyError::inconsistent(
            "policy metadata file does not match evidence manifest",
        ));
    }
    read_bytes(dir, &expected_policy.source_path).map_err(|error| {
        BundleVerifyError::file(format!(
            "policy source file referenced by manifest is missing: {}: {error}",
            expected_policy.source_path
        ))
    })?;
    Ok(())
}

/// Verify a decoded package: the envelope signer is pinned and commits to
/// the manifest and payload, every receipt and checkpoint signature verifies
/// under a pinned key, and counts, scope, proofs, transparency and the
/// disclosure notice agree with the signed data.
pub fn verify_decoded_package(
    package: &EvidenceImportPackage,
    trust: &VerifierTrust,
    embedded_http: Option<&dyn EmbeddedHttpReceiptVerifier>,
) -> Result<(CheckpointTransparencySummary, EvidenceTransparencyClaims), BundleVerifyError> {
    load_trust(trust)?;
    verify_envelope(&package.envelope, &package.manifest, trust)?;
    let actual_payload = payload_sha256(
        &package.bundle,
        package.transparency.as_ref(),
        package.federation_policy.as_ref(),
    )?;
    if actual_payload != package.envelope.body.payload_sha256 {
        return Err(BundleVerifyError::envelope(
            "evidence payload does not match its signed envelope commitment",
        ));
    }
    verify_bundle_signers(&package.bundle, trust)?;
    if package.manifest.schema != EVIDENCE_EXPORT_MANIFEST_SCHEMA {
        return Err(BundleVerifyError::schema(format!(
            "unsupported evidence manifest schema: expected {}, got {}",
            EVIDENCE_EXPORT_MANIFEST_SCHEMA, package.manifest.schema
        )));
    }
    if package.bundle.query != package.manifest.query {
        return Err(BundleVerifyError::inconsistent(
            "evidence import package query does not match the embedded manifest",
        ));
    }
    package
        .bundle
        .query
        .validate_read_boundary()
        .map_err(|error| BundleVerifyError::inconsistent(error.to_string()))?;
    verify_inventory(&package.manifest)?;
    verify_manifest_counts(&package.manifest, &package.bundle)?;
    verify_disclosure_notice(&package.manifest)?;
    let actual_federation_metadata = package
        .federation_policy
        .as_ref()
        .map(FederationPolicyDocument::attachment_metadata);
    if actual_federation_metadata != package.manifest.federation_policy {
        return Err(BundleVerifyError::inconsistent(
            "evidence import federation policy metadata does not match the embedded manifest",
        ));
    }
    if let Some(policy) = package.federation_policy.as_ref() {
        verify_federation_policy(policy)?;
        if package.manifest.exported_at < policy.body.created_at
            || package.manifest.exported_at > policy.body.expires_at
        {
            return Err(BundleVerifyError::inconsistent(
                "evidence import package export timestamp falls outside the federation policy validity window",
            ));
        }
        ensure_query_within_federation_policy(&policy.body.query, &package.manifest.query)?;
        if policy.body.require_proofs && package.manifest.counts.uncheckpointed_receipts != 0 {
            return Err(BundleVerifyError::inconsistent(
                "federation policy requires full checkpoint coverage, but the evidence import package contains uncheckpointed receipts",
            ));
        }
    }

    let lineage_by_capability = verify_lineage(&package.bundle.capability_lineage)?;
    let tool_receipts_by_seq = verify_tool_receipts(&package.bundle.tool_receipts, embedded_http)?;
    verify_child_receipts(&package.bundle.child_receipts)?;
    let checkpoints_by_seq = verify_checkpoints(&package.bundle.checkpoints, trust)?;
    let transparency =
        verify_transparency(&package.bundle.checkpoints, package.transparency.as_ref())?;
    let claims = transparency_claims(trust, &package.bundle, &transparency)?;
    verify_transparency_claim_boundary(
        package.manifest.claim_boundary.as_ref(),
        &package.bundle,
        &transparency,
    )?;
    verify_inclusion_proofs(
        &tool_receipts_by_seq,
        &checkpoints_by_seq,
        &package.bundle.inclusion_proofs,
        package.manifest.counts.uncheckpointed_receipts,
    )?;
    let proved: BTreeSet<u64> = package
        .bundle
        .inclusion_proofs
        .iter()
        .map(|proof| proof.receipt_seq)
        .collect();
    let expected: BTreeSet<(u64, &str)> = package
        .bundle
        .tool_receipts
        .iter()
        .filter(|record| !proved.contains(&record.seq))
        .map(|record| (record.seq, record.receipt.id.as_str()))
        .collect();
    let actual: BTreeSet<(u64, &str)> = package
        .bundle
        .uncheckpointed_receipts
        .iter()
        .map(|record| (record.seq, record.receipt_id.as_str()))
        .collect();
    if actual != expected
        || actual.len() != package.bundle.uncheckpointed_receipts.len()
        || count(actual.len()) != package.manifest.counts.uncheckpointed_receipts
    {
        return Err(BundleVerifyError::inconsistent(
            "uncheckpointed receipt inventory does not match proof coverage",
        ));
    }
    verify_query_scope(
        &package.bundle.query,
        &package.bundle.tool_receipts,
        &package.bundle.child_receipts,
        package.bundle.child_receipt_scope,
        &lineage_by_capability,
    )?;
    Ok((transparency, claims))
}

fn count(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn verify_envelope(
    envelope: &EvidencePackageEnvelope,
    manifest: &EvidenceExportManifest,
    trust: &VerifierTrust,
) -> Result<(), BundleVerifyError> {
    require_kernel_signer(trust, &envelope.signer_key)?;
    let signed = envelope.verify_signature().map_err(|error| {
        BundleVerifyError::envelope(format!(
            "evidence export envelope signature or schema is invalid: {error}"
        ))
    })?;
    if envelope.body.schema != EVIDENCE_EXPORT_COMMITMENT_SCHEMA || !signed {
        return Err(BundleVerifyError::envelope(
            "evidence export envelope signature or schema is invalid",
        ));
    }
    if envelope.body.manifest_sha256 != manifest_sha256(manifest)? {
        return Err(BundleVerifyError::envelope(
            "evidence manifest does not match its signed envelope commitment",
        ));
    }
    Ok(())
}

fn verify_bundle_signers(
    bundle: &EvidenceExportBundle,
    trust: &VerifierTrust,
) -> Result<(), BundleVerifyError> {
    for record in &bundle.tool_receipts {
        require_kernel_signer(trust, &record.receipt.kernel_key)?;
    }
    for record in &bundle.child_receipts {
        require_kernel_signer(trust, &record.receipt.kernel_key)?;
    }
    for checkpoint in &bundle.checkpoints {
        if !trust.is_checkpoint_key(&checkpoint.body.kernel_key) {
            return Err(BundleVerifyError::trust_missing(
                "evidence signer is outside the trusted kernel key set",
            ));
        }
    }
    Ok(())
}

/// Check supplied transparency records against the signed checkpoints, or
/// derive them when none are supplied.
pub fn verify_transparency(
    checkpoints: &[KernelCheckpoint],
    supplied: Option<&CheckpointTransparencySummary>,
) -> Result<CheckpointTransparencySummary, BundleVerifyError> {
    match supplied {
        Some(summary) => verify_checkpoint_transparency_records(checkpoints, summary),
        None => validate_checkpoint_transparency(checkpoints),
    }
    .map_err(|error| {
        BundleVerifyError::inconsistent(format!(
            "checkpoint transparency verification failed: {error}"
        ))
    })
}

/// Publication claims qualified only by the trust file's checkpoint anchor.
fn transparency_claims(
    trust: &VerifierTrust,
    bundle: &EvidenceExportBundle,
    transparency: &CheckpointTransparencySummary,
) -> Result<EvidenceTransparencyClaims, BundleVerifyError> {
    let anchor = match &trust.checkpoint_trust_anchor {
        None => None,
        Some(expected) => {
            if transparency.publications.is_empty()
                || transparency
                    .publications
                    .iter()
                    .any(|publication| publication.trust_anchor_binding.as_ref() != Some(expected))
            {
                return Err(BundleVerifyError::inconsistent(
                    "evidence publications do not match the verifier-supplied trust anchor binding",
                ));
            }
            Some(expected.trust_anchor_ref.as_str())
        }
    };
    let claims = build_evidence_transparency_claims(bundle, transparency, anchor);
    if anchor.is_some() && !claims.is_trust_anchored() {
        return Err(BundleVerifyError::inconsistent(
            "evidence trust anchor cannot qualify this publication set",
        ));
    }
    Ok(claims)
}

/// The exporter's claim boundary must be exactly the unanchored claims the
/// data supports; a package cannot qualify itself.
pub fn verify_transparency_claim_boundary(
    expected: Option<&EvidenceTransparencyClaims>,
    bundle: &EvidenceExportBundle,
    transparency: &CheckpointTransparencySummary,
) -> Result<(), BundleVerifyError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    expected
        .validate()
        .map_err(BundleVerifyError::inconsistent)?;
    let actual = build_evidence_transparency_claims(bundle, transparency, None);
    if expected != &actual {
        return Err(BundleVerifyError::inconsistent(
            "evidence package transparency claim boundary does not match the exported data",
        ));
    }
    Ok(())
}

/// Tool receipts are unique by sequence, signed, hash-consistent and carry
/// any embedded HTTP evidence they claim.
pub fn verify_tool_receipts<'a>(
    tool_receipts: &'a [EvidenceToolReceiptRecord],
    embedded_http: Option<&dyn EmbeddedHttpReceiptVerifier>,
) -> Result<BTreeMap<u64, &'a ChioReceipt>, BundleVerifyError> {
    let mut by_seq = BTreeMap::new();
    for record in tool_receipts {
        if by_seq.insert(record.seq, &record.receipt).is_some() {
            return Err(BundleVerifyError::inconsistent(format!(
                "duplicate tool receipt seq in evidence package: {}",
                record.seq
            )));
        }
        // Offline evidence accepts classical and hybrid receipt signatures.
        let signed = record
            .receipt
            .verify_signature_with_floor(ReceiptCryptoFloor::AllowHybrid)
            .map_err(|error| {
                BundleVerifyError::signature(format!(
                    "tool receipt signature verification failed: {}: {error}",
                    record.receipt.id
                ))
            })?;
        if !signed {
            return Err(BundleVerifyError::signature(format!(
                "tool receipt signature verification failed: {}",
                record.receipt.id
            )));
        }
        let action_hash = record.receipt.action.verify_hash().map_err(|error| {
            BundleVerifyError::signature(format!(
                "tool receipt action hash verification failed: {}: {error}",
                record.receipt.id
            ))
        })?;
        if !action_hash {
            return Err(BundleVerifyError::signature(format!(
                "tool receipt action hash verification failed: {}",
                record.receipt.id
            )));
        }
        verify_embedded_http_receipt(&record.receipt, embedded_http)?;
    }
    Ok(by_seq)
}

fn verify_embedded_http_receipt(
    receipt: &ChioReceipt,
    embedded_http: Option<&dyn EmbeddedHttpReceiptVerifier>,
) -> Result<(), BundleVerifyError> {
    let embedded = receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get(EMBEDDED_HTTP_RECEIPT_KEY));
    let Some(embedded) = embedded else {
        return if receipt.tool_server == "http" {
            Err(BundleVerifyError::inconsistent(format!(
                "HTTP receipt evidence missing: {}",
                receipt.id
            )))
        } else {
            Ok(())
        };
    };
    let Some(verifier) = embedded_http else {
        return Err(BundleVerifyError::unsupported(format!(
            "receipt {} embeds an HTTP receipt this verifier cannot check",
            receipt.id
        )));
    };
    match verifier.verify_projection(embedded, receipt) {
        Ok(true) => Ok(()),
        Ok(false) => Err(BundleVerifyError::signature(format!(
            "HTTP receipt projection verification failed: {}",
            receipt.id
        ))),
        Err(EmbeddedHttpError::Decode(error)) => Err(BundleVerifyError::schema(format!(
            "HTTP receipt evidence decoding failed: {}: {error}",
            receipt.id
        ))),
        Err(EmbeddedHttpError::Projection(error)) => Err(BundleVerifyError::signature(format!(
            "HTTP receipt projection verification failed: {}: {error}",
            receipt.id
        ))),
    }
}

/// Child receipts are unique by sequence and signed.
pub fn verify_child_receipts(
    child_receipts: &[EvidenceChildReceiptRecord],
) -> Result<(), BundleVerifyError> {
    let mut seen = BTreeSet::new();
    for record in child_receipts {
        if !seen.insert(record.seq) {
            return Err(BundleVerifyError::inconsistent(format!(
                "duplicate child receipt seq in evidence package: {}",
                record.seq
            )));
        }
        // Packages carry no policy crypto floor; classical and hybrid
        // signatures both verify.
        let signed = record
            .receipt
            .verify_signature_with_floor(ReceiptCryptoFloor::AllowHybrid)
            .map_err(|error| {
                BundleVerifyError::signature(format!(
                    "child receipt signature verification failed: {}: {error}",
                    record.receipt.id
                ))
            })?;
        if !signed {
            return Err(BundleVerifyError::signature(format!(
                "child receipt signature verification failed: {}",
                record.receipt.id
            )));
        }
    }
    Ok(())
}

/// Checkpoints have a supported schema, a valid signature under a pinned
/// key and unique sequences.
pub fn verify_checkpoints<'a>(
    checkpoints: &'a [KernelCheckpoint],
    trust: &VerifierTrust,
) -> Result<BTreeMap<u64, VerifiedCheckpoint<'a>>, BundleVerifyError> {
    let mut by_seq = BTreeMap::<u64, VerifiedCheckpoint<'a>>::new();
    for checkpoint in checkpoints {
        if !is_supported_checkpoint_schema(&checkpoint.body.schema) {
            return Err(BundleVerifyError::schema(format!(
                "unsupported checkpoint schema in evidence package: {}",
                checkpoint.body.schema
            )));
        }
        if !trust.is_checkpoint_key(&checkpoint.body.kernel_key) {
            return Err(BundleVerifyError::trust_missing(
                "evidence signer is outside the trusted kernel key set",
            ));
        }
        let checkpoint = verify_checkpoint_signature(checkpoint).map_err(|error| match error {
            CheckpointError::InvalidSignature => BundleVerifyError::signature(format!(
                "checkpoint signature verification failed: {}",
                checkpoint.body.checkpoint_seq
            )),
            error => BundleVerifyError::signature(format!(
                "checkpoint signature verification failed: {}: {error}",
                checkpoint.body.checkpoint_seq
            )),
        })?;
        if let Some(existing) = by_seq.get(&checkpoint.body.checkpoint_seq) {
            let digest = |checkpoint: &KernelCheckpoint| {
                checkpoint_body_sha256(&checkpoint.body).map_err(|error| {
                    BundleVerifyError::inconsistent(format!(
                        "checkpoint digest computation failed: {error}"
                    ))
                })
            };
            let existing_sha256 = digest(existing.checkpoint())?;
            let checkpoint_sha256 = digest(checkpoint.checkpoint())?;
            if existing_sha256 != checkpoint_sha256 {
                return Err(BundleVerifyError::inconsistent(format!(
                    "checkpoint transparency equivocation detected: checkpoint_seq {} has conflicting digests {} and {}",
                    checkpoint.body.checkpoint_seq, existing_sha256, checkpoint_sha256
                )));
            }
            return Err(BundleVerifyError::inconsistent(format!(
                "duplicate checkpoint_seq in evidence package: {}",
                checkpoint.body.checkpoint_seq
            )));
        }
        by_seq.insert(checkpoint.body.checkpoint_seq, checkpoint);
    }
    Ok(by_seq)
}

/// Lineage snapshots validate and are unique by capability.
pub fn verify_lineage(
    capability_lineage: &[CapabilitySnapshot],
) -> Result<BTreeMap<String, &CapabilitySnapshot>, BundleVerifyError> {
    let mut by_capability = BTreeMap::new();
    for snapshot in capability_lineage {
        snapshot.validate().map_err(|error| {
            BundleVerifyError::inconsistent(format!(
                "invalid capability lineage snapshot in evidence package: {error}"
            ))
        })?;
        if by_capability
            .insert(snapshot.capability_id.clone(), snapshot)
            .is_some()
        {
            return Err(BundleVerifyError::inconsistent(format!(
                "duplicate capability lineage snapshot in evidence package: {}",
                snapshot.capability_id
            )));
        }
    }
    Ok(by_capability)
}

/// Every inclusion proof binds a known receipt to a known checkpoint signed
/// by the same key, and the unproved receipts match the manifest count.
pub fn verify_inclusion_proofs(
    tool_receipts_by_seq: &BTreeMap<u64, &ChioReceipt>,
    checkpoints_by_seq: &BTreeMap<u64, VerifiedCheckpoint<'_>>,
    inclusion_proofs: &[ReceiptInclusionProof],
    expected_uncheckpointed_receipts: u64,
) -> Result<(), BundleVerifyError> {
    let mut proved_receipt_seqs = BTreeSet::new();
    for proof in inclusion_proofs {
        let checkpoint = checkpoints_by_seq
            .get(&proof.checkpoint_seq)
            .ok_or_else(|| {
                BundleVerifyError::inconsistent(format!(
                    "inclusion proof references missing checkpoint {}",
                    proof.checkpoint_seq
                ))
            })?;
        let receipt = tool_receipts_by_seq
            .get(&proof.receipt_seq)
            .ok_or_else(|| {
                BundleVerifyError::inconsistent(format!(
                    "inclusion proof references missing receipt seq {}",
                    proof.receipt_seq
                ))
            })?;
        if receipt.kernel_key != checkpoint.body.kernel_key {
            return Err(BundleVerifyError::signature(
                "receipt signer does not match its checkpoint signer",
            ));
        }
        if proof.merkle_root != checkpoint.body.merkle_root {
            return Err(BundleVerifyError::inconsistent(format!(
                "inclusion proof root mismatch for receipt seq {}",
                proof.receipt_seq
            )));
        }
        if proof.leaf_index >= checkpoint.body.tree_size {
            return Err(BundleVerifyError::inconsistent(format!(
                "inclusion proof leaf index {} exceeds checkpoint tree size {}",
                proof.leaf_index, checkpoint.body.tree_size
            )));
        }
        if proof.receipt_seq < checkpoint.body.batch_start_seq
            || proof.receipt_seq > checkpoint.body.batch_end_seq
        {
            return Err(BundleVerifyError::inconsistent(format!(
                "inclusion proof receipt seq {} falls outside checkpoint batch {}-{}",
                proof.receipt_seq, checkpoint.body.batch_start_seq, checkpoint.body.batch_end_seq
            )));
        }
        if !proved_receipt_seqs.insert(proof.receipt_seq) {
            return Err(BundleVerifyError::inconsistent(format!(
                "duplicate inclusion proof for receipt seq {}",
                proof.receipt_seq
            )));
        }
        let canonical = canonical_json_bytes(*receipt).map_err(|error| {
            BundleVerifyError::schema(format!("receipt is not canonicalizable: {error}"))
        })?;
        if !proof.verify(&canonical, &checkpoint.body.merkle_root) {
            return Err(BundleVerifyError::inconsistent(format!(
                "inclusion proof verification failed for receipt seq {}",
                proof.receipt_seq
            )));
        }
    }

    let derived_uncheckpointed = count(
        tool_receipts_by_seq
            .len()
            .saturating_sub(proved_receipt_seqs.len()),
    );
    if derived_uncheckpointed != expected_uncheckpointed_receipts {
        return Err(BundleVerifyError::inconsistent(format!(
            "uncheckpointed receipt count mismatch: manifest says {}, derived {}",
            expected_uncheckpointed_receipts, derived_uncheckpointed
        )));
    }
    Ok(())
}

/// Kind and boundary tallies, and the count of receipts that are authorized
/// decisions with a valid id, signature and action hash. A signed
/// observation is not authorized.
#[must_use]
pub fn receipt_semantic_summary(
    tool_receipts: &[EvidenceToolReceiptRecord],
) -> EvidenceReceiptSemanticSummary {
    let mut summary = EvidenceReceiptSemanticSummary::default();
    for record in tool_receipts {
        let semantics = record.receipt.semantic_fields();
        match semantics.receipt_kind {
            ReceiptKind::MediatedDecision => summary.mediated_decisions += 1,
            ReceiptKind::TraceObservation => summary.trace_observations += 1,
            ReceiptKind::AdvisoryEvaluation => summary.advisory_evaluations += 1,
        }
        match semantics.boundary_class {
            BoundaryClass::Prevent => summary.prevent += 1,
            BoundaryClass::DetectOnly => summary.detect_only += 1,
            BoundaryClass::AdvisoryOnly => summary.advisory_only += 1,
            BoundaryClass::CannotSee => summary.cannot_see += 1,
        }
        if chio_receipt_id(&record.receipt.body())
            .map(|id| id == record.receipt.id)
            .unwrap_or(false)
            && record.receipt.is_allowed()
            && record
                .receipt
                .verify_signature_with_floor(ReceiptCryptoFloor::AllowHybrid)
                .unwrap_or(false)
            && record.receipt.action.verify_hash().unwrap_or(false)
        {
            summary.authorized += 1;
        }
    }
    summary
}

/// The manifest's counts, proof coverage and semantic summary equal what the
/// bundle holds.
pub fn verify_manifest_counts(
    manifest: &EvidenceExportManifest,
    bundle: &EvidenceExportBundle,
) -> Result<(), BundleVerifyError> {
    let counts = &manifest.counts;
    if counts.tool_receipts != count(bundle.tool_receipts.len())
        || counts.child_receipts != count(bundle.child_receipts.len())
        || counts.checkpoints != count(bundle.checkpoints.len())
        || counts.capability_lineage != count(bundle.capability_lineage.len())
        || counts.inclusion_proofs != count(bundle.inclusion_proofs.len())
    {
        return Err(BundleVerifyError::inconsistent(
            "evidence package manifest counts do not match exported data",
        ));
    }
    let checkpointed_receipts = counts
        .tool_receipts
        .saturating_sub(counts.uncheckpointed_receipts);
    if manifest.proof_coverage.checkpointed_receipts != checkpointed_receipts
        || manifest.proof_coverage.uncheckpointed_receipts != counts.uncheckpointed_receipts
    {
        return Err(BundleVerifyError::inconsistent(
            "evidence package proof coverage summary does not match receipt counts",
        ));
    }
    if manifest.receipt_semantics != receipt_semantic_summary(&bundle.tool_receipts) {
        return Err(BundleVerifyError::inconsistent(
            "evidence package receipt semantic summary does not match exported data",
        ));
    }
    Ok(())
}

/// A tenant-scoped package carries exactly the canonical disclosure notice;
/// any other package carries none.
pub fn verify_disclosure_notice(
    manifest: &EvidenceExportManifest,
) -> Result<(), BundleVerifyError> {
    match (
        &manifest.disclosure_notice,
        EvidenceDisclosureNotice::for_query(&manifest.query),
    ) {
        (Some(actual), Some(expected)) => {
            if actual != &expected {
                return Err(BundleVerifyError::inconsistent(
                    "evidence package disclosure notice does not match the canonical \
                     tenant-scoped disclosure boundary",
                ));
            }
            Ok(())
        }
        (None, Some(_)) => Err(BundleVerifyError::inconsistent(
            "tenant-scoped evidence package is missing the required cross-tenant \
             disclosure notice",
        )),
        (Some(_), None) => Err(BundleVerifyError::inconsistent(
            "admin-all evidence package must not carry a tenant-scoped disclosure notice",
        )),
        (None, None) => Ok(()),
    }
}

/// Every exported record lies inside the query the package claims.
pub fn verify_query_scope(
    query: &EvidenceExportQuery,
    tool_receipts: &[EvidenceToolReceiptRecord],
    child_receipts: &[EvidenceChildReceiptRecord],
    child_receipt_scope: EvidenceChildReceiptScope,
    lineage_by_capability: &BTreeMap<String, &CapabilitySnapshot>,
) -> Result<(), BundleVerifyError> {
    let expected_child_scope = query.child_receipt_scope();
    if child_receipt_scope != expected_child_scope {
        return Err(BundleVerifyError::inconsistent(format!(
            "child receipt scope mismatch: manifest says {:?}, query implies {:?}",
            child_receipt_scope, expected_child_scope
        )));
    }
    if matches!(
        child_receipt_scope,
        EvidenceChildReceiptScope::OmittedNoJoinPath
    ) && !child_receipts.is_empty()
    {
        return Err(BundleVerifyError::inconsistent(
            "child receipts were exported despite an omitted child-receipt scope",
        ));
    }

    let tenant_scope = match &query.read_boundary {
        Some(ReceiptReadBoundary::TenantScoped { tenant }) => Some(tenant.as_str()),
        Some(ReceiptReadBoundary::AdminAll) | None => query
            .tenant
            .as_deref()
            .map(str::trim)
            .filter(|tenant| !tenant.is_empty()),
    };

    for record in tool_receipts {
        if let Some(tenant) = tenant_scope {
            if record.receipt.tenant_id.as_deref() != Some(tenant) {
                return Err(BundleVerifyError::inconsistent(format!(
                    "tool receipt {} is outside tenant scope {}",
                    record.receipt.id, tenant
                )));
            }
        }
        if let Some(capability_id) = &query.capability_id {
            if &record.receipt.capability_id != capability_id {
                return Err(BundleVerifyError::inconsistent(format!(
                    "tool receipt {} is outside capability filter {}",
                    record.receipt.id, capability_id
                )));
            }
        }
        if let Some(since) = query.since {
            if record.receipt.timestamp < since {
                return Err(BundleVerifyError::inconsistent(format!(
                    "tool receipt {} predates query lower bound {}",
                    record.receipt.id, since
                )));
            }
        }
        if let Some(until) = query.until {
            if record.receipt.timestamp > until {
                return Err(BundleVerifyError::inconsistent(format!(
                    "tool receipt {} exceeds query upper bound {}",
                    record.receipt.id, until
                )));
            }
        }
        if let Some(agent_subject) = &query.agent_subject {
            let snapshot = lineage_by_capability
                .get(record.receipt.capability_id.as_str())
                .ok_or_else(|| {
                    BundleVerifyError::inconsistent(format!(
                        "missing capability lineage for receipt capability {}",
                        record.receipt.capability_id
                    ))
                })?;
            if &snapshot.subject_key != agent_subject {
                return Err(BundleVerifyError::inconsistent(format!(
                    "tool receipt {} lineage subject {} does not match agent filter {}",
                    record.receipt.id, snapshot.subject_key, agent_subject
                )));
            }
        }
    }

    for record in child_receipts {
        if let Some(since) = query.since {
            if record.receipt.timestamp < since {
                return Err(BundleVerifyError::inconsistent(format!(
                    "child receipt {} predates query lower bound {}",
                    record.receipt.id, since
                )));
            }
        }
        if let Some(until) = query.until {
            if record.receipt.timestamp > until {
                return Err(BundleVerifyError::inconsistent(format!(
                    "child receipt {} exceeds query upper bound {}",
                    record.receipt.id, until
                )));
            }
        }
    }
    Ok(())
}
