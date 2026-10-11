//! Package authenticity and verifier-owned trust inputs.

use super::*;
use chio_core::receipt::checkpoint::CheckpointPublicationTrustAnchorBinding;
use chio_core::receipt::lineage::SignedExportEnvelope;
use chio_core::Keypair;

const ENVELOPE_SCHEMA: &str = "chio.evidence_export_commitment.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceVerificationPolicy {
    trusted_kernel_keys: Vec<PublicKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trusted_anchor: Option<CheckpointPublicationTrustAnchorBinding>,
}

impl EvidenceVerificationPolicy {
    pub fn new(
        trusted_kernel_keys: Vec<PublicKey>,
        trusted_anchor: Option<CheckpointPublicationTrustAnchorBinding>,
    ) -> Result<Self, CliError> {
        let policy = Self {
            trusted_kernel_keys,
            trusted_anchor,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn from_cli(keys: &[String], anchor_file: Option<&Path>) -> Result<Self, CliError> {
        let keys = keys
            .iter()
            .map(|key| PublicKey::from_hex(key))
            .collect::<Result<Vec<_>, _>>()?;
        let anchor = if let Some(path) = anchor_file {
            Some(crate::signed_input::read(path)?)
        } else {
            None
        };
        Self::new(keys, anchor)
    }

    pub(super) fn validate(&self) -> Result<(), CliError> {
        if self.trusted_kernel_keys.is_empty() || self.trusted_kernel_keys.len() > 64 {
            return Err(CliError::attest_error(
                "evidence verification requires 1 to 64 trusted kernel keys".to_owned(),
            ));
        }
        if self
            .trusted_kernel_keys
            .iter()
            .any(PublicKey::is_weak_ed25519)
        {
            return Err(CliError::attest_error(
                "weak Ed25519 keys cannot be trusted evidence signers".to_owned(),
            ));
        }
        if let Some(anchor) = &self.trusted_anchor {
            anchor.validate()?;
        }
        Ok(())
    }

    fn require_signer(&self, key: &PublicKey) -> Result<(), CliError> {
        if !self.trusted_kernel_keys.contains(key) {
            return Err(CliError::attest_error(
                "evidence signer is outside the trusted kernel key set".to_owned(),
            ));
        }
        Ok(())
    }

    pub(super) fn verify_bundle_signers(
        &self,
        bundle: &EvidenceExportBundle,
    ) -> Result<(), CliError> {
        for record in &bundle.tool_receipts {
            self.require_signer(&record.receipt.kernel_key)?;
        }
        for record in &bundle.child_receipts {
            self.require_signer(&record.receipt.kernel_key)?;
        }
        for checkpoint in &bundle.checkpoints {
            self.require_signer(&checkpoint.body.kernel_key)?;
        }
        Ok(())
    }

    pub(super) fn claims(
        &self,
        bundle: &EvidenceExportBundle,
        transparency: &CheckpointTransparencySummary,
    ) -> Result<EvidenceTransparencyClaims, CliError> {
        let anchor = match &self.trusted_anchor {
            None => None,
            Some(expected) => {
                if transparency.publications.is_empty()
                    || transparency.publications.iter().any(|publication| {
                        publication.trust_anchor_binding.as_ref() != Some(expected)
                    })
                {
                    return Err(CliError::attest_error("evidence publications do not match the verifier-supplied trust anchor binding".to_owned()));
                }
                Some(expected.trust_anchor_ref.as_str())
            }
        };
        let claims = build_evidence_transparency_claims(bundle, transparency, anchor);
        if anchor.is_some() && !claims.is_trust_anchored() {
            return Err(CliError::attest_error(
                "evidence trust anchor cannot qualify this publication set".to_owned(),
            ));
        }
        Ok(claims)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ExportCommitment {
    schema: String,
    manifest_sha256: String,
    payload_sha256: String,
}

pub(super) type PackageEnvelope = SignedExportEnvelope<ExportCommitment>;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Payload<'a> {
    bundle: &'a EvidenceExportBundle,
    transparency: Option<&'a CheckpointTransparencySummary>,
    federation_policy: Option<&'a FederationPolicyDocument>,
}

fn payload_hash(
    bundle: &EvidenceExportBundle,
    transparency: Option<&CheckpointTransparencySummary>,
    federation_policy: Option<&FederationPolicyDocument>,
) -> Result<String, CliError> {
    Ok(sha256_hex(&canonical_json_bytes(&Payload {
        bundle,
        transparency,
        federation_policy,
    })?))
}

pub(super) fn sign(
    manifest: &EvidenceExportManifest,
    bundle: &EvidenceExportBundle,
    transparency: Option<&CheckpointTransparencySummary>,
    federation_policy: Option<&FederationPolicyDocument>,
    keypair: &Keypair,
) -> Result<PackageEnvelope, CliError> {
    Ok(SignedExportEnvelope::sign(
        ExportCommitment {
            schema: ENVELOPE_SCHEMA.to_owned(),
            manifest_sha256: sha256_hex(&canonical_json_bytes(manifest)?),
            payload_sha256: payload_hash(bundle, transparency, federation_policy)?,
        },
        keypair,
    )?)
}

pub(super) fn verify_manifest(
    envelope: &PackageEnvelope,
    manifest: &EvidenceExportManifest,
    policy: &EvidenceVerificationPolicy,
) -> Result<(), CliError> {
    policy.validate()?;
    policy.require_signer(&envelope.signer_key)?;
    if envelope.body.schema != ENVELOPE_SCHEMA || !envelope.verify_signature()? {
        return Err(CliError::attest_error(
            "evidence export envelope signature or schema is invalid".to_owned(),
        ));
    }
    if envelope.body.manifest_sha256 != sha256_hex(&canonical_json_bytes(manifest)?) {
        return Err(CliError::attest_error(
            "evidence manifest does not match its signed envelope commitment".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn verify_payload(package: &EvidenceImportPackage) -> Result<(), CliError> {
    let actual = payload_hash(
        &package.bundle,
        package.transparency.as_ref(),
        package.federation_policy.as_ref(),
    )?;
    if actual != package.envelope.body.payload_sha256 {
        return Err(CliError::attest_error(
            "evidence payload does not match its signed envelope commitment".to_owned(),
        ));
    }
    Ok(())
}
