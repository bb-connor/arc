use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalExecutionAuthorityStepProofBody {
    pub schema: String,
    pub role: CapitalExecutionRole,
    pub principal_id: String,
    pub approved_at: u64,
    pub expires_at: u64,
}

pub type SignedCapitalExecutionAuthorityStepProof =
    SignedExportEnvelope<CapitalExecutionAuthorityStepProofBody>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CapitalExecutionAuthorityStep {
    pub role: CapitalExecutionRole,
    pub principal_id: String,
    pub approved_at: u64,
    pub expires_at: u64,
    pub authority_proof: SignedCapitalExecutionAuthorityStepProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl CapitalExecutionAuthorityStep {
    pub fn signed(
        role: CapitalExecutionRole,
        principal_keypair: &crate::crypto::Keypair,
        approved_at: u64,
        expires_at: u64,
        note: Option<String>,
    ) -> Result<Self, String> {
        let principal_id = principal_keypair.public_key().to_hex();
        let body = CapitalExecutionAuthorityStepProofBody {
            schema: CAPITAL_EXECUTION_AUTHORITY_STEP_PROOF_SCHEMA.to_string(),
            role,
            principal_id: principal_id.clone(),
            approved_at,
            expires_at,
        };
        let authority_proof = SignedCapitalExecutionAuthorityStepProof::sign(body, principal_keypair)
            .map_err(|error| error.to_string())?;
        Ok(Self {
            role,
            principal_id,
            approved_at,
            expires_at,
            authority_proof,
            note,
        })
    }
}

/// Refusal reasons for capital execution authority steps checked against the
/// operator-configured trust set.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapitalAuthorityTrustError {
    #[error("capital execution authority trust is not configured: issuance requires at least one --capital-authority-key")]
    Unconfigured,
    #[error("capital execution authority step `{principal_id}` is signed by a key outside the trusted capital authority set")]
    UntrustedSigner { principal_id: String },
    #[error("capital execution authority proof is invalid: {0}")]
    InvalidProof(String),
}

/// Operator-configured capital execution authority keys. Construction rejects
/// an empty set, so every value pins at least one key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedCapitalAuthority {
    keys: Vec<crate::crypto::PublicKey>,
}

impl TrustedCapitalAuthority {
    pub fn new(keys: Vec<crate::crypto::PublicKey>) -> Result<Self, CapitalAuthorityTrustError> {
        if keys.is_empty() {
            return Err(CapitalAuthorityTrustError::Unconfigured);
        }
        Ok(Self { keys })
    }

    pub fn keys(&self) -> &[crate::crypto::PublicKey] {
        &self.keys
    }

    /// Verifies one step under the trusted key matching its signer. The
    /// embedded signer key only selects a candidate; it never authorizes.
    pub fn verify_step(
        &self,
        step: &CapitalExecutionAuthorityStep,
    ) -> Result<(), CapitalAuthorityTrustError> {
        let invalid = |message: String| CapitalAuthorityTrustError::InvalidProof(message);
        if step.authority_proof.body.schema != CAPITAL_EXECUTION_AUTHORITY_STEP_PROOF_SCHEMA {
            return Err(invalid(format!(
                "schema must be {CAPITAL_EXECUTION_AUTHORITY_STEP_PROOF_SCHEMA}"
            )));
        }
        let trusted_key = self
            .keys
            .iter()
            .find(|key| **key == step.authority_proof.signer_key)
            .ok_or_else(|| CapitalAuthorityTrustError::UntrustedSigner {
                principal_id: step.principal_id.clone(),
            })?;
        if !step
            .authority_proof
            .verify_signature(trusted_key)
            .map_err(|error| invalid(error.to_string()))?
        {
            return Err(invalid("signature verification failed".to_string()));
        }
        if step.principal_id != trusted_key.to_hex() {
            return Err(invalid("signer must match principalId".to_string()));
        }
        let proof = &step.authority_proof.body;
        if proof.role != step.role
            || proof.principal_id != step.principal_id
            || proof.approved_at != step.approved_at
            || proof.expires_at != step.expires_at
        {
            return Err(invalid("body must match authorityChain step".to_string()));
        }
        Ok(())
    }

    pub fn verify_chain(
        &self,
        authority_chain: &[CapitalExecutionAuthorityStep],
    ) -> Result<(), CapitalAuthorityTrustError> {
        authority_chain
            .iter()
            .try_for_each(|step| self.verify_step(step))
    }
}

impl chio_core_types::receipt::lineage::SignedExportPayload for CapitalExecutionAuthorityStepProofBody {
    const SCHEMA_ID: &'static str = crate::CAPITAL_EXECUTION_AUTHORITY_STEP_PROOF_SCHEMA;
}
