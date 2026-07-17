use chio_core_types::crypto::{canonical_json_bytes, Keypair};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use crate::{fiscal_signer_key_id, FiscalDomain, FiscalError};

use super::proposal::FiscalGenesisPolicy;
use super::support::{
    all_fiscal_domains, lifecycle_digest, require_digest, require_positive, signed_envelope_digest,
    verify_envelope, MAX_SIGNED_LIFECYCLE_BYTES,
};

pub const FISCAL_RUNTIME_READINESS_SCHEMA: &str = "chio.fiscal.consumer-readiness.v1";
pub const FISCAL_RUNTIME_READINESS_ID_DOMAIN: &str = "chio.fiscal.consumer-readiness.id.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FiscalRuntimeReadiness {
    pub schema: String,
    pub readiness_id: String,
    pub governing_operator_id: String,
    pub genesis_policy_id: String,
    pub genesis_policy_digest: String,
    pub readiness_sequence: u64,
    pub runtime_registry_digest: String,
    pub ready_domains: Vec<FiscalDomain>,
    pub attested_at: u64,
    pub signer_key_id: String,
    pub signer_key_epoch: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FiscalRuntimeReadinessIdPreimage<'a> {
    schema: &'a str,
    governing_operator_id: &'a str,
    genesis_policy_id: &'a str,
    genesis_policy_digest: &'a str,
    readiness_sequence: u64,
    runtime_registry_digest: &'a str,
    ready_domains: &'a [FiscalDomain],
    attested_at: u64,
    signer_key_id: &'a str,
    signer_key_epoch: u64,
}

impl FiscalRuntimeReadiness {
    pub fn expected_id(&self) -> Result<String, FiscalError> {
        lifecycle_digest(
            FISCAL_RUNTIME_READINESS_ID_DOMAIN,
            &FiscalRuntimeReadinessIdPreimage {
                schema: &self.schema,
                governing_operator_id: &self.governing_operator_id,
                genesis_policy_id: &self.genesis_policy_id,
                genesis_policy_digest: &self.genesis_policy_digest,
                readiness_sequence: self.readiness_sequence,
                runtime_registry_digest: &self.runtime_registry_digest,
                ready_domains: &self.ready_domains,
                attested_at: self.attested_at,
                signer_key_id: &self.signer_key_id,
                signer_key_epoch: self.signer_key_epoch,
            },
        )
    }
}

pub type SignedFiscalRuntimeReadiness = SignedExportEnvelope<FiscalRuntimeReadiness>;

#[derive(Debug, Clone)]
pub struct FiscalRuntimeReadinessBuilder {
    pub readiness_sequence: u64,
    pub runtime_registry_digest: String,
    pub attested_at: u64,
}

impl FiscalRuntimeReadinessBuilder {
    pub fn sign(
        self,
        policy: &FiscalGenesisPolicy,
        keypair: &Keypair,
    ) -> Result<SignedFiscalRuntimeReadiness, FiscalError> {
        let mut body = FiscalRuntimeReadiness {
            schema: FISCAL_RUNTIME_READINESS_SCHEMA.to_owned(),
            readiness_id: String::new(),
            governing_operator_id: policy.governing_operator_id.clone(),
            genesis_policy_id: policy.policy_id.clone(),
            genesis_policy_digest: policy.digest()?,
            readiness_sequence: self.readiness_sequence,
            runtime_registry_digest: self.runtime_registry_digest,
            ready_domains: all_fiscal_domains().to_vec(),
            attested_at: self.attested_at,
            signer_key_id: fiscal_signer_key_id(&keypair.public_key())?,
            signer_key_epoch: policy.anchor_signer_key_epoch,
        };
        body.readiness_id = body.expected_id()?;
        SignedFiscalRuntimeReadiness::sign(body, keypair)
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedFiscalRuntimeReadiness {
    signed: SignedFiscalRuntimeReadiness,
    digest: String,
}

impl VerifiedFiscalRuntimeReadiness {
    pub fn verify(
        signed: SignedFiscalRuntimeReadiness,
        policy: &FiscalGenesisPolicy,
    ) -> Result<Self, FiscalError> {
        let body = &signed.body;
        if body.schema != FISCAL_RUNTIME_READINESS_SCHEMA {
            return Err(FiscalError::UnknownSchema(body.schema.clone()));
        }
        require_positive(body.readiness_sequence, "readiness.readiness_sequence")?;
        require_positive(body.attested_at, "readiness.attested_at")?;
        require_digest(
            &body.runtime_registry_digest,
            "readiness.runtime_registry_digest",
        )?;
        if body.readiness_id != body.expected_id()?
            || body.governing_operator_id != policy.governing_operator_id
            || body.genesis_policy_id != policy.policy_id
            || body.genesis_policy_digest != policy.digest()?
            || body.ready_domains.as_slice() != all_fiscal_domains()
            || body.signer_key_id != policy.anchor_signer_key_id
            || body.signer_key_epoch != policy.anchor_signer_key_epoch
            || signed.signer_key != policy.anchor_authority_key
        {
            return Err(FiscalError::InvalidField("readiness.binding"));
        }
        verify_envelope(&signed)?;
        let digest = signed_envelope_digest(&signed)?;
        Ok(Self { signed, digest })
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
        policy: &FiscalGenesisPolicy,
    ) -> Result<Self, FiscalError> {
        if bytes.is_empty() || bytes.len() > MAX_SIGNED_LIFECYCLE_BYTES {
            return Err(FiscalError::InvalidField("signed_readiness.size"));
        }
        let signed: SignedFiscalRuntimeReadiness = serde_json::from_slice(bytes)
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))?;
        let verified = Self::verify(signed, policy)?;
        if verified.canonical_bytes()?.as_slice() != bytes {
            return Err(FiscalError::Canonicalization(
                "signed fiscal runtime readiness is not canonical".to_owned(),
            ));
        }
        Ok(verified)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FiscalError> {
        canonical_json_bytes(&self.signed)
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))
    }

    #[must_use]
    pub const fn body(&self) -> &FiscalRuntimeReadiness {
        &self.signed.body
    }

    #[must_use]
    pub const fn signed(&self) -> &SignedFiscalRuntimeReadiness {
        &self.signed
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}
