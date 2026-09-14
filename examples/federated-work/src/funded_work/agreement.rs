use super::{allocation::Terms, observer::Domain};
use crate::common::{digest, Result};
use chio_core_types::{canonical_json_bytes, Keypair, PublicKey, Signature};
use chio_kernel::ToolCallRequest;
use serde::{Deserialize, Serialize};

pub const AGREEMENT_SCHEMA: &str = "chio.experimental.native-funded-w0-agreement.v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    pub authority_uuid: String,
    pub implementation_sha256: String,
    pub buyer_key: PublicKey,
    pub provider_key: PublicKey,
    pub domain: Domain,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkTerms {
    pub payer: String,
    pub beneficiary: String,
    pub verifier: String,
    pub amount: String,
    pub submit_by: u64,
    pub challenge_until: u64,
    pub resolve_by: u64,
    pub refund_after: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Agreement {
    pub schema: String,
    pub policy_sha256: String,
    pub authority_uuid: String,
    pub buyer_key: PublicKey,
    pub provider_key: PublicKey,
    pub request_id: String,
    pub request_sha256: String,
    pub domain: Domain,
    pub work: WorkTerms,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedAgreement {
    pub body: Agreement,
    pub buyer_signature: Signature,
    pub provider_signature: Signature,
}

impl Agreement {
    pub fn terms(&self) -> Result<Terms> {
        Ok(Terms {
            agreement_digest: format!("0x{}", digest(self)?),
            payer: self.work.payer.clone(),
            beneficiary: self.work.beneficiary.clone(),
            verifier: self.work.verifier.clone(),
            token: self.domain.token.clone(),
            amount: self.work.amount.clone(),
            submit_by: self.work.submit_by,
            challenge_until: self.work.challenge_until,
            resolve_by: self.work.resolve_by,
            refund_after: self.work.refund_after,
        })
    }

    pub fn sign(self, buyer: &Keypair, provider: &Keypair) -> Result<SignedAgreement> {
        let bytes = canonical_json_bytes(&self)?;
        Ok(SignedAgreement {
            body: self,
            buyer_signature: buyer.sign(&bytes),
            provider_signature: provider.sign(&bytes),
        })
    }
}

impl SignedAgreement {
    pub fn validate(&self, policy: &Policy, request: &ToolCallRequest) -> Result<Terms> {
        let body = &self.body;
        if body.schema != AGREEMENT_SCHEMA
            || body.policy_sha256 != digest(policy)?
            || body.authority_uuid != policy.authority_uuid
            || body.domain != policy.domain
            || body.buyer_key != policy.buyer_key
            || body.provider_key != policy.provider_key
            || body.buyer_key == body.provider_key
            || body.request_sha256 != digest(request)?
            || body.request_id != request.request_id
            || request.agent_id != policy.buyer_key.to_hex()
            || request.capability.subject != policy.buyer_key
        {
            return Err("agreement changes pinned native funding authority or request".into());
        }
        let bytes = canonical_json_bytes(body)?;
        if !policy
            .buyer_key
            .verify_strict(&bytes, &self.buyer_signature)
            || !policy
                .provider_key
                .verify_strict(&bytes, &self.provider_signature)
        {
            return Err("funding agreement signature invalid".into());
        }
        let terms = body.terms()?;
        terms.abi(&policy.domain.escrow)?;
        if terms.amount != "100" {
            return Err("native W0 profile requires exactly 100 mock units".into());
        }
        Ok(terms)
    }
}
