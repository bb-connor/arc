//! Bilateral consent to exact public work without sharing private native requests.
use super::{
    agreement::{Agreement, Policy, SignedAgreement, WorkTerms, AGREEMENT_SCHEMA},
    checkpoint_files,
    evidence::{self, Signed},
    native::Native,
};
use crate::common::{self, digest, Result};
use chio_core_types::{canonical_json_bytes, sha256_hex, Signature};
use chio_kernel::ToolCallRequest;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

pub const INTENT_SCHEMA: &str = "chio.experimental.funded-work-intent.v1";
const PROPOSAL_SCHEMA: &str = "chio.experimental.funded-work-proposal.v1";
const ACCEPTANCE_SCHEMA: &str = "chio.experimental.funded-work-acceptance.v1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Intent {
    pub schema: String,
    pub policy_sha256: String,
    pub request_id: String,
    pub input_sha256: String,
    pub work: WorkTerms,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Proposal {
    pub schema: String,
    pub policy: Policy,
    pub agreement: Agreement,
    pub input: String,
    pub issued_at: u64,
    pub provider_signature: Signature,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AcceptanceBody {
    pub schema: String,
    pub proposal_sha256: String,
    pub agreement: SignedAgreement,
}
pub type Acceptance = Signed<AcceptanceBody>;
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Original {
    proposal: Proposal,
    request: ToolCallRequest,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Consent {
    intent: Intent,
    proposal: Proposal,
    acceptance: Acceptance,
    accepted_at: u64,
}

fn retain<T: Serialize>(state: &Path, name: &str, value: &T) -> Result<()> {
    checkpoint_files::write(&state.join(name), value)?;
    fs::File::open(state)?.sync_all()?;
    Ok(())
}
fn validate_intent(intent: &Intent, policy: &Policy, input: &str) -> Result<()> {
    if intent.schema != INTENT_SCHEMA
        || intent.policy_sha256 != digest(policy)?
        || intent.input_sha256 != sha256_hex(input.as_bytes())
        || input.len() > 65536
        || intent.request_id.is_empty()
        || intent.request_id.len() > 512
        || intent
            .request_id
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
    {
        return Err("proposal differs from separately selected work intent".into());
    }
    Ok(())
}
fn validate(proposal: &Proposal, intent: &Intent, now: u64) -> Result<()> {
    validate_intent(intent, &proposal.policy, &proposal.input)?;
    proposal.agreement.validate_public(&proposal.policy)?;
    super::finding_acceptance::validate_context(
        &proposal.policy.finding_context,
        &proposal.policy.verifier_key,
        &proposal.policy.provider_key,
        now,
    )?;
    if proposal.schema != PROPOSAL_SCHEMA
        || proposal.issued_at > now
        || proposal.agreement.request_id != intent.request_id
        || canonical_json_bytes(&proposal.agreement.work)? != canonical_json_bytes(&intent.work)?
        || proposal.agreement.capture_waiver_terms.is_some()
        || canonical_json_bytes(proposal)?.len() > super::wire::MAX_ARTIFACT_BYTES
        || !proposal.policy.provider_key.verify_strict(
            &canonical_json_bytes(&proposal.agreement)?,
            &proposal.provider_signature,
        )
    {
        return Err("invalid original provider proposal".into());
    }
    Ok(())
}

pub(super) fn propose(native: &Native, intent: &Intent, input: &str) -> Result<Proposal> {
    validate_intent(intent, &native.policy, input)?;
    let state = &native.state;
    if state.join("provider-intent.json").try_exists()? {
        let retained: Intent = evidence::read(state.join("provider-intent.json"))?;
        if canonical_json_bytes(&retained)? != canonical_json_bytes(intent)? {
            return Err("provider cannot replace original work intent".into());
        }
        let original: Original = evidence::read(state.join("provider-proposal.json"))?;
        validate(&original.proposal, intent, original.proposal.issued_at)?;
        validate_request(&original)?;
        return Ok(original.proposal);
    }
    if state.join("provider-proposal.json").try_exists()? {
        return Err("original provider intent marker is missing".into());
    }
    super::finding_acceptance::validate_context(
        &native.policy.finding_context,
        &native.policy.verifier_key,
        &native.policy.provider_key,
        common::now()?,
    )?;
    // A crash after capability issuance must not issue a replacement request.
    retain(state, "provider-intent.json", intent)?;
    let request = native.request(&intent.request_id, input, intent.work.submit_by)?;
    let agreement = Agreement {
        schema: AGREEMENT_SCHEMA.into(),
        policy_sha256: digest(&native.policy)?,
        authority_uuid: native.policy.authority_uuid.clone(),
        buyer_key: native.policy.buyer_key.clone(),
        provider_key: native.policy.provider_key.clone(),
        request_id: request.request_id.clone(),
        request_sha256: digest(&request)?,
        finding_context_sha256: digest(&native.policy.finding_context)?,
        required_finding_facets: native.policy.required_finding_facets.clone(),
        domain: native.policy.domain.clone(),
        work: intent.work.clone(),
        capture_waiver_terms: None,
    };
    let provider_signature = common::key(state)?.sign(&canonical_json_bytes(&agreement)?);
    let proposal = Proposal {
        schema: PROPOSAL_SCHEMA.into(),
        policy: native.policy.clone(),
        agreement,
        input: input.into(),
        issued_at: common::now()?,
        provider_signature,
    };
    validate(&proposal, intent, common::now()?)?;
    retain(
        state,
        "provider-proposal.json",
        &Original {
            proposal: proposal.clone(),
            request,
        },
    )?;
    Ok(proposal)
}
fn validate_request(original: &Original) -> Result<()> {
    if digest(&original.request)? != original.proposal.agreement.request_sha256
        || original
            .request
            .arguments
            .get("input")
            .and_then(|v| v.as_str())
            != Some(original.proposal.input.as_str())
    {
        return Err("proposal lost original private request custody".into());
    }
    Ok(())
}
fn verify_acceptance(accepted: &Acceptance, proposal: &Proposal) -> Result<()> {
    if accepted.body.schema != ACCEPTANCE_SCHEMA
        || accepted.body.proposal_sha256 != digest(proposal)?
        || canonical_json_bytes(&accepted.body.agreement.body)?
            != canonical_json_bytes(&proposal.agreement)?
        || !proposal
            .policy
            .buyer_key
            .verify_strict(&canonical_json_bytes(&accepted.body)?, &accepted.signature)
    {
        return Err("buyer acceptance changes original public proposal".into());
    }
    accepted.body.agreement.validate_public(&proposal.policy)?;
    Ok(())
}
pub fn accept(state: &Path, intent: &Intent, proposal: &Proposal) -> Result<Acceptance> {
    let path = state.join("buyer-consent.json");
    let marker = state.join("buyer-intent.json");
    if path.try_exists()? {
        let original: Intent = evidence::read(&marker)?;
        if canonical_json_bytes(&original)? != canonical_json_bytes(intent)? {
            return Err("original buyer intent changed".into());
        }
        let stored: Consent = evidence::read(path)?;
        if canonical_json_bytes(&stored.intent)? != canonical_json_bytes(intent)?
            || canonical_json_bytes(&stored.proposal)? != canonical_json_bytes(proposal)?
        {
            return Err("buyer cannot replace original consent".into());
        }
        validate(proposal, intent, stored.accepted_at)?;
        verify_acceptance(&stored.acceptance, proposal)?;
        return Ok(stored.acceptance);
    }
    if marker.try_exists()? {
        return Err("original buyer consent is incomplete or missing".into());
    }
    let at = common::now()?;
    validate(proposal, intent, at)?;
    let key = common::key(state)?;
    if key.public_key() != proposal.policy.buyer_key {
        return Err("buyer seed differs from selected original identity".into());
    }
    retain(state, "buyer-intent.json", intent)?;
    let agreement = SignedAgreement {
        body: proposal.agreement.clone(),
        buyer_signature: key.sign(&canonical_json_bytes(&proposal.agreement)?),
        provider_signature: proposal.provider_signature.clone(),
    };
    let acceptance = evidence::sign(
        AcceptanceBody {
            schema: ACCEPTANCE_SCHEMA.into(),
            proposal_sha256: digest(proposal)?,
            agreement,
        },
        &key,
    )?;
    verify_acceptance(&acceptance, proposal)?;
    retain(
        state,
        "buyer-consent.json",
        &Consent {
            intent: intent.clone(),
            proposal: proposal.clone(),
            acceptance: acceptance.clone(),
            accepted_at: at,
        },
    )?;
    Ok(acceptance)
}
pub(super) fn original(
    native: &Native,
    accepted: &Acceptance,
) -> Result<(SignedAgreement, ToolCallRequest)> {
    let stored: Original = evidence::read(native.state.join("provider-proposal.json"))?;
    let intent: Intent = evidence::read(native.state.join("provider-intent.json"))?;
    validate(&stored.proposal, &intent, stored.proposal.issued_at)?;
    validate_request(&stored)?;
    verify_acceptance(accepted, &stored.proposal)?;
    accepted
        .body
        .agreement
        .validate(&native.policy, &stored.request)?;
    Ok((accepted.body.agreement.clone(), stored.request))
}
