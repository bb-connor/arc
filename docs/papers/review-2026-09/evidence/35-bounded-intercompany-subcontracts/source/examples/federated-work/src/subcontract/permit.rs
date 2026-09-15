//! A receiver-checked procurement permit, separate from issuer trust roots.
use super::*;
use chio_core_types::{receipt::lineage::SignedExportEnvelope, Keypair};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Permit {
    pub schema: String,
    pub parent_agreement_sha256: String,
    pub parent_request_sha256: String,
    pub child_agreement_sha256: String,
    pub delegate: PublicKey,
    pub specialist: PublicKey,
    pub price_ceiling: u64,
    pub currency: String,
    pub expires_at: u64,
}

pub type SignedPermit = SignedExportEnvelope<Permit>;

pub fn terms(parent: &review::ReviewRequest) -> Result<Permit> {
    let child = child_agreement(&parent.acceptance.quote.agreement)?;
    Ok(Permit {
        schema: "chio.example.subcontract-permit.v1".into(),
        parent_agreement_sha256: digest(&parent.acceptance.quote.agreement)?,
        parent_request_sha256: digest(parent)?,
        child_agreement_sha256: digest(&child)?,
        delegate: child.buyer.clone(),
        specialist: child.provider.clone(),
        price_ceiling: child.price_ceiling,
        currency: "TST".into(),
        expires_at: child.deadline,
    })
}

pub fn issue(parent: &review::ReviewRequest, signer: &Keypair) -> Result<SignedPermit> {
    if signer.public_key() != parent.acceptance.quote.agreement.provider {
        return Err("permit signer is not the parent receiver".into());
    }
    parent.validate(&Peers {
        buyer: parent.acceptance.quote.agreement.buyer.clone(),
        provider: signer.public_key(),
    })?;
    Ok(SignedPermit::sign(terms(parent)?, signer)?)
}

pub fn verify(
    permit: &SignedPermit,
    child: &Agreement,
    promisor: &PublicKey,
    live: Option<u64>,
) -> Result<()> {
    let body = &permit.body;
    let is_digest = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if &permit.signer_key != promisor
        || !permit.verify_signature()?
        || body.schema != "chio.example.subcontract-permit.v1"
        || !is_digest(&body.parent_agreement_sha256)
        || !is_digest(&body.parent_request_sha256)
        || body.child_agreement_sha256 != digest(child)?
        || child.profile != WORK_PROFILE
        || child.subcontracting
        || child.subcontract.is_some()
        || child.job_id != format!("child-{}", body.parent_agreement_sha256)
        || child.buyer != body.delegate
        || child.provider != body.specialist
        || body.delegate == *promisor
        || body.specialist == *promisor
        || body.delegate == body.specialist
        || child.price_ceiling != body.price_ceiling
        || body.price_ceiling != 100
        || body.currency != "TST"
        || child.deadline != body.expires_at
        || live.is_some_and(|now| now >= body.expires_at)
    {
        return Err("subcontract permit does not authorize this exact child procurement".into());
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiverPolicy {
    pub promisor: PublicKey,
    pub delegate: PublicKey,
}
impl ReceiverPolicy {
    pub fn load(state: &std::path::Path, peers: &Peers) -> Result<Option<Self>> {
        let path = state.join("delegation.json");
        if !path.exists() {
            return Ok(None);
        }
        let policy: Self = read(path)?;
        if policy.delegate != peers.buyer
            || policy.promisor == peers.provider
            || policy.promisor == policy.delegate
        {
            return Err("delegated receiver policy changes the configured agent or confuses authority roles".into());
        }
        Ok(Some(policy))
    }
}

pub fn verify_parent(
    parent: &review::ReviewRequest,
    child: &crate::market::QuoteRequest,
) -> Result<()> {
    let permit = child
        .subcontract_permit
        .as_ref()
        .ok_or("specialist evidence has no procurement permit")?;
    verify(
        permit,
        &child.agreement,
        &parent.acceptance.quote.agreement.provider,
        None,
    )?;
    if permit.body != terms(parent)? {
        return Err("specialist permit changes the parent request or agreement".into());
    }
    Ok(())
}
