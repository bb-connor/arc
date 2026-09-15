use super::{
    agreement::{Agreement, SignedAgreement, WorkTerms, AGREEMENT_SCHEMA},
    local_chain::LocalChain,
    native::Native,
    observer::Domain,
};
use crate::common::{digest, Result};
use chio_core_types::Keypair;
use serde_json::json;
use std::{path::Path, sync::Arc};

pub(super) struct Scenario {
    pub chain: Arc<LocalChain>,
    pub native: Native,
    pub agreement: SignedAgreement,
    pub request: chio_kernel::ToolCallRequest,
    pub funding: serde_json::Value,
}

pub(super) fn setup(state: &Path) -> Result<Scenario> {
    let chain = Arc::new(LocalChain::start()?);
    let setup = chain.request(json!({"method": "initialize"}))?;
    setup_on_chain(
        state,
        chain,
        &setup,
        &Keypair::generate(),
        "funded-native-w0",
    )
}

pub(super) fn setup_on_chain(
    state: &Path,
    chain: Arc<LocalChain>,
    setup: &serde_json::Value,
    buyer: &Keypair,
    request_id: &str,
) -> Result<Scenario> {
    let domain: Domain = serde_json::from_value(setup["domain"].clone())?;
    let work: WorkTerms = serde_json::from_value(setup["work"].clone())?;
    Native::provision(state, buyer.public_key(), domain.clone())?;
    let native = Native::open(state, chain.clone())?;
    let mut request = native.request(
        request_id,
        include_str!("../../fixtures/openapi.json"),
        work.submit_by,
    )?;
    let receiver = crate::common::key(state)?;
    let waiver =
        super::waiver_terms::authorize(&native.policy, &work, &mut request, &receiver, buyer)?;
    let agreement = Agreement {
        schema: AGREEMENT_SCHEMA.into(),
        policy_sha256: digest(&native.policy)?,
        authority_uuid: native.policy.authority_uuid.clone(),
        buyer_key: buyer.public_key(),
        provider_key: native.policy.provider_key.clone(),
        request_id: request.request_id.clone(),
        request_sha256: digest(&request)?,
        domain,
        work,
        capture_waiver_terms: Some(waiver),
    }
    .sign(buyer, &crate::common::key(state)?)?;
    let funding = chain.request(json!({"method": "fund", "terms": agreement.body.terms()?}))?;
    Ok(Scenario {
        chain,
        native,
        agreement,
        request,
        funding,
    })
}

pub fn run(state: &Path) -> Result<serde_json::Value> {
    let Scenario {
        chain,
        native,
        agreement,
        request,
        funding,
    } = setup(state)?;
    let first = native.execute(&agreement, &request)?;
    if first["allocationId"] != funding["allocationId"] {
        return Err("native allocation differs from contract".into());
    }
    drop(native);
    let recovered = Native::open(state, chain.clone())?;
    let replay = recovered.execute(&agreement, &request)?;
    let summary =
        chain.request(json!({"method": "summary", "allocation": funding["allocationId"]}))?;
    Ok(json!({"first": first, "replay": replay, "chain": summary}))
}
