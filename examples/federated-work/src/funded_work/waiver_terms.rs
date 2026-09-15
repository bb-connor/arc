//! Explicit original waiver authority, signed before funding and admission.
use super::agreement::{Agreement, Policy, WorkTerms};
use crate::common::{digest, Result};
use chio_core_types::Keypair;
use chio_kernel::{
    payment::{
        ContractualCaptureWaiverPolicyV1, ContractualCaptureWaiverTermsV1,
        SignedContractualCaptureWaiverTermsV1, CAPTURE_WAIVER_TERMS_ARGUMENT,
        CONTRACTUAL_CAPTURE_WAIVER_SCHEMA,
    },
    ToolCallRequest,
};
use serde_json::json;

pub(super) fn policy(policy: &Policy) -> ContractualCaptureWaiverPolicyV1 {
    ContractualCaptureWaiverPolicyV1 {
        receiver_key: policy.provider_key.clone(),
        counterparty_key: policy.buyer_key.clone(),
        observation_key: policy.verifier_key.clone(),
        rail: super::rail::RAIL.into(),
        currency: super::native::CURRENCY.into(),
    }
}

pub(super) fn context(policy: &Policy, work: &WorkTerms) -> Result<String> {
    digest(
        &json!({"schema":"chio.experimental.native-funded-waiver-context.v1","domain":policy.domain,"work":work}),
    )
}

pub(super) fn authorize(
    policy: &Policy,
    work: &WorkTerms,
    request: &mut ToolCallRequest,
    receiver: &Keypair,
    buyer: &Keypair,
) -> Result<SignedContractualCaptureWaiverTermsV1> {
    let issued_at_unix_ms = super::now_ms()?;
    let terms = SignedContractualCaptureWaiverTermsV1::sign(
        ContractualCaptureWaiverTermsV1 {
            schema: CONTRACTUAL_CAPTURE_WAIVER_SCHEMA.into(),
            policy_digest: digest(&self::policy(policy))?,
            contract_context_digest: context(policy, work)?,
            capability_digest: digest(&request.capability)?,
            request_id: request.request_id.clone(),
            issued_at_unix_ms,
            expires_at_unix_ms: issued_at_unix_ms
                .checked_add(86_400_000)
                .ok_or("waiver lifetime overflow")?,
        },
        receiver,
        buyer,
    )?;
    request.arguments[CAPTURE_WAIVER_TERMS_ARGUMENT] = json!(digest(&terms)?);
    Ok(terms)
}

pub(super) fn validate(
    agreement: &Agreement,
    policy: &Policy,
    request: &ToolCallRequest,
) -> Result<()> {
    let Some(terms) = &agreement.capture_waiver_terms else {
        if request
            .arguments
            .get(CAPTURE_WAIVER_TERMS_ARGUMENT)
            .is_some()
        {
            return Err("waiver digest requires explicit signed original terms".into());
        }
        return Ok(());
    };
    terms.verify(&self::policy(policy))?;
    let body = &terms.body;
    if body.contract_context_digest != context(policy, &agreement.work)?
        || body.capability_digest != digest(&request.capability)?
        || body.request_id != request.request_id
        || request.arguments[CAPTURE_WAIVER_TERMS_ARGUMENT].as_str()
            != Some(digest(terms)?.as_str())
        || body.issued_at_unix_ms > super::now_ms()?
        || body.expires_at_unix_ms <= body.issued_at_unix_ms
        || body.expires_at_unix_ms - body.issued_at_unix_ms > 86_400_000
    {
        return Err("waiver clause changes original contract or request authority".into());
    }
    Ok(())
}

pub(super) fn supported_arguments(arguments: &serde_json::Value) -> bool {
    arguments.as_object().is_some_and(|object| {
        object.len() == 1 && object.contains_key("input")
            || object.len() == 2
                && object.contains_key("input")
                && object
                    .get(CAPTURE_WAIVER_TERMS_ARGUMENT)
                    .and_then(|value| value.as_str())
                    .is_some_and(|hash| {
                        hash.len() == 64
                            && hash
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    })
    })
}
