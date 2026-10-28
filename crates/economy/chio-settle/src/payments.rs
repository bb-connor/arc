use chio_core::hashing::sha256;
use chio_core::web3::settlement::Web3SettlementDispatchArtifact;
use serde::{Deserialize, Serialize};

use crate::{SettlementError, VerifiedApproval};

#[path = "payments_approval.rs"]
mod approval_binding;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum X402SettlementMode {
    PrepaidAuthorization,
    EscrowBacked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct X402PaymentRequirements {
    pub version: String,
    pub chain_id: String,
    pub facilitator_url: String,
    pub resource: String,
    pub pay_to: String,
    pub accepted_tokens: Vec<String>,
    pub dispatch_id: String,
    pub capability_id: String,
    pub amount_minor_units: u64,
    pub currency: String,
    pub settlement_mode: X402SettlementMode,
    pub governed_authorization_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CircleNanopaymentPolicy {
    pub enabled: bool,
    pub managed_balance_id: String,
    pub supported_chain_ids: Vec<String>,
    pub supported_token_symbols: Vec<String>,
    pub max_amount_minor_units: u64,
    pub operator_managed_custody_explicit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedCircleNanopayment {
    pub payment_id: String,
    pub managed_balance_id: String,
    pub chain_id: String,
    pub amount_minor_units: u64,
    pub currency: String,
    pub beneficiary_address: String,
    pub dispatch_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Erc4337PaymasterPolicy {
    pub entry_point: String,
    pub paymaster_address: String,
    pub supported_chain_ids: Vec<String>,
    pub max_sponsor_gas_limit: u64,
    pub max_reimbursement_minor_units: u64,
    pub settlement_deduction_explicit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedPaymasterCompatibility {
    pub dispatch_id: String,
    pub chain_id: String,
    pub entry_point: String,
    pub paymaster_address: String,
    pub user_operation_hash: String,
    pub sponsor_gas_limit: u64,
    pub estimated_reimbursement_minor_units: u64,
    pub allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
}

pub fn build_x402_payment_requirements(
    dispatch: &Web3SettlementDispatchArtifact,
    mut approval: VerifiedApproval,
    facilitator_url: &str,
    resource: &str,
    accepted_tokens: Vec<String>,
    settlement_mode: X402SettlementMode,
) -> Result<X402PaymentRequirements, SettlementError> {
    approval.check_time()?;
    let approval_binding = approval.binding();
    approval_binding.require_symbol_only_lane()?;
    approval_binding.assert_dispatch("x402", dispatch)?;
    validate_x402_field("facilitator URL", facilitator_url)?;
    validate_x402_field("resource", resource)?;
    if accepted_tokens.is_empty() {
        return Err(SettlementError::InvalidInput(
            "x402 compatibility requires at least one accepted token".to_string(),
        ));
    }
    for (index, token) in accepted_tokens.iter().enumerate() {
        validate_x402_field(&format!("accepted token {index}"), token)?;
    }
    for token in &accepted_tokens {
        approval_binding.assert_token_symbol("x402", token)?;
    }
    let requirements = X402PaymentRequirements {
        version: "x402".to_string(),
        chain_id: dispatch.chain_id.clone(),
        facilitator_url: facilitator_url.to_string(),
        resource: resource.to_string(),
        pay_to: dispatch.beneficiary_address.clone(),
        accepted_tokens,
        dispatch_id: dispatch.dispatch_id.clone(),
        capability_id: dispatch
            .capital_instruction
            .body
            .query
            .capability_id
            .clone()
            .unwrap_or_else(|| dispatch.dispatch_id.clone()),
        amount_minor_units: dispatch.settlement_amount.units,
        currency: dispatch.settlement_amount.currency.clone(),
        settlement_mode,
        governed_authorization_required: true,
    };
    approval.consume()?;
    Ok(requirements)
}

fn validate_x402_field(label: &str, value: &str) -> Result<(), SettlementError> {
    if value.trim().is_empty() {
        return Err(SettlementError::InvalidInput(format!(
            "x402 compatibility requires {label}"
        )));
    }
    if value.trim() != value || value.chars().any(char::is_whitespace) {
        return Err(SettlementError::InvalidInput(format!(
            "x402 compatibility {label} must not contain whitespace"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBinding {
    pub schema: String,
    pub chain_id: u64,
    pub payee_address: String,
    pub amount_minor_units: u128,
    pub token_symbol: String,
    pub settlement_currency: String,
    pub token_contract: Option<String>,
    pub dispatch_id: String,
    pub capability_id: String,
}

pub fn evaluate_circle_nanopayment(
    dispatch: &Web3SettlementDispatchArtifact,
    mut approval: VerifiedApproval,
    policy: &CircleNanopaymentPolicy,
) -> Result<Option<PreparedCircleNanopayment>, SettlementError> {
    approval.check_time()?;
    if !policy.enabled {
        return Ok(None);
    }
    let approval_binding = approval.binding();
    approval_binding.require_symbol_only_lane()?;
    if !approval_binding
        .token_symbol
        .eq_ignore_ascii_case(&approval_binding.settlement_currency)
    {
        return Err(SettlementError::InvalidBinding(
            "circle requires token-native settlement currency".to_string(),
        ));
    }
    approval_binding.assert_dispatch("circle", dispatch)?;
    if !policy.operator_managed_custody_explicit {
        return Err(SettlementError::InvalidInput(
            "Circle nanopayment policy must keep operator-managed custody explicit".to_string(),
        ));
    }
    if !policy
        .supported_chain_ids
        .iter()
        .any(|chain_id| chain_id == &dispatch.chain_id)
    {
        return Ok(None);
    }
    if !policy
        .supported_token_symbols
        .iter()
        .any(|symbol| symbol == &dispatch.settlement_amount.currency)
    {
        return Ok(None);
    }
    if dispatch.settlement_amount.units > policy.max_amount_minor_units {
        return Ok(None);
    }
    let prepared = PreparedCircleNanopayment {
        payment_id: format!(
            "chio-circle-{}",
            &sha256(
                format!(
                    "{}:{}:{}",
                    dispatch.dispatch_id, dispatch.chain_id, dispatch.settlement_amount.units
                )
                .as_bytes()
            )
            .to_hex()[..16]
        ),
        managed_balance_id: policy.managed_balance_id.clone(),
        chain_id: dispatch.chain_id.clone(),
        amount_minor_units: dispatch.settlement_amount.units,
        currency: dispatch.settlement_amount.currency.clone(),
        beneficiary_address: dispatch.beneficiary_address.clone(),
        dispatch_id: dispatch.dispatch_id.clone(),
    };
    approval.consume()?;
    Ok(Some(prepared))
}

pub fn prepare_paymaster_compatibility(
    dispatch: &Web3SettlementDispatchArtifact,
    policy: &Erc4337PaymasterPolicy,
    user_operation_hash: &str,
    sponsor_gas_limit: u64,
    estimated_reimbursement_minor_units: u64,
) -> Result<PreparedPaymasterCompatibility, SettlementError> {
    if user_operation_hash.trim().is_empty() {
        return Err(SettlementError::InvalidInput(
            "ERC-4337 compatibility requires a user operation hash".to_string(),
        ));
    }
    let supported_chain = policy
        .supported_chain_ids
        .iter()
        .any(|chain_id| chain_id == &dispatch.chain_id);
    let within_budget = sponsor_gas_limit <= policy.max_sponsor_gas_limit
        && estimated_reimbursement_minor_units <= policy.max_reimbursement_minor_units;
    let allowed = supported_chain && within_budget && policy.settlement_deduction_explicit;
    let rejection_reason = if allowed {
        None
    } else if !supported_chain {
        Some("requested chain is outside the bounded paymaster surface".to_string())
    } else if !policy.settlement_deduction_explicit {
        Some(
            "paymaster reimbursement must remain an explicit settlement-side deduction".to_string(),
        )
    } else {
        Some("requested sponsorship exceeds the bounded gas or reimbursement policy".to_string())
    };

    Ok(PreparedPaymasterCompatibility {
        dispatch_id: dispatch.dispatch_id.clone(),
        chain_id: dispatch.chain_id.clone(),
        entry_point: policy.entry_point.clone(),
        paymaster_address: policy.paymaster_address.clone(),
        user_operation_hash: user_operation_hash.to_string(),
        sponsor_gas_limit,
        estimated_reimbursement_minor_units,
        allowed,
        rejection_reason,
    })
}

#[cfg(test)]
mod tests {
    use crate as settle_api;
    mod approval_support {
        include!("../tests/support/approval.rs");
    }
    use super::{
        build_x402_payment_requirements, evaluate_circle_nanopayment,
        prepare_paymaster_compatibility, ApprovalBinding, CircleNanopaymentPolicy,
        Erc4337PaymasterPolicy, X402SettlementMode,
    };
    use chio_core::web3::settlement::Web3SettlementDispatchArtifact;

    use chio_test_support::prelude::*;

    fn sample_dispatch() -> Web3SettlementDispatchArtifact {
        serde_json::from_str(include_str!(
            "../../../../docs/standards/CHIO_WEB3_SETTLEMENT_DISPATCH_EXAMPLE.json"
        ))
        .test_unwrap()
    }

    fn binding_for_dispatch(dispatch: &Web3SettlementDispatchArtifact) -> ApprovalBinding {
        ApprovalBinding {
            schema: "chio.settlement-binding.v1".to_string(),
            chain_id: 8453,
            payee_address: dispatch.beneficiary_address.clone(),
            amount_minor_units: u128::from(dispatch.settlement_amount.units),
            token_symbol: dispatch.settlement_amount.currency.clone(),
            settlement_currency: dispatch.settlement_amount.currency.clone(),
            token_contract: None,
            dispatch_id: dispatch.dispatch_id.clone(),
            capability_id: dispatch
                .capital_instruction
                .body
                .query
                .capability_id
                .clone()
                .unwrap_or_else(|| dispatch.dispatch_id.clone()),
        }
    }

    #[test]
    fn builds_x402_requirements() {
        let dispatch = sample_dispatch();
        let binding = binding_for_dispatch(&dispatch);
        let requirements = build_x402_payment_requirements(
            &dispatch,
            approval_support::witness(&binding),
            "https://facilitator.example/x402",
            "https://tool.example/v1/run",
            vec!["USD".to_string()],
            X402SettlementMode::PrepaidAuthorization,
        )
        .test_unwrap();

        assert!(requirements.governed_authorization_required);
        assert_eq!(requirements.dispatch_id, dispatch.dispatch_id);
        assert_eq!(requirements.accepted_tokens, vec!["USD".to_string()]);
    }

    #[test]
    fn x402_requirements_reject_blank_accepted_tokens() {
        let dispatch = sample_dispatch();
        let binding = binding_for_dispatch(&dispatch);

        let error = build_x402_payment_requirements(
            &dispatch,
            approval_support::witness(&binding),
            "https://facilitator.example/x402",
            "https://tool.example/v1/run",
            vec!["USD".to_string(), " ".to_string()],
            X402SettlementMode::PrepaidAuthorization,
        )
        .test_unwrap_err();

        assert!(error.to_string().contains("accepted token"));
    }

    #[test]
    fn assert_token_symbol_is_case_insensitive_and_fails_closed() {
        let mut binding = binding_for_dispatch(&sample_dispatch());
        binding.token_symbol = "USDC".to_string();
        // Case and surrounding whitespace must not matter.
        assert!(binding.assert_token_symbol("x402", " usdc ").is_ok());
        assert!(binding.assert_token_symbol("circle", "USDC").is_ok());
        // A genuinely different token must be rejected.
        let error = binding
            .assert_token_symbol("x402", "EURC")
            .test_unwrap_err();
        assert!(
            error.to_string().contains("token mismatch"),
            "a different token symbol must be rejected, got: {error}"
        );
    }

    #[test]
    fn evaluates_circle_nanopayment_candidate() {
        let dispatch = sample_dispatch();
        let binding = binding_for_dispatch(&dispatch);
        let prepared = evaluate_circle_nanopayment(
            &dispatch,
            approval_support::witness(&binding),
            &CircleNanopaymentPolicy {
                enabled: true,
                managed_balance_id: "bal_123".to_string(),
                supported_chain_ids: vec!["eip155:8453".to_string()],
                supported_token_symbols: vec!["USD".to_string()],
                max_amount_minor_units: 200,
                operator_managed_custody_explicit: true,
            },
        )
        .test_unwrap()
        .test_unwrap();

        assert_eq!(prepared.dispatch_id, dispatch.dispatch_id);
    }

    #[test]
    fn settlement_compatibility_lanes_reject_mismatched_approval_binding() {
        let dispatch = sample_dispatch();
        let mut binding = binding_for_dispatch(&dispatch);
        binding.amount_minor_units += 1;

        let error = build_x402_payment_requirements(
            &dispatch,
            approval_support::witness(&binding),
            "https://facilitator.example/x402",
            "https://tool.example/v1/run",
            vec!["USD".to_string()],
            X402SettlementMode::PrepaidAuthorization,
        )
        .test_unwrap_err();

        assert!(error.to_string().contains("amount mismatch"));
    }

    #[test]
    fn evaluates_paymaster_compatibility() {
        let dispatch = sample_dispatch();
        let prepared = prepare_paymaster_compatibility(
            &dispatch,
            &Erc4337PaymasterPolicy {
                entry_point: "0x1000000000000000000000000000000000000100".to_string(),
                paymaster_address: "0x1000000000000000000000000000000000000101".to_string(),
                supported_chain_ids: vec!["eip155:8453".to_string()],
                max_sponsor_gas_limit: 300_000,
                max_reimbursement_minor_units: 10,
                settlement_deduction_explicit: true,
            },
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            250_000,
            5,
        )
        .test_unwrap();

        assert!(prepared.allowed);
        assert!(prepared.rejection_reason.is_none());
    }
}
