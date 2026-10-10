#![cfg(feature = "web3")]

use chio_core::web3::settlement::Web3SettlementDispatchArtifact;
use chio_settle::{
    build_x402_payment_requirements, ApprovalBinding, SettlementError, X402PaymentRequirements,
    X402SettlementMode,
};
use chio_test_support::prelude::*;

fn fixture() -> (Web3SettlementDispatchArtifact, ApprovalBinding) {
    // This is a synthetic requirements fixture. No rail or payment service is invoked.
    let dispatch: Web3SettlementDispatchArtifact = serde_json::from_str(include_str!(
        "../../../../docs/standards/CHIO_WEB3_SETTLEMENT_DISPATCH_EXAMPLE.json"
    ))
    .test_unwrap();
    let binding = ApprovalBinding {
        chain_id: 8453,
        payee_address: dispatch.beneficiary_address.clone(),
        amount_minor_units: u128::from(dispatch.settlement_amount.units),
        token_symbol: dispatch.settlement_amount.currency.clone(),
        token_contract: None,
        approval_expires_at: 1_744_000_600,
    };
    (dispatch, binding)
}

fn requirements(tokens: &[&str]) -> Result<X402PaymentRequirements, SettlementError> {
    let (dispatch, binding) = fixture();
    build_x402_payment_requirements(
        &dispatch,
        &binding,
        "https://facilitator.example/x402",
        "https://tool.example/v1/run",
        tokens.iter().map(|token| (*token).to_string()).collect(),
        X402SettlementMode::PrepaidAuthorization,
    )
}

#[test]
fn x402_rejects_an_extra_token_after_the_approved_token() {
    let result = requirements(&["USD", "EURC"]);
    assert!(
        matches!(&result, Err(SettlementError::InvalidBinding(_))),
        "USD approval published requirements authorizing another token: {result:?}"
    );
}

#[test]
fn x402_rejects_an_extra_token_before_the_approved_token() {
    let result = requirements(&["EURC", "USD"]);
    assert!(
        matches!(&result, Err(SettlementError::InvalidBinding(_))),
        "token order must not authorize EURC through a USD approval: {result:?}"
    );
}

#[test]
fn x402_rejects_an_extra_token_among_duplicate_case_variants() {
    let result = requirements(&["usd", "USD", "eUrC"]);
    assert!(
        matches!(&result, Err(SettlementError::InvalidBinding(_))),
        "duplicate approved symbols must not conceal an unapproved token: {result:?}"
    );
}

#[test]
fn x402_preserves_the_single_approved_token_in_both_modes() {
    let (dispatch, binding) = fixture();
    for mode in [
        X402SettlementMode::PrepaidAuthorization,
        X402SettlementMode::EscrowBacked,
    ] {
        let result = build_x402_payment_requirements(
            &dispatch,
            &binding,
            "https://facilitator.example/x402",
            "https://tool.example/v1/run",
            vec!["USD".to_string()],
            mode,
        )
        .test_unwrap();
        assert_eq!(result.accepted_tokens, vec!["USD".to_string()]);
        assert_eq!(result.currency, "USD");
        assert_eq!(result.amount_minor_units, dispatch.settlement_amount.units);
        assert_eq!(result.chain_id, dispatch.chain_id);
        assert_eq!(result.pay_to, dispatch.beneficiary_address);
        assert_eq!(result.dispatch_id, dispatch.dispatch_id);
        assert_eq!(result.settlement_mode, mode);
        assert!(result.governed_authorization_required);
    }
}

#[test]
fn x402_rejects_a_missing_approved_token() {
    for tokens in [&["EURC"][..], &["EURC", "USDC"][..]] {
        assert!(matches!(
            requirements(tokens),
            Err(SettlementError::InvalidBinding(_))
        ));
    }
}

#[test]
fn x402_rejects_an_empty_accepted_token_list() {
    assert!(matches!(
        requirements(&[]),
        Err(SettlementError::InvalidInput(message))
            if message == "x402 compatibility requires at least one accepted token"
    ));
}

#[test]
fn x402_preserves_case_equivalent_approved_symbols() {
    let (dispatch, mut binding) = fixture();
    binding.token_symbol = " usd ".to_string();
    for symbol in ["usd", "UsD"] {
        let result = build_x402_payment_requirements(
            &dispatch,
            &binding,
            "https://facilitator.example/x402",
            "https://tool.example/v1/run",
            vec![symbol.to_string()],
            X402SettlementMode::PrepaidAuthorization,
        )
        .test_unwrap();
        assert_eq!(result.accepted_tokens, vec![symbol.to_string()]);
        assert_eq!(result.currency, "USD");
    }
}

#[test]
fn x402_preserves_duplicate_approved_symbols_without_coercion() {
    for tokens in [&["USD", "USD"][..], &["USD", "usd", "UsD"][..]] {
        let result = requirements(tokens).test_unwrap();
        let expected: Vec<_> = tokens.iter().map(|token| (*token).to_string()).collect();
        assert_eq!(result.accepted_tokens, expected);
        assert_eq!(result.currency, "USD");
    }
}

#[test]
fn x402_rejects_unicode_token_substitution() {
    assert!(matches!(
        requirements(&["U\u{ff33}D"]),
        Err(SettlementError::InvalidBinding(_))
    ));
}

#[test]
fn x402_keeps_accepted_token_whitespace_validation() {
    for symbol in ["", " USD", "USD ", "U SD", "USD\n"] {
        assert!(matches!(
            requirements(&["USD", symbol]),
            Err(SettlementError::InvalidInput(message)) if message.contains("accepted token")
        ));
    }
}

#[test]
fn x402_keeps_chain_payee_amount_and_currency_binding_checks() {
    for field in ["chain", "payee", "amount", "token"] {
        let (dispatch, mut binding) = fixture();
        match field {
            "chain" => binding.chain_id += 1,
            "payee" => {
                binding.payee_address = "0x3333333333333333333333333333333333333333".to_string();
            }
            "amount" => binding.amount_minor_units += 1,
            "token" => binding.token_symbol = "EURC".to_string(),
            _ => unreachable!("all binding fields are listed"),
        }
        let result = build_x402_payment_requirements(
            &dispatch,
            &binding,
            "https://facilitator.example/x402",
            "https://tool.example/v1/run",
            vec!["USD".to_string()],
            X402SettlementMode::PrepaidAuthorization,
        );
        assert!(
            matches!(result, Err(SettlementError::InvalidBinding(message))
                if message.contains(&format!("{field} mismatch"))),
            "lost the existing {field} approval binding"
        );
    }
}
