use std::sync::Arc;

use chio_core::credit::SignedCapitalExecutionInstruction;
use chio_core::web3::settlement::Web3SettlementDispatchArtifact;
use chio_core_types::canonical::UntrustedJsonText;
use chio_core_types::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedTransactionIntent, GovernedTransactionIntentBody,
};
use chio_core_types::crypto::Keypair;
use chio_security_types::clock::FixedClock;
use chio_settle::{
    build_x402_payment_requirements, evaluate_circle_nanopayment, verify_governed_approval,
    ApprovalBinding, CircleNanopaymentPolicy, InMemoryApprovalReplayStore, SettlementError,
    X402SettlementMode,
};

pub fn settlement_approval_witness(data: &[u8]) {
    let _ = exercise(data);
}

fn exercise(data: &[u8]) -> bool {
    let Ok(binding_value) = UntrustedJsonText::from_wire(data, 4096)
        .and_then(|input| input.decode_signed::<serde_json::Value>())
    else {
        return false;
    };
    let intent = GovernedTransactionIntent {
        id: "fuzz-settlement-intent".into(),
        server_id: "settlement".into(),
        tool_name: "prepare".into(),
        purpose: "fuzz settlement binding".into(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(serde_json::json!({"chioSettlementBinding": binding_value})),
        body: GovernedTransactionIntentBody::ToolInvocation,
    };
    let Ok(intent_hash) = intent.binding_hash() else {
        return false;
    };
    let approver = Keypair::from_seed(&[91; 32]);
    let subject = Keypair::from_seed(&[92; 32]);
    let token = GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: "fuzz-settlement-approval".into(),
            approver: approver.public_key(),
            subject: subject.public_key(),
            governed_intent_hash: intent_hash,
            request_id: "fuzz-settlement-request".into(),
            threshold_proposal_hash: None,
            issued_at: 90,
            expires_at: 120,
            decision: GovernedApprovalDecision::Approved,
        },
        &approver,
    )
    .unwrap_or_else(|error| panic!("fixed approval signer: {error}"));
    let clock = Arc::new(FixedClock::new(100));
    let replay = Arc::new(InMemoryApprovalReplayStore::default());
    let verify = |token: &GovernedApprovalToken| {
        verify_governed_approval(
            token,
            &intent,
            &approver.public_key(),
            &subject.public_key(),
            "fuzz-settlement-request",
            clock.clone(),
            replay.clone(),
        )
    };
    let Ok(witness) = verify(&token) else {
        return false;
    };
    let binding: ApprovalBinding = serde_json::from_value(binding_value).unwrap_or_else(|error| {
        panic!("verified commitment must decode to its declared binding: {error}")
    });
    let mut corrupted = token.clone();
    corrupted.id.push('x');
    assert!(
        matches!(verify(&corrupted), Err(SettlementError::Verification(reason))
        if reason == "settlement approval signature invalid")
    );
    let mut dispatch: Web3SettlementDispatchArtifact = serde_json::from_str(include_str!(
        "../../../docs/standards/CHIO_WEB3_SETTLEMENT_DISPATCH_EXAMPLE.json"
    ))
    .unwrap_or_else(|error| panic!("checked-in dispatch fixture: {error}"));
    let mut body = dispatch.capital_instruction.body.clone();
    body.query.capability_id = Some("settlement-capability".to_owned());
    let capital_signer = Keypair::from_seed(&[93; 32]);
    dispatch.capital_instruction = SignedCapitalExecutionInstruction::sign(body, &capital_signer)
        .unwrap_or_else(|error| panic!("fixed capital signer: {error}"));
    assert!(dispatch
        .capital_instruction
        .verify_signature(&capital_signer.public_key())
        .unwrap_or_else(|error| panic!("generated capital signature: {error}")));
    let tokens = vec![binding.token_symbol.clone()];
    let prepared = build_x402_payment_requirements(
        &dispatch,
        witness,
        "https://facilitator.example/x402",
        "https://tool.example/v1/run",
        tokens.clone(),
        X402SettlementMode::PrepaidAuthorization,
    );
    if let Ok(prepared) = prepared {
        assert_eq!(prepared.dispatch_id, binding.dispatch_id);
        assert_eq!(prepared.capability_id, binding.capability_id);
        assert_eq!(prepared.chain_id, format!("eip155:{}", binding.chain_id));
        assert_eq!(
            u128::from(prepared.amount_minor_units),
            binding.amount_minor_units
        );
        assert!(prepared
            .currency
            .eq_ignore_ascii_case(&binding.settlement_currency));
        assert!(prepared.pay_to.eq_ignore_ascii_case(&binding.payee_address));
        assert_eq!(prepared.accepted_tokens, tokens);
        assert!(binding.token_contract.is_none());
        let replayed = build_x402_payment_requirements(
            &dispatch,
            verify(&token)
                .unwrap_or_else(|error| panic!("verification does not consume replay: {error}")),
            "https://facilitator.example/x402",
            "https://tool.example/v1/run",
            tokens,
            X402SettlementMode::PrepaidAuthorization,
        );
        assert!(
            matches!(replayed, Err(SettlementError::Verification(reason))
            if reason == "settlement approval already consumed")
        );
        let circle = evaluate_circle_nanopayment(
            &dispatch,
            verify(&token)
                .unwrap_or_else(|error| panic!("verification does not consume replay: {error}")),
            &CircleNanopaymentPolicy {
                enabled: true,
                managed_balance_id: "balance".into(),
                supported_chain_ids: vec![dispatch.chain_id.clone()],
                supported_token_symbols: vec![dispatch.settlement_amount.currency.clone()],
                max_amount_minor_units: u64::MAX,
                operator_managed_custody_explicit: true,
            },
        );
        assert!(!matches!(circle, Ok(Some(_))));
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn valid_seeds_reach_artifact_issuance_and_replay_refusal() {
        assert!(super::exercise(include_bytes!(
            "../../corpus/settlement_approval_witness/valid-usd.json"
        )));
        assert!(super::exercise(include_bytes!(
            "../../corpus/settlement_approval_witness/valid-usdc-rail.json"
        )));
    }
}
