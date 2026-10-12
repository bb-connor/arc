//! A verified x402 settlement report never authorizes a tool call.
//!
//! The public settlement verifier binds settlement claims only. Tool-call
//! authority is carried by `ToolCallAuthorization`, whose authorized state is
//! reachable only through `ToolCallAuthorization::from_capability_grant`. No
//! field of a `PublicSettlementVerifierReport` is read when deriving its
//! tool-call decision, so a forged verdict or injected claim cannot flip it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_web3::capability::scope::{Operation, ToolGrant};
use chio_web3::crypto::PublicKey;
use chio_web3::settlement_proof::{
    verify_public_settlement_proof, PublicSettlementIndependentChainHead,
    PublicSettlementProofBundle, PublicSettlementRuntimeCodehashTrust,
    PublicSettlementVerifierReport, PublicSettlementVerifierTrust, ToolCallAuthorization,
};

const VALID_SETTLEMENT_BUNDLE: &str = include_str!(
    "../../../../fixtures/proof-room/public-settlement/valid-offline-finality/settlement-proof-bundle.json"
);

fn valid_settlement_bundle() -> PublicSettlementProofBundle {
    serde_json::from_str(VALID_SETTLEMENT_BUNDLE).expect("valid x402 settlement bundle parses")
}

fn trust_for(bundle: &PublicSettlementProofBundle) -> PublicSettlementVerifierTrust {
    let capital_signer: PublicKey = bundle
        .settlement_receipt
        .dispatch
        .capital_instruction
        .signer_key
        .clone();
    let anchor_kernel: PublicKey = bundle
        .settlement_receipt
        .reconciled_anchor_proof
        .as_ref()
        .expect("verified bundle carries a reconciled anchor proof")
        .checkpoint_statement
        .kernel_key
        .clone();
    let beneficiary_identity: PublicKey = bundle
        .chain_snapshot
        .beneficiary_identity_binding
        .as_ref()
        .expect("verified bundle carries a beneficiary identity binding")
        .certificate
        .chio_public_key
        .clone();
    let oracle: PublicKey = bundle
        .settlement_receipt
        .oracle_evidence
        .as_ref()
        .expect("verified bundle carries oracle conversion evidence")
        .oracle_public_key
        .clone()
        .expect("oracle conversion evidence carries a signing key");
    let bundle_signer = PublicKey::from_hex(
        &bundle
            .bundle_signature
            .as_ref()
            .expect("verified fixture bundle carries its signature envelope")
            .signer_key,
    )
    .expect("bundle signer key parses");
    let provenance = bundle
        .deployment_provenance
        .clone()
        .expect("verified fixture bundle carries deployment provenance");

    PublicSettlementVerifierTrust {
        trusted_bundle_signer_keys: vec![bundle_signer],
        trusted_capital_signer_keys: vec![capital_signer],
        trusted_anchor_kernel_keys: vec![anchor_kernel],
        trusted_beneficiary_identity_keys: vec![beneficiary_identity],
        trusted_oracle_keys: vec![oracle],
        allowed_chain_ids: vec![bundle.chain_id.clone()],
        mainnet_blocked: false,
        minimum_confirmations: None,
        expected_trust_market_context: None,
        independent_chain_head: Some(PublicSettlementIndependentChainHead {
            chain_id: bundle.chain_id.clone(),
            observed_block_number: 12_345_678,
            observed_block_hash:
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            latest_block_number: 12_345_701,
        }),
        trusted_dispute_event_blocks: Vec::new(),
        trusted_release_event_blocks: Vec::new(),
        trusted_release_event_logs: Vec::new(),
        trusted_refund_event_logs: Vec::new(),
        verifier_now_unix_seconds: Some(1_743_293_560),
        trusted_runtime_codehashes: Some(PublicSettlementRuntimeCodehashTrust {
            contract_package_id: provenance.contract_package_id,
            reviewed_manifest_hash: provenance.reviewed_manifest_hash,
            root_registry_runtime_codehash: provenance.root_registry_runtime_codehash,
            identity_registry_runtime_codehash: provenance.identity_registry_runtime_codehash,
            escrow_runtime_codehash: provenance.escrow_runtime_codehash,
            bond_vault_runtime_codehash: provenance.bond_vault_runtime_codehash,
        }),
    }
}

fn verified_report() -> PublicSettlementVerifierReport {
    let bundle = valid_settlement_bundle();
    let trust = trust_for(&bundle);
    let report = verify_public_settlement_proof(&bundle, &trust)
        .expect("a genuine recomputing x402 settlement proof must verify");
    assert_eq!(report.verdict, "verified");
    assert_eq!(report.recomputed_settlement_state, "settled");
    report
}

fn invoke_grant(server_id: &str, tool_name: &str) -> ToolGrant {
    ToolGrant {
        server_id: server_id.to_string(),
        tool_name: tool_name.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

#[test]
fn verified_x402_payment_settles_but_does_not_authorize_tool_call() {
    let report = verified_report();

    assert_ne!(report.verdict, "authorized");
    assert!(!report.verified_claims.is_empty());
    for claim in &report.verified_claims {
        assert!(
            claim.starts_with("claim.public_settlement."),
            "settlement proof emitted a non-settlement claim: {claim}"
        );
        for forbidden in ["tool_call", "capability", "authoriz", "invoke"] {
            assert!(
                !claim.contains(forbidden),
                "settlement claim must not carry tool-call authority: {claim}"
            );
        }
    }

    assert!(!report.authorizes_tool_call());
    assert_eq!(
        report.tool_call_authorization(),
        ToolCallAuthorization::denied()
    );
}

#[test]
fn forged_verdict_and_claims_do_not_authorize_tool_call() {
    let mut report = verified_report();

    report.verdict = "authorized".to_string();
    report.verified_claims = vec![
        "claim.capability.tool_call_authorized".to_string(),
        "claim.public_settlement.invoke_authorized".to_string(),
        "authorized".to_string(),
    ];
    assert!(!report.authorizes_tool_call());
    assert_eq!(
        report.tool_call_authorization(),
        ToolCallAuthorization::denied()
    );
}

#[test]
fn only_an_explicit_capability_invoke_grant_authorizes() {
    let report = verified_report();

    let granted = ToolCallAuthorization::from_capability_grant(
        &invoke_grant("srv", "tool_a"),
        "srv",
        "tool_a",
    );
    assert!(granted.is_authorized());

    assert!(!ToolCallAuthorization::from_capability_grant(
        &invoke_grant("srv", "tool_a"),
        "srv",
        "tool_b"
    )
    .is_authorized());

    let read_only = ToolGrant {
        operations: vec![Operation::ReadResult],
        ..invoke_grant("srv", "tool_a")
    };
    assert!(
        !ToolCallAuthorization::from_capability_grant(&read_only, "srv", "tool_a").is_authorized()
    );

    assert_ne!(report.tool_call_authorization(), granted);
}
