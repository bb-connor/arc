use chio_core::credit::SignedCapitalExecutionInstruction;
use chio_core::crypto::Keypair;
use chio_core::web3::settlement::Web3SettlementDispatchArtifact;
use chio_test_support::prelude::*;

pub fn fixture() -> Web3SettlementDispatchArtifact {
    let mut dispatch: Web3SettlementDispatchArtifact = serde_json::from_str(include_str!(
        "../../../../../docs/standards/CHIO_WEB3_SETTLEMENT_DISPATCH_EXAMPLE.json"
    ))
    .test_unwrap();
    set_capability(&mut dispatch, Some("settlement-capability".to_owned()));
    dispatch
}

pub fn set_capability(dispatch: &mut Web3SettlementDispatchArtifact, capability: Option<String>) {
    let mut body = dispatch.capital_instruction.body.clone();
    body.query.capability_id = capability;
    dispatch.capital_instruction =
        SignedCapitalExecutionInstruction::sign(body, &Keypair::from_seed(&[73; 32])).test_unwrap();
    assert!(dispatch
        .capital_instruction
        .verify_signature()
        .test_unwrap());
}
