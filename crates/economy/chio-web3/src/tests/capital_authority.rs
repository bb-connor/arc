use super::*;

const INSTRUCTION_REFUSAL: &str =
    "capital instruction signer is not a trusted capital authority key";
const BOND_REFUSAL: &str = "credit bond signer is not a trusted capital authority key";
const EMPTY_REFUSAL: &str = "web3 settlement capital authority must name at least one trusted key";

fn outside_keypair() -> Keypair {
    Keypair::from_seed(&[0x52; 32])
}

fn resign_instruction(dispatch: &mut Web3SettlementDispatchArtifact, signer: &Keypair) {
    dispatch.capital_instruction =
        SignedCapitalExecutionInstruction::sign(dispatch.capital_instruction.body.clone(), signer)
            .unwrap();
}

fn bond_signed_by(signer: &Keypair) -> crate::credit::SignedCreditBond {
    crate::credit::SignedCreditBond::sign(sample_active_bond().body, signer).unwrap()
}

fn signer_refusal(result: Result<(), Web3ContractError>) -> String {
    match result {
        Err(Web3ContractError::SettlementSignatureInvalid(message)) => message,
        other => panic!("expected a signer refusal, got {other:?}"),
    }
}

#[test]
fn dispatch_refuses_an_instruction_signed_outside_the_capital_authority() {
    let mut dispatch = sample_dispatch();
    resign_instruction(&mut dispatch, &outside_keypair());

    assert_eq!(
        signer_refusal(validate_web3_settlement_dispatch(
            &dispatch,
            &capital_authority()
        )),
        INSTRUCTION_REFUSAL
    );
}

#[test]
fn dispatch_refuses_an_instruction_under_a_rotated_out_key() {
    let rotated = [outside_keypair().public_key()];

    assert_eq!(
        signer_refusal(validate_web3_settlement_dispatch(
            &sample_dispatch(),
            &rotated
        )),
        INSTRUCTION_REFUSAL
    );
}

#[test]
fn dispatch_refuses_a_bond_signed_outside_the_capital_authority() {
    let mut dispatch = sample_dispatch();
    dispatch.bond = Some(bond_signed_by(&outside_keypair()));

    assert_eq!(
        signer_refusal(validate_web3_settlement_dispatch(
            &dispatch,
            &capital_authority()
        )),
        BOND_REFUSAL
    );
}

#[test]
fn dispatch_refuses_a_bond_under_a_rotated_out_key() {
    let successor = outside_keypair();
    let mut dispatch = sample_dispatch();
    resign_instruction(&mut dispatch, &successor);
    dispatch.bond = Some(sample_active_bond());

    assert_eq!(
        signer_refusal(validate_web3_settlement_dispatch(
            &dispatch,
            &[successor.public_key()]
        )),
        BOND_REFUSAL
    );
}

#[test]
fn dispatch_accepts_a_bond_and_instruction_from_a_member() {
    let mut dispatch = sample_dispatch();
    dispatch.bond = Some(sample_active_bond());

    assert!(validate_web3_settlement_dispatch(
        &dispatch,
        &[
            outside_keypair().public_key(),
            treasury_keypair().public_key()
        ]
    )
    .is_ok());
}

#[test]
fn dispatch_refuses_an_empty_capital_authority() {
    assert!(matches!(
        validate_web3_settlement_dispatch(&sample_dispatch(), &[]),
        Err(Web3ContractError::InvalidSettlement(message)) if message == EMPTY_REFUSAL
    ));
}

#[test]
fn execution_receipt_refuses_an_instruction_signed_outside_the_capital_authority() {
    assert_eq!(
        signer_refusal(validate_web3_settlement_execution_receipt(
            &sample_execution_receipt(),
            &[outside_keypair().public_key()]
        )),
        INSTRUCTION_REFUSAL
    );
}

#[test]
fn public_settlement_proof_refuses_a_bond_signed_outside_the_capital_authority() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.settlement_receipt.dispatch.bond = Some(bond_signed_by(&outside_keypair()));

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::SettlementSignatureInvalid(message)) if message == BOND_REFUSAL
    ));
}
