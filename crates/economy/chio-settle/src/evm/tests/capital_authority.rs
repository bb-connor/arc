use super::*;

const CAPITAL_AUTHORITY_REFUSAL_BOND: &str =
    "verification error: credit bond signer is not a trusted settlement capital authority key";
const CAPITAL_AUTHORITY_REFUSAL_INSTRUCTION: &str = "verification error: capital execution instruction signer is not a trusted settlement capital authority key";
const EMPTY_CAPITAL_AUTHORITY: &str = "invalid input: settlement config capital_authority.trusted_keys must name at least one capital authority key";

fn outside_keypair() -> Keypair {
    Keypair::from_seed(&[0x52; 32])
}

fn bond_lock_config() -> SettlementChainConfig {
    let mut config = sample_config();
    align_config_to_anchor_proof(&mut config, &sample_primary_proof());
    config
}

fn bond_signed_by(keypair: &Keypair) -> SignedCreditBond {
    let bond = sample_credit_bond("bond-authority", "facility-authority", 400, 250);
    SignedCreditBond::sign(bond.body, keypair).test_expect("bond signature")
}

async fn bond_lock_error(config: &SettlementChainConfig, bond: SignedCreditBond) -> String {
    prepare_bond_lock(
        config,
        &BondLockRequest {
            principal_address: "0x1000000000000000000000000000000000000005".to_string(),
            bond,
        },
        &sample_binding_for_config(config),
    )
    .await
    .test_expect_err("bond lock must refuse")
    .to_string()
}

#[tokio::test]
async fn bond_lock_refuses_a_bond_signed_outside_the_capital_authority() {
    let config = bond_lock_config();
    let bond = bond_signed_by(&outside_keypair());
    assert!(bond
        .verify_signature(&outside_keypair().public_key())
        .test_unwrap());

    assert_eq!(
        bond_lock_error(&config, bond).await,
        CAPITAL_AUTHORITY_REFUSAL_BOND
    );
}

#[tokio::test]
async fn bond_lock_refuses_a_bond_under_a_rotated_out_key() {
    let mut config = bond_lock_config();
    config.capital_authority.trusted_keys = vec![outside_keypair().public_key()];

    assert_eq!(
        bond_lock_error(&config, bond_signed_by(&instruction_keypair())).await,
        CAPITAL_AUTHORITY_REFUSAL_BOND
    );
}

#[tokio::test]
async fn bond_lock_refuses_an_empty_capital_authority() {
    let mut config = bond_lock_config();
    config.capital_authority.trusted_keys.clear();

    assert_eq!(
        bond_lock_error(&config, bond_signed_by(&instruction_keypair())).await,
        EMPTY_CAPITAL_AUTHORITY
    );
}

fn escrow_request(instruction: SignedCapitalExecutionInstruction) -> EscrowDispatchRequest {
    EscrowDispatchRequest {
        dispatch_id: "dispatch-authority".to_string(),
        issued_at: 1_743_292_800,
        trust_profile_id: "chio.unit".to_string(),
        contract_package_id: "chio.contracts.unit".to_string(),
        capability_id: "cap-escrow-authority".to_string(),
        depositor_address: "0x1000000000000000000000000000000000000001".to_string(),
        beneficiary_address: "0x1000000000000000000000000000000000000002".to_string(),
        capital_instruction: instruction,
        settlement_path: Web3SettlementPath::MerkleProof,
        oracle_evidence_required_for_fx: false,
        note: None,
    }
}

fn instruction_signed_by(
    config: &SettlementChainConfig,
    keypair: &Keypair,
) -> SignedCapitalExecutionInstruction {
    let instruction = sample_capital_instruction(
        config,
        "0x1000000000000000000000000000000000000002",
        "cei-authority",
        150,
    );
    SignedCapitalExecutionInstruction::sign(instruction.body, keypair)
        .test_expect("instruction signature")
}

async fn escrow_dispatch_error(
    config: &SettlementChainConfig,
    instruction: SignedCapitalExecutionInstruction,
) -> String {
    prepare_web3_escrow_dispatch(
        config,
        &escrow_request(instruction),
        &sample_binding_for_config(config),
    )
    .await
    .test_expect_err("escrow dispatch must refuse")
    .to_string()
}

#[tokio::test]
async fn escrow_dispatch_refuses_an_instruction_signed_outside_the_capital_authority() {
    let config = sample_config();
    let instruction = instruction_signed_by(&config, &outside_keypair());
    assert!(instruction
        .verify_signature(&outside_keypair().public_key())
        .test_unwrap());

    assert_eq!(
        escrow_dispatch_error(&config, instruction).await,
        CAPITAL_AUTHORITY_REFUSAL_INSTRUCTION
    );
}

#[tokio::test]
async fn escrow_dispatch_refuses_an_instruction_under_a_rotated_out_key() {
    let mut config = sample_config();
    config.capital_authority.trusted_keys = vec![outside_keypair().public_key()];
    let instruction = instruction_signed_by(&config, &instruction_keypair());

    assert_eq!(
        escrow_dispatch_error(&config, instruction).await,
        CAPITAL_AUTHORITY_REFUSAL_INSTRUCTION
    );
}

#[tokio::test]
async fn escrow_dispatch_refuses_an_empty_capital_authority() {
    let mut config = sample_config();
    config.capital_authority.trusted_keys.clear();
    let instruction = instruction_signed_by(&config, &instruction_keypair());

    assert_eq!(
        escrow_dispatch_error(&config, instruction).await,
        EMPTY_CAPITAL_AUTHORITY
    );
}

#[test]
fn failure_receipt_refuses_a_dispatch_instruction_outside_the_capital_authority() {
    let outside = crate::SettlementCapitalAuthority {
        trusted_keys: vec![outside_keypair().public_key()],
    };
    let error = build_failure_receipt(
        &hex_dispatch(),
        &outside,
        "exec-failed".to_string(),
        "settlement-ref".to_string(),
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        "node rejected tx".to_string(),
    )
    .test_expect_err("failure receipt must refuse")
    .to_string();

    assert_eq!(
        error,
        "verification error: invalid settlement: capital instruction signer is not a trusted capital authority key"
    );
}
