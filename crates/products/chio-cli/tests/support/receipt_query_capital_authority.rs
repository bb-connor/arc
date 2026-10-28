use chio_core::crypto::Keypair;
pub(crate) use chio_kernel::{CapitalExecutionAuthorityStep, CapitalExecutionRole};

pub(crate) fn signed_capital_authority_chain(
    owner_role: CapitalExecutionRole,
    owner_approved_at: u64,
    owner_expires_at: u64,
    custodian_approved_at: u64,
    custodian_expires_at: u64,
) -> (Vec<CapitalExecutionAuthorityStep>, String) {
    let owner = capital_owner_keypair();
    let custodian = capital_custodian_keypair();
    let custodian_id = custodian.public_key().to_hex();
    let authority_chain = vec![
        CapitalExecutionAuthorityStep::signed(
            owner_role,
            &owner,
            owner_approved_at,
            owner_expires_at,
            None,
        )
        .expect("sign capital owner authority step"),
        CapitalExecutionAuthorityStep::signed(
            CapitalExecutionRole::Custodian,
            &custodian,
            custodian_approved_at,
            custodian_expires_at,
            None,
        )
        .expect("sign capital custodian authority step"),
    ];
    (authority_chain, custodian_id)
}

fn capital_owner_keypair() -> Keypair {
    Keypair::from_seed(&[0x41; 32])
}

fn capital_custodian_keypair() -> Keypair {
    Keypair::from_seed(&[0x42; 32])
}

/// `--capital-authority-key` arguments pinning the keys that sign
/// [`signed_capital_authority_chain`] steps.
pub(crate) fn capital_authority_key_args() -> Vec<String> {
    [capital_owner_keypair(), capital_custodian_keypair()]
        .iter()
        .flat_map(|keypair| {
            [
                "--capital-authority-key".to_string(),
                keypair.public_key().to_hex(),
            ]
        })
        .collect()
}
