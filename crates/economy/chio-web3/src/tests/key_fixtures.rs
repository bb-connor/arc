use super::Keypair;

pub(super) fn operator_keypair() -> Keypair {
    Keypair::from_seed(&[7u8; 32])
}

pub(super) fn treasury_keypair() -> Keypair {
    Keypair::from_seed(&[9u8; 32])
}

pub(super) fn custodian_keypair() -> Keypair {
    Keypair::from_seed(&[11u8; 32])
}

pub(super) fn beneficiary_keypair() -> Keypair {
    Keypair::from_seed(&[13u8; 32])
}

pub(super) fn oracle_keypair() -> Keypair {
    Keypair::from_seed(&[15u8; 32])
}

pub(super) fn settlement_bundle_keypair() -> Keypair {
    treasury_keypair()
}
