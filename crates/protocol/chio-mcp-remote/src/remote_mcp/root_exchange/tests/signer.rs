//! The seed-file exchange signer: seed custody at load, and every artifact
//! it signs verifying under the pinned exchange key.

use std::os::unix::fs::PermissionsExt as _;

use super::*;
use crate::root_exchange::signer::{ExchangeSigner, ExchangeSignerError};
use chio_control_plane::CliError;
use chio_core::capability::token::{CapabilityTokenBody, CHIO_CAPABILITY_SCHEMA};
use chio_core::crypto::verify_wrapped;
use chio_core::root_authority::{HttpsUrl, KeySnapshotSource, Uri};

const SEED: [u8; 32] = [0x41; 32];

fn seed_file(dir: &tempfile::TempDir, mode: u32) -> std::path::PathBuf {
    let path = dir.path().join("exchange.seed");
    std::fs::write(&path, format!("{}\n", Keypair::from_seed(&SEED).seed_hex())).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn pinned_exchange_key() -> PublicKey {
    Keypair::from_seed(&SEED).public_key()
}

fn root_body(issuer: PublicKey) -> CapabilityTokenBody {
    CapabilityTokenBody {
        id: "cap_root_1".to_owned(),
        issuer,
        subject: Keypair::from_seed(&[0x42; 32]).public_key(),
        scope: ChioScope {
            grants: vec![grant("search")],
            ..ChioScope::default()
        },
        issued_at: NOW,
        expires_at: NOW + 300,
        delegation_chain: Vec::new(),
        aggregate_invocation_budget: None,
    }
}

#[test]
fn seed_file_signature_verifies_against_pinned_exchange_key() {
    let dir = tempfile::tempdir().unwrap();
    let signer = ExchangeSigner::seed_file(&seed_file(&dir, 0o600)).unwrap();
    assert_eq!(signer.key(), &pinned_exchange_key());

    let root = signer.sign_root(root_body(pinned_exchange_key())).unwrap();
    verify_wrapped(
        &pinned_exchange_key(),
        CHIO_CAPABILITY_SCHEMA,
        &root.signing_body(),
        &root.signature,
    )
    .unwrap();
    let foreign = Keypair::from_seed(&[0x43; 32]).public_key();
    assert!(matches!(
        verify_wrapped(
            &foreign,
            CHIO_CAPABILITY_SCHEMA,
            &root.signing_body(),
            &root.signature,
        ),
        Err(chio_core::Error::SignatureRejected)
    ));

    let snapshot = signer
        .sign_snapshot(
            &Uri::new(ISSUER).unwrap(),
            &KeySnapshotSource::JwksUrl(HttpsUrl::new(JWKS_URL).unwrap()),
            Vec::new(),
            NOW,
        )
        .unwrap();
    assert_eq!(snapshot.exchange_key, pinned_exchange_key());
    snapshot.verify_signature(&pinned_exchange_key()).unwrap();
}

#[test]
fn seed_file_group_readable_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let error = ExchangeSigner::seed_file(&seed_file(&dir, 0o640)).unwrap_err();
    assert_eq!(
        error,
        ExchangeSignerError::SeedFileRefused(
            CliError::cli_io_error(
                "authority seed must be singly linked with mode 0600 or stricter"
            )
            .to_string()
        )
    );
}

#[test]
fn seed_file_world_readable_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let error = ExchangeSigner::seed_file(&seed_file(&dir, 0o604)).unwrap_err();
    assert_eq!(
        error,
        ExchangeSignerError::SeedFileRefused(
            CliError::cli_io_error(
                "authority seed must be singly linked with mode 0600 or stricter"
            )
            .to_string()
        )
    );
}

#[test]
fn seed_file_with_malformed_seed_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let path = seed_file(&dir, 0o600);
    std::fs::write(&path, "not a seed\n").unwrap();
    let expected = CliError::from(Keypair::from_seed_hex("not a seed").unwrap_err()).to_string();
    assert_eq!(
        ExchangeSigner::seed_file(&path).unwrap_err(),
        ExchangeSignerError::SeedFileRefused(expected)
    );
}

#[test]
fn seed_file_signer_refuses_a_root_with_a_foreign_issuer() {
    let dir = tempfile::tempdir().unwrap();
    let signer = ExchangeSigner::seed_file(&seed_file(&dir, 0o600)).unwrap();
    let foreign = Keypair::from_seed(&[0x43; 32]).public_key();
    assert_eq!(
        signer.sign_root(root_body(foreign)).unwrap_err(),
        ExchangeSignerError::IssuerNotExchangeKey
    );
}
