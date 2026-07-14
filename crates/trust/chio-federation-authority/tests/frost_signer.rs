use std::collections::BTreeMap;

use chio_core_types::sha256_hex;
use chio_federation_authority::{
    create_frost_signature_share, prepare_frost_signer, FrostCeremonySecret,
    FrostCeremonySecretKind,
};
use frost_ed25519::keys::{IdentifierList, KeyPackage};
use frost_ed25519::{keys, round1, round2, SigningKey, SigningPackage};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use zeroize::Zeroizing;

#[test]
fn signer_uses_one_nonce_for_one_exact_message_and_commitment() {
    let mut rng = ChaCha20Rng::from_seed([0x81; 32]);
    let signing_key = SigningKey::new(&mut rng);
    let (shares, public_key_package) =
        keys::split(&signing_key, 3, 2, IdentifierList::Default, &mut rng)
            .unwrap_or_else(|error| panic!("split key: {error}"));
    let mut key_packages = shares
        .into_values()
        .map(|share| {
            KeyPackage::try_from(share)
                .unwrap_or_else(|error| panic!("verify key package: {error}"))
        })
        .collect::<Vec<_>>();
    let local = key_packages.remove(0);
    let peer = key_packages.remove(0);
    let local_secret = FrostCeremonySecret::from_custody_bytes(
        FrostCeremonySecretKind::KeyPackage,
        Zeroizing::new(
            local
                .serialize()
                .unwrap_or_else(|error| panic!("serialize local key: {error}")),
        ),
    )
    .unwrap_or_else(|error| panic!("load local key: {error}"));
    let mut local_rng = ChaCha20Rng::from_seed([0x82; 32]);
    let local_preparation = prepare_frost_signer(&local_secret, &mut local_rng)
        .unwrap_or_else(|error| panic!("prepare local signer: {error}"));
    let local_commitment =
        round1::SigningCommitments::deserialize(local_preparation.commitment_bytes())
            .unwrap_or_else(|error| panic!("decode local commitment: {error}"));
    let (peer_nonces, peer_commitment) = round1::commit(peer.signing_share(), &mut rng);
    let message = b"exact FROST authorization message";
    let mut commitments = BTreeMap::new();
    commitments.insert(*local.identifier(), local_commitment);
    commitments.insert(*peer.identifier(), peer_commitment);
    let signing_package = SigningPackage::new(commitments, message);
    let signing_package_bytes = signing_package
        .serialize()
        .unwrap_or_else(|error| panic!("serialize signing package: {error}"));
    let local_share = create_frost_signature_share(
        &local_secret,
        local_preparation.nonce_secret(),
        &signing_package_bytes,
        &sha256_hex(message),
        local_preparation.commitment_bytes(),
    )
    .unwrap_or_else(|error| panic!("create local share: {error}"));
    let peer_share = round2::sign(&signing_package, &peer_nonces, &peer)
        .unwrap_or_else(|error| panic!("create peer share: {error}"));
    let mut signature_shares = BTreeMap::new();
    signature_shares.insert(
        *local.identifier(),
        round2::SignatureShare::deserialize(local_share.share_bytes())
            .unwrap_or_else(|error| panic!("decode local share: {error}")),
    );
    signature_shares.insert(*peer.identifier(), peer_share);
    frost_ed25519::aggregate(&signing_package, &signature_shares, &public_key_package)
        .unwrap_or_else(|error| panic!("aggregate signature: {error}"));

    assert!(create_frost_signature_share(
        &local_secret,
        local_preparation.nonce_secret(),
        &signing_package_bytes,
        &sha256_hex(b"another message"),
        local_preparation.commitment_bytes(),
    )
    .is_err());
}
