# chio-federation-authority

`chio-federation-authority` issues signed capability leases, destructive-action
governance receipts, and revocation checkpoints from local authority profiles.
It assembles verifier trust bundles and provides authenticated FROST key
ceremony, signer, and coordinator APIs for federation integrations.

## Usage

Start one participant's round of a two-party FROST ceremony entirely offline.
The fixed signing and sealing seeds below are example keys. Deployment requires
protected key custody and a cryptographic random source.

```rust
use chio_core_types::Keypair;
use chio_federation_authority::{
    begin_frost_ceremony, FrostCeremonyConfig, FrostCeremonyParticipant,
    FrostDkgRound, FrostSealingKey,
};
use rand_core::OsRng;
use zeroize::Zeroizing;

let signing = [Keypair::from_seed(&[1; 32]), Keypair::from_seed(&[2; 32])];
let sealing = [
    FrostSealingKey::from_custody_bytes(Zeroizing::new([3; 32])),
    FrostSealingKey::from_custody_bytes(Zeroizing::new([4; 32])),
];
let mut participants = Vec::new();
for i in 0..2 {
    participants.push(FrostCeremonyParticipant {
        participant_id: format!("operator-{i}"),
        transport_key_id: format!("signing-{i}"),
        transport_public_key: signing[i].public_key(),
        sealing_key_id: format!("sealing-{i}"),
        sealing_public_key: sealing[i].public_key()?,
    });
}
let config = FrostCeremonyConfig {
    scope_id: "treaty-example".into(), key_epoch: 1, threshold: 2,
    predecessor_roster_digest: None, participants,
    local_participant_id: "operator-0".into(),
};
let round = begin_frost_ceremony(&config, &signing[0], &sealing[0], &mut OsRng)?;
assert_eq!(round.package.round(), FrostDkgRound::Round1);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Complete ceremonies through `advance_frost_ceremony` and
`complete_frost_ceremony`, exchanging authenticated public packages and retaining
secret custody records. The crate leaves delivery and durable custody to callers.

## Guarantees

- `issue_authority_bundle` validates profile, request, and local keys; requires
  active authorities, matching signing keys, allowed action classes, and
  contained validity intervals before signing leases and governance receipts.
- `publish_revocation_checkpoint` requires the active pinned authority and
  validates the request. Epoch monotonicity uses the optional supplied previous
  height; callers retain and authenticate the actual previous checkpoint.
- `begin_frost_ceremony` binds scope, epoch, participants, signing keys, and
  sealing keys. Round transitions authenticate transcript packages; round-two
  plaintext is available only through recipient-bound authenticated opening.
- `create_frost_signature_share` consumes its nonce object and checks the exact
  authorized message digest and prepared commitment. `aggregate_frost_authorization`
  checks the signing set and verifies shares before producing the group proof.
- Local seed documents and FROST secret types redact debug output and use
  secret or zeroizing storage. Private custody export requires explicit APIs.

## Status

These are library issuance and cryptographic workflow APIs. Publication,
operator authorization, checkpoint history, and durable nonce consumption are
integration responsibilities. Trust-bundle assembly runs the buyer verifier's
bundle loader; execution still requires current evidence and admission checks.
This crate declares no Cargo features.

## Related

- [Architecture](ARCHITECTURE.md)
- [Federation contracts](../chio-federation/README.md)
- [Governance](../chio-governance/README.md)
- [Portable trust and federation](../../../spec/PROTOCOL.md#10-portable-trust-and-federation)

[License](../../../LICENSE)
