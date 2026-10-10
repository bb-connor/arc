use chio_core_types::crypto::Keypair;

/// Decode and authenticate arbitrary round-two deliveries against the fixed
/// three-of-five vector roster. The public fixture seeds are test material.
pub fn frost_round2_envelope(data: &[u8]) {
    use chio_federation_authority::{
        FrostCeremonyConfig, FrostCeremonyParticipant, FrostSealingKey, SealedFrostRound2Package,
    };
    use std::sync::OnceLock;
    static CONTEXT: OnceLock<(FrostCeremonyConfig, FrostSealingKey)> = OnceLock::new();
    let (config, sealing) = CONTEXT.get_or_init(|| {
        let participants = (0..5_u8)
            .map(|i| FrostCeremonyParticipant {
                participant_id: format!("peer-{i}"),
                transport_key_id: format!("sign-{i}"),
                transport_public_key: Keypair::from_seed(&[i + 1; 32]).public_key(),
                sealing_key_id: format!("seal-{i}"),
                sealing_public_key: FrostSealingKey::from_custody_bytes(zeroize::Zeroizing::new(
                    [i + 11; 32],
                ))
                .public_key()
                .unwrap_or_else(|e| panic!("fuzz fixture key: {e}")),
            })
            .collect();
        (
            FrostCeremonyConfig {
                scope_id: "sealed-vector".into(),
                key_epoch: 1,
                threshold: 3,
                predecessor_roster_digest: None,
                participants,
                local_participant_id: "peer-1".into(),
            },
            FrostSealingKey::from_custody_bytes(zeroize::Zeroizing::new([12; 32])),
        )
    });
    if let Ok(envelope) = SealedFrostRound2Package::from_wire(data) {
        let _ = envelope.verify(config);
        let _ = envelope.open(config, sealing);
    }
}
