use super::*;
use crate::serving_owner::ProvisionedAuthority;
use chio_federation_authority::{FrostCeremonyParticipant, FrostSealingKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[test]
fn share_insert_rolls_back_when_the_projection_commit_is_refused(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = ProvisionedAuthority::open();
    let store = fixture.authority.frost_store();
    let fence = fixture.authority.mutation_fence();
    let custody = FrostCustodyKey::new("inbox-test", [99; 32])?;
    let signing = [
        chio_core::Keypair::from_seed(&[1; 32]),
        chio_core::Keypair::from_seed(&[2; 32]),
    ];
    let sealing = [
        FrostSealingKey::from_custody_bytes(Zeroizing::new([11; 32])),
        FrostSealingKey::from_custody_bytes(Zeroizing::new([12; 32])),
    ];
    let participants = (0..2)
        .map(|i| {
            Ok(FrostCeremonyParticipant {
                participant_id: format!("peer-{i}"),
                transport_key_id: format!("sign-{i}"),
                transport_public_key: signing[i].public_key(),
                sealing_key_id: format!("seal-{i}"),
                sealing_public_key: sealing[i].public_key()?,
            })
        })
        .collect::<Result<Vec<_>, chio_federation_authority::FrostCeremonyError>>()?;
    let config = FrostCeremonyConfig {
        scope_id: "inbox-rollback".into(),
        key_epoch: 1,
        threshold: 2,
        predecessor_roster_digest: None,
        participants,
        local_participant_id: "peer-0".into(),
    };
    let mut peer = config.clone();
    peer.local_participant_id = "peer-1".into();
    let mut rng = ChaCha20Rng::from_seed([31; 32]);
    let first = store.begin_ceremony(
        &config,
        &signing[0],
        &sealing[0],
        &custody,
        &mut rng,
        &fence,
        1000,
    )?;
    let remote = begin_frost_ceremony(&peer, &signing[1], &sealing[1], &mut rng)?;
    let round1 = vec![first.package, remote.package];
    store.advance_ceremony(&config, &signing[0], &custody, &round1, &fence, 2000)?;
    let incoming = advance_frost_ceremony(&peer, &signing[1], remote.secret, &round1)?
        .packages
        .remove(0);
    store.connection()?.execute_batch("CREATE TEMP TRIGGER refuse_inbox_commit BEFORE INSERT ON main.frost_projection_commits WHEN NEW.projection_type = 'ceremony_inbox' BEGIN SELECT RAISE(ABORT, 'inbox-cutpoint'); END;")?;
    let result = store.accept_round2_package(&config, &custody, &incoming, &fence, 2500);
    assert!(
        matches!(&result, Err(FrostStoreError::Unavailable(detail)) if detail.contains("inbox-cutpoint")),
        "{result:?}"
    );
    {
        let connection = store.connection()?;
        assert!(connection.is_autocommit());
        assert_eq!(
            connection.query_row::<i64, _, _>(
                "SELECT COUNT(*) FROM frost_round2_acceptances",
                [],
                |row| row.get(0)
            )?,
            0
        );
        assert_eq!(connection.query_row::<i64, _, _>("SELECT COUNT(*) FROM frost_projection_commits WHERE projection_type = 'ceremony_inbox'", [], |row| row.get(0))?, 0);
        connection.execute_batch("DROP TRIGGER refuse_inbox_commit")?;
    }
    store.accept_round2_package(&config, &custody, &incoming, &fence, 2501)?;
    assert_eq!(
        store.connection()?.query_row::<i64, _, _>(
            "SELECT COUNT(*) FROM frost_round2_acceptances",
            [],
            |row| row.get(0)
        )?,
        1
    );
    Ok(())
}
