use super::*;
use chio_federation_authority::{
    FrostCeremonySecret, FrostCeremonySecretKind, FrostRound1Package, SealedFrostRound2Package,
};
use chio_store_sqlite::FrostStoreError;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Ready {
    fixture: StoreFixture,
    participants: Vec<ParticipantFixture>,
    authority: SqliteAuthorityStore,
    frost: SqliteFrostStore,
    round1: Vec<FrostRound1Package>,
    round2: Vec<SealedFrostRound2Package>,
    alternate: SealedFrostRound2Package,
}

fn ready() -> Result<Ready, Box<dyn std::error::Error>> {
    let fixture = StoreFixture::new();
    let participants = participants();
    let (authority, frost) = fixture.open();
    let mut rng = ChaCha20Rng::from_seed([70; 32]);
    let local = &participants[0];
    let first = frost.begin_ceremony(
        &local.config,
        &local.transport_key,
        &test_sealing_key(&local.config),
        &custody(),
        &mut rng,
        &authority.mutation_fence(),
        1000,
    )?;
    let mut round1 = vec![first.package];
    let mut secrets = Vec::new();
    for peer in participants.iter().skip(1) {
        let first = begin_frost_ceremony(
            &peer.config,
            &peer.transport_key,
            &test_sealing_key(&peer.config),
            &mut rng,
        )?;
        round1.push(first.package);
        secrets.push(first.secret);
    }
    let round2_local = frost.advance_ceremony(
        &local.config,
        &local.transport_key,
        &custody(),
        &round1,
        &authority.mutation_fence(),
        2000,
    )?;
    let repeated = FrostCeremonySecret::from_custody_bytes(
        FrostCeremonySecretKind::Round1,
        zeroize::Zeroizing::new(secrets[0].custody_bytes().to_vec()),
    )?;
    let alternate = advance_frost_ceremony(
        &participants[1].config,
        &participants[1].transport_key,
        repeated,
        &round1,
    )?
    .packages
    .into_iter()
    .find(|p| p.recipient_participant_id() == local.config.local_participant_id)
    .ok_or("alternate")?;
    let mut round2 = round2_local.packages;
    for (peer, secret) in participants.iter().skip(1).zip(secrets) {
        round2.extend(
            advance_frost_ceremony(&peer.config, &peer.transport_key, secret, &round1)?.packages,
        );
    }
    Ok(Ready {
        fixture,
        participants,
        authority,
        frost,
        round1,
        round2,
        alternate,
    })
}

fn incoming(ready: &Ready) -> &SealedFrostRound2Package {
    ready
        .round2
        .iter()
        .find(|p| {
            p.recipient_participant_id() == ready.participants[0].config.local_participant_id
                && p.sender_participant_id() == ready.alternate.sender_participant_id()
        })
        .unwrap_or_else(|| panic!("inbound fixture"))
}

#[test]
fn durable_inbox_retries_survive_restart_and_completion_requires_acceptance() -> TestResult {
    let mut r = ready()?;
    let config = r.participants[0].config.clone();
    assert!(matches!(
        r.frost.complete_ceremony(
            &config,
            &custody(),
            &r.round1,
            &r.round2,
            &r.authority.mutation_fence(),
            3000
        ),
        Err(FrostStoreError::Round2NotAccepted)
    ));
    for package in r
        .round2
        .iter()
        .filter(|p| p.recipient_participant_id() == config.local_participant_id)
    {
        r.frost.accept_round2_package(
            &config,
            &custody(),
            package,
            &r.authority.mutation_fence(),
            2500,
        )?;
        r.frost.accept_round2_package(
            &config,
            &custody(),
            package,
            &r.authority.mutation_fence(),
            2501,
        )?;
        let opened = package.open(&config, &test_sealing_key(&config))?;
        assert_database_files_exclude(&r.fixture.database, opened.secret_bytes());
        assert_database_files_exclude(
            &r.fixture.database,
            hex::encode(opened.secret_bytes()).as_bytes(),
        );
    }
    (r.authority, r.frost) = reopen(&r.fixture, r.authority, r.frost);
    for package in r
        .round2
        .iter()
        .filter(|p| p.recipient_participant_id() == config.local_participant_id)
    {
        r.frost.accept_round2_package(
            &config,
            &custody(),
            package,
            &r.authority.mutation_fence(),
            2502,
        )?;
    }
    let completed = r.frost.complete_ceremony(
        &config,
        &custody(),
        &r.round1,
        &r.round2,
        &r.authority.mutation_fence(),
        3000,
    )?;
    assert_eq!(completed.state, FrostCeremonyState::Completed);
    (r.authority, r.frost) = reopen(&r.fixture, r.authority, r.frost);
    assert_eq!(
        r.frost.complete_ceremony(
            &config,
            &custody(),
            &r.round1,
            &r.round2,
            &r.authority.mutation_fence(),
            3001
        )?,
        completed
    );
    assert_database_files_exclude(
        &r.fixture.database,
        test_sealing_key(&config).custody_bytes(),
    );
    Ok(())
}

#[test]
fn authenticated_conflict_commits_terminal_failure_across_reopen_and_epoch_retry() -> TestResult {
    let mut r = ready()?;
    let config = r.participants[0].config.clone();
    let package = incoming(&r).clone();
    assert_ne!(package.envelope_digest()?, r.alternate.envelope_digest()?);
    r.frost.accept_round2_package(
        &config,
        &custody(),
        &package,
        &r.authority.mutation_fence(),
        2500,
    )?;
    (r.authority, r.frost) = reopen(&r.fixture, r.authority, r.frost);
    assert!(matches!(
        r.frost.accept_round2_package(
            &config,
            &custody(),
            &r.alternate,
            &r.authority.mutation_fence(),
            2501
        ),
        Err(FrostStoreError::CeremonyFailed)
    ));
    (r.authority, r.frost) = reopen(&r.fixture, r.authority, r.frost);
    assert_eq!(
        r.frost
            .load_ceremony(&config.ceremony_id()?, &custody())?
            .ok_or("ceremony")?
            .state,
        FrostCeremonyState::Failed
    );
    assert!(matches!(
        r.frost.accept_round2_package(
            &config,
            &custody(),
            &package,
            &r.authority.mutation_fence(),
            2502
        ),
        Err(FrostStoreError::CeremonyFailed)
    ));
    let mut rng = ChaCha20Rng::from_seed([90; 32]);
    assert!(matches!(
        r.frost.begin_ceremony(
            &config,
            &r.participants[0].transport_key,
            &test_sealing_key(&config),
            &custody(),
            &mut rng,
            &r.authority.mutation_fence(),
            2502
        ),
        Err(FrostStoreError::CeremonyFailed)
    ));
    assert!(matches!(
        r.frost.complete_ceremony(
            &config,
            &custody(),
            &r.round1,
            &r.round2,
            &r.authority.mutation_fence(),
            3000
        ),
        Err(FrostStoreError::CeremonyFailed)
    ));
    let mut fresh = config.clone();
    fresh.key_epoch += 1;
    let started = r.frost.begin_ceremony(
        &fresh,
        &r.participants[0].transport_key,
        &test_sealing_key(&fresh),
        &custody(),
        &mut rng,
        &r.authority.mutation_fence(),
        3000,
    )?;
    assert_eq!(started.state, FrostCeremonyState::Round1Ready);
    assert_ne!(started.ceremony_id, config.ceremony_id()?);
    Ok(())
}

#[test]
fn external_database_writes_fence_before_acceptance() -> TestResult {
    let r = ready()?;
    let config = &r.participants[0].config;
    let sql = rusqlite::Connection::open(&r.fixture.database)?;
    sql.execute_batch("CREATE TRIGGER reject_inbox_commit BEFORE INSERT ON frost_projection_commits WHEN NEW.projection_type = 'ceremony_inbox' BEGIN SELECT RAISE(ABORT, 'inbox-cutpoint'); END;")?;
    let result = r.frost.accept_round2_package(
        config,
        &custody(),
        incoming(&r),
        &r.authority.mutation_fence(),
        2500,
    );
    assert!(
        matches!(&result, Err(FrostStoreError::Unavailable(detail)) if detail.contains("authority database changed outside its serving-owner connection")),
        "{result:?}"
    );
    let count: i64 = sql.query_row("SELECT COUNT(*) FROM frost_round2_acceptances", [], |row| {
        row.get(0)
    })?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn concurrent_duplicate_acceptance_is_one_committed_row() -> TestResult {
    let r = ready()?;
    let config = &r.participants[0].config;
    let package = incoming(&r);
    let fence = r.authority.mutation_fence();
    std::thread::scope(|scope| {
        let threads = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    r.frost
                        .accept_round2_package(config, &custody(), package, &fence, 2500)
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread
                .join()
                .unwrap_or_else(|_| panic!("accept thread"))
                .unwrap_or_else(|e| panic!("accept: {e}"));
        }
    });
    let sql = rusqlite::Connection::open(&r.fixture.database)?;
    assert_eq!(
        sql.query_row::<i64, _, _>("SELECT COUNT(*) FROM frost_round2_acceptances", [], |row| {
            row.get(0)
        })?,
        1
    );
    assert_eq!(sql.query_row::<i64, _, _>("SELECT COUNT(*) FROM frost_projection_commits WHERE projection_type = 'ceremony_inbox'", [], |row| row.get(0))?, 1);
    Ok(())
}

#[test]
fn tampered_delivery_does_not_fail_ceremony_and_clock_regression_does_not_write() -> TestResult {
    let r = ready()?;
    let config = &r.participants[0].config;
    let mut json = serde_json::to_value(incoming(&r))?;
    json["transportSignature"] = serde_json::json!("00".repeat(64));
    let tampered = serde_json::from_value(json)?;
    assert!(matches!(
        r.frost.accept_round2_package(
            config,
            &custody(),
            &tampered,
            &r.authority.mutation_fence(),
            2500
        ),
        Err(FrostStoreError::Ceremony(
            chio_federation_authority::FrostCeremonyError::Sealing(
                chio_federation_authority::FrostSealingError::Signature
            )
        ))
    ));
    assert_eq!(
        r.frost
            .load_ceremony(&config.ceremony_id()?, &custody())?
            .ok_or("ceremony")?
            .state,
        FrostCeremonyState::Round2Ready
    );
    r.frost.accept_round2_package(
        config,
        &custody(),
        incoming(&r),
        &r.authority.mutation_fence(),
        2500,
    )?;
    assert!(matches!(
        r.frost.accept_round2_package(
            config,
            &custody(),
            incoming(&r),
            &r.authority.mutation_fence(),
            2400
        ),
        Err(FrostStoreError::Conflict(
            "trusted time regressed behind the inbox"
        ))
    ));
    Ok(())
}

#[test]
fn conflict_after_completion_disables_the_completed_key_across_restart() -> TestResult {
    let mut r = ready()?;
    let config = r.participants[0].config.clone();
    for package in r
        .round2
        .iter()
        .filter(|p| p.recipient_participant_id() == config.local_participant_id)
    {
        r.frost.accept_round2_package(
            &config,
            &custody(),
            package,
            &r.authority.mutation_fence(),
            2500,
        )?;
    }
    let completed = r.frost.complete_ceremony(
        &config,
        &custody(),
        &r.round1,
        &r.round2,
        &r.authority.mutation_fence(),
        3000,
    )?;
    assert!(matches!(
        r.frost.accept_round2_package(
            &config,
            &custody(),
            &r.alternate,
            &r.authority.mutation_fence(),
            3001
        ),
        Err(FrostStoreError::CeremonyFailed)
    ));
    (r.authority, r.frost) = reopen(&r.fixture, r.authority, r.frost);
    let record = r
        .frost
        .load_ceremony(&completed.ceremony_id, &custody())?
        .ok_or("ceremony")?;
    assert_eq!(record.state, FrostCeremonyState::Failed);
    assert_eq!(record.state_version, 4);
    assert!(matches!(
        r.frost.load_completed_key_package(
            &completed.ceremony_id,
            &custody(),
            &r.authority.mutation_fence()
        ),
        Err(FrostStoreError::Conflict("ceremony is not complete"))
    ));
    Ok(())
}

#[test]
fn reopening_refuses_deleted_committed_acceptance() -> TestResult {
    let r = ready()?;
    let config = &r.participants[0].config;
    r.frost.accept_round2_package(
        config,
        &custody(),
        incoming(&r),
        &r.authority.mutation_fence(),
        2500,
    )?;
    drop(r.frost);
    drop(r.authority);
    let sql = rusqlite::Connection::open(&r.fixture.database)?;
    sql.execute("DELETE FROM frost_round2_acceptances", [])?;
    drop(sql);
    let error = match SqliteAuthorityStore::open_serving(&r.fixture.database, &r.fixture.lock_root)
    {
        Ok(_) => panic!("deleted committed acceptance was accepted"),
        Err(error) => error,
    };
    assert!(
        matches!(&error, chio_store_sqlite::SqliteServingOwnerError::Invalid(detail)
        if detail.contains("committed round-two acceptance is missing")),
        "{error:?}"
    );
    Ok(())
}

#[test]
fn completion_rejects_substituting_a_freshly_sealed_local_transcript() -> TestResult {
    let r = ready()?;
    let local = &r.participants[0];
    for envelope in r
        .round2
        .iter()
        .filter(|p| p.recipient_participant_id() == local.config.local_participant_id)
    {
        r.frost.accept_round2_package(
            &local.config,
            &custody(),
            envelope,
            &r.authority.mutation_fence(),
            2500,
        )?;
    }
    let mut rng = ChaCha20Rng::from_seed([70; 32]);
    let repeat = begin_frost_ceremony(
        &local.config,
        &local.transport_key,
        &test_sealing_key(&local.config),
        &mut rng,
    )?;
    assert_eq!(repeat.package, r.round1[0]);
    let alternative = advance_frost_ceremony(
        &local.config,
        &local.transport_key,
        repeat.secret,
        &r.round1,
    )?;
    let mut substituted = r.round2.clone();
    for envelope in &mut substituted {
        if envelope.sender_participant_id() == local.config.local_participant_id {
            *envelope = alternative
                .packages
                .iter()
                .find(|p| p.recipient_participant_id() == envelope.recipient_participant_id())
                .ok_or("local recipient")?
                .clone();
        }
    }
    let result = r.frost.complete_ceremony(
        &local.config,
        &custody(),
        &r.round1,
        &substituted,
        &r.authority.mutation_fence(),
        3000,
    );
    assert!(
        matches!(
            &result,
            Err(FrostStoreError::Conflict(
                "transcript differs from committed outbound packages"
            ))
        ),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn completion_rejects_a_different_valid_round_one_transcript() -> TestResult {
    let r = ready()?;
    let peer = &r.participants[1];
    let mut rng = ChaCha20Rng::from_seed([99; 32]);
    let first = begin_frost_ceremony(
        &peer.config,
        &peer.transport_key,
        &test_sealing_key(&peer.config),
        &mut rng,
    )?;
    let mut substituted = r.round1.clone();
    substituted[1] = first.package;
    assert_ne!(substituted, r.round1);
    let result = r.frost.complete_ceremony(
        &r.participants[0].config,
        &custody(),
        &substituted,
        &r.round2,
        &r.authority.mutation_fence(),
        3000,
    );
    assert!(
        matches!(
            &result,
            Err(FrostStoreError::Conflict(
                "round-one transcript changed after advancement"
            ))
        ),
        "{result:?}"
    );
    Ok(())
}
