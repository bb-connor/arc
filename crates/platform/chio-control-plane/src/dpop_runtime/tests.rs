use super::*;
use crate::DurableAdmissionRuntime;
use chio_security_types::clock::FixedClock;

fn fixture_clock() -> Arc<dyn Clock> {
    Arc::new(FixedClock::new(1_800_000_000))
}

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[path = "tests/clock.rs"]
mod clock;

#[test]
fn serving_dpop_load_refuses_missing_authority_without_creating_one() -> TestResult {
    let directory = crate::durable_admission::private_tempdir()?;
    let runtime = DurableAdmissionRuntime::open_with_clock(
        &directory.path().join("authority.db"),
        fixture_clock(),
    )?;
    let store = runtime
        .local_authority_store()
        .ok_or("missing local store")?;
    let id = AdmissionIdentifier::try_new("dpop_authority", "serving")?;
    let now = fixture_clock().read()?;
    let error = load_local_dpop_authority(&store, &id, now)
        .err()
        .ok_or("expected refusal")?;
    assert_refusal(error, "DPoP authority is not registered")?;
    assert!(store
        .admission_operation_store()
        .load_dpop_replay_migration(&id, &store.mutation_fence(), now.unix_millis().get())?
        .is_none());
    Ok(())
}

#[test]
fn initialized_dpop_authority_survives_reopen_without_replacement() -> TestResult {
    let directory = crate::durable_admission::private_tempdir()?;
    let database = directory.path().join("authority.db");
    let id = AdmissionIdentifier::try_new("dpop_authority", "serving")?;
    let expected = {
        let runtime = DurableAdmissionRuntime::open_with_clock(&database, fixture_clock())?;
        let store = runtime
            .local_authority_store()
            .ok_or("missing local store")?;
        initialize_local_dpop_authority(&store, &id, &DpopConfig::default(), fixture_clock())?
    };
    let runtime = DurableAdmissionRuntime::open_with_clock(&database, fixture_clock())?;
    let store = runtime
        .local_authority_store()
        .ok_or("missing local store")?;
    assert_eq!(
        load_local_dpop_authority(&store, &id, fixture_clock().read()?)?,
        expected
    );
    assert_eq!(
        initialize_local_dpop_authority(&store, &id, &DpopConfig::default(), fixture_clock(),)?,
        expected
    );
    let different_policy = DpopConfig {
        proof_ttl_secs: 301,
        ..DpopConfig::default()
    };
    let error = initialize_local_dpop_authority(&store, &id, &different_policy, fixture_clock())
        .err()
        .ok_or("expected policy refusal")?;
    assert_refusal(error, "DPoP authority freshness policy does not match")?;
    assert_eq!(
        load_local_dpop_authority(&store, &id, fixture_clock().read()?)?,
        expected
    );
    Ok(())
}

#[test]
fn dpop_initialization_refuses_to_replace_an_unactivated_source() -> TestResult {
    let directory = crate::durable_admission::private_tempdir()?;
    let runtime = DurableAdmissionRuntime::open_with_clock(
        &directory.path().join("authority.db"),
        fixture_clock(),
    )?;
    let store = runtime
        .local_authority_store()
        .ok_or("missing local store")?;
    let operations = store.admission_operation_store();
    let fence = store.mutation_fence();
    let id = AdmissionIdentifier::try_new("dpop_authority", "serving")?;
    let source = DpopNonceStore::with_clock(
        8,
        8,
        chio_kernel::dpop::DEFAULT_DPOP_IDENTITY_BYTE_CAPACITY,
        std::time::Duration::from_secs(300),
        fixture_clock(),
    )?;
    let snapshot = source.preview_unsealed(&DpopReplaySourceBinding {
        dpop_authority_id: id.clone(),
        destination_authority_id: AdmissionIdentifier::try_new("destination", &fence.store_uuid)?,
    })?;
    let expected = operations.expect_dpop_replay_source(
        &AdmissionIdentifier::try_new("instance", snapshot.instance_id())?,
        &id,
        &source,
        &fence,
        fixture_clock().read()?.unix_millis().get(),
    )?;
    for imported in [false, true] {
        let before = if imported {
            operations.import_dpop_replay_source(
                &id,
                expected.expectation_id(),
                &source,
                &fence,
                fixture_clock().read()?.unix_millis().get(),
            )?
        } else {
            expected.clone()
        };
        assert_eq!(before.imported_inactive(), imported);
        assert_eq!(before.authority(), None);
        let error =
            initialize_local_dpop_authority(&store, &id, &DpopConfig::default(), fixture_clock())
                .err()
                .ok_or("expected inactive initialization refusal")?;
        assert_refusal(error, "DPoP authority is not activated")?;
        let error = load_local_dpop_authority(&store, &id, fixture_clock().read()?)
            .err()
            .ok_or("expected inactive serving refusal")?;
        assert_refusal(error, "DPoP authority is not activated")?;
        assert_eq!(
            operations.load_dpop_replay_migration(
                &id,
                &fence,
                fixture_clock().read()?.unix_millis().get(),
            )?,
            Some(before)
        );
    }
    Ok(())
}

#[test]
fn invalid_freshness_neither_registers_nor_replaces_an_authority() -> TestResult {
    let directory = crate::durable_admission::private_tempdir()?;
    let runtime = DurableAdmissionRuntime::open_with_clock(
        &directory.path().join("authority.db"),
        fixture_clock(),
    )?;
    let store = runtime
        .local_authority_store()
        .ok_or("missing local store")?;
    let operations = store.admission_operation_store();
    let fence = store.mutation_fence();
    for active in [false, true] {
        let id =
            AdmissionIdentifier::try_new("authority", if active { "active" } else { "absent" })?;
        if active {
            initialize_local_dpop_authority(&store, &id, &DpopConfig::default(), fixture_clock())?;
        }
        let before = operations.load_dpop_replay_migration(
            &id,
            &fence,
            fixture_clock().read()?.unix_millis().get(),
        )?;
        assert_eq!(
            before.as_ref().is_some_and(|record| record.is_active()),
            active
        );
        for (proof_ttl_secs, max_clock_skew_secs) in [(0, 30), (3601, 30), (300, 301)] {
            let policy = DpopConfig {
                proof_ttl_secs,
                max_clock_skew_secs,
                ..DpopConfig::default()
            };
            let error = initialize_local_dpop_authority(&store, &id, &policy, fixture_clock())
                .err()
                .ok_or("invalid freshness was accepted")?;
            assert_refusal(error, "DPoP freshness policy exceeds its bounds")?;
            assert_eq!(
                operations.load_dpop_replay_migration(
                    &id,
                    &fence,
                    fixture_clock().read()?.unix_millis().get(),
                )?,
                before
            );
        }
    }
    Ok(())
}

fn assert_refusal(error: CliError, expected: &str) -> TestResult {
    let CliError::Chio(error) = error else {
        return Err("expected registered refusal".into());
    };
    assert_eq!(error.code().as_str(), "urn:chio:error:cli:other");
    assert_eq!(error.message(), expected);
    Ok(())
}
