use super::*;
use chio_security_types::clock::{ClockError, MonotonicInstant, UnixMillis};
use std::sync::Mutex;

struct ScriptedClock(Mutex<Result<ClockReading, ClockError>>);

impl Clock for ScriptedClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        *self.0.lock().map_err(|_| ClockError::Unavailable)?
    }
}

impl ScriptedClock {
    fn set(&self, reading: Result<ClockReading, ClockError>) -> Result<(), ClockError> {
        *self.0.lock().map_err(|_| ClockError::Unavailable)? = reading;
        Ok(())
    }
}

#[test]
fn initializer_preserves_supplied_clock_errors_without_registration() -> TestResult {
    let directory = crate::durable_admission::private_tempdir()?;
    let runtime = DurableAdmissionRuntime::open_with_clock(
        &directory.path().join("authority.db"),
        fixture_clock(),
    )?;
    let store = runtime
        .local_authority_store()
        .ok_or("missing local store")?;
    let id = AdmissionIdentifier::try_new("authority", "clock-refusal")?;
    for fault in [
        ClockError::Unavailable,
        ClockError::BeforeEpoch,
        ClockError::Overflow,
    ] {
        let error = initialize_local_dpop_authority(
            &store,
            &id,
            &DpopConfig::default(),
            Arc::new(ScriptedClock(Mutex::new(Err(fault)))),
        )
        .err()
        .ok_or("failed clock authorized initialization")?;
        assert_eq!(error.report().code, fault.code());
        let CliError::Clock(retained) = error else {
            return Err("expected typed clock error".into());
        };
        assert_eq!(retained, fault);
        assert_eq!(
            store
                .admission_operation_store()
                .load_dpop_replay_migration(
                    &id,
                    &store.mutation_fence(),
                    fixture_clock().read()?.unix_millis().get(),
                )?,
            None
        );
    }
    Ok(())
}

#[test]
fn owning_store_clock_faults_refuse_initialization_and_serving_without_mutation() -> TestResult {
    let initial = ClockReading::new(
        UnixMillis::new(1_800_000_000_000),
        MonotonicInstant::from_nanos(10),
    );
    for active in [false, true] {
        let directory = crate::durable_admission::private_tempdir()?;
        let clock = Arc::new(ScriptedClock(Mutex::new(Ok(initial))));
        let runtime = DurableAdmissionRuntime::open_with_clock(
            &directory.path().join("authority.db"),
            clock.clone(),
        )?;
        let store = runtime
            .local_authority_store()
            .ok_or("missing local store")?;
        let id = AdmissionIdentifier::try_new("authority", "store-clock-refusal")?;
        if active {
            initialize_local_dpop_authority(&store, &id, &DpopConfig::default(), clock.clone())?;
        }
        let operations = store.admission_operation_store();
        let fence = store.mutation_fence();
        let before =
            operations.load_dpop_replay_migration(&id, &fence, initial.unix_millis().get())?;
        assert_eq!(
            before.as_ref().is_some_and(|record| record.is_active()),
            active
        );
        for (reading, expected) in [
            (Err(ClockError::Unavailable), ClockError::Unavailable),
            (
                Ok(ClockReading::new(
                    UnixMillis::new(1_799_999_999_999),
                    initial.monotonic(),
                )),
                ClockError::WallClockRegression,
            ),
            (
                Ok(ClockReading::new(
                    initial.unix_millis(),
                    MonotonicInstant::from_nanos(9),
                )),
                ClockError::MonotonicRegression,
            ),
        ] {
            clock.set(reading)?;
            let error = initialize_local_dpop_authority(
                &store,
                &id,
                &DpopConfig::default(),
                fixture_clock(),
            )
            .err()
            .ok_or("faulted owning clock authorized initialization")?;
            let message = format!("admission operation invariant failed: {}", expected.code());
            assert_refusal(error, &message)?;
            let error = load_local_dpop_authority(&store, &id, initial)
                .err()
                .ok_or("faulted owning clock authorized serving")?;
            assert_refusal(error, &message)?;
            clock.set(Ok(initial))?;
            assert_eq!(
                operations.load_dpop_replay_migration(&id, &fence, initial.unix_millis().get())?,
                before
            );
        }
    }
    Ok(())
}
