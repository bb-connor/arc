use super::*;
use chio_kernel::admission_operation::{AdmissionIdentifier, DurableAdmissionMode};
use chio_security_types::clock::{Clock, FixedClock};
use std::{error::Error, fs, sync::Arc};

type TestResult = Result<(), Box<dyn Error>>;

fn assert_registered_refusal(error: CliError, message: &str) -> TestResult {
    let CliError::Chio(error) = error else {
        return Err("expected registered CLI refusal".into());
    };
    assert_eq!(error.code().as_str(), "urn:chio:error:cli:other");
    assert_eq!(error.message(), message);
    Ok(())
}

#[test]
fn off_mode_refuses_even_an_activated_authority_without_attaching_stores() -> TestResult {
    let directory = tempfile::tempdir()?;
    let clock: Arc<dyn Clock> = Arc::new(FixedClock::new(1_800_000_000));
    let runtime = DurableAdmissionRuntime::open_with_clock(
        &directory.path().join("authority.db"),
        clock.clone(),
    )?;
    let store = runtime
        .local_authority_store()
        .ok_or("missing local store")?;
    let authority = chio_control_plane::initialize_local_dpop_authority(
        &store,
        &AdmissionIdentifier::try_new("authority", "cli-off-mode")?,
        &chio_kernel::DpopConfig::default(),
        clock.clone(),
    )?;
    let policy_path = directory.path().join("policy.yaml");
    fs::write(
        &policy_path,
        "kernel:\n  durable_admission_mode: off\n  allow_unsafe_durable_admission_off: true\n  allow_ephemeral_receipt_log: true\n",
    )?;
    let mut kernel = chio_control_plane::build_kernel_with_clock(
        chio_control_plane::policy::load_policy(&policy_path)?,
        &runtime.kernel_keypair(),
        clock.clone(),
    );
    assert_eq!(kernel.durable_admission_mode(), DurableAdmissionMode::Off);
    let operations = store.admission_operation_store();
    let before = operations
        .load_dpop_replay_migration(
            authority.dpop_authority_id(),
            &store.mutation_fence(),
            clock.read()?.unix_millis().get(),
        )?
        .ok_or("missing activated record")?;
    let error = attach_durable_admission_runtime(&mut kernel, Some(&runtime), Some(&authority))
        .err()
        .ok_or("Off mode accepted configured DPoP")?;
    assert_registered_refusal(
        error,
        "configured DPoP replay authority requires durable admission",
    )?;
    assert_eq!(kernel.operation_owned_dpop_authority(), None);
    assert!(!kernel.has_durable_admission_store());
    assert_eq!(kernel.durable_admission_mode(), DurableAdmissionMode::Off);
    assert_eq!(
        operations.load_dpop_replay_migration(
            authority.dpop_authority_id(),
            &store.mutation_fence(),
            clock.read()?.unix_millis().get(),
        )?,
        Some(before)
    );
    Ok(())
}
