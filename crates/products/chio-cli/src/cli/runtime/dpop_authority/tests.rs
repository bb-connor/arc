use super::*;
use chio_core::canonical::{canonical_json_bytes, UntrustedJsonError};
use chio_kernel::admission_operation::{
    AdmissionDigest, AdmissionIdentifier, DurableAdmissionMode,
};
use chio_kernel::dpop::authority::{DpopReplayAuthority, DpopReplayAuthorityInput};
use chio_security_types::clock::{Clock, FixedClock};
use std::{error::Error, fs, sync::Arc};

type TestResult = Result<(), Box<dyn Error>>;

fn descriptor() -> Result<DpopReplayAuthority, Box<dyn Error>> {
    Ok(DpopReplayAuthority::new(DpopReplayAuthorityInput {
        destination_store_uuid: AdmissionIdentifier::try_new(
            "destination",
            "550e8400-e29b-41d4-a716-446655440000",
        )?,
        dpop_authority_id: AdmissionIdentifier::try_new("authority", "cli-config-test")?,
        expectation_id: AdmissionDigest::try_new("expectation", "a".repeat(64))?,
        proof_ttl_secs: 300,
        max_clock_skew_secs: 30,
    })?)
}

fn assert_registered_refusal(error: CliError, message: &str) -> TestResult {
    let CliError::Chio(error) = error else {
        return Err("expected registered CLI refusal".into());
    };
    assert_eq!(error.code().as_str(), "urn:chio:error:cli:other");
    assert_eq!(error.message(), message);
    Ok(())
}

#[test]
fn descriptor_sources_preserve_the_selected_value_and_input_bytes() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("authority.json");
    let authority = descriptor()?;
    let mut bytes = canonical_json_bytes(&authority)?;
    bytes.resize(4096, b' ');
    fs::write(&path, &bytes)?;
    assert_eq!(configured_dpop_replay_authority_from_path(None)?, None);
    assert_eq!(
        configured_dpop_replay_authority_from_path(Some(&path))?,
        Some(authority)
    );
    assert_eq!(fs::read(&path)?, bytes);
    assert_eq!(fs::read_dir(directory.path())?.count(), 1);
    Ok(())
}

#[test]
fn configured_missing_file_is_an_io_refusal_without_creation() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("absent.json");
    let error = configured_dpop_replay_authority_from_path(Some(&path))
        .err()
        .ok_or("missing configured file was accepted")?;
    assert_eq!(error.report().code, "CHIO-CLI-IO");
    let CliError::Io(error) = error else {
        return Err("expected file I/O refusal".into());
    };
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    assert_eq!(fs::read_dir(directory.path())?.count(), 0);
    Ok(())
}

#[cfg(unix)]
#[test]
fn descriptor_file_refuses_directories_and_symlinks() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let error = configured_dpop_replay_authority_from_path(Some(directory.path()))
        .err()
        .ok_or("directory accepted as an authority file")?;
    let CliError::Io(error) = error else {
        return Err("expected regular-file refusal".into());
    };
    assert_eq!(error.kind(), std::io::ErrorKind::Other);
    assert_eq!(error.to_string(), "input must be a regular file");
    let path = directory.path().join("authority.json");
    let link = directory.path().join("authority-link.json");
    let bytes = canonical_json_bytes(&descriptor()?)?;
    fs::write(&path, &bytes)?;
    std::os::unix::fs::symlink(&path, &link)?;
    let error = configured_dpop_replay_authority_from_path(Some(&link))
        .err()
        .ok_or("symlink accepted as an authority file")?;
    let CliError::Io(error) = error else {
        return Err("expected no-follow file refusal".into());
    };
    assert_eq!(error.raw_os_error(), Some(libc::ELOOP));
    assert_eq!(fs::read(&path)?, bytes);
    assert_eq!(fs::read_link(&link)?, path);
    assert_eq!(fs::read_dir(directory.path())?.count(), 2);
    Ok(())
}

#[test]
fn descriptor_file_rejects_the_first_byte_over_its_bound() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("authority.json");
    let mut bytes = canonical_json_bytes(&descriptor()?)?;
    bytes.resize(4097, b' ');
    fs::write(&path, &bytes)?;
    let error = configured_dpop_replay_authority_from_path(Some(&path))
        .err()
        .ok_or("oversized descriptor was accepted")?;
    let CliError::Io(error) = error else {
        return Err("expected bounded file I/O refusal".into());
    };
    assert_eq!(error.kind(), std::io::ErrorKind::Other);
    let source = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<UntrustedJsonError>())
        .ok_or("missing retained size error")?;
    assert!(matches!(
        source,
        UntrustedJsonError::TooLarge {
            bytes: 4097,
            bound: 4096
        }
    ));
    assert_eq!(source.code(), "urn:chio:error:attest:signed-json-too-large");
    assert_eq!(fs::read(&path)?, bytes);
    assert_eq!(fs::read_dir(directory.path())?.count(), 1);
    Ok(())
}

#[test]
fn descriptor_file_rejects_duplicate_keys_before_typed_projection() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("authority.json");
    let bytes = br#"{"proof_ttl_secs":300,"proof_ttl_secs":301}"#;
    fs::write(&path, bytes)?;
    let error = configured_dpop_replay_authority_from_path(Some(&path))
        .err()
        .ok_or("duplicate authority field was accepted")?;
    assert_eq!(
        error.report().code,
        "urn:chio:error:attest:signed-json-invalid-input"
    );
    let CliError::SignedJson(UntrustedJsonError::SignedInput(
        chio_core::error::Error::CanonicalJson(message),
    )) = error
    else {
        return Err("expected original duplicate-key refusal".into());
    };
    assert_eq!(
        message,
        "duplicate object key: \"proof_ttl_secs\" at line 1 column 43"
    );
    assert_eq!(fs::read(&path)?, bytes);
    Ok(())
}

#[test]
fn descriptor_file_rejects_null_missing_and_invalid_authority_fields() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("authority.json");
    let mut invalid = serde_json::to_value(descriptor()?)?;
    invalid["proof_ttl_secs"] = 0.into();
    for (bytes, expected) in [
        (
            b"null".to_vec(),
            "invalid type: null, expected struct DpopReplayAuthorityInput",
        ),
        (b"{}".to_vec(), "missing field `destination_store_uuid`"),
        (
            serde_json::to_vec(&invalid)?,
            "DPoP proof verification failed: durable DPoP profile: durable freshness policy exceeds its bounds",
        ),
    ] {
        fs::write(&path, &bytes)?;
        let error = configured_dpop_replay_authority_from_path(Some(&path))
            .err()
            .ok_or("invalid authority shape was accepted")?;
        assert_eq!(error.report().code, "urn:chio:error:attest:signed-json-invalid-shape");
        let CliError::SignedJson(UntrustedJsonError::Decode(source)) = error else {
            return Err("expected retained authority decode error".into());
        };
        assert_eq!(source.classify(), serde_json::error::Category::Data);
        assert_eq!(source.to_string(), expected);
        assert_eq!(fs::read(&path)?, bytes);
    }
    assert_eq!(fs::read_dir(directory.path())?.count(), 1);
    Ok(())
}

#[test]
fn off_mode_refuses_even_an_activated_authority_without_attaching_stores() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
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
