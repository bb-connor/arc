//! The passport status registry has one writer at a time, across threads and
//! processes: an overlapping update is refused as busy instead of replacing a
//! newer file with an older copy.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier};

use super::test_fixtures::{passport_issued_at, Fallible};
use super::*;
use crate::signed_input::lock_registry;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ISSUED_AT: u64 = 1_730_000_000;
const PUBLISHED_AT: u64 = ISSUED_AT + 60;
/// Names the registry the child-process holder locks.
const HOLDER_REGISTRY: &str = "CHIO_TEST_PASSPORT_REGISTRY_LOCK_HOLDER";
const HOLDER_READY: &str = "passport-registry-lock-held";

/// A registry at `path` holding one published record, whose id is returned.
fn one_published(path: &Path) -> Fallible<String> {
    let passport = passport_issued_at(111, ISSUED_AT)?;
    let record = PassportStatusRegistry::update(path, |registry| {
        registry.publish(
            &passport,
            PUBLISHED_AT,
            PassportStatusDistribution::default(),
        )
    })?;
    Ok(record.passport_id)
}

fn revoke(path: &Path, passport_id: &str) -> Result<PassportLifecycleRecord, RegistryUpdateError> {
    PassportStatusRegistry::update(path, |registry| {
        registry.revoke(passport_id, Some("compromised"), Some(PUBLISHED_AT + 5))
    })
}

fn status(path: &Path, passport_id: &str) -> Fallible<Option<PassportLifecycleState>> {
    Ok(PassportStatusRegistry::load(path)?
        .get(passport_id)
        .map(|record| record.status))
}

#[test]
fn an_update_overlapping_a_publish_is_busy_and_the_revocation_persists_on_retry() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("passport-statuses.json");
    let passport_id = one_published(&path)?;
    let fresh = passport_issued_at(112, ISSUED_AT)?;
    let inside = Arc::new(Barrier::new(2));
    let attempted = Arc::new(Barrier::new(2));
    let publisher = {
        let (path, inside, attempted) = (path.clone(), Arc::clone(&inside), Arc::clone(&attempted));
        std::thread::spawn(move || {
            PassportStatusRegistry::update(&path, |registry| {
                inside.wait();
                attempted.wait();
                registry.publish(
                    &fresh,
                    PUBLISHED_AT + 10,
                    PassportStatusDistribution::default(),
                )
            })
            .map(|record| record.passport_id)
            .map_err(|error| error.to_string())
        })
    };
    inside.wait();
    let before = fs::read(&path)?;
    let overlapping = revoke(&path, &passport_id);
    assert!(
        matches!(overlapping, Err(RegistryUpdateError::Busy)),
        "{overlapping:?}"
    );
    assert_eq!(fs::read(&path)?, before);
    attempted.wait();
    let published = publisher.join().map_err(|_| "publisher panicked")??;

    revoke(&path, &passport_id)?;
    assert_eq!(
        status(&path, &passport_id)?,
        Some(PassportLifecycleState::Revoked)
    );
    assert_eq!(
        status(&path, &published)?,
        Some(PassportLifecycleState::Active)
    );
    Ok(())
}

#[test]
fn a_publish_overlapping_a_revocation_is_busy_and_never_reverts_it() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("passport-statuses.json");
    let passport_id = one_published(&path)?;
    let inside = Arc::new(Barrier::new(2));
    let attempted = Arc::new(Barrier::new(2));
    let revoker = {
        let (path, passport_id) = (path.clone(), passport_id.clone());
        let (inside, attempted) = (Arc::clone(&inside), Arc::clone(&attempted));
        std::thread::spawn(move || {
            PassportStatusRegistry::update(&path, |registry| {
                inside.wait();
                attempted.wait();
                registry.revoke(&passport_id, Some("compromised"), Some(PUBLISHED_AT + 5))
            })
            .map_err(|error| error.to_string())
        })
    };
    inside.wait();
    let fresh = passport_issued_at(113, ISSUED_AT)?;
    let publish = |path: &Path| {
        PassportStatusRegistry::update(path, |registry| {
            registry.publish(
                &fresh,
                PUBLISHED_AT + 10,
                PassportStatusDistribution::default(),
            )
        })
    };
    assert!(matches!(publish(&path), Err(RegistryUpdateError::Busy)));
    attempted.wait();
    revoker.join().map_err(|_| "revoker panicked")??;

    let published = publish(&path)?;
    assert_eq!(
        status(&path, &passport_id)?,
        Some(PassportLifecycleState::Revoked)
    );
    assert_eq!(
        status(&path, &published.passport_id)?,
        Some(PassportLifecycleState::Active)
    );
    Ok(())
}

/// Run as a child process by `another_process_holding_the_lock_makes_updates_busy`:
/// takes the lock of the registry named by the environment, reports it, and
/// holds it until its standard input closes. Without that environment it
/// does nothing.
#[test]
fn registry_lock_holder_for_child_process() -> TestResult {
    let Some(path) = std::env::var_os(HOLDER_REGISTRY) else {
        return Ok(());
    };
    let _lock = lock_registry(Path::new(&path)).map_err(CliError::from)?;
    let mut stdout = std::io::stdout();
    writeln!(stdout, "{HOLDER_READY}")?;
    stdout.flush()?;
    let mut released = Vec::new();
    std::io::stdin().read_to_end(&mut released)?;
    Ok(())
}

#[test]
fn another_process_holding_the_lock_makes_updates_busy() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("passport-statuses.json");
    let passport_id = one_published(&path)?;
    let mut holder = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "passport_verifier::registry_writer_lock_tests::registry_lock_holder_for_child_process",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(HOLDER_REGISTRY, &path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let output = holder.stdout.take().ok_or("holder stdout")?;
    let mut lines = BufReader::new(output).lines();
    loop {
        let line = lines
            .next()
            .ok_or("the holder exited before taking the lock")??;
        if line.contains(HOLDER_READY) {
            break;
        }
    }

    let before = fs::read(&path)?;
    let busy = revoke(&path, &passport_id);
    assert!(matches!(busy, Err(RegistryUpdateError::Busy)), "{busy:?}");
    assert_eq!(fs::read(&path)?, before);

    drop(holder.stdin.take());
    assert!(holder.wait()?.success());
    revoke(&path, &passport_id)?;
    assert_eq!(
        status(&path, &passport_id)?,
        Some(PassportLifecycleState::Revoked)
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn directory_aliases_of_one_registry_share_its_lock() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let real = directory.path().join("real");
    let path = real.join("passport-statuses.json");
    let passport_id = one_published(&path)?;
    std::os::unix::fs::symlink(&real, directory.path().join("alias"))?;
    fs::create_dir(real.join("nested"))?;
    let aliases = [
        directory
            .path()
            .join("alias")
            .join("passport-statuses.json"),
        real.join("nested")
            .join("..")
            .join("passport-statuses.json"),
        real.join(".").join("passport-statuses.json"),
    ];
    for alias in aliases {
        let held = lock_registry(&alias).map_err(CliError::from)?;
        assert_eq!(held.destination(), fs::canonicalize(&path)?.as_path());
        assert!(
            matches!(revoke(&path, &passport_id), Err(RegistryUpdateError::Busy)),
            "{}",
            alias.display()
        );
        drop(held);
    }
    revoke(&path, &passport_id)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn a_registry_path_that_is_a_symbolic_link_is_refused() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let target = directory.path().join("passport-statuses.json");
    let passport_id = one_published(&target)?;
    let link = directory.path().join("linked-statuses.json");
    std::os::unix::fs::symlink(&target, &link)?;
    let before = fs::read(&target)?;
    match revoke(&link, &passport_id) {
        Err(RegistryUpdateError::Load(error)) => {
            assert!(error.to_string().contains("is a symbolic link"), "{error}")
        }
        other => {
            return Err(format!("a symbolic-link registry path must be refused: {other:?}").into())
        }
    }
    assert_eq!(fs::read(&target)?, before);
    assert!(fs::symlink_metadata(&link)?.file_type().is_symlink());
    Ok(())
}

#[cfg(unix)]
#[test]
fn a_lock_file_that_is_shared_or_linked_is_refused() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("passport-statuses.json");
    let passport_id = one_published(&path)?;
    let lock = directory.path().join(".passport-statuses.json.lock");
    assert!(lock.is_file(), "the writer lock lives beside the registry");

    fs::set_permissions(&lock, fs::Permissions::from_mode(0o644))?;
    let shared = revoke(&path, &passport_id);
    assert!(
        matches!(&shared, Err(RegistryUpdateError::Load(error)) if error.to_string().contains("is not a private regular file")),
        "{shared:?}"
    );
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600))?;

    let second_name = directory.path().join("second-name.lock");
    fs::hard_link(&lock, &second_name)?;
    let linked = revoke(&path, &passport_id);
    assert!(
        matches!(&linked, Err(RegistryUpdateError::Load(error)) if error.to_string().contains("is not a private regular file")),
        "{linked:?}"
    );
    fs::remove_file(&second_name)?;

    assert_eq!(
        status(&path, &passport_id)?,
        Some(PassportLifecycleState::Active)
    );
    revoke(&path, &passport_id)?;
    Ok(())
}
