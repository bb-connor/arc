//! Genuine pre-activation blob custody cannot discount mediated object capacity.
use super::*;

fn private_process_connection(path: &std::path::Path) -> TestResult<rusqlite::Connection> {
    let root = std::fs::canonicalize(path)?;
    let directory = std::fs::symlink_metadata(&root)?;
    let journal = root.join("process.db");
    let file = std::fs::symlink_metadata(&journal)?;
    if !directory.is_dir() || !file.is_file() {
        return Err("actual private process journal".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if directory.permissions().mode() & 0o077 != 0
            || file.permissions().mode() & 0o077 != 0
            || file.nlink() != 1
        {
            return Err("actual private process journal custody".into());
        }
    }
    Ok(rusqlite::Connection::open_with_flags(
        journal,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?)
}

fn raw_blob_rows(path: &std::path::Path) -> TestResult<Vec<Vec<rusqlite::types::Value>>> {
    let connection = private_process_connection(path)?;
    rows(
        &connection,
        "SELECT * FROM main.process_state_blobs ORDER BY process_id,sha256",
    )
}

fn rows(
    connection: &rusqlite::Connection,
    sql: &str,
) -> TestResult<Vec<Vec<rusqlite::types::Value>>> {
    let mut statement = connection.prepare(sql)?;
    let columns = statement.column_count();
    let mapped = statement.query_map([], |row| {
        (0..columns)
            .map(|column| row.get::<_, rusqlite::types::Value>(column))
            .collect::<Result<Vec<_>, _>>()
    })?;
    let retained = mapped.collect::<Result<Vec<_>, _>>()?;
    Ok(retained)
}

fn process_blob_custody(f: &KnowledgeFixture) -> TestResult<Vec<Vec<Vec<rusqlite::types::Value>>>> {
    let connection = private_process_connection(&f.f.path)?;
    Ok(vec![
        rows(
            &connection,
            "SELECT * FROM main.process_state_blobs ORDER BY process_id,sha256",
        )?,
        rows(
            &connection,
            "SELECT * FROM main.process_artifact_objects ORDER BY process_id,object_id",
        )?,
    ])
}

#[test]
fn artifacts_quarantined_pre_activation_bytes_do_not_discount_new_object_custody() -> TestResult {
    let f = RecoveryFixture::new(false)?;
    f.process.create_root(
        "quarantined-capacity-root",
        &f.control,
        ProcessLimits {
            max_processes: 1,
            max_depth: 0,
            max_calls: 1,
            state: chio_process::ProcessStateLimits {
                max_bytes: 16,
                max_blobs: 2,
            },
        },
    )?;
    let process = ProcessId::new("quarantined-capacity-root")?;
    let bytes = b"12345678";
    let raw = f.process.put_blob(process.as_str(), bytes)?;
    assert_eq!(f.process.read_blob(process.as_str(), &raw.sha256)?, bytes);
    let connection = private_process_connection(&f.path)?;
    let quarantined: bool = connection.query_row(
        "SELECT legacy_quarantined FROM main.process_state_blobs WHERE process_id=?1 AND sha256=?2",
        rusqlite::params![process.as_str(), raw.sha256],
        |row| row.get(0),
    )?;
    assert!(
        quarantined,
        "the real raw producer must retain quarantined custody"
    );
    drop(connection);
    let raw_before = raw_blob_rows(&f.path)?;
    let f = KnowledgeFixture::from(f)?;
    let before = f.broker.storage_usage(&process)?;
    assert_eq!((before.tree_bytes, before.tree_blobs), (8, 1));
    let seal = f
        .broker
        .stage(&ArtifactObjectId::new("new-equal-object")?, &process, bytes)?;
    assert!(seal.generation.as_str().starts_with("object:"));
    assert_eq!(f.broker.read_private(&seal)?, bytes);
    assert_eq!(raw_blob_rows(&f.f.path)?, raw_before);
    assert!(f
        .f
        .process
        .read_blob(process.as_str(), &raw.sha256)
        .is_err());
    let full = f.broker.storage_usage(&process)?;
    assert_eq!((full.tree_bytes, full.tree_blobs), (16, 2));
    let before = process_blob_custody(&f)?;
    let calls = f.f.process.process(process.as_str())?.tree_calls;
    let mut errors = Vec::new();
    for (id, candidate) in [
        ("another-equal-object", bytes),
        ("different-object", b"abcdefgh"),
    ] {
        let error = f
            .broker
            .stage(&ArtifactObjectId::new(id)?, &process, candidate)
            .err()
            .ok_or("a new logical object must consume independent capacity")?;
        assert!(matches!(error, KernelError::DurableAdmission(_)));
        errors.push(error.to_string());
        assert_eq!(f.broker.storage_usage(&process)?, full);
        assert_eq!(process_blob_custody(&f)?, before);
    }
    assert_eq!(errors[0], errors[1]);
    assert_eq!(f.f.process.process(process.as_str())?.tree_calls, calls);
    Ok(())
}

#[test]
fn artifacts_publication_quota_refuses_matching_and_distinct_pre_activation_guesses() -> TestResult
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().to_path_buf();
    std::fs::write(path.join("bounded-artifact-storage"), b"")?;
    let f = RecoveryFixture::open(path, Some(directory), false)?;
    let process = ProcessId::new("root")?;
    let initial = f.process.storage(process.as_str())?;
    assert_eq!(initial.limits.max_bytes, 131_072);
    assert_eq!(initial.limits.max_blobs, 32);
    assert_eq!((initial.tree_bytes, initial.tree_blobs), (0, 0));
    let hidden = vec![b's'; 131_008];
    let distinct = vec![b'd'; hidden.len()];
    let raw = f.process.put_blob(process.as_str(), &hidden)?;
    assert_eq!(f.process.read_blob(process.as_str(), &raw.sha256)?, hidden);
    let connection = private_process_connection(&f.path)?;
    let quarantined: bool = connection.query_row(
        "SELECT legacy_quarantined FROM main.process_state_blobs WHERE process_id=?1 AND sha256=?2",
        rusqlite::params![process.as_str(), raw.sha256],
        |row| row.get(0),
    )?;
    assert!(quarantined);
    drop(connection);
    let raw_before = raw_blob_rows(&f.path)?;
    let f = KnowledgeFixture::from(f)?;
    let usage = f.broker.storage_usage(&process)?;
    assert_eq!((usage.tree_bytes, usage.tree_blobs), (131_008, 1));
    // The ordinary public producer completes with the exact remaining capacity.
    let small = [b't'; 64];
    let input = f.input("remaining-capacity-positive", &small)?;
    let reference = f.runtime.publish(&f.f.control, &input, &small, None)?;
    assert_eq!(reference.scope, f.profile.scope);
    assert_eq!(raw_blob_rows(&f.f.path)?, raw_before);
    let full = f.broker.storage_usage(&process)?;
    assert_eq!((full.tree_bytes, full.tree_blobs), (131_072, 2));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let seen = observed.clone();
    let runtime = f.runtime.clone().with_test_cutpoint(Arc::new(move |stage| {
        seen.lock()
            .map_err(|_| KernelError::Internal("publication stage observer".into()))?
            .push(stage);
        Ok(())
    }));
    let before = process_blob_custody(&f)?;
    let calls = f.f.process.process(process.as_str())?.tree_calls;
    let mut errors = Vec::new();
    for (id, candidate) in [
        ("matching-pre-activation-guess", hidden.as_slice()),
        ("distinct-pre-activation-guess", distinct.as_slice()),
    ] {
        let input = f.input(id, candidate)?;
        let error = runtime
            .publish(&f.f.control, &input, candidate, None)
            .err()
            .ok_or("full logical capacity must refuse both public guesses")?;
        assert!(matches!(error, KernelError::DurableAdmission(_)));
        errors.push(error.to_string());
        assert_eq!(f.broker.storage_usage(&process)?, full);
        assert_eq!(process_blob_custody(&f)?, before);
        let reservation = f.runtime.reserve(&f.f.control, &input)?;
        assert_eq!(reservation.state, ArtifactPublicationStateV1::Reserved);
        let view = serde_json::to_value(reservation)?;
        let fields = view.as_object().ok_or("public reservation view")?;
        for private in ["object", "seal", "installation_generation"] {
            assert!(!fields.contains_key(private));
        }
        assert_eq!(
            view["metadata"]["content"],
            serde_json::to_value(input.content)?
        );
    }
    assert_eq!(errors[0], errors[1]);
    assert_eq!(
        *observed.lock().map_err(|_| "publication stage observer")?,
        vec![crate::knowledge::KnowledgeCutpoint::Reserved; 2],
        "both guesses must reach the real reserved object before blob capacity refuses",
    );
    assert_eq!(raw_blob_rows(&f.f.path)?, raw_before);
    assert_eq!(f.f.process.process(process.as_str())?.tree_calls, calls);
    Ok(())
}
