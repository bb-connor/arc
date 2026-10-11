//! Explicit operator policy and owned evidence maintenance.
use super::*;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Archive policy for API-protect and `chio start`. No policy is enabled by default.
#[derive(Clone, Debug)]
pub struct ProtectRetentionConfig {
    pub retention_days: u64,
    pub archive_path: PathBuf,
    pub check_interval_secs: u64,
}

impl ProtectRetentionConfig {
    pub(crate) fn validate(
        &self,
        receipt_db: Option<&str>,
    ) -> Result<chio_kernel::RetentionConfig, ProtectError> {
        let invalid = |message: &str| ProtectError::Config(format!("receipt retention: {message}"));
        let live = receipt_db
            .filter(|path| !chio_store_sqlite::is_in_memory_sqlite_path(path))
            .ok_or_else(|| invalid("requires a durable receipt store"))?;
        if self.retention_days == 0 || self.retention_days.checked_mul(86_400).is_none() {
            return Err(invalid("days must be positive and fit in seconds"));
        }
        if !(1..=86_400).contains(&self.check_interval_secs) {
            return Err(invalid(
                "check interval must be between 1 and 86400 seconds",
            ));
        }
        // Resolve the parent without creating anything. A misspelled directory
        // must fail before the listener or receipt store starts serving.
        fn resolved_destination(path: &Path) -> Result<PathBuf, std::io::Error> {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let name = path.file_name().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "archive needs a file name",
                )
            })?;
            Ok(parent.canonicalize()?.join(name))
        }
        let archive = resolved_destination(&self.archive_path)?;
        let live = resolved_destination(&chio_store_sqlite::sqlite_filesystem_path(live))?;
        if archive == live {
            return Err(invalid("archive must differ from the live database"));
        }
        match std::fs::symlink_metadata(&archive) {
            Ok(metadata) => {
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err(invalid("archive must be a regular file without symlinks"));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if metadata.nlink() != 1 {
                        return Err(invalid("archive must not have hard links"));
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let archive_path = archive
            .to_str()
            .ok_or_else(|| invalid("archive path must be UTF-8"))?
            .to_owned();
        Ok(chio_kernel::RetentionConfig {
            retention_days: self.retention_days,
            archive_path,
            check_interval_secs: self.check_interval_secs,
            max_size_bytes: u64::MAX,
            rotation_timeout: Duration::from_secs(5),
            tenant_id: None,
            explicit_cutoff_unix_secs: None,
        })
    }
}

pub(crate) fn start_maintenance(
    store: Arc<chio_store_sqlite::SqliteReceiptStore>,
    config: chio_kernel::RetentionConfig,
) -> Result<chio_kernel::receipt_store::RetentionMaintenanceHandle, ProtectError> {
    Ok(chio_kernel::receipt_store::RetentionMaintenanceHandle::spawn(store, config)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_kernel::{ReceiptQuery, ReceiptStore};
    use chio_test_support::prelude::*;

    #[test]
    fn retention_policy_rejects_ephemeral_alias_and_invalid_durations() {
        let directory = tempfile::tempdir().test_unwrap();
        let live = directory.path().join("live.db");
        let mut policy = ProtectRetentionConfig {
            retention_days: 1,
            archive_path: directory.path().join("archive.db"),
            check_interval_secs: 1,
        };
        assert!(policy
            .validate(None)
            .test_unwrap_err()
            .to_string()
            .contains("durable receipt store"));
        assert!(policy
            .validate(Some(":memory:"))
            .test_unwrap_err()
            .to_string()
            .contains("durable receipt store"));
        policy.archive_path = live.clone();
        assert!(policy
            .validate(live.to_str())
            .test_unwrap_err()
            .to_string()
            .contains("must differ"));
        policy.archive_path = directory.path().join("archive.db");
        for days in [0, u64::MAX] {
            policy.retention_days = days;
            assert!(policy
                .validate(live.to_str())
                .test_unwrap_err()
                .to_string()
                .contains("days must be positive"));
        }
        policy.retention_days = 1;
        for seconds in [0, 86401] {
            policy.check_interval_secs = seconds;
            assert!(policy
                .validate(live.to_str())
                .test_unwrap_err()
                .to_string()
                .contains("check interval"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn retention_policy_preserves_archive_metadata_io_errors() {
        let directory = tempfile::tempdir().test_unwrap();
        let policy = ProtectRetentionConfig {
            retention_days: 1,
            archive_path: directory.path().join("x".repeat(5000)),
            check_interval_secs: 1,
        };
        let error = policy
            .validate(directory.path().join("live.db").to_str())
            .test_unwrap_err();
        assert!(
            matches!(error, ProtectError::Io(_)),
            "archive inspection errors must reject before serving: {error}"
        );
    }

    #[test]
    fn scheduled_retention_rotates_and_keeps_exportable_history() {
        let directory = tempfile::tempdir().test_unwrap();
        let live = directory.path().join("live.db");
        let store = Arc::new(chio_store_sqlite::SqliteReceiptStore::open(&live).test_unwrap());
        let state = super::super::tests::test_state(Vec::new(), "http://127.0.0.1:1".into());
        let receipt = build_manual_receipt(
            &state,
            "old".into(),
            "/denied".into(),
            HttpMethod::Post,
            "caller".into(),
            None,
            Verdict::deny("policy", "test"),
            403,
            100,
            chio_core_types::sha256_hex(b"request"),
            None,
            None,
            "test",
        )
        .test_unwrap();
        let receipt = receipt
            .to_chio_receipt_with_keypair(&state.signer_keypair)
            .test_unwrap();
        store.append_chio_receipt(&receipt).test_unwrap();
        let canonical = store.receipts_canonical_bytes_range(1, 1).test_unwrap();
        let checkpoint = chio_kernel::checkpoint::build_checkpoint(
            1,
            1,
            1,
            &canonical.into_iter().map(|(_, b)| b).collect::<Vec<_>>(),
            &state.signer_keypair,
        )
        .test_unwrap();
        store.store_checkpoint(&checkpoint).test_unwrap();
        let policy = ProtectRetentionConfig {
            retention_days: 1,
            archive_path: directory.path().join("archive.db"),
            check_interval_secs: 1,
        };
        let config = policy.validate(live.to_str()).test_unwrap();
        let maintenance = start_maintenance(store.clone(), config.clone()).test_unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(6);
        while store
            .query_live_receipts(&ReceiptQuery::default().local_operator_admin())
            .test_unwrap()
            .total_count
            != 0
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(
            store
                .query_live_receipts(&ReceiptQuery::default().local_operator_admin())
                .test_unwrap()
                .total_count,
            0,
            "configured maintenance must rotate on its interval"
        );
        drop(maintenance);
        store
            .flush_receipt_writes_with_timeout(Duration::from_secs(5))
            .test_unwrap();
        let bundle = store
            .build_evidence_export_bundle(&chio_kernel::EvidenceExportQuery::admin_all())
            .test_unwrap();
        assert_eq!(bundle.tool_receipts.len(), 1);
        assert_eq!(bundle.inclusion_proofs.len(), 1);
        assert!(store.receipt_store_health().test_unwrap().healthy);
        let extra = build_manual_receipt(
            &state,
            "after-archive".into(),
            "/denied".into(),
            HttpMethod::Post,
            "caller".into(),
            None,
            Verdict::deny("policy", "test"),
            403,
            101,
            chio_core_types::sha256_hex(b"request"),
            None,
            None,
            "test",
        )
        .test_unwrap();
        store
            .append_chio_receipt(
                &extra
                    .to_chio_receipt_with_keypair(&state.signer_keypair)
                    .test_unwrap(),
            )
            .test_unwrap();
        store
            .create_next_receipt_checkpoint(1, &state.signer_keypair)
            .test_unwrap();
        // Changing the archive after committing a watermark cannot erase the
        // retained prefix. A scheduled failure must remain visible in readiness.
        let mut wrong = config;
        wrong.archive_path = directory
            .path()
            .join("wrong-archive.db")
            .to_string_lossy()
            .into_owned();
        let failed_worker = start_maintenance(store.clone(), wrong).test_unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(6);
        while store
            .receipt_store_health()
            .test_unwrap()
            .retention_error
            .is_none()
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(50));
        }
        drop(failed_worker);
        let health = store.receipt_store_health().test_unwrap();
        assert!(!health.healthy);
        assert!(
            health.retention_error.is_some(),
            "failed retention must remain observable after worker shutdown"
        );
        drop(store);
        let reopened = chio_store_sqlite::SqliteReceiptStore::open(&live).test_unwrap();
        assert_eq!(
            reopened
                .query_receipts(&ReceiptQuery::default().local_operator_admin())
                .test_unwrap()
                .total_count,
            2
        );
    }
}
