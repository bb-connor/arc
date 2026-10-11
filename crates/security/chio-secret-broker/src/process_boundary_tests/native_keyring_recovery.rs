//! Restart through the production loader after selector activation and failed receipt delivery.
use super::*;
use chio_core_types::receipt::body::ChioReceipt;
use chio_core_types::receipt::lineage::ChildRequestReceipt;
use chio_kernel::{ReceiptStore, ReceiptStoreError};

pub(super) struct ReceiptFailure {
    pub inner: Arc<SqliteReceiptStore>,
    pub fail_active: AtomicBool,
}
impl ReceiptStore for ReceiptFailure {
    fn durable_sink_id(&self) -> Option<&str> {
        self.inner.durable_sink_id()
    }
    fn supports_native_security_receipts(&self) -> bool {
        self.inner.supports_native_security_receipts()
    }
    fn append_chio_receipt(
        &self,
        receipt: &ChioReceipt,
    ) -> std::result::Result<(), ReceiptStoreError> {
        if self.fail_active.load(Ordering::SeqCst)
            && receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.pointer("/keyEnterpriseReceipt/body/stage"))
                .and_then(serde_json::Value::as_str)
                == Some("active")
        {
            return Err(ReceiptStoreError::Unsupported(
                "injected active receipt outage".into(),
            ));
        }
        self.inner.append_chio_receipt(receipt)
    }
    fn append_child_receipt(
        &self,
        receipt: &ChildRequestReceipt,
    ) -> std::result::Result<(), ReceiptStoreError> {
        self.inner.append_child_receipt(receipt)
    }
    fn load_chio_receipt(
        &self,
        id: &str,
    ) -> std::result::Result<Option<ChioReceipt>, ReceiptStoreError> {
        self.inner.load_chio_receipt(id)
    }
}

fn failure<T>(result: std::result::Result<T, chio_control_plane::CliError>) -> TestResult<String> {
    match result {
        Ok(_) => Err("incomplete rotation reported success".into()),
        Err(error) => Ok(error.to_string()),
    }
}

pub(super) fn interrupt_and_resume(
    runtime: chio_control_plane::KeyringRuntimeComposition,
    services: &mut KeyServices,
    directory: &Path,
    config: &Path,
    seed: &Path,
    receipts: Arc<ReceiptFailure>,
) -> TestResult<chio_control_plane::KeyringRuntimeComposition> {
    let original_seed = fs::read(seed)?;
    let error = failure(runtime.rotate_remote_authority_seed(seed))?;
    assert!(error.contains("injected active receipt outage"), "{error}");
    let status = runtime.authority_status()?;
    assert_eq!(status.signing_epoch, 1);
    let head = status.operator_head;
    assert_eq!(fs::read(seed)?, original_seed);
    let mut pending_name = seed.as_os_str().to_os_string();
    pending_name.push(".chio-keyring-pending");
    let pending = PathBuf::from(pending_name);
    let handoff = fs::read(&pending)?;
    let error = failure(runtime.startup_readiness())?;
    assert!(error.contains("injected active receipt outage"), "{error}");
    services.stop_auditor(0);
    let error = failure(runtime.startup_readiness())?;
    assert!(
        !error.contains("injected active receipt outage"),
        "auditor loss must deny before forwarding: {error}"
    );
    drop(runtime);
    let _error = failure(
        chio_control_plane::load_keyring_runtime_from_authority_seed(
            config,
            seed,
            receipts.clone(),
        ),
    )?;
    assert_eq!(fs::read(seed)?, original_seed);
    assert_eq!(fs::read(&pending)?, handoff);
    services.restart_auditor(directory, 0)?;
    // The autonomous auditor has a real startup interval. Poll a signed readiness
    // predicate; this is service readiness, not race synchronization.
    let started = Instant::now();
    loop {
        let error = failure(
            chio_control_plane::load_keyring_runtime_from_authority_seed(
                config,
                seed,
                receipts.clone(),
            ),
        )?;
        if error.contains("injected active receipt outage") {
            break;
        }
        if started.elapsed() >= Duration::from_secs(10) {
            return Err(error.into());
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(fs::read(seed)?, original_seed);
    assert_eq!(fs::read(&pending)?, handoff);
    receipts.fail_active.store(false, Ordering::SeqCst);
    let (key, recovered) = chio_control_plane::load_keyring_runtime_from_authority_seed(
        config,
        seed,
        receipts.clone(),
    )?;
    assert_eq!(recovered.authority_status()?.operator_head, head);
    assert_eq!(recovered.authority_status()?.signing_epoch, 1);
    assert_eq!(key.public_key(), status.public_key);
    assert!(!pending.try_exists()?);
    recovered.startup_readiness()?;
    let receipt_count = receipts.inner.tool_receipt_count()?;
    drop(recovered);
    let (again, reopened) = chio_control_plane::load_keyring_runtime_from_authority_seed(
        config,
        seed,
        receipts.clone(),
    )?;
    assert_eq!(receipts.inner.tool_receipt_count()?, receipt_count);
    assert_eq!(again.public_key(), key.public_key());
    assert_eq!(reopened.authority_status()?.operator_head, head);
    Ok(reopened)
}

#[test]
fn confined_broker_public_keyring_startup_recovers_exact_activation_after_auditor_and_receipt_loss(
) -> TestResult {
    let directory = crate::private_tempdir()?;
    let caller = Keypair::from_seed(&[217; 32]);
    let _delivery =
        KeyringDelivery::new_with_interruption(directory.path(), &caller.public_key(), true)?;
    Ok(())
}
