#![cfg(test)]

use super::*;
use chio_test_support::prelude::*;

#[tokio::test]
async fn protect_transport_denies_public_plaintext_before_spec_or_store_work(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("must-not-exist.db");
    let mut config = minimal_config();
    config.listen_addr = "0.0.0.0:0".into();
    config.receipt_db = Some(database.to_string_lossy().into_owned());
    config.spec_path = Some("missing-spec.yaml".into());
    config.spec_content = None;
    let result = ProtectProxy::new(config)
        .run_with_observer(|_| panic!("unsafe listener published"))
        .await;
    assert!(result
        .err()
        .ok_or("unsafe listener started")?
        .to_string()
        .contains("non-loopback"));
    assert!(!database.exists());
    Ok(())
}

#[tokio::test]
async fn protect_transport_serves_over_tls() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert = directory.path().join("cert.pem");
    let key = directory.path().join("key.pem");
    std::fs::write(&cert, identity.cert.pem())?;
    std::fs::write(&key, identity.key_pair.serialize_pem())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
    }
    let mut config = minimal_config();
    config.spec_content =
        Some("openapi: 3.1.0\ninfo: {title: TLS, version: '1'}\npaths: {}\n".into());
    config.transport = chio_http_serve::ServerTransportConfig {
        tls_cert: Some(cert),
        tls_key: Some(key),
        allow_plaintext: false,
    };
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(ProtectProxy::new(config).run_with_observer(|address| {
        let _ = sender.send(address);
    }));
    let address = tokio::time::timeout(std::time::Duration::from_secs(5), receiver).await??;
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(
            identity.cert.pem().as_bytes(),
        )?)
        .build()?;
    let response = client
        .get(format!("https://localhost:{}/chio/live", address.port()))
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test]
async fn evidence_durable_start_refuses_missing_custody_before_spec_or_store() {
    let directory = tempfile::tempdir().test_unwrap();
    let path = directory.path().join("must-not-exist.db");
    let mut config = minimal_config();
    config.receipt_db = Some(path.to_string_lossy().into_owned());
    config.spec_content = None;
    config.spec_path = Some("missing-spec.yaml".into());
    let error = ProtectProxy::new(config).run().await.test_unwrap_err();
    assert!(
        error.to_string().contains("private signing custody"),
        "{error}"
    );
    assert!(!path.exists());
}

#[cfg(unix)]
#[test]
fn evidence_custody_is_existing_private_and_stable() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().test_unwrap();
    let path = directory.path().join("signer.seed");
    let mut config = minimal_config();
    config.signer_seed_file = Some(path.clone());
    assert!(super::super::evidence::load_signer(&config, true).is_err());
    assert!(!path.exists());
    let key = Keypair::generate();
    std::fs::write(&path, key.seed_hex()).test_unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).test_unwrap();
    let first = super::super::evidence::load_signer(&config, true).test_unwrap();
    let second = super::super::evidence::load_signer(&config, true).test_unwrap();
    assert_eq!(first.public_key(), key.public_key());
    assert_eq!(second.public_key(), key.public_key());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).test_unwrap();
    assert!(super::super::evidence::load_signer(&config, true).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).test_unwrap();
    let link = directory.path().join("alias.seed");
    std::os::unix::fs::symlink(&path, &link).test_unwrap();
    config.signer_seed_file = Some(link);
    assert!(super::super::evidence::load_signer(&config, true).is_err());
    config.signer_seed_file = Some(path.clone());
    std::fs::hard_link(&path, directory.path().join("hard.seed")).test_unwrap();
    assert!(super::super::evidence::load_signer(&config, true).is_err());
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evidence_startup_ignores_oversized_legacy_receipts_and_preserves_revocations(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("receipts.db");
    let canonical = chio_store_sqlite::SqliteReceiptStore::open(&database)?;
    let raw = rusqlite::Connection::open(&database)?;
    raw.execute_batch("CREATE TABLE http_receipts (raw_json TEXT); INSERT INTO http_receipts VALUES (zeroblob(2000000)); CREATE TABLE revoked_capabilities (capability_id TEXT PRIMARY KEY); INSERT INTO revoked_capabilities VALUES ('legacy-revoked');")?;
    assert_eq!(
        canonical.legacy_revoked_capability_ids()?,
        vec!["legacy-revoked"]
    );
    drop(raw);
    drop(canonical);
    let key = Keypair::generate();
    let seed = directory.path().join("signer.seed");
    std::fs::write(&seed, key.seed_hex())?;
    std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600))?;
    let mut config = minimal_config();
    config.receipt_db = Some(database.to_string_lossy().into_owned());
    config.signer_seed_file = Some(seed);
    config.sidecar_control_token = Some("evidence-test-control".into());
    config.spec_content =
        Some("openapi: 3.0.3\ninfo:\n  title: Evidence\n  version: 1.0.0\npaths: {}\n".into());
    let (ready, address) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(ProtectProxy::new(config).run_with_observer(move |address| {
        let _ = ready.send(address);
    }));
    let address = tokio::time::timeout(Duration::from_secs(10), address).await??;
    let response = reqwest::Client::new().post(format!("http://{address}/v1/receipts"))
            .bearer_auth("evidence-test-control")
            .json(&serde_json::json!({"job_name":"legacy-restart", "namespace":"operator", "job_uid":"one", "outcome":"succeeded", "steps":[]}))
            .send().await?;
    assert_eq!(response.status(), StatusCode::OK);
    task.abort();
    let _ = task.await;
    let reopened = chio_store_sqlite::SqliteReceiptStore::open(&database)?;
    let receipts =
        reopened.query_receipts(&chio_kernel::ReceiptQuery::default().local_operator_admin())?;
    assert_eq!(receipts.total_count, 1);
    assert_eq!(receipts.receipts[0].receipt.kernel_key, key.public_key());
    assert_eq!(
        reopened.legacy_revoked_capability_ids()?,
        vec!["legacy-revoked"]
    );
    let error = reopened
        .build_evidence_export_bundle(&chio_kernel::EvidenceExportQuery::admin_all())
        .test_unwrap_err();
    assert!(error.to_string().contains("legacy mutable receipt history"));
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receipt_retention_runs_from_the_actual_proxy_serving_lifetime(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("receipts.db");
    let archive = directory.path().join("archive.db");
    let fixture = super::super::tests::test_state(Vec::new(), "http://127.0.0.1:1".into());
    let receipt = build_manual_receipt(
        &fixture,
        "aged".into(),
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
    )?;
    let store = chio_store_sqlite::SqliteReceiptStore::open(&database)?;
    store.append_chio_receipt_returning_seq(
        &receipt.to_chio_receipt_with_keypair(&fixture.signer_keypair)?,
    )?;
    let bytes = store.receipts_canonical_bytes_range(1, 1)?;
    let checkpoint = chio_kernel::checkpoint::build_checkpoint(
        1,
        1,
        1,
        &bytes.into_iter().map(|(_, b)| b).collect::<Vec<_>>(),
        &fixture.signer_keypair,
    )?;
    store.store_checkpoint(&checkpoint)?;
    let seed = directory.path().join("signer.seed");
    std::fs::write(&seed, fixture.signer_keypair.seed_hex())?;
    std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600))?;
    let mut config = minimal_config();
    config.receipt_db = Some(database.to_string_lossy().into_owned());
    config.signer_seed_file = Some(seed);
    config.receipt_retention = Some(super::super::ProtectRetentionConfig {
        retention_days: 1,
        archive_path: archive.clone(),
        check_interval_secs: 1,
    });
    config.spec_content =
        Some("openapi: 3.0.3\ninfo:\n  title: Evidence\n  version: 1.0.0\npaths: {}\n".into());
    let (ready, address) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(ProtectProxy::new(config).run_with_observer(move |address| {
        let _ = ready.send(address);
    }));
    let _address = tokio::time::timeout(Duration::from_secs(10), address).await??;
    let query = chio_kernel::ReceiptQuery::default().local_operator_admin();
    tokio::time::timeout(Duration::from_secs(8), async {
        while store.query_live_receipts(&query)?.total_count != 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok::<_, chio_kernel::ReceiptStoreError>(())
    })
    .await??;
    assert!(archive.is_file());
    let bundle =
        store.build_evidence_export_bundle(&chio_kernel::EvidenceExportQuery::admin_all())?;
    assert_eq!(bundle.tool_receipts.len(), 1);
    assert_eq!(bundle.inclusion_proofs.len(), 1);
    task.abort();
    let _ = task.await;
    drop(store);
    let reopened = chio_store_sqlite::SqliteReceiptStore::open(&database)?;
    assert_eq!(reopened.query_receipts(&query)?.total_count, 1);
    Ok(())
}

fn minimal_config() -> ProtectConfig {
    ProtectConfig {
        transport: Default::default(),
        upstream: "http://127.0.0.1:1".to_string(),
        spec_content: Some("{}".to_string()),
        spec_sha256: None,
        allow_anonymous_reads: false,
        spec_path: None,
        listen_addr: "127.0.0.1:0".to_string(),
        receipt_db: None,
        allow_ephemeral_receipts: true,
        sidecar_control_token: None,
        receipt_retention: None,
        signer_seed_file: None,
        signer_seed_hex: None,
        trusted_capability_issuers: Vec::new(),
        approval: None,
        control_url: None,
        control_token: None,
        budget_db: None,
        revocation_db: None,
        require_nonce: false,
        allow_advisory: false,
        upstream_request_timeout: crate::DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
    }
}

#[test]
fn with_payment_adapter_threads_adapter_and_defaults_none() {
    // The sidecar CLI threads the operator's resolved payment adapter here so
    // the proxy installs it on the mediation kernel and governed MustPrepay
    // can be prepaid. Absent the builder call the adapter defaults to `None`,
    // which keeps governed MustPrepay denied fail-closed.
    let default = ProtectProxy::new(minimal_config());
    assert!(
        default.payment_adapter.is_none(),
        "a proxy defaults to no payment adapter, keeping governed MustPrepay denied"
    );

    let configured = ProtectProxy::new(minimal_config()).with_payment_adapter(Some(Box::new(
        chio_kernel::payment::SimPaymentAdapter::new(),
    )));
    assert!(
        configured.payment_adapter.is_some(),
        "with_payment_adapter must thread the configured adapter into the proxy"
    );
}

#[test]
fn threshold_approval_context_requires_explicit_trusted_source() {
    let default = ProtectProxy::new(minimal_config());
    assert!(default.threshold_approval_context_resolver.is_none());

    let resolver: Arc<dyn ThresholdApprovalContextResolver> = Arc::new(|_: &str, _: u64| {
        Err(chio_kernel::approval::ApprovalStoreError::Backend(
            "authority unavailable".into(),
        ))
    });
    let configured = ProtectProxy::new(minimal_config())
        .with_threshold_approval_context_resolver(resolver.clone());
    assert!(configured
        .threshold_approval_context_resolver
        .as_ref()
        .is_some_and(|configured| Arc::ptr_eq(configured, &resolver)));
}
