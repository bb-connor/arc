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
async fn evidence_startup_refuses_unknown_receipt_tables() -> Result<(), Box<dyn std::error::Error>>
{
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("receipts.db");
    chio_store_sqlite::initialize_receipt_approval_database(&database)?;
    let canonical = chio_store_sqlite::SqliteReceiptStore::open(&database)?;
    let raw = rusqlite::Connection::open(&database)?;
    raw.execute_batch("CREATE TABLE http_receipts (raw_json TEXT); INSERT INTO http_receipts VALUES (zeroblob(2000000));")?;
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
    let error = tokio::time::timeout(
        Duration::from_secs(10),
        ProtectProxy::new(config).run_with_observer(|_| panic!("invalid receipt catalog served")),
    )
    .await?
    .err()
    .ok_or("unknown receipt table was admitted")?;
    assert!(
        matches!(&error, ProtectError::ReceiptStore(message) if message == "schema catalog differs from its canonical definition"),
        "{error:?}"
    );
    let count: i64 = rusqlite::Connection::open(&database)?.query_row(
        "SELECT COUNT(*) FROM http_receipts WHERE length(raw_json) = 2000000",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1);
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evidence_startup_refuses_a_receipt_database_holding_revocations(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("receipts.db");
    chio_store_sqlite::initialize_receipt_approval_database(&database)?;
    drop(chio_store_sqlite::SqliteReceiptStore::open(&database)?);
    rusqlite::Connection::open(&database)?.execute_batch(
        "CREATE TABLE revoked_capabilities (capability_id TEXT PRIMARY KEY); INSERT INTO revoked_capabilities VALUES ('revoked-in-receipt-db');",
    )?;
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
    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        ProtectProxy::new(config).run_with_observer(|_| {}),
    )
    .await;
    assert!(
        matches!(&outcome, Ok(Err(ProtectError::ReceiptStore(message))) if message == "schema catalog differs from its canonical definition"),
        "{outcome:?}"
    );
    let mut revocations = database.into_os_string();
    revocations.push(".revocations");
    assert!(!std::path::Path::new(&revocations).exists());
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
    chio_store_sqlite::initialize_receipt_approval_database(&database)?;
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
    let bundle = store.build_evidence_export_bundle(
        &chio_core_types::receipt::evidence::EvidenceExportQuery::admin_all(),
    )?;
    assert_eq!(bundle.tool_receipts.len(), 1);
    assert_eq!(bundle.inclusion_proofs.len(), 1);
    task.abort();
    let _ = task.await;
    drop(store);
    let reopened = chio_store_sqlite::SqliteReceiptStore::open(&database)?;
    assert_eq!(reopened.query_receipts(&query)?.total_count, 1);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn durable_admission_refuses_external_budget_before_serving(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::budget_store::BudgetStore as _;
    let externals: [fn(&mut ProtectConfig, String); 2] = [
        |config, budget_db| config.budget_db = Some(budget_db),
        |config, _| config.control_url = Some("http://127.0.0.1:1".into()),
    ];
    for configure_external in externals {
        let directory = tempfile::tempdir()?;
        let sidecar = durable_sidecar(directory.path())?;
        let budget_db = directory.path().join("external-budget.db");
        let external = chio_store_sqlite::budget_store::SqliteBudgetStore::open(&budget_db)?;
        assert!(external.try_increment(&sidecar.capability.id, 0, Some(1))?);
        drop(external);
        let mut config = sidecar.config;
        configure_external(&mut config, budget_db.to_string_lossy().into_owned());
        let error = ProtectProxy::new(config)
            .run_with_observer(|_| panic!("sidecar served with an external budget"))
            .await
            .err()
            .ok_or("sidecar started with an external budget")?;
        assert!(
            matches!(error, ProtectError::ExternalBudgetWithDurableAdmission),
            "{error}"
        );
        assert!(!directory.path().join("receipts.db").exists());
        assert!(!directory
            .path()
            .join("receipts.db.authority-locks")
            .exists());
    }
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn durable_receipt_store_enables_mediation_without_external_budget(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let sidecar = durable_sidecar(directory.path())?;
    let (ready, address) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(
        ProtectProxy::new(sidecar.config).run_with_observer(move |address| {
            let _ = ready.send(address);
        }),
    );
    let address = tokio::time::timeout(Duration::from_secs(10), address).await??;
    let evaluate = |request_id: &'static str| {
        reqwest::Client::new()
            .post(format!("http://{address}/v1/evaluate"))
            .json(&serde_json::json!({
                "capability": sidecar.capability,
                "tool_server": "budget-srv",
                "tool_name": "charge",
                "parameters": {"invoice": request_id},
                "request_id": request_id,
            }))
            .send()
    };
    let reserved: serde_json::Value = evaluate("first").await?.json().await?;
    let exhausted: serde_json::Value = evaluate("second").await?.json().await?;
    task.abort();
    let _ = task.await;
    assert_eq!(reserved["status"], "reserved", "{reserved}");
    assert_eq!(exhausted["status"], "deny", "{exhausted}");
    Ok(())
}

#[tokio::test]
async fn payment_adapter_without_a_durable_receipt_store_refuses_startup(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let mut config = minimal_config();
    config.budget_db = Some(
        directory
            .path()
            .join("budget.db")
            .to_string_lossy()
            .into_owned(),
    );
    config.spec_content = Some(
        "openapi: 3.0.3
info:
  title: Ledger
  version: 1.0.0
paths: {}
"
        .into(),
    );
    let outcome = ProtectProxy::new(config)
        .with_payment_adapter(Some(Box::new(
            chio_kernel::payment::SimPaymentAdapter::new(),
        )))
        .run_with_observer(|_| panic!("sidecar served a payment adapter without its ledger"))
        .await;
    assert!(
        matches!(
            &outcome,
            Err(ProtectError::Config(message)) if message
                == "a payment adapter requires a durable receipt store for its settlement ledger"
        ),
        "{outcome:?}"
    );
    Ok(())
}

#[tokio::test]
async fn payment_adapter_without_any_budget_authority_refuses_startup(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = minimal_config();
    config.spec_content =
        Some("openapi: 3.0.3\ninfo:\n  title: Ledger\n  version: 1.0.0\npaths: {}\n".into());
    assert!(config.receipt_db.is_none());
    assert!(config.budget_db.is_none());
    assert!(config.control_url.is_none());
    let outcome = ProtectProxy::new(config)
        .with_payment_adapter(Some(Box::new(
            chio_kernel::payment::SimPaymentAdapter::new(),
        )))
        .run_with_observer(|_| panic!("sidecar served a payment adapter without its ledger"))
        .await;
    assert!(
        matches!(
            &outcome,
            Err(ProtectError::Config(message)) if message
                == "a payment adapter requires a durable receipt store for its settlement ledger"
        ),
        "{outcome:?}"
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn payment_adapter_installs_the_settlement_ledger_on_the_durable_receipt_store(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let sidecar = durable_sidecar(directory.path())?;
    let (ready, address) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(
        ProtectProxy::new(sidecar.config)
            .with_payment_adapter(Some(Box::new(
                chio_kernel::payment::SimPaymentAdapter::new(),
            )))
            .run_with_observer(move |address| {
                let _ = ready.send(address);
            }),
    );
    let published = tokio::time::timeout(Duration::from_secs(10), address).await;
    task.abort();
    let _ = task.await;
    assert!(matches!(published, Ok(Ok(_))), "{published:?}");
    Ok(())
}

#[cfg(unix)]
struct DurableSidecar {
    config: ProtectConfig,
    capability: CapabilityToken,
}

/// A durable sidecar and a capability its signer issued for one invocation.
#[cfg(unix)]
fn durable_sidecar(
    directory: &std::path::Path,
) -> Result<DurableSidecar, Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let signer = Keypair::generate();
    let seed = directory.join("signer.seed");
    std::fs::write(&seed, signer.seed_hex())?;
    std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600))?;
    let mut config = minimal_config();
    config.receipt_db = Some(directory.join("receipts.db").to_string_lossy().into_owned());
    config.signer_seed_file = Some(seed);
    config.sidecar_control_token = Some("durable-budget-control".into());
    config.spec_content =
        Some("openapi: 3.0.3\ninfo:\n  title: Budget\n  version: 1.0.0\npaths: {}\n".into());
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "durable-budget-capability".into(),
            issuer: signer.public_key(),
            subject: Keypair::generate().public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "budget-srv".into(),
                    tool_name: "charge".into(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: Some(1),
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            // This fixture exercises budget ownership, not token expiry. Keep
            // its lifetime valid through 2100 without an ambient clock read.
            issued_at: 1,
            expires_at: 4_102_444_800,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &signer,
    )?;
    Ok(DurableSidecar { config, capability })
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
        dpop_replay_authority: None,
        receipt_retention: None,
        signer_seed_file: None,
        signer_seed_hex: None,
        trusted_capability_issuers: Vec::new(),
        approval: None,
        control_url: None,
        control_token: None,
        control_egress_allowances: Default::default(),
        budget_db: None,
        revocation_db: None,
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
