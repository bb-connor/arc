#![cfg(test)]

use super::cluster_join_budget;
use super::{
    await_receipt_writer, await_receipt_writer_seed, open_configured_joint_authority_store,
    open_service_receipt_store, validate_finding_purchase_runtime_dependencies,
    validate_injected_joint_authority_store, ReceiptWriterStartup, SqliteAuthorityStore,
    SqliteReceiptStore, TrustServiceConfig,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[tokio::test]
async fn trust_transport_denies_public_plaintext_before_store_creation(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = chio_test_support::private_tempdir()?;
    let database = directory.path().join("must-not-exist.db");
    let mut config = test_config(database.clone());
    config.listen = "0.0.0.0:0".parse()?;
    let error = super::serve_async(config, None, None, None, None, None, None)
        .await
        .err()
        .ok_or("unsafe listener started")?;
    assert!(error.to_string().contains("non-loopback"));
    assert!(!database.exists());
    Ok(())
}

#[tokio::test]
async fn trust_transport_serves_authenticated_requests_over_tls(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = chio_test_support::private_tempdir()?;
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
    let reservation = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = reservation.local_addr()?;
    drop(reservation);
    let mut config = test_config(directory.path().join("unused.db"));
    config.joint_authority_db_path = None;
    config.revocation_db_path = Some(directory.path().join("revocations.db"));
    config.listen = address;
    config.transport = chio_http_serve::ServerTransportConfig {
        tls_cert: Some(cert),
        tls_key: Some(key),
        allow_plaintext: false,
    };
    let server = tokio::spawn(super::serve_async(
        config, None, None, None, None, None, None,
    ));
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(
            identity.cert.pem().as_bytes(),
        )?)
        .build()?;
    let response = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(response) = client
                .get(format!(
                    "https://localhost:{}{}",
                    address.port(),
                    super::REVOCATIONS_PATH
                ))
                .bearer_auth("service-token")
                .send()
                .await
            {
                break response;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    server.abort();
    let _ = server.await;
    Ok(())
}

fn test_config(joint_authority_db_path: PathBuf) -> TrustServiceConfig {
    TrustServiceConfig {
        transport: Default::default(),
        listen: "127.0.0.1:0"
            .parse()
            .unwrap_or_else(|error| panic!("fixed loopback address must parse: {error}")),
        service_token: "service-token".to_string(),
        tenant_read_tokens: BTreeMap::new(),
        authority_workload_token: None,
        receipt_db_path: None,
        receipt_query_snapshot_quota_bytes: 2_147_483_648,
        revocation_db_path: None,
        authority_seed_path: None,
        authority_db_path: None,
        authority_keyring_config_path: None,
        authority_keyring_receipt_anchor_root: None,
        budget_db_path: None,
        joint_authority_db_path: Some(joint_authority_db_path),
        fiscal_runtime: None,
        enterprise_providers_file: None,
        federation_policies_file: None,
        scim_lifecycle_file: None,
        verifier_policies_file: None,
        verifier_challenge_db_path: None,
        passport_statuses_file: None,
        passport_issuance_offers_file: None,
        certification_registry_file: None,
        certification_discovery_file: None,
        issuance_policy: None,
        runtime_assurance_policy: None,
        advertise_url: None,
        allow_local_peer_urls: true,
        certification_public_metadata_ttl_seconds: 300,
        peer_urls: Vec::new(),
        cluster_sync_interval: Duration::from_millis(25),
        authority_replication_max_future_skew_seconds: 0,
        roster_policy: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        finding_market: None,
    }
}

#[cfg(unix)]
fn secure_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// The cluster-loop join must not add a second wait on top of the HTTP drain:
/// for every point at which the drain could return, the drain time already
/// spent plus the join budget it hands out stays within one drain window, so
/// the whole teardown fits the platform stop grace rather than overrunning it
/// and being escalated to a kill.
#[test]
fn cluster_join_never_extends_teardown_past_the_drain_window() {
    let drain = Duration::from_secs(25);
    // A drain that ran to its deadline leaves no budget at all.
    assert_eq!(cluster_join_budget(drain, drain), Duration::ZERO);
    for elapsed_ms in [0u64, 1_000, 12_500, 24_000, 25_000] {
        let elapsed = Duration::from_millis(elapsed_ms).min(drain);
        assert!(
            elapsed + cluster_join_budget(drain, elapsed) <= drain,
            "teardown at elapsed={elapsed:?} must stay within the drain window"
        );
    }
}

#[test]
fn purchase_runtime_requires_rail_and_authority_status_resolution() {
    assert!(validate_finding_purchase_runtime_dependencies(false, false, false).is_ok());
    assert!(validate_finding_purchase_runtime_dependencies(true, true, true).is_ok());

    let Err(missing_rail) = validate_finding_purchase_runtime_dependencies(true, false, true)
    else {
        panic!("purchase runtime without a rail must fail closed");
    };
    assert!(missing_rail.to_string().contains("settlement rail"));

    let Err(missing_status) = validate_finding_purchase_runtime_dependencies(true, true, false)
    else {
        panic!("purchase runtime without status resolution must fail closed");
    };
    assert!(missing_status
        .to_string()
        .contains("authority-status resolver"));
}

#[cfg(unix)]
#[test]
fn injected_challenge_authority_must_match_configured_database(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = chio_test_support::private_tempdir()?;
    secure_directory(temp.path())?;
    let configured_database = temp.path().join("configured.db");
    let configured_locks = temp.path().join("configured-locks");
    let injected_database = temp.path().join("injected.db");
    let injected_locks = temp.path().join("injected-locks");
    std::fs::create_dir(&configured_locks)?;
    secure_directory(&configured_locks)?;
    std::fs::create_dir(&injected_locks)?;
    secure_directory(&injected_locks)?;
    SqliteAuthorityStore::provision(&configured_database, &configured_locks)?;
    SqliteAuthorityStore::provision(&injected_database, &injected_locks)?;
    let injected = SqliteAuthorityStore::open_serving(&injected_database, &injected_locks)?;

    let matching = test_config(injected_database);
    validate_injected_joint_authority_store(&matching, &injected)?;

    let mismatched = test_config(configured_database);
    let error = match validate_injected_joint_authority_store(&mismatched, &injected) {
        Ok(()) => panic!("a different configured authority database must fail closed"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("does not match"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn configured_joint_authority_hardens_an_existing_lock_root(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    let temp = chio_test_support::private_tempdir()?;
    secure_directory(temp.path())?;
    let database = temp.path().join("joint-authority.db");
    let lock_root = crate::durable_admission_lock_root(&database)?;
    std::fs::create_dir(&lock_root)?;
    std::fs::set_permissions(&lock_root, std::fs::Permissions::from_mode(0o775))?;

    let store = open_configured_joint_authority_store(&test_config(database))?
        .ok_or("configured authority store was not opened")?;
    assert_eq!(
        std::fs::metadata(&lock_root)?.permissions().mode() & 0o077,
        0,
        "startup must remove group and other access before provisioning"
    );
    drop(store);
    Ok(())
}

fn signed_receipt(
    keypair: &chio_core::crypto::Keypair,
    index: usize,
) -> Result<chio_core::receipt::body::ChioReceipt, Box<dyn std::error::Error>> {
    use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
    use chio_core::receipt::decision::{Decision, ToolCallAction};
    Ok(ChioReceipt::sign(
        ChioReceiptBody {
            id: format!("startup-receipt-{index}"),
            timestamp: 100,
            capability_id: "startup-capability".to_string(),
            tool_server: "startup-server".to_string(),
            tool_name: "startup-tool".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({ "index": index }))?,
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: format!("content-{index}"),
            policy_hash: "startup-policy".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        keypair,
    )?)
}

/// Persist `receipts` signed receipts under checkpoints of ten.
fn checkpointed_history(path: &Path, receipts: usize) -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::ReceiptStore;
    let keypair = std::sync::Arc::new(chio_core::crypto::Keypair::generate());
    let store = SqliteReceiptStore::open(path)?;
    store.enable_background_checkpoints(chio_store_sqlite::BackgroundCheckpointSigner {
        keypair: std::sync::Arc::clone(&keypair),
        max_batch: 10,
    })?;
    for index in 0..receipts {
        store.append_chio_receipt(&signed_receipt(&keypair, index)?)?;
    }
    store.flush_receipt_writes()?;
    Ok(())
}

#[test]
fn startup_refuses_a_receipt_history_that_fails_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = chio_test_support::private_tempdir()?;
    let database = temp.path().join("receipts.sqlite3");
    checkpointed_history(&database, 20)?;
    let tamper = rusqlite::Connection::open(&database)?;
    let triggers = tamper
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'trigger' AND tbl_name = 'checkpoint_tree_heads'",
        )?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    for trigger in triggers {
        tamper.execute_batch(&format!("DROP TRIGGER \"{trigger}\""))?;
    }
    // The interior checkpoint's tree-head projection no longer mirrors its
    // signed row.
    assert_eq!(
        tamper.execute(
            "UPDATE checkpoint_tree_heads SET issued_at = issued_at + 1 WHERE checkpoint_seq = 1",
            [],
        )?,
        1
    );
    drop(tamper);

    let error = match open_service_receipt_store(Some(&database)) {
        Ok(_) => panic!("a receipt history that fails verification must refuse startup"),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains("trust-control receipt store")
            && error.contains("tree head projection for checkpoint 1 diverges"),
        "{error}"
    );
    Ok(())
}

#[test]
fn startup_serves_while_its_one_writer_still_verifies_a_healthy_history(
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(open_service_receipt_store(None)?.is_none());
    let temp = chio_test_support::private_tempdir()?;
    let database = temp.path().join("receipts.sqlite3");
    checkpointed_history(&database, 200)?;

    // A writer probed before its seed finishes is never a startup failure; the
    // store crate holds a seed to prove the Seeding state deterministically.
    let store = SqliteReceiptStore::open(&database)?;
    assert!(matches!(
        await_receipt_writer(&store, Duration::ZERO)?,
        ReceiptWriterStartup::Seeding | ReceiptWriterStartup::Ready
    ));
    // The same writer finishes its seed; nothing reopened or reseeded it, and
    // polling far more often than the seed takes is never a cutoff.
    await_receipt_writer_seed(&store, Duration::from_millis(1))?;
    assert_eq!(
        await_receipt_writer(&store, Duration::from_secs(30))?,
        ReceiptWriterStartup::Ready
    );

    let shared = open_service_receipt_store(Some(&database))?.ok_or("store was not opened")?;
    assert!(shared.writer_joins_on_reaper());
    Ok(())
}
