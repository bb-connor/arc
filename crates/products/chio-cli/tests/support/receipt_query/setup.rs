pub(crate) fn setup_with_receipts(prefix: &str) -> TestSetup {
    let dir = unique_dir(prefix);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let receipt_db_path = dir.join("receipts.sqlite3");
    let revocation_db_path = dir.join("revocations.sqlite3");
    let authority_db_path = dir.join("authority.sqlite3");
    let budget_db_path = dir.join("budgets.sqlite3");

    {
        let store = SqliteReceiptStore::open(&receipt_db_path).expect("open receipt store");

        store
            .append_chio_receipt(&make_receipt(
                "r-1",
                "cap-1",
                "shell",
                "bash",
                Decision::Allow,
                1000,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-2",
                "cap-1",
                "shell",
                "bash",
                Decision::Allow,
                1001,
                None,
            ))
            .unwrap();
        store
            .append_chio_receipt(&make_receipt(
                "r-3",
                "cap-1",
                "files",
                "read",
                Decision::Allow,
                1002,
                None,
            ))
            .unwrap();

        store
            .append_chio_receipt(&make_receipt(
                "r-4",
                "cap-2",
                "shell",
                "bash",
                Decision::Allow,
                1003,
                None,
            ))
            .unwrap();

        store
            .append_chio_receipt(&make_receipt(
                "r-5",
                "cap-1",
                "shell",
                "bash",
                Decision::Deny {
                    reason: "policy".to_string(),
                    guard: "allow_guard".to_string(),
                },
                1004,
                Some(200),
            ))
            .unwrap();
    }

    let service_token = "test-secret-token".to_string();
    let client = build_test_client();
    let mut startup_error = None;
    let mut started = None;
    for _ in 0..3 {
        let listen = reserve_listen_addr();
        let mut service = spawn_trust_service(
            listen,
            &service_token,
            &receipt_db_path,
            &revocation_db_path,
            &authority_db_path,
            &budget_db_path,
        );
        let base_url = format!("http://{listen}");
        match wait_for_trust_service_result(&client, &base_url, &mut service) {
            Ok(()) => {
                started = Some((service, base_url));
                break;
            }
            Err(error) => {
                startup_error = Some(error);
                drop(service);
            }
        }
    }
    let (service, base_url) = started.unwrap_or_else(|| {
        panic!(
            "trust service did not become ready after retries: {}",
            startup_error
                .clone()
                .unwrap_or_else(|| "unknown startup failure".to_string())
        )
    });
    if let Some(error) = startup_error.take() {
        eprintln!("receipt_query startup retry recovered after: {error}");
    }

    TestSetup {
        dir,
        _receipt_db_path: receipt_db_path,
        _revocation_db_path: revocation_db_path,
        _authority_db_path: authority_db_path,
        _budget_db_path: budget_db_path,
        base_url,
        service_token,
        _service: service,
        client,
    }
}
