use super::*;
use chio_cage::{
    render_tool_confinement, ConfinementBackendKind, ConfinementDisclosure,
    NATIVE_LAUNCH_METADATA_KEY,
};
use chio_core::receipt::body::ChioReceipt;

fn launch_receipt(database: &Path, receipt_id: &str) -> ChioReceipt {
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open cage receipt store");
    let raw: String = connection
        .query_row(
            "SELECT raw_json FROM chio_tool_receipts WHERE receipt_id = ?1",
            [receipt_id],
            |row| row.get(0),
        )
        .expect("persisted cage launch receipt");
    serde_json::from_str(&raw).expect("decode cage launch receipt")
}

#[test]
fn mcp_serve_http_adapted_server_call_binds_its_verified_cage_launch() {
    skip_when_loopback_denied!(mcp_serve_http_adapted_server_call_binds_its_verified_cage_launch);
    let dir = unique_test_dir();
    fs::create_dir_all(&dir).expect("create temp dir");
    let listen = reserve_listen_addr();
    let token = "test-token";
    let _server = spawn_http_server(&dir, listen, token);
    let client = Client::builder()
        .timeout(HTTP_CLIENT_TIMEOUT)
        .build()
        .expect("build reqwest client");
    let base_url = format!("http://{listen}");
    wait_for_server(&client, &base_url);

    let (session_id, protocol_version) = initialize_session(&client, &base_url, token);
    let response = post_json(
        &client,
        &base_url,
        token,
        Some(&session_id),
        Some(&protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tools/call",
            "params": {"name": "echo_json", "arguments": {"message": "confined"}}
        }),
    );
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let (result, _) = read_sse_until_response(response, json!(30), |_| {});
    assert_eq!(result["result"]["isError"], false);

    let receipts: Value = get_admin_tool_receipts(
        &client,
        &base_url,
        EDGE_ADMIN_TOKEN,
        &[("tool_name", "echo_json"), ("limit", "10")],
    )
    .json()
    .expect("tool receipts json");
    let [tool] = receipts["receipts"]
        .as_array()
        .expect("tool receipts array")
        .as_slice()
    else {
        panic!("expected one echo_json receipt: {receipts}");
    };
    let tool: ChioReceipt = serde_json::from_value(tool.clone()).expect("decode tool receipt");
    let reference =
        &tool.metadata.as_ref().expect("tool receipt metadata")[NATIVE_LAUNCH_METADATA_KEY];
    let receipt_id = reference["receipt_id"]
        .as_str()
        .expect("native_launch receipt id");

    let security = http_security_material(&dir, &dir.join("mock_http_mcp_server.py"), None, None);
    let policy: Value = serde_json::from_slice(
        &fs::read(&security.cage_policy_path).expect("read signed cage launch policy"),
    )
    .expect("decode signed cage launch policy");
    let receipt_policy = &policy["body"]["receipt"];
    let launch = launch_receipt(
        Path::new(
            receipt_policy["database_path"]
                .as_str()
                .expect("cage receipt database path"),
        ),
        receipt_id,
    );
    let launch_signer = chio_core::PublicKey::from_hex(
        receipt_policy["trusted_signer_public_key"]
            .as_str()
            .expect("trusted cage receipt signer"),
    )
    .expect("decode trusted cage receipt signer");
    let admission =
        chio_control_plane::durable_admission_sidecar_path(&default_session_db_path(&dir, listen))
            .expect("durable admission database path");
    let mut kernel_seed = admission.into_os_string();
    kernel_seed.push(".kernel.seed");
    let kernel = chio_control_plane::load_existing_authority_keypair(Path::new(&kernel_seed))
        .expect("load the receipt-signing kernel key")
        .public_key();

    assert_eq!(tool.kernel_key, kernel, "tool receipt signer");
    assert!(tool
        .verify_integrity_embedded_key()
        .expect("verify tool receipt"));
    let launch_bytes = chio_core::canonical_json_bytes(&launch).expect("canonical launch receipt");
    assert_eq!(
        reference["receipt_sha256"],
        json!(chio_core::sha256_hex(&launch_bytes))
    );
    assert_eq!(launch.tool_server, tool.tool_server);
    assert_eq!(launch.kernel_key, launch_signer, "launch receipt signer");
    assert_eq!(
        render_tool_confinement(&tool, Some(&launch), &kernel, &launch_signer),
        ConfinementDisclosure::Confined(ConfinementBackendKind::LinuxCage)
    );
    assert_eq!(
        render_tool_confinement(&tool, None, &kernel, &launch_signer),
        ConfinementDisclosure::Unconfined(tool.tool_origin.into())
    );
    assert_eq!(
        render_tool_confinement(&tool, Some(&launch), &kernel, &kernel),
        ConfinementDisclosure::Unconfined(tool.tool_origin.into())
    );
}
