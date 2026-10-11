//! A configured authority database is provisioned when the service starts, and
//! unauthenticated routes then serve it without committing an authority write.

use super::{spawn_portable_oid4vp_trust_service_with_authority_db, wait_for_trust_service};
use chio_test_support::ctx::TestUnwrap;
use chio_test_support::loopback::{reserve_listen_addr, skip_when_loopback_bind_denied};
use reqwest::blocking::Client;
use rusqlite::{Connection, OpenFlags};

#[test]
fn trust_serve_provisions_its_authority_database_so_public_reads_never_write() {
    if skip_when_loopback_bind_denied(
        "trust_serve_provisions_its_authority_database_so_public_reads_never_write",
    ) {
        return;
    }
    let temporary = chio_test_support::private_tempdir().test_unwrap("private authority fixture");
    let authority_db_path = temporary.path().join("authority.sqlite3");
    let listen = reserve_listen_addr();
    let base_url = format!("http://{listen}");
    let service_token = "authority-startup-service-token";
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .test_unwrap("http client");
    assert!(!authority_db_path.exists());
    let mut service = spawn_portable_oid4vp_trust_service_with_authority_db(
        listen,
        service_token,
        &base_url,
        &authority_db_path,
        &temporary.path().join("issuance.json"),
        &temporary.path().join("verifier.sqlite3"),
        &temporary.path().join("statuses.json"),
    );
    wait_for_trust_service(&client, &base_url, &mut service);
    assert!(
        authority_db_path.exists(),
        "startup provisions the configured authority database"
    );

    let witness = Connection::open_with_flags(&authority_db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .test_unwrap("authority witness");
    let data_version = |witness: &Connection| -> i64 {
        witness
            .query_row("PRAGMA data_version", [], |row| row.get(0))
            .test_unwrap("authority data version")
    };
    let observed_ms = |witness: &Connection| -> i64 {
        witness
            .query_row(
                "SELECT observed_ms FROM authority_state WHERE singleton_id = 1",
                [],
                |row| row.get(0),
            )
            .test_unwrap("authority clock floor")
    };
    let version = data_version(&witness);
    let floor = observed_ms(&witness);
    for path in [
        "/.well-known/openid-credential-issuer",
        "/.well-known/jwks.json",
        "/.well-known/chio-oid4vp-verifier",
        "/v1/public/passport/discovery/transparency",
        "/health",
    ] {
        let response = client
            .get(format!("{base_url}{path}"))
            .send()
            .test_unwrap("public read");
        assert_eq!(response.status(), reqwest::StatusCode::OK, "{path}");
        if path == "/health" {
            let health: serde_json::Value = response.json().test_unwrap("health body");
            assert_eq!(health["authority"]["available"], true);
            assert_eq!(health["authority"]["backend"], "sqlite");
        }
        assert_eq!(
            data_version(&witness),
            version,
            "{path} wrote the authority"
        );
        assert_eq!(observed_ms(&witness), floor, "{path} moved the clock floor");
    }
}
