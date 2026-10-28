//! Trust control serves under witnessed keyring custody through the real CLI.
use super::*;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc;

const SERVICE_TOKEN: &str = "keyring-trust-service-token";
const LISTENING: &str = "Chio trust control service listening";
const SNAPSHOT_BUILDING: &str = "receipt_query_snapshot_building";
const STARTUP_WINDOW: Duration = Duration::from_secs(120);
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[test]
fn keyring_trust_service_starts_and_serves_admin_receipt_reads() -> TestResult {
    // The owning release runner builds chio beside the original witness binary.
    let binary = fs::canonicalize(
        PathBuf::from(required_environment("CHIO_KEYLOG_WITNESS")).with_file_name("chio"),
    )?;
    let directory = crate::private_tempdir()?;
    let root = fs::canonicalize(directory.path())?;
    let keyring = KeyringDelivery::new(&root, &Keypair::from_seed(&[227; 32]).public_key())?
        .into_process_host();
    let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?
        .local_addr()?
        .port();
    let access_config = root.join("trust-access.toml");
    fs::write(&access_config, access_config_text())?;
    let mut child = Command::new(binary)
        .env_clear()
        .env("RUST_LOG", "warn,chio_control_plane=info")
        .arg("--authority-seed-file")
        .arg(&keyring.seed_path)
        .arg("--receipt-db")
        .arg(keyring.config_path.with_file_name("key-receipts.sqlite3"))
        .args(["trust", "serve", "--listen", &format!("127.0.0.1:{port}")])
        .arg("--access-config")
        .arg(&access_config)
        .arg("--authority-keyring-config")
        .arg(&keyring.config_path)
        .arg("--authority-keyring-receipt-anchor-root")
        .arg(keyring.receipt_anchors.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let stderr = child.stderr.take().ok_or("trust service stderr")?;
    let _service = ManagedChild::new(child);
    let (lines, events) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stderr)
            .lines()
            .map_while(std::io::Result::ok)
        {
            if lines.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + STARTUP_WINDOW;
    let mut log = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match events.recv_timeout(remaining) {
            Ok(line) if line.contains(LISTENING) => break,
            Ok(line) => log.push(line),
            Err(_) => {
                return Err(format!("trust service did not start:\n{}", log.join("\n")).into())
            }
        }
    }

    // Listening precedes the first published receipt snapshot. Only its typed
    // building refusal is retried, at the server's Retry-After pace.
    loop {
        let response = admin_receipt_query(port, deadline)?;
        if response.starts_with("HTTP/1.1 200 ") {
            return Ok(());
        }
        let pause = building_retry_after(&response)
            .ok_or_else(|| format!("admin receipt query refused:\n{response}"))?;
        if Instant::now() + pause >= deadline {
            return Err(format!("receipt snapshot still building:\n{response}").into());
        }
        thread::sleep(pause);
    }
}

fn admin_receipt_query(port: u16, deadline: Instant) -> TestResult<String> {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&address, remaining(deadline)?)?;
    let request = format!(
        "GET /v1/receipts/query HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {SERVICE_TOKEN}\r\nConnection: close\r\n\r\n"
    );
    stream.set_write_timeout(Some(remaining(deadline)?))?;
    stream.write_all(request.as_bytes())?;
    let mut response = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        if response.len() + read > MAX_RESPONSE_BYTES {
            return Err(
                format!("admin receipt response exceeds {MAX_RESPONSE_BYTES} bytes").into(),
            );
        }
        response.extend_from_slice(&chunk[..read]);
    }
    // A response completed after the deadline is not accepted.
    remaining(deadline)?;
    Ok(String::from_utf8(response)?)
}

fn remaining(deadline: Instant) -> TestResult<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| "admin receipt query deadline elapsed".into())
}

fn building_retry_after(response: &str) -> Option<Duration> {
    let (head, body) = response.split_once("\r\n\r\n")?;
    let mut lines = head.lines();
    if !lines.next()?.starts_with("HTTP/1.1 503 ") {
        return None;
    }
    let refusal: serde_json::Value = serde_json::from_str(body).ok()?;
    if refusal["code"] != SNAPSHOT_BUILDING {
        return None;
    }
    lines.find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.eq_ignore_ascii_case("retry-after") {
            return None;
        }
        value.trim().parse().ok().map(Duration::from_secs)
    })
}

/// One deployment credential for `SERVICE_TOKEN` holding every caller scope,
/// which includes the capability issuance a keyring authority requires.
fn access_config_text() -> String {
    let scopes = chio_control_plane::trust_control::caller_credentials::Scope::ALL
        .iter()
        .filter(|scope| !scope.is_cluster())
        .map(|scope| format!("\"{}\"", scope.as_str()))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "deployment = \"keyring-trust\"\ninternal_listen = \"127.0.0.1:0\"\n[[credentials]]\nid = \"keyring-trust-client\"\nkind = \"deployment\"\nsecret_sha256 = \"{}\"\nscopes = [{scopes}]\ndeployment = \"keyring-trust\"\ntenant_authority = \"deployment\"\n",
        chio_core_types::crypto::sha256_hex(SERVICE_TOKEN.as_bytes())
    )
}
