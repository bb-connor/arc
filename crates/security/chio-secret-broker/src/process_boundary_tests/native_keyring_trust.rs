//! Trust control serves under witnessed keyring custody through the real CLI.
use super::*;
use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::sync::mpsc;

const SERVICE_TOKEN: &str = "keyring-trust-service-token";
const LISTENING: &str = "Chio trust control service listening";
const STARTUP_WINDOW: Duration = Duration::from_secs(120);

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
    let mut child = Command::new(binary)
        .env_clear()
        .env("RUST_LOG", "warn,chio_control_plane=info")
        .arg("--authority-seed-file")
        .arg(&keyring.seed_path)
        .arg("--receipt-db")
        .arg(keyring.config_path.with_file_name("key-receipts.sqlite3"))
        .args(["trust", "serve", "--listen", &format!("127.0.0.1:{port}")])
        .args(["--service-token", SERVICE_TOKEN])
        .args(["--authority-workload-token", "keyring-trust-workload-token"])
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

    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))?;
    write!(
        stream,
        "GET /v1/receipts/query HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {SERVICE_TOKEN}\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
    Ok(())
}
