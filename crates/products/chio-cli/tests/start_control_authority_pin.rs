//! `chio start` is the sidecar convenience alias for `chio api protect`, so the
//! global `--control-authority-public-key` pin must make the sidecar trust the
//! capabilities that authority issues.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use chio_core::capability::scope::ChioScope;
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::{Keypair, PublicKey};

const CONTROL_TOKEN: &str = "start-pin-control-token";
const NOT_TRUSTED: &str = "capability issuer is not trusted";
const BANNER_TIMEOUT: Duration = Duration::from_secs(60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

struct Sidecar {
    child: Child,
    base_url: String,
    stdout_reader: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Sidecar {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.stdout_reader.take() {
            let _ = reader.join();
        }
    }
}

fn spawn_start(pin: Option<&PublicKey>) -> Sidecar {
    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command
        .args([
            "start",
            "--listen",
            "127.0.0.1:0",
            "--allow-ephemeral-receipts",
        ])
        .env_remove("CHIO_CONTROL_AUTHORITY_PUBLIC_KEY")
        .env_remove("CHIO_TRUSTED_ISSUER_KEY")
        .env_remove("CHIO_TRUSTED_ISSUER_KEYS")
        .env("CHIO_SIDECAR_CONTROL_TOKEN", CONTROL_TOKEN)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(pin) = pin {
        command.args(["--control-authority-public-key", &pin.to_hex()]);
    }
    let mut sidecar = Sidecar {
        child: command.spawn().expect("spawn chio start"),
        base_url: String::new(),
        stdout_reader: None,
    };
    let stdout = sidecar.child.stdout.take().expect("piped stdout");
    let (banner_tx, banner_rx) = mpsc::channel();
    // The reader owns the pipe until the child exits, so later route lines
    // never hit a closed read end.
    sidecar.stdout_reader = Some(std::thread::spawn(move || {
        let mut lines = BufReader::new(stdout).lines();
        if let Some(Ok(banner)) = lines.next() {
            let _ = banner_tx.send(banner);
        }
        lines.for_each(drop);
    }));
    let banner = banner_rx
        .recv_timeout(BANNER_TIMEOUT)
        .expect("chio start printed its banner");
    sidecar.base_url = banner
        .strip_prefix("chio sidecar listening on ")
        .unwrap_or_else(|| panic!("unexpected chio start banner: {banner:?}"))
        .to_string();
    sidecar
}

fn capability_signed_by(authority: &Keypair) -> CapabilityToken {
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-start-pin".to_string(),
            issuer: authority.public_key(),
            subject: Keypair::generate().public_key(),
            scope: ChioScope::default(),
            // The fixture window ends in 2100 and stays inside canonical JSON's
            // exact-integer range without depending on the test runner's clock.
            issued_at: 1,
            expires_at: 4_102_444_800,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        authority,
    )
    .expect("sign capability")
}

fn validate(sidecar: &Sidecar, token: &CapabilityToken) -> serde_json::Value {
    ureq::post(&format!("{}/v1/capabilities/validate", sidecar.base_url))
        .timeout(REQUEST_TIMEOUT)
        .set("Authorization", &format!("Bearer {CONTROL_TOKEN}"))
        .send_json(serde_json::to_value(token).expect("serialize capability"))
        .expect("validate capability")
        .into_json()
        .expect("validate response body")
}

#[test]
fn start_trusts_the_pinned_control_authority() {
    let authority = Keypair::generate();
    let token = capability_signed_by(&authority);

    let pinned = spawn_start(Some(&authority.public_key()));
    let response = validate(&pinned, &token);
    assert_eq!(response["valid"], true, "{response}");
}

#[test]
fn start_without_a_pin_does_not_trust_the_authority() {
    let authority = Keypair::generate();
    let token = capability_signed_by(&authority);

    let unpinned = spawn_start(None);
    let response = validate(&unpinned, &token);
    assert_eq!(response["valid"], false, "{response}");
    assert_eq!(response["reason"], NOT_TRUSTED, "{response}");
}
