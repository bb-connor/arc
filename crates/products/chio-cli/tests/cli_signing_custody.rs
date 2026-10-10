#![cfg(target_os = "linux")]
//! Local issuer commands own provisioning; signed reads and remote calls do not.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use chio_kernel::SignedLiabilityProvider;
use serde_json::{json, Value};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    directory: tempfile::TempDir,
    receipt: PathBuf,
    authority_parent: PathBuf,
    seed: PathBuf,
    database: PathBuf,
    input: PathBuf,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = chio_test_support::private_tempdir()?;
        let receipt = directory.path().join("receipts.sqlite3");
        let authority_parent = directory.path().join("authority");
        let seed = authority_parent.join("authority.seed");
        let database = authority_parent.join("authority.sqlite3");
        let input = directory.path().join("provider.json");
        fs::write(&input, serde_json::to_vec(&provider_report())?)?;
        Ok(Self {
            directory,
            receipt,
            authority_parent,
            seed,
            database,
            input,
        })
    }

    fn command(&self, sqlite: bool) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
        command
            .current_dir(self.directory.path())
            .args(["--json", "--receipt-db"]);
        command.arg(&self.receipt).arg(if sqlite {
            "--authority-db"
        } else {
            "--authority-seed-file"
        });
        command.arg(if sqlite { &self.database } else { &self.seed });
        command
    }

    fn issue(&self, sqlite: bool) -> std::io::Result<Output> {
        self.command(sqlite)
            .args(["trust", "liability-provider", "issue", "--input-file"])
            .arg(&self.input)
            .output()
    }

    fn export(&self, sqlite: bool) -> std::io::Result<Output> {
        self.command(sqlite)
            .args(["trust", "behavioral-feed", "export"])
            .output()
    }

    fn provision(&self, sqlite: bool) -> Result<chio_core::PublicKey, Box<dyn std::error::Error>> {
        if sqlite {
            return Ok(
                chio_store_sqlite::SqliteCapabilityAuthority::open(&self.database)?
                    .local_keypair()?
                    .public_key(),
            );
        }
        fs::create_dir(&self.authority_parent)?;
        Ok(chio_control_plane::load_or_create_authority_keypair(&self.seed)?.public_key())
    }
}

fn provider_report() -> Value {
    json!({
        "schema": "chio.market.provider.v1",
        "displayName": "CLI Owner Carrier",
        "providerId": "cli-owner-carrier",
        "providerType": "admitted_carrier",
        "providerUrl": "https://carrier.example.com",
        "lifecycleState": "active",
        "supportBoundary": {
            "curatedRegistryOnly": true,
            "automaticTrustAdmission": false,
            "permissionlessFederationSupported": false,
            "boundCoverageSupported": false
        },
        "policies": [{
            "jurisdiction": "us-ny",
            "coverageClasses": ["tool_execution"],
            "supportedCurrencies": ["USD"],
            "requiredEvidence": ["credit_provider_risk_package"],
            "claimsSupported": true,
            "quoteTtlSeconds": 1800
        }],
        "provenance": {"sourceRef": "cli-owner-fixture", "configuredBy": "operator@example.com", "configuredAt": 1}
    })
}

fn issued(output: &Output) -> Result<SignedLiabilityProvider, Box<dyn std::error::Error>> {
    assert!(
        output.status.success(),
        "CLI issue refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let signed: SignedLiabilityProvider = serde_json::from_slice(&output.stdout)?;
    assert!(signed.verify_signature()?);
    Ok(signed)
}

fn refusal(output: &Output) -> Result<Value, Box<dyn std::error::Error>> {
    assert!(!output.status.success(), "refused command succeeded");
    assert!(
        output.stdout.is_empty(),
        "refusal emitted an artifact or signature"
    );
    Ok(serde_json::from_slice(&output.stderr)?)
}

#[test]
fn local_sqlite_issuer_provisions_fresh_owner_custody() -> TestResult {
    let fixture = Fixture::new()?;
    let signed = issued(&fixture.issue(true)?)?;
    assert!(fixture.database.exists());
    let owner = chio_store_sqlite::SqliteCapabilityAuthority::open(&fixture.database)?;
    assert_eq!(signed.signer_key, owner.local_keypair()?.public_key());
    Ok(())
}

#[test]
fn local_seed_issuer_provisions_fresh_owner_custody() -> TestResult {
    let fixture = Fixture::new()?;
    let signed = issued(&fixture.issue(false)?)?;
    assert_eq!(
        signed.signer_key,
        chio_control_plane::load_existing_authority_keypair(&fixture.seed)?.public_key()
    );
    assert!(fixture.seed.exists());
    Ok(())
}

#[test]
fn local_issuance_keeps_existing_owner_signers() -> TestResult {
    for sqlite in [false, true] {
        let fixture = Fixture::new()?;
        let key = fixture.provision(sqlite)?;
        let original_seed = if sqlite {
            None
        } else {
            Some(fs::read(&fixture.seed)?)
        };
        let signed = issued(&fixture.issue(sqlite)?)?;
        assert_eq!(signed.signer_key, key);
        if let Some(original) = original_seed {
            assert_eq!(fs::read(&fixture.seed)?, original);
        }
    }
    Ok(())
}

#[test]
fn signed_export_refuses_lost_custody_without_recreation() -> TestResult {
    for sqlite in [false, true] {
        let fixture = Fixture::new()?;
        fixture.provision(sqlite)?;
        issued(&fixture.issue(sqlite)?)?;
        let healthy = fixture.export(sqlite)?;
        assert!(
            healthy.status.success(),
            "healthy export: {}",
            String::from_utf8_lossy(&healthy.stderr)
        );
        let missing = if sqlite {
            &fixture.database
        } else {
            &fixture.seed
        };
        fs::remove_file(missing)?;
        let error = refusal(&fixture.export(sqlite)?)?;
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .ok_or("missing refusal message")?;
        assert!(
            if sqlite {
                message.contains("already initialized by its owner")
            } else {
                message.contains("No such file or directory")
            },
            "wrong refusal: {message}"
        );
        assert!(!missing.exists(), "signed read recreated custody");
    }
    Ok(())
}

#[test]
fn invalid_or_conflicting_local_configuration_creates_no_custody() -> TestResult {
    let fixture = Fixture::new()?;
    let output = fixture
        .command(false)
        .arg("--authority-db")
        .arg(&fixture.database)
        .args(["trust", "liability-provider", "issue", "--input-file"])
        .arg(&fixture.input)
        .output()?;
    let error = refusal(&output)?;
    assert!(error
        .get("message")
        .and_then(Value::as_str)
        .is_some_and(|message| message.contains("not both")));
    assert!(!fixture.authority_parent.exists());

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(fixture.directory.path())
        .args(["--json", "--receipt-db"])
        .arg(&fixture.receipt)
        .args(["trust", "liability-provider", "issue", "--input-file"])
        .arg(&fixture.input)
        .output()?;
    let error = refusal(&output)?;
    assert!(error
        .get("message")
        .and_then(Value::as_str)
        .is_some_and(|message| message.contains("--authority-seed-file")
            && message.contains("--authority-db")));
    assert!(!fixture.authority_parent.exists());
    Ok(())
}

#[test]
fn malformed_input_and_receipt_preflight_do_not_initialize_custody() -> TestResult {
    for sqlite in [false, true] {
        let fixture = Fixture::new()?;
        fs::write(&fixture.input, b"{")?;
        refusal(&fixture.issue(sqlite)?)?;
        assert!(!fixture.authority_parent.exists());
        assert!(
            !fixture.receipt.exists(),
            "parsing failure opened receipt storage"
        );
    }
    let fixture = Fixture::new()?;
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(fixture.directory.path())
        .args(["--json", "--authority-db"])
        .arg(&fixture.database)
        .args(["trust", "liability-provider", "issue", "--input-file"])
        .arg(&fixture.input)
        .output()?;
    let error = refusal(&output)?;
    assert!(error
        .get("message")
        .and_then(Value::as_str)
        .is_some_and(|message| message.contains("requires --receipt-db")));
    assert!(!fixture.authority_parent.exists());
    Ok(())
}

#[test]
fn invalid_provider_report_does_not_initialize_custody() -> TestResult {
    let fixture = Fixture::new()?;
    let mut report = provider_report();
    let object = report.as_object_mut().ok_or("provider report object")?;
    object.insert("providerId".into(), Value::String(String::new()));
    fs::write(&fixture.input, serde_json::to_vec(&report)?)?;
    let error = refusal(&fixture.issue(true)?)?;
    assert!(error
        .get("message")
        .and_then(Value::as_str)
        .is_some_and(|message| message.contains("provider_id must not be empty")));
    assert!(!fixture.authority_parent.exists());
    Ok(())
}

#[test]
fn owner_custody_can_persist_after_semantic_issuance_refusal_without_output() -> TestResult {
    for sqlite in [false, true] {
        let fixture = Fixture::new()?;
        let output = fixture
            .command(sqlite)
            .args([
                "trust",
                "liability-provider",
                "issue",
                "--supersedes-provider-record-id",
                "missing-prior",
                "--input-file",
            ])
            .arg(&fixture.input)
            .output()?;
        let error = refusal(&output)?;
        assert!(error
            .get("message")
            .and_then(Value::as_str)
            .is_some_and(|message| message
                .contains("superseded liability provider `missing-prior` not found")));
        assert!(if sqlite {
            fixture.database.exists()
        } else {
            fixture.seed.exists()
        });
        let key = if sqlite {
            chio_store_sqlite::SqliteCapabilityAuthority::open(&fixture.database)?
                .local_keypair()?
        } else {
            chio_control_plane::load_existing_authority_keypair(&fixture.seed)?
        };
        assert!(!String::from_utf8_lossy(&output.stderr).contains(&key.seed_hex()));
    }
    Ok(())
}

#[test]
fn remote_issuance_does_not_provision_local_material() -> TestResult {
    let fixture = Fixture::new()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let server = std::thread::spawn(move || -> Result<String, String> {
        let deadline = Instant::now() + Duration::from_secs(10);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => return Err(error.to_string()),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|error| error.to_string())?;
        let mut buffer = [0; 8192];
        let count = stream
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        let request =
            String::from_utf8_lossy(buffer.get(..count).ok_or("request bound")?).into_owned();
        let body = r#"{"error":"remote fixture refused issuance"}"#;
        write!(stream, "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).map_err(|error| error.to_string())?;
        Ok(request)
    });
    let output = fixture
        .command(false)
        .arg("--authority-db")
        .arg(&fixture.database)
        .args([
            "--control-url",
            &format!("http://{address}"),
            "--control-token",
            "remote-fixture-token",
            "trust",
            "liability-provider",
            "issue",
            "--input-file",
        ])
        .arg(&fixture.input)
        .output()?;
    let request = server
        .join()
        .map_err(|_| "remote fixture panicked")?
        .map_err(std::io::Error::other)?;
    assert!(
        request.starts_with("POST /v1/liability/providers/issue "),
        "wrong remote call: {request}"
    );
    let error = refusal(&output)?;
    assert!(error
        .get("message")
        .and_then(Value::as_str)
        .is_some_and(|message| message.contains("409")
            && message.contains("remote fixture refused issuance")));
    assert!(!fixture.authority_parent.exists());
    assert!(!fixture.receipt.exists());
    Ok(())
}
