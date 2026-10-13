//! Actual CLI transport preserves opaque setup proofs and pins trusted operator evidence.
use chio_core_types::{
    canonical_json_bytes,
    capability::{
        scope::{ChioScope, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    },
    recovery::*,
    Keypair,
};
use std::{
    io::{Read, Write},
    net::TcpListener,
    process::{Command, Output},
    sync::mpsc,
    thread,
    time::Duration,
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn capability() -> Result<Vec<u8>> {
    let key = Keypair::from_seed(&[31; 32]);
    Ok(canonical_json_bytes(&CapabilityToken::sign(
        CapabilityTokenBody {
            id: "setup-transport-capability".into(),
            issuer: key.public_key(),
            subject: key.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "chio.recovery".into(),
                    tool_name: "inspect".into(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..Default::default()
            },
            issued_at: 1,
            expires_at: 2,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        &key,
    )?)?)
}
fn product_body(name: &str) -> Result<serde_json::Value> {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../spec/vectors/recovery/v1/product-contracts.json"
    ))?;
    Ok(vectors["cases"]
        .as_array()
        .ok_or("cases")?
        .iter()
        .find(|case| case["name"] == name)
        .ok_or("product vector")?["body"]
        .clone())
}
fn probe() -> Result<SignedRecoverySetupProbeV1> {
    Ok(SignedRecoverySetupProbeV1::sign(
        serde_json::from_value(product_body("recovery-setup-probe.schema.json")?)?,
        &Keypair::from_seed(&[32; 32]),
    )?)
}
fn report() -> Result<SignedRecoverySetupReportV1> {
    Ok(SignedRecoverySetupReportV1::sign(
        serde_json::from_value(product_body("recovery-setup-report.schema.json")?)?,
        &Keypair::from_seed(&[32; 32]),
    )?)
}

#[derive(Default)]
struct TransportOptions<'a> {
    endpoint_prefix: &'a str,
    operator_key: Option<&'a str>,
    command: Option<&'a [u8]>,
}
struct Invocation {
    output: Output,
    request: Option<serde_json::Value>,
    target: Option<String>,
}
fn invoke_with(
    action: &str,
    status: &str,
    response: Vec<u8>,
    options: TransportOptions<'_>,
) -> Result<Invocation> {
    let directory = tempfile::tempdir()?;
    let cap = capability()?;
    let cap_file = directory.path().join("capability.json");
    std::fs::write(&cap_file, &cap)?;
    let proof = canonical_json_bytes(&probe()?)?;
    let proof_file = directory.path().join("probe.json");
    std::fs::write(&proof_file, &proof)?;
    let command_file = directory.path().join("command.json");
    if let Some(bytes) = options.command {
        std::fs::write(&command_file, bytes)?;
    }
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let endpoint = format!(
        "http://{}{}",
        listener.local_addr()?,
        options.endpoint_prefix
    );
    let status = status.to_owned();
    let (finished, completion) = mpsc::channel();
    let receiver = thread::spawn(move || -> std::io::Result<Option<Vec<u8>>> {
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    // Process startup shares the CLI child lifetime, not a shorter accept clock.
                    if matches!(
                        completion.try_recv(),
                        Ok(()) | Err(mpsc::TryRecvError::Disconnected)
                    ) {
                        return Ok(None);
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => return Err(error),
            }
        };
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut wire = Vec::new();
        loop {
            let mut part = [0; 4096];
            let length = stream.read(&mut part)?;
            if length == 0 {
                return Err(std::io::Error::other("truncated request"));
            }
            wire.extend_from_slice(&part[..length]);
            if wire.len() > 73728 {
                return Err(std::io::Error::other("request bound"));
            }
            if let Some(header_end) = wire.windows(4).position(|p| p == b"\r\n\r\n") {
                let headers =
                    std::str::from_utf8(&wire[..header_end]).map_err(std::io::Error::other)?;
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(str::to_owned)
                    })
                    .ok_or_else(|| std::io::Error::other("content length"))?
                    .parse()
                    .map_err(std::io::Error::other)?;
                if wire.len() >= header_end + 4 + length {
                    break;
                }
            }
        }
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nLocation: http://127.0.0.1:1/secret\r\nConnection: close\r\n\r\n",
            response.len()
        )?;
        stream.write_all(&response)?;
        Ok(Some(wire))
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_chio"));
    child.arg("recovery");
    if matches!(action, "probe" | "qualify") {
        child.arg("setup");
    }
    child
        .args([action, "--endpoint", &endpoint, "--capability"])
        .arg(&cap_file);
    match action {
        "probe" | "settle" => {
            child.args(["--workflow-id", probe()?.body().benign_workflow.as_str()]);
        }
        "qualify" => {
            child.arg("--probe").arg(&proof_file);
        }
        "command" => {
            child.arg("--command").arg(&command_file);
        }
        _ => return Err("fixture action".into()),
    }
    if let Some(key) = options.operator_key {
        child.args(["--operator-key", key]);
    }
    let output = child.output()?;
    let _ = finished.send(());
    let wire = receiver.join().map_err(|_| "transport thread")??;
    let Some(wire) = wire else {
        return Ok(Invocation {
            output,
            request: None,
            target: None,
        });
    };
    let start = wire
        .windows(4)
        .position(|p| p == b"\r\n\r\n")
        .ok_or("headers")?
        + 4;
    let request: serde_json::Value = serde_json::from_slice(&wire[start..])?;
    assert_eq!(
        request["capability"]
            .as_str()
            .ok_or("capability")?
            .as_bytes(),
        cap
    );
    if action == "qualify" {
        assert_eq!(request["probe"].as_str().ok_or("proof")?.as_bytes(), proof);
    }
    if let Some(command) = options.command {
        assert_eq!(
            request["command"].as_str().ok_or("command")?.as_bytes(),
            command
        );
    }
    let target = std::str::from_utf8(&wire)?
        .lines()
        .next()
        .ok_or("request target")?
        .to_owned();
    Ok(Invocation {
        output,
        request: Some(request),
        target: Some(target),
    })
}
fn invoke(action: &str, status: &str, response: Vec<u8>) -> Result<(Output, serde_json::Value)> {
    let invocation = invoke_with(action, status, response, TransportOptions::default())?;
    let target = invocation.target.ok_or("missing request target")?;
    assert!(target.starts_with(&format!("POST /v1/recovery/setup/{action} ")));
    Ok((
        invocation.output,
        invocation.request.ok_or("missing request")?,
    ))
}

#[test]
fn setup_cli_probe_preserves_native_proof_and_requests_operator_restart() -> Result {
    let (output, _) = invoke("probe", "200 OK", canonical_json_bytes(&probe()?)?)?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The operator must be able to feed these exact bytes to qualify.
    let signed: SignedRecoverySetupProbeV1 = decode_contract(&output.stdout)?;
    assert_eq!(signed, probe()?);
    assert!(String::from_utf8_lossy(&output.stderr).contains("restart"));
    Ok(())
}
#[test]
fn setup_cli_qualify_refuses_wrong_shape_and_redirect_without_retries() -> Result {
    for (status, bytes) in [
        ("200 OK", b"{}".to_vec()),
        ("307 Temporary Redirect", b"{}".to_vec()),
    ] {
        let (output, _) = invoke("qualify", status, bytes)?;
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("secret"));
    }
    Ok(())
}

#[test]
fn setup_cli_reports_only_known_bounded_refusal_categories() -> Result {
    for (status, category) in [
        ("400 Bad Request", "recovery.invalid_command"),
        ("403 Forbidden", "recovery.authority_denied"),
        ("409 Conflict", "recovery.conflict"),
        ("409 Conflict", "recovery.unsupported_profile"),
        ("409 Conflict", "recovery.uncovered_mediation"),
        ("409 Conflict", "recovery.restart_required"),
        ("409 Conflict", "recovery.unknown_effect"),
        ("409 Conflict", "recovery.probe_expired"),
        ("409 Conflict", "recovery.origin_refused"),
        ("413 Payload Too Large", "recovery.projection_too_large"),
        ("503 Service Unavailable", "recovery.unavailable"),
        ("503 Service Unavailable", "recovery.busy"),
    ] {
        let (output, _) = invoke("qualify", status, category.as_bytes().to_vec())?;
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(category),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
    }
    let (output, _) = invoke(
        "qualify",
        "409 Conflict",
        b"private-error-canary: provider credentials".to_vec(),
    )?;
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("private-error-canary"));
    Ok(())
}

#[test]
fn recovery_cli_refuses_diagnostics_that_only_resemble_public_categories() -> Result {
    for (status, body) in [
        ("409 Conflict", "recovery.conflict: private-error-canary"),
        (
            "409 Conflict",
            "recovery.restart_required\nprivate-error-canary",
        ),
        ("409 Conflict", " recovery.uncovered_mediation"),
        ("502 Bad Gateway", "recovery.restart_required"),
    ] {
        let (output, _) = invoke("qualify", status, body.as_bytes().to_vec())?;
        assert!(!output.status.success());
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(!message.contains("private-error-canary"));
        assert!(!message.contains("recovery.restart_required"));
        assert!(!message.contains("recovery.uncovered_mediation"));
    }
    Ok(())
}

#[test]
fn recovery_cli_preserves_endpoint_path_prefixes() -> Result {
    for (prefix, expected) in [
        (
            "/control/private",
            "POST /control/private/v1/recovery/setup/probe HTTP/1.1",
        ),
        (
            "/control/private/",
            "POST /control/private/v1/recovery/setup/probe HTTP/1.1",
        ),
        (
            "/control%20panel%2Fprivate",
            "POST /control%20panel%2Fprivate/v1/recovery/setup/probe HTTP/1.1",
        ),
    ] {
        let invocation = invoke_with(
            "probe",
            "200 OK",
            canonical_json_bytes(&probe()?)?,
            TransportOptions {
                endpoint_prefix: prefix,
                ..Default::default()
            },
        )?;
        assert!(
            invocation.output.status.success(),
            "{}",
            String::from_utf8_lossy(&invocation.output.stderr)
        );
        assert_eq!(invocation.target.as_deref(), Some(expected));
    }
    Ok(())
}

#[test]
fn recovery_cli_dispatches_commands_at_the_native_text_byte_limit() -> Result {
    let command = vec![b'x'; 32768];
    let invocation = invoke_with(
        "command",
        "200 OK",
        b"{}".to_vec(),
        TransportOptions {
            command: Some(&command),
            ..Default::default()
        },
    )?;
    assert!(
        invocation.output.status.success(),
        "{}",
        String::from_utf8_lossy(&invocation.output.stderr)
    );
    assert_eq!(
        invocation.request.ok_or("request")?["command"]
            .as_str()
            .ok_or("command")?
            .len(),
        32768
    );
    Ok(())
}

#[test]
fn recovery_cli_refuses_commands_above_the_native_text_byte_limit_before_dispatch() -> Result {
    for command in [
        vec![b'x'; 32769],
        vec![b'x'; 40960],
        "é".repeat(16385).into_bytes(),
    ] {
        let invocation = invoke_with(
            "command",
            "200 OK",
            b"{}".to_vec(),
            TransportOptions {
                command: Some(&command),
                ..Default::default()
            },
        )?;
        assert!(!invocation.output.status.success());
        assert!(
            invocation.request.is_none(),
            "oversized command reached the recovery host"
        );
        assert!(invocation.output.stdout.is_empty());
    }
    Ok(())
}

#[test]
fn setup_cli_qualify_keeps_unpinned_reports_explicitly_untrusted() -> Result {
    let bytes = canonical_json_bytes(&report()?)?;
    let (output, _) = invoke("qualify", "200 OK", bytes.clone())?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, bytes);
    let message = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    assert!(message.contains("untrusted"));
    assert!(message.contains("--operator-key"));
    assert!(!message.contains("readiness"));
    Ok(())
}

#[test]
fn setup_cli_qualify_authenticates_readiness_with_the_independent_operator_key() -> Result {
    let key = Keypair::from_seed(&[32; 32]).public_key().to_hex();
    let bytes = canonical_json_bytes(&report()?)?;
    let invocation = invoke_with(
        "qualify",
        "200 OK",
        bytes.clone(),
        TransportOptions {
            operator_key: Some(&key),
            ..Default::default()
        },
    )?;
    assert!(
        invocation.output.status.success(),
        "{}",
        String::from_utf8_lossy(&invocation.output.stderr)
    );
    assert!(invocation.request.is_some());
    assert_eq!(invocation.output.stdout, bytes);
    let message = String::from_utf8_lossy(&invocation.output.stderr).to_ascii_lowercase();
    assert!(message.contains("readiness"));
    assert!(message.contains("pinned"));
    Ok(())
}

#[test]
fn setup_cli_rejects_a_valid_envelope_signed_by_a_different_operator() -> Result {
    let key = Keypair::from_seed(&[32; 32]).public_key().to_hex();
    let foreign = Keypair::from_seed(&[33; 32]);
    let wrong_key = foreign.public_key().to_hex();
    let probe_bytes = canonical_json_bytes(&probe()?)?;
    let report = report()?;
    let report_bytes = canonical_json_bytes(&report)?;
    let foreign_report = SignedRecoverySetupReportV1::sign(report.body().clone(), &foreign)?;
    let foreign_report = canonical_json_bytes(&foreign_report)?;
    for (action, response, operator_key, accepted) in [
        ("probe", probe_bytes.clone(), key.as_str(), true),
        ("qualify", report_bytes.clone(), key.as_str(), true),
        ("probe", probe_bytes, wrong_key.as_str(), false),
        ("qualify", report_bytes, wrong_key.as_str(), false),
        ("qualify", foreign_report, key.as_str(), false),
    ] {
        let invocation = invoke_with(
            action,
            "200 OK",
            response.clone(),
            TransportOptions {
                operator_key: Some(operator_key),
                ..Default::default()
            },
        )?;
        assert_eq!(
            invocation.output.status.success(),
            accepted,
            "{}",
            String::from_utf8_lossy(&invocation.output.stderr)
        );
        if accepted {
            assert_eq!(invocation.output.stdout, response);
        } else {
            assert!(invocation.output.stdout.is_empty());
            assert!(!String::from_utf8_lossy(&invocation.output.stderr)
                .to_ascii_lowercase()
                .contains("readiness"));
        }
    }
    Ok(())
}

#[test]
fn setup_cli_refuses_a_signed_probe_for_a_different_workflow() -> Result {
    let operator = Keypair::from_seed(&[32; 32]);
    let key = operator.public_key().to_hex();
    let requested = probe()?;
    let mut body = requested.body().clone();
    body.benign_workflow = serde_json::from_value(serde_json::json!("unrelated-workflow"))?;
    let unrelated = SignedRecoverySetupProbeV1::sign(body, &operator)?;
    assert!(unrelated.verify_signature()?);
    assert_eq!(unrelated.authority_key(), requested.authority_key());
    assert_ne!(
        unrelated.body().benign_workflow,
        requested.body().benign_workflow
    );
    let invocation = invoke_with(
        "probe",
        "200 OK",
        canonical_json_bytes(&unrelated)?,
        TransportOptions {
            operator_key: Some(&key),
            ..Default::default()
        },
    )?;
    let request = invocation.request.ok_or("missing actual request")?;
    assert_eq!(
        request["workflow_id"],
        requested.body().benign_workflow.as_str()
    );
    assert!(
        !invocation.output.status.success(),
        "accepted a signed probe for another workflow"
    );
    assert!(invocation.output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&invocation.output.stderr).contains("probe retained"));
    Ok(())
}

#[test]
fn setup_cli_refuses_a_signed_report_for_a_different_probe() -> Result {
    let operator = Keypair::from_seed(&[32; 32]);
    let key = operator.public_key().to_hex();
    let supplied = probe()?;
    let report = report()?;
    assert_eq!(&report.body().probe, supplied.body());
    let mut changed_deployment = report.body().clone();
    changed_deployment.probe.deployment = serde_json::from_value(serde_json::json!(vec![2; 32]))?;
    assert_eq!(changed_deployment.probe.probe_id, supplied.body().probe_id);
    let mut changed_identifier = report.body().clone();
    changed_identifier.probe.probe_id =
        serde_json::from_value(serde_json::json!("unrelated-setup-probe"))?;
    for (case, body) in [
        ("same_identifier_changed_deployment", changed_deployment),
        ("changed_probe_identifier", changed_identifier),
    ] {
        let unrelated_probe = SignedRecoverySetupProbeV1::sign(body.probe.clone(), &operator)?;
        assert!(unrelated_probe.verify_signature()?);
        assert_ne!(unrelated_probe.body(), supplied.body());
        let unrelated = SignedRecoverySetupReportV1::sign(body, &operator)?;
        assert!(unrelated.verify_signature()?);
        assert_eq!(unrelated.authority_key(), supplied.authority_key());
        let invocation = invoke_with(
            "qualify",
            "200 OK",
            canonical_json_bytes(&unrelated)?,
            TransportOptions {
                operator_key: Some(&key),
                ..Default::default()
            },
        )?;
        let request = invocation.request.ok_or("missing actual request")?;
        let retained: SignedRecoverySetupProbeV1 =
            decode_contract(request["probe"].as_str().ok_or("probe")?.as_bytes())?;
        assert_eq!(retained, supplied);
        assert!(
            !invocation.output.status.success(),
            "accepted an unrelated signed setup report: {case}"
        );
        assert!(invocation.output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&invocation.output.stderr)
            .to_ascii_lowercase()
            .contains("readiness"));
    }
    Ok(())
}
