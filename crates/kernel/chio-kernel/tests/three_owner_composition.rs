//! Native three-owner composition. Local modeled money and one administrator.
#![cfg(all(feature = "admission-test-support", unix))]

use chio_core::{
    canonical_json_bytes,
    crypto::{sha256_hex, Keypair},
};
use chio_kernel::*;
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::Duration,
};
#[path = "three_owner_composition/bank.rs"]
mod bank;
#[path = "three_owner_composition/fixture.rs"]
mod fixture;
use bank::Bank;
use fixture::*;
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn setup(root: &Path) -> Result {
    directory(root)?;
    Bank::provision(root)?;
    let buyer = open(root, 1, "none", false)?;
    let seed = request(
        &buyer,
        1,
        json!({"sourceVersion":1,"recipient":key(1).public_key().to_hex()}),
    )?;
    let response = buyer.evaluate_tool_call_blocking(&seed)?;
    let source = handoff(&response)?;
    verify_handoff(&source, 1)?;
    write(root.join("request-1.json"), &seed)?;
    write(root.join("source.json"), &source)?;
    drop(buyer);
    let child = open(root, 3, "none", false)?;
    let child_request = request(
        &child,
        3,
        json!({"sourceVersion":1,"source":source,
        "recipient":key(3).public_key().to_hex()}),
    )?;
    write(root.join("request-3.json"), &child_request)?;
    drop(child);
    let parent = open(root, 2, "none", false)?;
    let parent_request = request(
        &parent,
        2,
        json!({"sourceVersion":1,"source":source,
        "recipient":key(2).public_key().to_hex(),"childRequestSha256":digest(&child_request)?}),
    )?;
    write(root.join("request-2.json"), &parent_request)?;
    Ok(())
}

#[test]
fn composition_worker() -> Result {
    let Some(root) = std::env::var_os("CHIO_COMPOSITION_ROOT") else {
        return Ok(());
    };
    let root = PathBuf::from(root);
    let cut = std::env::var("CHIO_COMPOSITION_CUT")?;
    let label = std::env::var("CHIO_COMPOSITION_LABEL")?;
    let run = || -> Result<Value> {
        let parent = open(
            &root,
            2,
            &cut,
            std::env::var("CHIO_COMPOSITION_BAD")? == "true",
        )?;
        let request: ToolCallRequest = read(root.join("request-2.json"))?;
        let response = evaluate(&parent, &request)?;
        let output = match &response.output {
            Some(ToolCallOutput::Value(v)) => Some(v.clone()),
            None => None,
            _ => return Err("unexpected stream".into()),
        };
        Ok(
            json!({"kind":"response","verdict":format!("{:?}",response.verdict),
            "output":output,"receipt":response.receipt}),
        )
    };
    let value = run().unwrap_or_else(|e| json!({"kind":"blocked","error":e.to_string()}));
    write(root.join(format!("{label}.json")), &value)?;
    Ok(())
}

fn worker(root: &Path, cut: &str, label: &str, bad: bool) -> Result<std::process::Output> {
    Ok(Command::new(std::env::current_exe()?)
        .args(["--exact", "composition_worker", "--nocapture"])
        .env("CHIO_COMPOSITION_ROOT", root)
        .env("CHIO_COMPOSITION_CUT", cut)
        .env("CHIO_COMPOSITION_LABEL", label)
        .env("CHIO_COMPOSITION_BAD", bad.to_string())
        .output()?)
}
fn identities(root: &Path) -> Result<Vec<Value>> {
    let mut values = vec![];
    for role in 1..=3 {
        let db = rusqlite::Connection::open(root.join(format!("owner-{role}/authority.db")))?;
        let rows: i64 = db.query_row("SELECT count(*) FROM admission_operations", [], |r| {
            r.get(0)
        })?;
        assert_eq!(rows, 1, "role {role}");
        let (operation, hold, authorization): (String, String, String) = db.query_row(
            "SELECT operation_id,hold_id,authorization_id FROM payment_journal",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let effects: u64 = read(root.join(format!("effects-{role}.json")))?;
        assert_eq!(effects, 1, "role {role} redispatched");
        values.push(json!({"role":role,"operation":operation,"hold":hold,"authorization":authorization,"effects":effects}));
    }
    assert_ne!(values[0]["operation"], values[1]["operation"]);
    assert_ne!(values[1]["operation"], values[2]["operation"]);
    assert_ne!(values[0]["operation"], values[2]["operation"]);
    Ok(values)
}

#[test]
fn approved_artifacts_and_earned_child_survive_parent_finalization_loss() -> Result {
    run_trajectory("none", true)?;
    run_trajectory("none", false)?;
    for cut in [
        "tool-return-recorded",
        "post-return-evaluation-begun",
        "post-return-resolved",
        "security-release-acknowledged",
        "security-release-checkpointed",
        "terminal-projected",
    ] {
        run_trajectory(cut, true)?;
    }
    Ok(())
}
fn run_trajectory(cut: &str, bad: bool) -> Result {
    use std::os::unix::process::ExitStatusExt;
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    setup(root)?;
    let first = worker(root, cut, "first", bad)?;
    if cut == "none" {
        assert!(
            first.status.success(),
            "{}",
            String::from_utf8_lossy(&first.stderr)
        );
    } else {
        assert_eq!(
            first.status.signal(),
            Some(9),
            "{cut}: {} {}",
            String::from_utf8_lossy(&first.stdout),
            String::from_utf8_lossy(&first.stderr)
        );
        let reached: Value = read(root.join("reached-cut.json"))?;
        assert_eq!(reached["cut"], cut);
    }
    let before = identities(root)?;
    let earned: Value = read(root.join("child-earned.json"))?;
    verify_handoff(&earned, 3)?;
    let recovery = worker(root, "none", "recovered", bad)?;
    assert!(
        recovery.status.success(),
        "{}",
        String::from_utf8_lossy(&recovery.stderr)
    );
    let recovered: Value = read(root.join("recovered.json"))?;
    let checkpointed = matches!(
        cut,
        "none" | "security-release-checkpointed" | "terminal-projected"
    );
    if checkpointed {
        assert_eq!(recovered["kind"], "response", "{cut}: {recovered}");
        assert_eq!(recovered["verdict"], if bad { "Deny" } else { "Allow" });
        if bad {
            assert!(recovered["output"].is_null());
        } else {
            assert_eq!(recovered["output"], expected(2));
        }
        if cut == "none" {
            let first: Value = read(root.join("first.json"))?;
            assert_eq!(first["receipt"], recovered["receipt"]);
        }
    } else {
        assert_eq!(recovered["kind"], "blocked", "{cut}: {recovered}");
        assert!(
            recovered["error"]
                .as_str()
                .is_some_and(|s| s.contains("original release owner")),
            "{cut}: {recovered}"
        );
    }
    let again = worker(root, "none", "again", bad)?;
    assert!(again.status.success());
    let again: Value = read(root.join("again.json"))?;
    assert_eq!(again, recovered, "recovery changed its original outcome");
    assert_eq!(identities(root)?, before);
    assert_eq!(
        Bank::balances(root)?,
        if bad {
            vec![0, 1000, 70, 30]
        } else {
            vec![0, 900, 170, 30]
        }
    );
    let child = open(root, 3, "none", false)?;
    let request: ToolCallRequest = read(root.join("request-3.json"))?;
    let replay = handoff(&child.evaluate_tool_call_blocking(&request)?)?;
    assert_eq!(replay, earned, "parent loss changed earned child receipt");
    let ack_expected = matches!(
        cut,
        "none"
            | "security-release-acknowledged"
            | "security-release-checkpointed"
            | "terminal-projected"
    );
    assert_eq!(
        root.join("release-ack.json").exists(),
        ack_expected,
        "a fresh callback replaced the original owner"
    );
    let record = json!({"cut":cut,"parentRejected":bad,"identities":before,
        "balances":Bank::balances(root)?,"parentRecovery":recovered,"childReceipt":earned["receipt"],
        "sameChildReplay":true,"independentAdministration":false,"realMoney":false});
    if let Some(out) = std::env::var_os("CHIO_COMPOSITION_EVIDENCE") {
        let out = PathBuf::from(out);
        fs::create_dir_all(&out)?;
        write(out.join(format!("{cut}-{bad}.json")), &record)?;
    }
    Ok(())
}

#[test]
fn mutated_approvals_and_artifact_handoffs_never_dispatch() -> Result {
    for mutation in [
        "signature",
        "missing-approval",
        "parameters",
        "recipient",
        "version",
        "operation",
        "source-content",
        "source-receipt",
    ] {
        let temp = tempfile::tempdir()?;
        let root = temp.path();
        setup(root)?;
        let child = open(root, 3, "none", false)?;
        let mut req: ToolCallRequest = read(root.join("request-3.json"))?;
        match mutation {
            "missing-approval" => req.approval_token = None,
            "parameters" => req.arguments["extra"] = json!("unapproved"),
            "recipient" => req.arguments["recipient"] = json!(key(1).public_key().to_hex()),
            "version" => req.arguments["sourceVersion"] = json!(2),
            "operation" => req.request_id = "fresh-operation".into(),
            "signature" => {
                let mut token = req.approval_token.take().ok_or("approval")?;
                // Preserve every binding field so the native verifier must
                // reach cryptographic signature validation to reject this.
                token.signature = chio_core::crypto::Signature::from_bytes(&[0; 64]);
                req.approval_token = Some(token);
            }
            "source-content" | "source-receipt" => {
                let mut args = req.arguments.clone();
                if mutation == "source-content" {
                    args["source"]["output"]["text"] = json!("CANARY-PRIVATE");
                } else {
                    args["source"]["receipt"]["content_hash"] = json!("00".repeat(32));
                }
                // Fresh, genuine approval cannot turn invalid source evidence into authority.
                req = request(&child, 3, args)?;
            }
            _ => return Err("unknown mutation".into()),
        }
        let response = child.evaluate_tool_call_blocking(&req)?;
        assert_eq!(
            response.verdict,
            Verdict::Deny,
            "{mutation}: {:?}",
            response.reason
        );
        assert!(response.output.is_none());
        if mutation == "signature" {
            assert!(
                response
                    .reason
                    .as_deref()
                    .is_some_and(|s| s.contains("approval token verification failed")),
                "signature control never reached cryptographic verification: {:?}",
                response.reason
            );
        }
        assert!(!root.join("effects-3.json").exists(), "{mutation}");
        assert_eq!(Bank::balances(root)?, vec![0, 1000, 100, 0]);
    }
    Ok(())
}

#[test]
fn approval_authority_cannot_replace_receiver_owned_capability() -> Result {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    setup(root)?;
    let child = open(root, 3, "none", false)?;
    let mut req: ToolCallRequest = read(root.join("request-3.json"))?;
    let mut body = req.capability.body();
    body.issuer = key(2).public_key();
    req.capability = chio_core::capability::token::CapabilityToken::sign(body, &key(2))?;
    let response = child.evaluate_tool_call_blocking(&req)?;
    assert_eq!(
        response.verdict,
        Verdict::Deny,
        "approval authority became receiver authority"
    );
    assert!(!root.join("effects-3.json").exists());
    Ok(())
}

#[test]
fn test_rail_cannot_spend_refundable_parent_backing_on_child_claims() -> Result {
    let temp = tempfile::tempdir()?;
    Bank::provision(temp.path())?;
    let parent = Bank {
        root: temp.path().into(),
        role: 2,
    };
    let child = Bank {
        root: temp.path().into(),
        role: 3,
    };
    let authorization = |amount, reference: &str| PaymentAuthorizeRequest {
        amount_units: amount,
        currency: "USD".into(),
        payer: "fixture-payer".into(),
        payee: "fixture-payee".into(),
        reference: reference.into(),
        governed: None,
        commerce: None,
    };
    parent.authorize(&authorization(100, "parent"))?;
    child.authorize(&authorization(80, "child"))?;
    child.authorize(&authorization(80, "child"))?;
    assert!(child.authorize(&authorization(81, "child")).is_err());
    assert!(child.authorize(&authorization(30, "underbacked")).is_err());
    assert_eq!(Bank::balances(temp.path())?, vec![180, 900, 20, 0]);
    parent.release("parent", "original-parent-release")?;
    child.capture("child", 80, "USD", "original-child-capture")?;
    child.capture("child", 80, "USD", "original-child-capture")?;
    assert!(parent.release("child", "parent-cancellation").is_err());
    assert!(child.release("child", "parent-cancellation").is_err());
    assert!(child
        .capture("child", 80, "USD", "different-reference")
        .is_err());
    assert_eq!(Bank::balances(temp.path())?, vec![0, 1000, 20, 80]);
    Ok(())
}
