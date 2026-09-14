mod support;

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection, Verdict};
use chio_process::ProcessRuntime;
use serde_json::{json, Value};
use support::Result;

#[derive(Debug, PartialEq)]
struct RetainedSnapshot {
    operation_and_claim: Vec<Vec<rusqlite::types::Value>>,
    commit_head: Vec<Vec<rusqlite::types::Value>>,
    anchor: Vec<u8>,
}

fn retained_snapshot(dir: &std::path::Path) -> Result<RetainedSnapshot> {
    let connection = rusqlite::Connection::open(dir.join("authority.db"))?;
    let rows = |table: &str| -> Result<Vec<Vec<rusqlite::types::Value>>> {
        let mut statement = connection.prepare(&format!("SELECT * FROM {table}"))?;
        let columns = statement.column_count();
        let values = statement.query_map([], |row| {
            (0..columns).map(|column| row.get(column)).collect()
        })?;
        Ok(values.collect::<std::result::Result<Vec<_>, _>>()?)
    };
    let store: String =
        connection.query_row("SELECT store_uuid FROM chio_serving_owner", [], |row| {
            row.get(0)
        })?;
    Ok(RetainedSnapshot {
        operation_and_claim: rows("admission_operations")?,
        commit_head: rows("admission_operation_commit_meta")?,
        anchor: std::fs::read(dir.join("locks").join(format!("{store}.lock")))?,
    })
}

/// `append` is a side effect; `read` is declared free of side effects and
/// records each execution in a separate log only so the test can count them.
struct AppendServer {
    path: PathBuf,
    crash_after_effect: bool,
}

#[async_trait::async_trait]
impl ToolServerConnection for AppendServer {
    fn server_id(&self) -> &str {
        "tools"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["append".into(), "read".into()]
    }
    fn tool_is_read_only(&self, tool: &str) -> bool {
        tool == "read"
    }
    async fn invoke(
        &self,
        tool: &str,
        _: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        let (path, line) = if tool == "read" {
            (self.path.with_file_name("reads.log"), "read-executed")
        } else {
            (self.path.clone(), "external-effect")
        };
        let append = || -> std::io::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(&path)?;
            writeln!(file, "{line}")?;
            file.sync_all()
        };
        append().map_err(|e| KernelError::Internal(e.to_string()))?;
        if self.crash_after_effect {
            // The real OS process exits after the external effect, before the
            // tool returns or any Rust destructor can reconcile the operation.
            std::process::exit(73);
        }
        Ok(json!({"published": true}))
    }
}

fn phase(dir: &std::path::Path, phase: &str) -> Result<std::process::ExitStatus> {
    Ok(Command::new(std::env::current_exe()?)
        .args(["--exact", "subprocess_worker", "--nocapture"])
        .env("CHIO_PROCESS_TEST_DIRECTORY", dir)
        .env("CHIO_PROCESS_TEST_PHASE", phase)
        .status()?)
}

#[test]
fn completed_effect_survives_abrupt_exit_and_a_fresh_os_process() -> Result {
    let dir = tempfile::tempdir()?;
    assert_eq!(phase(dir.path(), "complete-then-exit")?.code(), Some(74));
    assert!(phase(dir.path(), "recover-complete")?.success());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("external.log"))?,
        "external-effect\n"
    );
    Ok(())
}

#[test]
fn unknown_effect_is_not_redispatched_after_process_death() -> Result {
    let dir = tempfile::tempdir()?;
    assert_eq!(phase(dir.path(), "crash-in-tool")?.code(), Some(73));
    assert!(phase(dir.path(), "recover-unknown")?.success());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("external.log"))?,
        "external-effect\n"
    );
    Ok(())
}

#[test]
fn unknown_read_only_outcome_is_redispatched_under_a_fresh_request_identity() -> Result {
    let dir = tempfile::tempdir()?;
    assert_eq!(phase(dir.path(), "crash-in-read")?.code(), Some(73));
    assert!(phase(dir.path(), "recover-read")?.success());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("reads.log"))?,
        "read-executed\nread-executed\n"
    );
    assert!(!dir.path().join("external.log").exists());
    Ok(())
}

#[test]
fn original_artifact_calls_keep_one_dispatch_and_identity_after_host_death() -> Result {
    for artifact in ["dpop", "intent", "approval", "nonce", "supplemental"] {
        let dir = tempfile::tempdir()?;
        assert_eq!(
            phase(dir.path(), &format!("crash-artifact-{artifact}"))?.code(),
            Some(73),
            "{artifact}"
        );
        let original = std::fs::read(dir.path().join("original-request.json"))?;
        assert!(
            phase(dir.path(), &format!("recover-artifact-{artifact}"))?.success(),
            "{artifact}"
        );
        assert_eq!(
            std::fs::read(dir.path().join("original-request.json"))?,
            original
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("reads.log"))?,
            "read-executed\n",
            "{artifact}"
        );
    }
    Ok(())
}

#[test]
fn unknown_monetary_read_retains_one_original_payment_hold() -> Result {
    let dir = tempfile::tempdir()?;
    assert_eq!(phase(dir.path(), "crash-monetary-read")?.code(), Some(73));
    let payment_snapshot = || -> Result<(i64, String, String, i64)> {
        let database = rusqlite::Connection::open_with_flags(
            dir.path().join("payments.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        Ok(database.query_row("SELECT COUNT(*), MIN(authorization_id), MIN(state), SUM(amount_units) FROM chio_finding_operator_payments", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))?)
    };
    let before = payment_snapshot()?;
    assert_eq!(before.0, 1);
    assert_eq!(before.2, "held");
    assert_eq!(before.3, 100);
    assert!(phase(dir.path(), "recover-monetary-read")?.success());
    assert_eq!(payment_snapshot()?, before);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("reads.log"))?,
        "read-executed\n"
    );
    Ok(())
}

#[test]
fn unknown_quota_read_keeps_the_original_charge_and_dispatch_identity() -> Result {
    let dir = tempfile::tempdir()?;
    assert_eq!(phase(dir.path(), "crash-quota-read")?.code(), Some(73));
    let hold_snapshot = || -> Result<(String, i64, i64)> {
        let database = rusqlite::Connection::open_with_flags(
            dir.path().join("authority.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        Ok(database.query_row("SELECT MIN(hold_id), COUNT(*), SUM(invocation_count_debited) FROM budget_authorization_holds", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?)
    };
    let before = hold_snapshot()?;
    assert_eq!((before.1, before.2), (1, 1));
    assert!(phase(dir.path(), "recover-quota-read")?.success());
    assert_eq!(hold_snapshot()?, before);
    assert_eq!(
        std::fs::read_to_string(dir.path().join("reads.log"))?,
        "read-executed\n"
    );
    Ok(())
}

#[test]
fn repeatedly_unknown_reads_stop_at_the_third_dispatch() -> Result {
    let dir = tempfile::tempdir()?;
    for _ in 0..3 {
        assert_eq!(phase(dir.path(), "crash-repeated-read")?.code(), Some(73));
    }
    assert!(phase(dir.path(), "recover-repeated-read")?.success());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("reads.log"))?,
        "read-executed\nread-executed\nread-executed\n"
    );
    Ok(())
}

#[test]
fn read_only_recovery_keeps_the_request_identity_when_a_grant_is_present() -> Result {
    let dir = tempfile::tempdir()?;
    assert_eq!(phase(dir.path(), "crash-granted-read")?.code(), Some(73));
    assert!(phase(dir.path(), "recover-granted-read")?.success());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("reads.log"))?,
        "read-executed\n"
    );
    Ok(())
}

#[test]
fn known_only_policy_survives_host_death_and_cannot_be_relaxed() -> Result {
    let dir = tempfile::tempdir()?;
    assert_eq!(phase(dir.path(), "crash-known-read")?.code(), Some(73));
    assert!(phase(dir.path(), "recover-known-read")?.success());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("reads.log"))?,
        "read-executed\n"
    );
    Ok(())
}

#[tokio::test]
async fn subprocess_worker() -> Result {
    let Some(dir) = std::env::var_os("CHIO_PROCESS_TEST_DIRECTORY") else {
        return Ok(());
    };
    let dir = PathBuf::from(dir);
    let phase = std::env::var("CHIO_PROCESS_TEST_PHASE")?;
    let kernel = support::kernel_with_artifacts(
        &dir,
        Box::new(AppendServer {
            path: dir.join("external.log"),
            crash_after_effect: phase.starts_with("crash-artifact-")
                || matches!(
                    phase.as_str(),
                    "crash-in-tool"
                        | "crash-in-read"
                        | "crash-granted-read"
                        | "crash-known-read"
                        | "crash-repeated-read"
                        | "crash-quota-read"
                        | "crash-monetary-read"
                ),
        }),
        phase.ends_with("monetary-read"),
        phase.ends_with("artifact-nonce"),
        phase.ends_with("artifact-supplemental"),
    )?;
    let runtime = ProcessRuntime::open(dir.join("process.db"), kernel.clone())?;
    if phase.contains("-artifact-") {
        let first = phase.starts_with("crash-");
        let request_path = dir.join("original-request.json");
        let request = if first {
            support::root(&runtime, &kernel, 1)?;
            let mut request = runtime.tool_request("root", "peek", "tools", "read", json!({}))?;
            if phase.ends_with("dpop") {
                request.dpop_proof = Some(chio_kernel::dpop::DpopProof::sign(
                    chio_kernel::dpop::DpopProofBody {
                        schema: chio_kernel::dpop::DPOP_SCHEMA.into(),
                        replay_authority: None,
                        capability_id: request.capability.id.clone(),
                        tool_server: "tools".into(),
                        tool_name: "read".into(),
                        action_hash: chio_core_types::crypto::sha256_hex(
                            &chio_core_types::crypto::canonical_json_bytes(&request.arguments)?,
                        ),
                        nonce: request.request_id.clone(),
                        issued_at: request.capability.issued_at,
                        agent_key: support::parent_key().public_key(),
                    },
                    &support::parent_key(),
                )?);
            } else if phase.ends_with("supplemental") {
                request.supplemental_authorization = Some(chio_core_types::capability::supplemental_authorization::OpaqueSupplementalAuthorization {
                    signed_extension: support::supplemental::issue(&request)?,
                });
            } else if phase.ends_with("nonce") {
                let preflight = kernel.evaluate_tool_call(&request).await?;
                assert_eq!(preflight.verdict, Verdict::Allow, "{:?}", preflight.reason);
                request.execution_nonce = Some(*preflight.execution_nonce.ok_or("issued nonce")?);
            } else {
                let intent: chio_core_types::capability::governance::GovernedTransactionIntent =
                    serde_json::from_value(
                        json!({"id": "read-intent", "server_id": "tools", "tool_name": "read", "purpose": "one recorded read"}),
                    )?;
                if phase.ends_with("approval") {
                    use chio_core_types::capability::governance::{
                        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
                    };
                    request.approval_token = Some(GovernedApprovalToken::sign(
                        GovernedApprovalTokenBody {
                            id: "read-approval".into(),
                            approver: support::issuer().public_key(),
                            subject: request.capability.subject.clone(),
                            governed_intent_hash: intent.binding_hash()?,
                            request_id: request.request_id.clone(),
                            threshold_proposal_hash: None,
                            issued_at: request.capability.issued_at,
                            expires_at: request.capability.expires_at,
                            decision: GovernedApprovalDecision::Approved,
                        },
                        &support::issuer(),
                    )?);
                }
                request.governed_intent = Some(intent);
            }
            let mut file = std::fs::File::create(&request_path)?;
            file.write_all(&serde_json::to_vec(&request)?)?;
            file.sync_all()?;
            request
        } else {
            serde_json::from_slice(&std::fs::read(&request_path)?)?
        };
        let response = runtime.invoke("root", "peek", &request).await?;
        assert!(
            !first,
            "original call did not reach crashing tool: {:?}",
            response.reason
        );
        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response.receipt.verify_signature()?);
        assert_eq!(response.request_id, request.request_id);
        let metadata = response.receipt.metadata.as_ref().ok_or("metadata")?;
        assert_eq!(metadata["chio_process"]["attempt"], 1);
        assert_eq!(
            metadata["admission_operation"]["projected_state"],
            "outcome_unknown_after_dispatch"
        );
        assert_eq!(runtime.process("root")?.tree_calls, 1);
        return Ok(());
    }
    if phase.ends_with("quota-read") || phase.ends_with("monetary-read") {
        if phase.starts_with("crash-") {
            let mut scope = support::scope(&["read"]);
            scope.grants[0].max_invocations = Some(10);
            if phase.ends_with("monetary-read") {
                scope.grants[0].max_cost_per_invocation =
                    Some(chio_core_types::capability::scope::MonetaryAmount {
                        units: 100,
                        currency: "USD".into(),
                    });
                scope.grants[0].max_total_cost =
                    Some(chio_core_types::capability::scope::MonetaryAmount {
                        units: 1000,
                        currency: "USD".into(),
                    });
            }
            let capability =
                kernel.issue_capability(&support::parent_key().public_key(), scope, 3600)?;
            runtime.create_root("root", &capability, support::limits(1))?;
        }
        let request = runtime.tool_request("root", "peek", "tools", "read", json!({}))?;
        let original_id = runtime.request_id("root", "peek")?;
        let response = runtime.invoke("root", "peek", &request).await?;
        assert!(phase.starts_with("recover-"));
        assert_eq!(response.verdict, Verdict::Deny);
        assert_eq!(response.request_id, original_id);
        assert!(response.receipt.verify_signature()?);
        assert_eq!(
            response.receipt.metadata.as_ref().ok_or("metadata")?["chio_process"]["attempt"],
            1
        );
        assert_eq!(runtime.process("root")?.tree_calls, 1);
        return Ok(());
    }
    if phase.ends_with("repeated-read") {
        if runtime.process("root").is_err() {
            support::root(&runtime, &kernel, 1)?;
        }
        let request = runtime.tool_request("root", "peek", "tools", "read", json!({}))?;
        let response = runtime.invoke("root", "peek", &request).await?;
        assert_eq!(phase, "recover-repeated-read");
        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response.receipt.verify_signature()?);
        let metadata = response.receipt.metadata.as_ref().ok_or("metadata")?;
        assert_eq!(metadata["chio_process"]["attempt"], 3);
        assert_eq!(
            metadata["admission_operation"]["schema"],
            "chio.admission-receipt.v1"
        );
        assert_eq!(
            metadata["admission_operation"]["projected_state"],
            "outcome_unknown_after_dispatch"
        );
        assert_eq!(runtime.process("root")?.tree_calls, 1);
        return Ok(());
    }
    if matches!(
        phase.as_str(),
        "crash-in-tool"
            | "complete-then-exit"
            | "crash-in-read"
            | "crash-granted-read"
            | "crash-known-read"
    ) {
        support::root(&runtime, &kernel, 1)?;
    }
    if phase == "crash-known-read" || phase == "recover-known-read" {
        let request = runtime.tool_request("root", "model", "tools", "read", json!({}))?;
        let retained_before = if phase == "recover-known-read" {
            Some(retained_snapshot(&dir)?)
        } else {
            None
        };
        let response = runtime.invoke_known_only("root", "model", &request).await?;
        assert_eq!(phase, "recover-known-read");
        assert_eq!(response.verdict, Verdict::Deny);
        assert_eq!(response.request_id, runtime.request_id("root", "model")?);
        assert!(response.receipt.verify_signature()?);
        assert!(matches!(
            runtime.invoke("root", "model", &request).await,
            Err(chio_process::ProcessError::Conflict)
        ));
        let again = runtime.invoke_known_only("root", "model", &request).await?;
        assert_eq!(again.verdict, Verdict::Deny);
        assert_eq!(again.request_id, response.request_id);
        assert!(again.receipt.verify_signature()?);
        let receipt = serde_json::to_value(&again.receipt)?;
        assert_eq!(
            receipt["metadata"]["chio_process"]["recovery_policy"],
            "known_outcome_only"
        );
        assert_eq!(
            receipt["metadata"]["admission_operation"]["projected_state"],
            "outcome_unknown_after_dispatch"
        );
        assert_eq!(runtime.process("root")?.tree_calls, 1);
        let projection = &receipt["metadata"]["admission_operation"];
        let dispatch = &projection["retained_dispatch_commit"];
        assert_eq!(projection["store_fence"], dispatch["store_fence"]);
        assert_eq!(
            projection["coordinator_lease_id"],
            dispatch["coordinator_lease_id"]
        );
        assert_eq!(
            projection["coordinator_lease_epoch"],
            dispatch["coordinator_lease_epoch"]
        );
        let connection = rusqlite::Connection::open(dir.join("authority.db"))?;
        let current_epoch: i64 =
            connection.query_row("SELECT owner_epoch FROM chio_serving_owner", [], |row| {
                row.get(0)
            })?;
        assert!(
            current_epoch
                > projection["store_fence"]["owner_epoch"]
                    .as_i64()
                    .ok_or("historical epoch")?
        );
        assert_eq!(retained_before, Some(retained_snapshot(&dir)?));
        return Ok(());
    }
    if phase == "crash-granted-read" || phase == "recover-granted-read" {
        let mut request = runtime.tool_request("root", "peek", "tools", "read", json!({}))?;
        // This embedding does not install a flow runtime. The signed artifact
        // still binds the logical request and must prevent fresh dispatch.
        let body = serde_json::from_value(json!({
            "domain_version": 1, "grant_id": "grant-a",
            "capability_id": request.capability.id, "tenant_id": "tenant-a",
            "subject_id": "subject-a", "agent_id": "agent-a", "session_id": "session-a",
            "source_label_hash": vec![1; 32],
            "target_label": {"kind": "known", "owners": {}, "compartments": []},
            "destination_id": "tools", "tool_name": "read", "purpose": "recovery-test",
            "request_hash": vec![2; 32], "issued_at_unix_seconds": 100,
            "expires_at_unix_seconds": 200, "authority_key_id": "authority-a"
        }))?;
        request.declassification_grant = Some(chio_core_types::SignedDeclassificationGrant::sign(
            body,
            &support::issuer(),
        )?);
        let response = runtime.invoke("root", "peek", &request).await?;
        assert_eq!(phase, "recover-granted-read");
        assert_eq!(response.verdict, Verdict::Deny);
        assert_eq!(response.request_id, runtime.request_id("root", "peek")?);
        assert_eq!(
            runtime
                .tool_request("root", "peek", "tools", "read", json!({}))?
                .request_id,
            request.request_id
        );
        assert!(response.receipt.verify_signature()?);
        return Ok(());
    }
    if phase == "crash-in-read" || phase == "recover-read" {
        let request = runtime.tool_request("root", "peek", "tools", "read", json!({}))?;
        let first = runtime.request_id("root", "peek")?;
        if phase == "crash-in-read" {
            assert_eq!(request.request_id, first);
            let _ = runtime.invoke("root", "peek", &request).await;
            unreachable!("the read-only tool exits the process before returning");
        }
        // Recovery reports the first dispatch unknown; a read-only tool earns a
        // fresh dispatch under the next attempt's identity, still one logical call.
        assert_eq!(request.request_id, first);
        let response = runtime.invoke("root", "peek", &request).await?;
        assert_eq!(
            response.verdict,
            Verdict::Allow,
            "{:?} {:?}",
            response.reason,
            response.receipt.metadata
        );
        assert_ne!(response.request_id, first);
        assert!(response.receipt.verify_signature()?);
        let again = runtime.tool_request("root", "peek", "tools", "read", json!({}))?;
        assert_eq!(again.request_id, response.request_id);
        let replay = runtime.invoke("root", "peek", &again).await?;
        assert_eq!(replay.request_id, response.request_id);
        assert_eq!(
            serde_json::to_value(&replay.receipt)?,
            serde_json::to_value(&response.receipt)?
        );
        assert!(matches!(
            runtime.invoke("root", "peek", &request).await,
            Err(chio_process::ProcessError::Invalid(_))
        ));
        assert_eq!(runtime.process("root")?.tree_calls, 1);
        return Ok(());
    }
    let request = runtime.tool_request(
        "root",
        "publish",
        "tools",
        "append",
        json!({"report": "v1"}),
    )?;
    let response = runtime.invoke("root", "publish", &request).await?;
    if phase == "recover-unknown" {
        assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
        assert!(response.output.is_none());
        assert!(response.receipt.verify_signature()?);
        assert!(
            response
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("OutcomeUnknownAfterDispatch"),
            "{:?}",
            response.reason
        );
    } else {
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        let receipt = serde_json::to_value(&response.receipt)?;
        if phase == "complete-then-exit" {
            let mut file = std::fs::File::create(dir.join("original-receipt.json"))?;
            file.write_all(&serde_json::to_vec(&receipt)?)?;
            file.sync_all()?;
            std::process::exit(74);
        }
        let original: Value =
            serde_json::from_slice(&std::fs::read(dir.join("original-receipt.json"))?)?;
        assert_eq!(receipt, original);
    }
    assert_eq!(runtime.process("root")?.tree_calls, 1);
    Ok(())
}
