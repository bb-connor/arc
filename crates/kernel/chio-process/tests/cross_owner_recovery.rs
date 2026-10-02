//! Separate local owners and an out-of-process physical-effect oracle.
//! This harness does not supply authenticated federation or PR #1172 mediation.
mod support;

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair};
use chio_kernel::admission_operation::DurableAdmissionMode;
use chio_kernel::{ChioKernel, KernelError, NestedFlowBridge, ToolServerConnection, Verdict};
use chio_process::ProcessRuntime;
use chio_store_sqlite::{SqliteAuthorityStore, SqliteReceiptStore};
use serde_json::{json, Value};
use support::Result;

fn durable_write(path: &Path, bytes: &[u8]) -> Result {
    let mut file = std::fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

struct Endpoint(Child);
impl Drop for Endpoint {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn endpoint(dir: &Path) -> Result<Endpoint> {
    let mut child = Endpoint(
        Command::new(std::env::current_exe()?)
            .args(["--exact", "endpoint_worker", "--nocapture"])
            .env("CHIO_EDGE_ENDPOINT_DIR", dir)
            .stdout(Stdio::null())
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    while !dir.join("address").exists() {
        if child.0.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err("endpoint did not become ready".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(child)
}

#[test]
fn endpoint_worker() -> Result {
    let Some(dir) = std::env::var_os("CHIO_EDGE_ENDPOINT_DIR") else {
        return Ok(());
    };
    let dir = PathBuf::from(dir);
    let listener = TcpListener::bind("127.0.0.1:0")?;
    // Publish readiness only after the complete address has been written.
    durable_write(
        &dir.join("address.tmp"),
        listener.local_addr()?.to_string().as_bytes(),
    )?;
    std::fs::rename(dir.join("address.tmp"), dir.join("address"))?;
    for connection in listener.incoming() {
        let mut stream = connection?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line)?;
        let value: Value = serde_json::from_str(&line)?;
        let mut log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("effects.jsonl"))?;
        writeln!(log, "{}", serde_json::to_string(&value)?)?;
        log.sync_all()?;
        stream.write_all(b"{\"applied\":true}\n")?;
    }
    Ok(())
}

struct Remote {
    address: String,
    owner: u8,
    cut: String,
}
#[async_trait::async_trait]
impl ToolServerConnection for Remote {
    fn server_id(&self) -> &str {
        "tools"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["append".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        arguments: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        if self.cut == "before_send" {
            std::process::exit(71);
        }
        let send = || -> Result<Value> {
            let mut stream = TcpStream::connect(&self.address)?;
            stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            stream.set_write_timeout(Some(Duration::from_secs(10)))?;
            writeln!(
                stream,
                "{}",
                json!({"owner":self.owner,"arguments":arguments})
            )?;
            let mut response = String::new();
            BufReader::new(stream).read_line(&mut response)?;
            Ok(serde_json::from_str(&response)?)
        };
        let output = send().map_err(|e| KernelError::Internal(e.to_string()))?;
        if self.cut == "hidden_retry" {
            send().map_err(|e| KernelError::Internal(e.to_string()))?;
        }
        if self.cut == "after_effect" {
            std::process::exit(72);
        }
        Ok(output)
    }
}

fn kernel(dir: &Path, owner: u8, remote: Remote) -> Result<Arc<ChioKernel>> {
    support::private_dir(dir)?;
    let locks = dir.join("locks");
    support::private_dir(&locks)?;
    let database = dir.join("authority.db");
    if !database.exists() {
        SqliteAuthorityStore::provision(&database, &locks)?;
    }
    let authority = SqliteAuthorityStore::open_serving_with_clock(
        &database,
        &locks,
        chio_test_support::clock::clock(),
    )?;
    let mut config = support::config();
    config.keypair = Keypair::from_seed(&[owner; 32]);
    let mut kernel = ChioKernel::new_with_clock(config, chio_test_support::clock::clock());
    let receipts = SqliteReceiptStore::open(dir.join("receipts.db"))?;
    receipts.wait_for_writer_ready(Duration::from_secs(30))?;
    kernel.set_receipt_store(Box::new(receipts))?;
    kernel.set_revocation_store(Box::new(authority.revocation_store()));
    kernel.set_budget_store(Box::new(authority.budget_store()));
    kernel.set_durable_admission_store(
        Arc::new(authority.admission_operation_store()),
        Arc::new(authority.tool_outcome_store()),
        authority.mutation_fence(),
    )?;
    kernel.configure_durable_admission(DurableAdmissionMode::All, false)?;
    let nonce = chio_kernel::execution_nonce::ExecutionNonceConfig {
        nonce_ttl_secs: 300,
        nonce_store_capacity: 64,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        nonce.clone(),
        Box::new(chio_kernel::execution_nonce::InMemoryExecutionNonceStore::from_config(&nonce)),
    );
    kernel.register_tool_server(Box::new(remote));
    kernel.reconcile_durable_admission_startup()?;
    Ok(Arc::new(kernel))
}

fn phase(dir: &Path, owner: u8, cut: &str) -> Result<std::process::ExitStatus> {
    Ok(Command::new(std::env::current_exe()?)
        .args(["--exact", "owner_worker", "--nocapture"])
        .env("CHIO_EDGE_ROOT", dir)
        .env("CHIO_EDGE_OWNER", owner.to_string())
        .env("CHIO_EDGE_CUT", cut)
        .status()?)
}

#[tokio::test]
async fn owner_worker() -> Result {
    let Some(root) = std::env::var_os("CHIO_EDGE_ROOT") else {
        return Ok(());
    };
    let root = PathBuf::from(root);
    let owner: u8 = std::env::var("CHIO_EDGE_OWNER")?.parse()?;
    let cut = std::env::var("CHIO_EDGE_CUT")?;
    let dir = root.join(format!("owner-{owner}"));
    let kernel = kernel(
        &dir,
        owner,
        Remote {
            address: std::fs::read_to_string(root.join("address"))?,
            owner,
            cut: cut.clone(),
        },
    )?;
    let runtime = ProcessRuntime::open(dir.join("process.db"), kernel.clone())?;
    if !dir.join("request.json").exists() {
        let capability = kernel.issue_capability(
            &Keypair::from_seed(&[owner + 10; 32]).public_key(),
            support::scope(&["append"]),
            3600,
        )?;
        runtime.create_root("root", &capability, support::limits(1))?;
        let request = runtime.tool_request(
            "root",
            "work",
            "tools",
            "append",
            json!({"source":"prepared-artifact","version":1,"recipient":"public-issue"}),
        )?;
        durable_write(&dir.join("request.json"), &serde_json::to_vec(&request)?)?;
    }
    let request: chio_kernel::ToolCallRequest =
        serde_json::from_slice(&std::fs::read(dir.join("request.json"))?)?;
    if cut == "before_admission" {
        std::process::exit(70);
    }
    let response = runtime.invoke("root", "work", &request).await?;
    assert!(response.receipt.verify_signature()?);
    assert_eq!(response.request_id, request.request_id);
    assert_eq!(runtime.process("root")?.tree_calls, 1);
    let prior = dir.join("response.json");
    if prior.exists() {
        let old: Value = serde_json::from_slice(&std::fs::read(&prior)?)?;
        if cut == "recover_unknown" {
            let current = serde_json::to_value(&response.receipt)?;
            for field in [
                "operation_id",
                "request_binding_hash",
                "request_id",
                "retained_dispatch_commit",
                "projected_state",
                "projected_operation_version",
            ] {
                assert_eq!(
                    old["receipt"]["metadata"]["admission_operation"][field],
                    current["metadata"]["admission_operation"][field]
                );
            }
        } else {
            assert_eq!(
                canonical_json_bytes(&old["receipt"])?,
                canonical_json_bytes(&response.receipt)?
            );
        }
        assert_eq!(
            old["nonce"],
            serde_json::to_value(&response.execution_nonce)?
        );
    }
    if cut == "recover_unknown" {
        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response.output.is_none());
        assert_eq!(
            response.receipt.metadata.as_ref().ok_or("metadata")?["admission_operation"]
                ["projected_state"],
            "outcome_unknown_after_dispatch"
        );
    } else {
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        assert_eq!(
            response.output,
            Some(chio_kernel::ToolCallOutput::Value(json!({"applied":true})))
        );
    }
    assert!(response.execution_nonce.is_some());
    // Source bytes, version, recipient and original identity are one frozen request.
    for field in ["source", "version", "recipient"] {
        let mut changed = request.clone();
        changed.arguments[field] = json!("forged");
        assert!(runtime.invoke("root", "work", &changed).await.is_err());
    }
    let mut changed = request.clone();
    changed.request_id = "forged-context".into();
    assert!(runtime.invoke("root", "work", &changed).await.is_err());
    let mut changed = request.clone();
    changed.capability.subject = Keypair::from_seed(&[99; 32]).public_key();
    assert!(runtime.invoke("root", "work", &changed).await.is_err());
    durable_write(
        &prior,
        &serde_json::to_vec(&json!({"receipt":response.receipt,"nonce":response.execution_nonce}))?,
    )?;
    if cut == "after_outcome" {
        std::process::exit(73);
    }
    durable_write(
        &dir.join("application-release.json"),
        &serde_json::to_vec(&response.output.as_ref().map(|value| match value {
            chio_kernel::ToolCallOutput::Value(value) => value.clone(),
            _ => Value::Null,
        }))?,
    )?;
    if cut == "after_release" {
        std::process::exit(74);
    }
    println!(
        "{}",
        json!({"owner":owner,"cut":cut,"tree_calls":1,
        "request_sha256":sha256_hex(&canonical_json_bytes(&request)?),
        "receipt_id":response.receipt.id,"verdict":format!("{:?}", response.verdict),
        "metadata":response.receipt.metadata})
    );
    Ok(())
}

fn effects(dir: &Path) -> Result<Vec<Value>> {
    if !dir.join("effects.jsonl").exists() {
        return Ok(Vec::new());
    }
    std::fs::read_to_string(dir.join("effects.jsonl"))?
        .lines()
        .map(|line| serde_json::from_str(line).map_err(Into::into))
        .collect()
}

#[test]
fn separate_owners_keep_exact_custody_across_real_process_death() -> Result {
    for owners in [2_u8, 3] {
        for (cut, exit, first_effects, unknown) in [
            ("before_admission", 70, 1, false),
            ("before_send", 71, 0, true),
            ("after_effect", 72, 1, true),
            ("after_outcome", 73, 1, false),
            ("after_release", 74, 1, false),
        ] {
            let dir = tempfile::tempdir()?;
            let _endpoint = endpoint(dir.path())?;
            assert_eq!(phase(dir.path(), 1, cut)?.code(), Some(exit));
            for owner in 2..=owners {
                assert!(phase(dir.path(), owner, "complete")?.success());
                assert!(phase(dir.path(), owner, "complete")?.success());
            }
            let recovery = if unknown {
                "recover_unknown"
            } else {
                "complete"
            };
            for _ in 0..2 {
                assert!(phase(dir.path(), 1, recovery)?.success());
            }
            let observed = effects(dir.path())?;
            for owner in 1..=owners {
                let count = observed.iter().filter(|e| e["owner"] == owner).count();
                assert_eq!(count, if owner == 1 { first_effects } else { 1 });
            }
            println!(
                "{}",
                json!({"scenario":"separate_owners","owners":owners,"cut":cut,
                "first_owner_effects":first_effects,"first_owner_unknown":unknown,
                "other_owners_completed":owners-1,"effects":observed})
            );
        }
    }
    Ok(())
}

#[test]
fn hidden_connector_retry_is_a_counterexample_to_unqualified_effect_cardinality() -> Result {
    let dir = tempfile::tempdir()?;
    let _endpoint = endpoint(dir.path())?;
    assert!(phase(dir.path(), 1, "hidden_retry")?.success());
    assert!(phase(dir.path(), 1, "complete")?.success());
    assert_eq!(effects(dir.path())?.len(), 2);
    println!(
        "{}",
        json!({"scenario":"hidden_connector_retry","native_calls":1,
        "physical_effects":2,"profile_qualified":false})
    );
    Ok(())
}
