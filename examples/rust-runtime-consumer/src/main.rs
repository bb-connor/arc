//! Offline embedding example: scope denial, original receipts and durable replay.
//! The fixed signing seed is demonstration data, never an operational identity.

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::receipt::body::ChioReceipt;
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolCallOutput, ToolCallRequest,
    ToolServerConnection, Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_store_sqlite::SqliteAuthorityStore;
use serde_json::{json, Value};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

struct Echo(PathBuf);

#[async_trait::async_trait]
impl ToolServerConnection for Echo {
    fn server_id(&self) -> &str {
        "preview"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["echo".into(), "forbidden".into()]
    }
    async fn invoke(
        &self,
        _tool: &str,
        arguments: Value,
        _bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        // An independent durable count exposes accidental execution on replay.
        let record = || -> std::io::Result<()> {
            let mut file = OpenOptions::new().create(true).append(true).open(&self.0)?;
            writeln!(file, "effect")?;
            file.sync_all()
        };
        record().map_err(|err| KernelError::Internal(err.to_string()))?;
        Ok(arguments)
    }
}

fn key() -> Keypair {
    Keypair::from_seed(&[39; 32])
}

fn open(state: &Path) -> Result<(SqliteAuthorityStore, ChioKernel)> {
    let authority =
        SqliteAuthorityStore::open_serving(state.join("authority.db"), state.join("locks"))?;
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: key(),
        ca_public_keys: Vec::new(),
        max_delegation_depth: 5,
        policy_hash: sha256_hex(b"rust-preview-embedding"),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        // The admission authority persists the original signed outcome. This
        // small embedding example does not claim a durable transparency log.
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    });
    kernel.set_durable_admission_store(
        Arc::new(authority.admission_operation_store()),
        Arc::new(authority.tool_outcome_store()),
        authority.mutation_fence(),
    )?;
    kernel.register_tool_server(Box::new(Echo(state.join("effects.txt"))));
    kernel.reconcile_durable_admission_startup()?;
    Ok((authority, kernel))
}

fn verify(receipt: &ChioReceipt) -> Result<()> {
    if receipt.kernel_key != key().public_key() || !receipt.verify_signature()? {
        return Err("receipt does not verify against the pinned example identity".into());
    }
    Ok(())
}

fn initial(state: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(state)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(state.join("locks"))?;
    SqliteAuthorityStore::provision(state.join("authority.db"), state.join("locks"))?;
    let (authority, kernel) = open(state)?;
    let agent = Keypair::generate();
    let capability = kernel.issue_capability(
        &agent.public_key(),
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "preview".into(),
                tool_name: "echo".into(),
                operations: vec![Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        },
        300,
    )?;
    let request = ToolCallRequest {
        request_id: "preview-call".into(),
        agent_id: agent.public_key().to_hex(),
        capability,
        server_id: "preview".into(),
        tool_name: "echo".into(),
        arguments: json!({"value": 42}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    let Some(ToolCallOutput::Value(output)) = &response.output else {
        return Err("echo did not return a value".into());
    };
    if response.verdict != Verdict::Allow || *output != json!({"value": 42}) {
        return Err(format!("allowed call failed: {:?}", response.reason).into());
    }
    verify(&response.receipt)?;
    let mut denied = request.clone();
    denied.request_id = "preview-denied".into();
    denied.tool_name = "forbidden".into();
    let denial = kernel.evaluate_tool_call_blocking(&denied)?;
    if denial.verdict != Verdict::Deny {
        return Err("out-of-scope call was allowed".into());
    }
    verify(&denial.receipt)?;
    fs::write(state.join("request.json"), serde_json::to_vec(&request)?)?;
    fs::write(
        state.join("expected.json"),
        serde_json::to_vec(&json!({
            "receipt": response.receipt, "output": output,
            "owner_epoch": authority.mutation_fence().owner_epoch,
        }))?,
    )?;
    Ok(())
}

fn recover(state: &Path) -> Result<()> {
    let request = serde_json::from_slice(&fs::read(state.join("request.json"))?)?;
    let expected: Value = serde_json::from_slice(&fs::read(state.join("expected.json"))?)?;
    let (authority, kernel) = open(state)?;
    if authority.mutation_fence().owner_epoch
        <= expected["owner_epoch"].as_u64().ok_or("missing epoch")?
    {
        return Err("restart did not advance the serving fence".into());
    }
    let response = kernel.evaluate_tool_call_blocking(&request)?;
    verify(&response.receipt)?;
    let Some(ToolCallOutput::Value(output)) = &response.output else {
        return Err("replay did not return a value".into());
    };
    if response.verdict != Verdict::Allow
        || canonical_json_bytes(&response.receipt)? != canonical_json_bytes(&expected["receipt"])?
        || *output != expected["output"]
    {
        return Err("restart changed the original outcome or signed receipt".into());
    }
    if fs::read_to_string(state.join("effects.txt"))? != "effect\n" {
        return Err("denial or recovery executed another tool effect".into());
    }
    Ok(())
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let first = args
        .next()
        .ok_or("usage: chio-rust-preview-consumer NEW_STATE_DIRECTORY")?;
    let recovery = first == "--recover";
    let path = if recovery {
        args.next().ok_or("missing recovery state")?
    } else {
        first
    };
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let state = std::path::absolute(path)?;
    if recovery {
        return recover(&state);
    }
    initial(&state)?;
    let status = std::process::Command::new(std::env::current_exe()?)
        .arg("--recover")
        .arg(&state)
        .status()?;
    if !status.success() {
        return Err(format!("recovery child failed: {status}").into());
    }
    println!(
        "{}",
        json!({"allowed": true, "denied": true, "receipts_verified": 3,
        "restart_replayed_original": true, "tool_effects": 1})
    );
    Ok(())
}
