//! Measure the existing mailbox/resource boundary without changing its contract.
//! The baseline resource has durable operation deduplication and version checks.
//! This is deterministic native execution, not live-model workload evidence.

#![cfg(feature = "mailboxes")]

mod support;

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chio_core_types::capability::attenuation::scope_hash;
use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair};
use chio_kernel::{
    ChioKernel, KernelError, NestedFlowBridge, ToolCallOutput, ToolCallResponse,
    ToolInvocationContext, ToolInvocationCost, ToolServerConnection, Verdict,
};
use chio_process::mailboxes::{MailboxConfig, MailboxLimits, MailboxServer, SERVER_ID};
use chio_process::{ProcessError, ProcessRegistry, ProcessRuntime};
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use support::Result;

/// Application-owned CAS resource, independent of the kernel/mailbox journals.
struct Resource(Mutex<rusqlite::Connection>);

impl Resource {
    fn open(path: &Path) -> Result<Self> {
        let connection = rusqlite::Connection::open(path)?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS document (
               singleton INTEGER PRIMARY KEY CHECK(singleton=1),
               version INTEGER NOT NULL, value TEXT NOT NULL);
             INSERT OR IGNORE INTO document VALUES (1, 0, 'initial');
             CREATE TABLE IF NOT EXISTS operations (
               id TEXT PRIMARY KEY, request_hash TEXT NOT NULL, result TEXT NOT NULL);",
        )?;
        Ok(Self(Mutex::new(connection)))
    }

    fn execute(&self, context: &ToolInvocationContext, arguments: Value) -> Result<Value> {
        let mut connection = self.0.lock().map_err(|_| "resource lock poisoned")?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let hash = sha256_hex(&canonical_json_bytes(&json!({
            "tool": context.tool_name(), "arguments": arguments,
            "capability": context.capability_hash(),
        }))?);
        let retained: Option<(String, String)> = transaction
            .query_row(
                "SELECT request_hash, result FROM operations WHERE id=?1",
                [context.request_id()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((previous_hash, result)) = retained {
            if hash != previous_hash {
                return Err("resource operation identity conflict".into());
            }
            return Ok(serde_json::from_str(&result)?);
        }
        let (version, current): (i64, String) = transaction.query_row(
            "SELECT version, value FROM document WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let result = match context.tool_name() {
            "read" => json!({"version": version, "value": current}),
            "append" => {
                let expected = arguments["expected_version"]
                    .as_i64()
                    .ok_or("missing version")?;
                let value = arguments["value"].as_str().ok_or("missing value")?;
                if expected != version {
                    json!({"status": "version_conflict", "version": version})
                } else {
                    transaction.execute(
                        "UPDATE document SET version=version+1, value=?1 WHERE singleton=1 AND version=?2",
                        params![value, expected],
                    )?;
                    json!({"status": "committed", "version": version + 1})
                }
            }
            _ => return Err("unconfigured resource operation".into()),
        };
        transaction.execute(
            "INSERT INTO operations VALUES (?1, ?2, ?3)",
            params![context.request_id(), hash, serde_json::to_string(&result)?],
        )?;
        transaction.commit()?;
        Ok(result)
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for Resource {
    fn server_id(&self) -> &str {
        "tools"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["read".into(), "append".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        _: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        Err(KernelError::ToolServerError(
            "kernel context required".into(),
        ))
    }
    async fn invoke_with_context(
        &self,
        context: &ToolInvocationContext,
        arguments: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        // Exercise the resource's own replay contract, independently of the
        // kernel's retained outcome, by delivering each admitted request twice.
        let first = self
            .execute(context, arguments.clone())
            .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
        let replay = self
            .execute(context, arguments)
            .map_err(|error| KernelError::ToolServerError(error.to_string()))?;
        if replay != first {
            return Err(KernelError::ToolServerError(
                "resource replay changed the result".into(),
            ));
        }
        Ok(first)
    }
    async fn invoke_with_cost_and_context(
        &self,
        context: &ToolInvocationContext,
        arguments: Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<(Value, Option<ToolInvocationCost>), KernelError> {
        Ok((
            self.invoke_with_context(context, arguments, bridge).await?,
            None,
        ))
    }
}

fn combined_scope() -> ChioScope {
    let mut scope = support::scope(&["read", "append"]);
    scope.grants.extend(
        ["send_jobs", "claim_jobs", "complete_jobs"].map(|name| ToolGrant {
            server_id: SERVER_ID.into(),
            tool_name: name.into(),
            operations: vec![Operation::Invoke, Operation::Delegate],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }),
    );
    scope
        .grants
        .sort_by(|a, b| (&a.server_id, &a.tool_name).cmp(&(&b.server_id, &b.tool_name)));
    scope
}

fn host(path: &Path) -> Result<(Arc<ChioKernel>, ProcessRuntime)> {
    let resource = Resource::open(&path.join("resource.db"))?;
    let mut kernel = Arc::try_unwrap(support::kernel(path, Box::new(resource))?)
        .map_err(|_| "shared test kernel")?;
    let registry = ProcessRegistry::open(path.join("process.db"), &kernel)?;
    let mailbox = MailboxServer::open(
        path.join("mailboxes.db"),
        &kernel,
        vec![MailboxConfig {
            id: "jobs".into(),
            renewable_leases: false,
            limits: MailboxLimits {
                max_pending_messages: 2,
                max_pending_bytes: 1024,
                max_message_bytes: 512,
                max_messages: 8,
            },
        }],
    )?
    .attest_senders(registry);
    kernel.set_capability_trust_root(
        support::issuer().public_key(),
        scope_hash(&combined_scope())?,
    );
    kernel.register_tool_server(Box::new(mailbox));
    let kernel = Arc::new(kernel);
    let runtime = ProcessRuntime::open(path.join("process.db"), kernel.clone())?;
    Ok((kernel, runtime))
}

async fn call(
    runtime: &ProcessRuntime,
    process: &str,
    key: &str,
    server: &str,
    tool: &str,
    arguments: Value,
) -> Result<ToolCallResponse> {
    let request = runtime.tool_request(process, key, server, tool, arguments)?;
    Ok(Box::pin(runtime.invoke(process, key, &request)).await?)
}

fn allowed(response: &ToolCallResponse) -> Result<Value> {
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert!(response.receipt.verify_signature()?);
    match &response.output {
        Some(ToolCallOutput::Value(value)) => Ok(value.clone()),
        _ => Err("missing tool value".into()),
    }
}

#[tokio::test]
async fn mailbox_claims_do_not_fence_independent_resource_mutations() -> Result {
    let directory = tempfile::tempdir()?;
    let (kernel, runtime) = host(directory.path())?;
    let root =
        kernel.issue_capability(&support::parent_key().public_key(), combined_scope(), 3600)?;
    runtime.create_root("root", &root, support::limits(100))?;
    for id in ["old", "replacement"] {
        let cap = support::child(
            &root,
            &support::parent_key(),
            id,
            &Keypair::generate(),
            combined_scope(),
        )?;
        runtime.spawn("root", id, &cap)?;
    }
    allowed(
        &call(
            &runtime,
            "root",
            "send",
            SERVER_ID,
            "send_jobs",
            json!({"message_key": "edit", "payload": {"resource": "document"}}),
        )
        .await?,
    )?;
    let first = allowed(
        &call(
            &runtime,
            "old",
            "claim",
            SERVER_ID,
            "claim_jobs",
            json!({"limit": 1, "lease_ms": 1000}),
        )
        .await?,
    )?;
    assert_eq!(first["messages"][0]["claim"], "1");
    let deadline = first["messages"][0]["lease_expires_at_ms"]
        .as_u64()
        .ok_or("missing deadline")?;
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    tokio::time::sleep(Duration::from_millis(deadline.saturating_sub(now) + 5)).await;
    let second = allowed(
        &call(
            &runtime,
            "replacement",
            "claim",
            SERVER_ID,
            "claim_jobs",
            json!({"limit": 1, "lease_ms": 300_000}),
        )
        .await?,
    )?;
    assert_eq!(second["messages"][0]["claim"], "2");
    let superseded = call(
        &runtime,
        "old",
        "complete",
        SERVER_ID,
        "complete_jobs",
        json!({"sequence": "1", "claim": "1"}),
    )
    .await?;
    assert_eq!(superseded.verdict, Verdict::Deny);
    assert!(superseded.receipt.verify_signature()?);

    let update = json!({"expected_version": 0, "value": "replacement result"});
    let committed = call(
        &runtime,
        "replacement",
        "publish",
        "tools",
        "append",
        update.clone(),
    )
    .await?;
    assert_eq!(allowed(&committed)?["status"], "committed");
    let replay = call(
        &runtime,
        "replacement",
        "publish",
        "tools",
        "append",
        update,
    )
    .await?;
    assert_eq!(
        serde_json::to_value(&committed.receipt)?,
        serde_json::to_value(&replay.receipt)?
    );
    assert_eq!(allowed(&replay)?["version"], 1);

    let stale_version = allowed(
        &call(
            &runtime,
            "old",
            "stale-version",
            "tools",
            "append",
            json!({"expected_version": 0, "value": "old result"}),
        )
        .await?,
    )?;
    assert_eq!(stale_version["status"], "version_conflict");
    let current =
        allowed(&call(&runtime, "old", "read-current", "tools", "read", json!({})).await?)?;
    assert_eq!(current["version"], 1);
    // A new operation with the current version still has a valid tool grant.
    // This records the existing boundary, not a desired ownership guarantee.
    let stale_owner = allowed(
        &call(
            &runtime,
            "old",
            "new-publish",
            "tools",
            "append",
            json!({"expected_version": 1, "value": "superseded worker result"}),
        )
        .await?,
    )?;
    assert_eq!(stale_owner["status"], "committed");
    assert_eq!(stale_owner["version"], 2);
    let database = rusqlite::Connection::open(directory.path().join("resource.db"))?;
    let value: String =
        database.query_row("SELECT value FROM document WHERE singleton=1", [], |row| {
            row.get(0)
        })?;
    assert_eq!(value, "superseded worker result");
    runtime.cancel("old")?;
    let cancelled = runtime.tool_request(
        "old",
        "after-cancel",
        "tools",
        "append",
        json!({"expected_version": 2, "value": "cancelled"}),
    )?;
    assert!(matches!(
        Box::pin(runtime.invoke("old", "after-cancel", &cancelled)).await,
        Err(ProcessError::Cancelled(_))
    ));
    println!(
        "{}",
        json!({
            "evidence_kind": "deterministic_kernel_boundary", "live_model": false,
            "same_operation_replayed": true, "stale_version_refused": true,
            "stale_mailbox_completion_refused": true, "superseded_worker_mutations": 1,
            "final_resource_version": 2, "explicit_process_cancellation_refused": true,
        })
    );
    Ok(())
}
