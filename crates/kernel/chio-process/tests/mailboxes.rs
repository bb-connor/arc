#![cfg(feature = "mailboxes")]

mod support;

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chio_core_types::capability::attenuation::scope_hash;
use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core_types::crypto::Keypair;
use chio_kernel::{
    ChioKernel, KernelError, NestedFlowBridge, ToolCallOutput, ToolCallResponse,
    ToolInvocationContext, ToolInvocationCost, ToolServerConnection, Verdict,
};
use chio_process::mailboxes::{MailboxConfig, MailboxLimits, MailboxServer, SERVER_ID};
use chio_process::{ProcessError, ProcessRegistry, ProcessRuntime};
use serde_json::{json, Value};
use support::Result;

struct Unused;
#[async_trait::async_trait]
impl ToolServerConnection for Unused {
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
        Err(KernelError::ToolServerError("unused test server".into()))
    }
}

/// Inject the effect-to-kernel-journal gap without replacing the mailbox effect.
struct InterruptedRenewal(MailboxServer);

#[async_trait::async_trait]
impl ToolServerConnection for InterruptedRenewal {
    fn server_id(&self) -> &str {
        SERVER_ID
    }
    fn tool_names(&self) -> Vec<String> {
        self.0.tool_names()
    }
    async fn invoke(
        &self,
        _: &str,
        _: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        Err(KernelError::ToolServerError("context required".into()))
    }
    async fn invoke_with_context(
        &self,
        context: &ToolInvocationContext,
        arguments: Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        let result = self
            .0
            .invoke_with_context(context, arguments, bridge)
            .await?;
        if context.tool_name() == "renew_jobs" {
            return Err(KernelError::ToolServerError(
                "injected loss after committed renewal".into(),
            ));
        }
        Ok(result)
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

#[tokio::test]
async fn committed_renewal_with_unknown_kernel_outcome_is_not_redispatched() -> Result {
    let directory = tempfile::tempdir()?;
    let mut channels = config();
    channels[0].renewable_leases = true;
    let renewal = json!({"sequence": "1", "claim": "1", "lease_ms": 300_000});
    let database = directory.path().join("mailboxes.db");
    let deadline = || -> Result<i64> {
        Ok(rusqlite::Connection::open(&database)?.query_row(
            "SELECT lease_expires_at FROM mailbox_messages WHERE channel='jobs' AND sequence=1",
            [],
            |row| row.get(0),
        )?)
    };
    {
        let mut kernel = Arc::try_unwrap(support::kernel(directory.path(), Box::new(Unused))?)
            .map_err(|_| "shared kernel")?;
        let registry = ProcessRegistry::open(directory.path().join("process.db"), &kernel)?;
        let server =
            MailboxServer::open(&database, &kernel, channels.clone())?.attest_senders(registry);
        let names = server.tool_names();
        let names: Vec<_> = names.iter().map(String::as_str).collect();
        let grants = scope(&names);
        kernel.set_capability_trust_root(support::issuer().public_key(), scope_hash(&grants)?);
        kernel.register_tool_server(Box::new(InterruptedRenewal(server)));
        let kernel = Arc::new(kernel);
        let runtime = ProcessRuntime::open(directory.path().join("process.db"), kernel.clone())?;
        let cap = kernel.issue_capability(&support::parent_key().public_key(), grants, 3600)?;
        runtime.create_root("root", &cap, support::limits(100))?;
        value(
            &Box::pin(invoke(
                &runtime,
                "root",
                "send",
                "send_jobs",
                json!({"message_key": "one", "payload": 1}),
            ))
            .await?,
        )?;
        value(
            &Box::pin(invoke(
                &runtime,
                "root",
                "claim",
                "claim_jobs",
                json!({"limit": 1, "lease_ms": 60_000}),
            ))
            .await?,
        )?;
        let before = deadline()?;
        let interrupted = Box::pin(invoke(
            &runtime,
            "root",
            "renew",
            "renew_jobs",
            renewal.clone(),
        ))
        .await?;
        assert_eq!(interrupted.verdict, Verdict::Deny);
        assert!(deadline()? > before);
    }
    let retained = deadline()?;
    let kernel = attesting_kernel_with(directory.path(), channels)?;
    let runtime = ProcessRuntime::open(directory.path().join("process.db"), kernel)?;
    let replay = Box::pin(invoke(&runtime, "root", "renew", "renew_jobs", renewal)).await?;
    assert_eq!(replay.verdict, Verdict::Deny);
    assert!(replay.receipt.verify_signature()?);
    assert_eq!(
        serde_json::to_value(&replay.receipt)?["metadata"]["admission_operation"]["retained_state"],
        "outcome_unknown_after_dispatch",
    );
    assert_eq!(deadline()?, retained);
    Ok(())
}

fn config() -> Vec<MailboxConfig> {
    ["jobs", "other"]
        .into_iter()
        .map(|id| MailboxConfig {
            id: id.into(),
            renewable_leases: false,
            limits: MailboxLimits {
                max_pending_messages: 1,
                max_pending_bytes: 128,
                max_message_bytes: 128,
                max_messages: 3,
            },
        })
        .collect()
}

fn scope(names: &[&str]) -> ChioScope {
    let mut scope = ChioScope {
        grants: names
            .iter()
            .map(|name| ToolGrant {
                server_id: SERVER_ID.to_owned(),
                tool_name: (*name).to_owned(),
                operations: vec![Operation::Invoke, Operation::Delegate],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            })
            .collect(),
        ..Default::default()
    };
    scope.grants.sort_by(|a, b| a.tool_name.cmp(&b.tool_name));
    scope
}

fn kernel(path: &Path) -> Result<Arc<ChioKernel>> {
    let mut kernel = Arc::try_unwrap(support::kernel(path, Box::new(Unused))?)
        .map_err(|_| "test kernel still shared")?;
    let server = MailboxServer::open(path.join("mailboxes.db"), &kernel, config())?;
    chio_manifest::validate_manifest(&server.manifest())?;
    let names = server.tool_names();
    let names: Vec<_> = names.iter().map(String::as_str).collect();
    kernel.set_capability_trust_root(support::issuer().public_key(), scope_hash(&scope(&names))?);
    kernel.register_tool_server(Box::new(server));
    Ok(Arc::new(kernel))
}

fn attesting_kernel(path: &Path) -> Result<Arc<ChioKernel>> {
    attesting_kernel_with(path, config())
}

fn attesting_kernel_with(path: &Path, channels: Vec<MailboxConfig>) -> Result<Arc<ChioKernel>> {
    let mut kernel = Arc::try_unwrap(support::kernel(path, Box::new(Unused))?)
        .map_err(|_| "test kernel still shared")?;
    let registry = ProcessRegistry::open(path.join("process.db"), &kernel)?;
    let server =
        MailboxServer::open(path.join("mailboxes.db"), &kernel, channels)?.attest_senders(registry);
    let names = server.tool_names();
    let names: Vec<_> = names.iter().map(String::as_str).collect();
    kernel.set_capability_trust_root(support::issuer().public_key(), scope_hash(&scope(&names))?);
    kernel.register_tool_server(Box::new(server));
    Ok(Arc::new(kernel))
}

fn processes(path: &Path, kernel: Arc<ChioKernel>) -> Result<ProcessRuntime> {
    let runtime = ProcessRuntime::open(path.join("process.db"), kernel.clone())?;
    let parent = kernel.issue_capability(
        &support::parent_key().public_key(),
        scope(&[
            "send_jobs",
            "receive_jobs",
            "ack_jobs",
            "claim_jobs",
            "complete_jobs",
            "send_other",
            "receive_other",
            "ack_other",
            "claim_other",
            "complete_other",
        ]),
        3600,
    )?;
    runtime.create_root("root", &parent, support::limits(100))?;
    for (id, names) in [
        ("sender", vec!["send_jobs"]),
        ("receiver", vec!["receive_jobs", "ack_jobs"]),
        ("outsider", vec!["receive_other"]),
        ("worker_a", vec!["claim_jobs", "complete_jobs"]),
        ("worker_b", vec!["claim_jobs", "complete_jobs"]),
    ] {
        let cap = support::child(
            &parent,
            &support::parent_key(),
            id,
            &Keypair::generate(),
            scope(&names),
        )?;
        runtime.spawn("root", id, &cap)?;
    }
    Ok(runtime)
}

async fn invoke(
    runtime: &ProcessRuntime,
    id: &str,
    key: &str,
    tool: &str,
    args: Value,
) -> Result<ToolCallResponse> {
    let request = runtime.tool_request(id, key, SERVER_ID, tool, args)?;
    Ok(runtime.invoke(id, key, &request).await?)
}

#[tokio::test]
async fn renewal_requires_its_grant_and_replays_the_original_deadline_after_restart() -> Result {
    let directory = tempfile::tempdir()?;
    let mut channels = config();
    channels[0].renewable_leases = true;
    let renewal = json!({"sequence": "1", "claim": "1", "lease_ms": 300_000});
    let first = {
        let kernel = attesting_kernel_with(directory.path(), channels.clone())?;
        let runtime = ProcessRuntime::open(directory.path().join("process.db"), kernel.clone())?;
        let names = ["send_jobs", "claim_jobs", "complete_jobs", "renew_jobs"];
        let parent = kernel.issue_capability(
            &support::parent_key().public_key(),
            scope(&[
                "send_jobs",
                "receive_jobs",
                "ack_jobs",
                "claim_jobs",
                "complete_jobs",
                "renew_jobs",
                "send_other",
                "receive_other",
                "ack_other",
                "claim_other",
                "complete_other",
            ]),
            3600,
        )?;
        runtime.create_root("root", &parent, support::limits(100))?;
        for (id, grants) in [
            ("holder", &names[..]),
            ("peer", &names[..]),
            ("ungranted", &names[..3]),
        ] {
            let cap = support::child(
                &parent,
                &support::parent_key(),
                id,
                &Keypair::generate(),
                scope(grants),
            )?;
            runtime.spawn("root", id, &cap)?;
        }
        let sent = Box::pin(invoke(
            &runtime,
            "root",
            "send",
            "send_jobs",
            json!({"message_key": "one", "payload": 1}),
        ))
        .await?;
        value(&sent)?;
        let claimed = Box::pin(invoke(
            &runtime,
            "holder",
            "claim",
            "claim_jobs",
            json!({"limit": 1, "lease_ms": 60_000}),
        ))
        .await?;
        let original = value(&claimed)?;
        for id in ["peer", "ungranted"] {
            let refused = Box::pin(invoke(
                &runtime,
                id,
                "refused",
                "renew_jobs",
                renewal.clone(),
            ))
            .await?;
            assert_eq!(refused.verdict, Verdict::Deny);
            assert!(refused.receipt.verify_signature()?);
        }
        let renewed = Box::pin(invoke(
            &runtime,
            "holder",
            "renew-1",
            "renew_jobs",
            renewal.clone(),
        ))
        .await?;
        let result = value(&renewed)?;
        assert_eq!(result["status"], "renewed");
        assert!(
            result["lease_expires_at_ms"].as_u64()
                > original["messages"][0]["lease_expires_at_ms"].as_u64()
        );
        renewed
    };
    let kernel = attesting_kernel_with(directory.path(), channels.clone())?;
    let runtime = ProcessRuntime::open(directory.path().join("process.db"), kernel)?;
    let replayed = Box::pin(invoke(
        &runtime,
        "holder",
        "renew-1",
        "renew_jobs",
        renewal.clone(),
    ))
    .await?;
    assert_eq!(replayed.output, first.output);
    assert_eq!(
        serde_json::to_value(replayed.receipt)?,
        serde_json::to_value(first.receipt)?
    );
    let peer = Box::pin(invoke(
        &runtime,
        "peer",
        "claim",
        "claim_jobs",
        json!({"limit": 1, "lease_ms": 1000}),
    ))
    .await?;
    assert_eq!(value(&peer)?["messages"], json!([]));
    runtime.cancel("holder")?;
    assert!(Box::pin(invoke(
        &runtime,
        "holder",
        "renew-2",
        "renew_jobs",
        renewal.clone()
    ))
    .await
    .is_err());
    // Direct server calls, including calls to an unattesting server, cannot
    // manufacture the kernel-selected claimant.
    drop(runtime);
    let plain_kernel = support::kernel(directory.path(), Box::new(Unused))?;
    let plain = MailboxServer::open(directory.path().join("plain.db"), &plain_kernel, channels)?;
    assert!(plain.invoke("renew_jobs", renewal, None).await.is_err());
    Ok(())
}

#[test]
fn renewal_opt_in_preserves_legacy_configuration_and_manifest() -> Result {
    let directory = tempfile::tempdir()?;
    let kernel = support::kernel(directory.path(), Box::new(Unused))?;
    let legacy: MailboxConfig = serde_json::from_value(json!({"id": "jobs"}))?;
    assert!(!legacy.renewable_leases);
    assert_eq!(
        serde_json::to_value(&legacy)?,
        json!({"id": "jobs", "limits": MailboxLimits::default()})
    );
    let default = MailboxServer::open(
        directory.path().join("old.db"),
        &kernel,
        vec![legacy.clone()],
    )?;
    let mut enabled = legacy;
    enabled.renewable_leases = true;
    let current = MailboxServer::open(directory.path().join("new.db"), &kernel, vec![enabled])?;
    assert!(!current.tool_is_read_only("renew_jobs"));
    let mut manifest = current.manifest();
    chio_manifest::validate_manifest(&manifest)?;
    assert_eq!(manifest.tools.len(), default.manifest().tools.len() + 1);
    manifest.tools.retain(|tool| tool.name != "renew_jobs");
    assert_eq!(
        serde_json::to_value(manifest)?,
        serde_json::to_value(default.manifest())?
    );
    Ok(())
}

fn value(response: &ToolCallResponse) -> Result<Value> {
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert!(response.receipt.verify_signature()?);
    match response.output.clone() {
        Some(ToolCallOutput::Value(value)) => Ok(value),
        _ => Err("missing mailbox value".into()),
    }
}

#[tokio::test]
async fn real_kernel_scopes_handoffs_and_replays_acknowledged_payloads_after_restart() -> Result {
    let directory = tempfile::tempdir()?;
    let send = json!({"message_key": "review", "payload": {"text": "ready"}});
    let receive = json!({"after_sequence": "0", "limit": 1});
    let (first_send, first_read) = {
        let kernel = kernel(directory.path())?;
        let runtime = processes(directory.path(), kernel)?;
        let sent = invoke(&runtime, "sender", "send", "send_jobs", send.clone()).await?;
        assert_eq!(value(&sent)?, json!({"status": "sent", "sequence": "1"}));
        for (id, key, tool, args) in [
            ("sender", "cannot-read", "receive_jobs", receive.clone()),
            ("receiver", "cannot-send", "send_jobs", send.clone()),
            ("outsider", "wrong-channel", "receive_jobs", receive.clone()),
        ] {
            assert_eq!(
                invoke(&runtime, id, key, tool, args).await?.verdict,
                Verdict::Deny
            );
        }
        let read = invoke(
            &runtime,
            "receiver",
            "read",
            "receive_jobs",
            receive.clone(),
        )
        .await?;
        assert_eq!(
            value(&read)?["messages"],
            json!([{"sequence": "1", "payload": {"text": "ready"}, "sender": null}])
        );
        let ack = invoke(
            &runtime,
            "receiver",
            "ack",
            "ack_jobs",
            json!({"through_sequence": "1"}),
        )
        .await?;
        assert_eq!(value(&ack)?["status"], "acknowledged");
        let old_cursor = invoke(
            &runtime,
            "receiver",
            "new-read",
            "receive_jobs",
            receive.clone(),
        )
        .await?;
        assert_eq!(value(&old_cursor)?["status"], "cursor_expired");
        let duplicate = invoke(&runtime, "sender", "duplicate", "send_jobs", send.clone()).await?;
        assert_eq!(
            value(&duplicate)?,
            json!({"status": "acknowledged", "sequence": "1"})
        );
        let changed = invoke(
            &runtime,
            "sender",
            "changed-payload",
            "send_jobs",
            json!({"message_key": "review", "payload": {"text": "different"}}),
        )
        .await?;
        assert_eq!(changed.verdict, Verdict::Deny);
        (sent, read)
    };
    let kernel = kernel(directory.path())?;
    let runtime = ProcessRuntime::open(directory.path().join("process.db"), kernel)?;
    let replayed_send = invoke(&runtime, "sender", "send", "send_jobs", send).await?;
    let replayed_read = invoke(
        &runtime,
        "receiver",
        "read",
        "receive_jobs",
        receive.clone(),
    )
    .await?;
    assert_eq!(
        serde_json::to_value(replayed_send.receipt)?,
        serde_json::to_value(first_send.receipt)?
    );
    assert_eq!(
        serde_json::to_value(&replayed_read.receipt)?,
        serde_json::to_value(first_read.receipt)?
    );
    assert_eq!(replayed_read.output, first_read.output);
    runtime.cancel("receiver")?;
    let request = runtime.tool_request("receiver", "read", SERVER_ID, "receive_jobs", receive)?;
    assert!(matches!(
        runtime.invoke("receiver", "read", &request).await,
        Err(ProcessError::Cancelled(_))
    ));
    Ok(())
}

#[tokio::test]
async fn pending_capacity_lifetime_limits_and_message_keys_survive_acknowledgement() -> Result {
    let directory = tempfile::tempdir()?;
    let kernel = kernel(directory.path())?;
    let server = MailboxServer::open(directory.path().join("mailboxes.db"), &kernel, config())?;
    for sequence in 1..=3 {
        let sent = server.invoke("send_jobs", json!({"message_key": format!("message-{sequence}"), "payload": {"data": sequence}}), None).await?;
        assert_eq!(sent["sequence"], sequence.to_string());
        let other = server
            .invoke(
                "send_jobs",
                json!({"message_key": "blocked", "payload": {}}),
                None,
            )
            .await?;
        assert_eq!(
            other["status"],
            if sequence == 3 { "exhausted" } else { "full" }
        );
        let messages = server
            .invoke(
                "receive_jobs",
                json!({"after_sequence": (sequence - 1).to_string(), "limit": 16}),
                None,
            )
            .await?;
        assert_eq!(messages["messages"].as_array().map(Vec::len), Some(1));
        server
            .invoke(
                "ack_jobs",
                json!({"through_sequence": sequence.to_string()}),
                None,
            )
            .await?;
    }
    let duplicate = server
        .invoke(
            "send_jobs",
            json!({"message_key": "message-1", "payload": {"data": 1}}),
            None,
        )
        .await?;
    assert_eq!(
        duplicate,
        json!({"status": "acknowledged", "sequence": "1"})
    );
    let repeated_ack = server
        .invoke("ack_jobs", json!({"through_sequence": "1"}), None)
        .await?;
    assert_eq!(repeated_ack["through_sequence"], "3");
    for (tool, args) in [
        (
            "send_jobs",
            json!({"message_key": "message-1", "payload": "changed"}),
        ),
        (
            "send_jobs",
            json!({"message_key": "large", "payload": "x".repeat(129)}),
        ),
        ("receive_jobs", json!({"after_sequence": "03", "limit": 1})),
        ("receive_jobs", json!({"after_sequence": "3", "limit": 17})),
        ("receive_jobs", json!({"after_sequence": "4", "limit": 1})),
        ("ack_jobs", json!({"through_sequence": "4"})),
        (
            "send_jobs",
            json!({"message_key": "other", "payload": {}, "sender": "forged"}),
        ),
    ] {
        assert!(server.invoke(tool, args, None).await.is_err());
    }
    Ok(())
}

#[tokio::test]
async fn byte_capacity_frees_after_ack_and_full_results_need_a_new_poll() -> Result {
    let directory = tempfile::tempdir()?;
    let kernel = kernel(directory.path())?;
    let mut channels = config();
    channels[0].limits.max_pending_messages = 2;
    let server = MailboxServer::open(directory.path().join("bytes.db"), &kernel, channels)?;
    // Both fit the per-message and count limits, but not the combined byte limit.
    // Canonical UTF-8 bytes include the JSON string quotes.
    let payload = json!("é".repeat(40));
    for (key, expected) in [("first", "sent"), ("second", "full")] {
        let result = server
            .invoke(
                "send_jobs",
                json!({"message_key": key, "payload": payload}),
                None,
            )
            .await?;
        assert_eq!(result["status"], expected);
    }
    server
        .invoke("ack_jobs", json!({"through_sequence": "1"}), None)
        .await?;
    let result = server
        .invoke(
            "send_jobs",
            json!({"message_key": "second", "payload": payload}),
            None,
        )
        .await?;
    assert_eq!(result, json!({"status": "sent", "sequence": "2"}));

    let runtime = processes(directory.path(), kernel)?;
    let args = json!({"after_sequence": "0", "limit": 1});
    let empty = invoke(&runtime, "receiver", "poll-1", "receive_jobs", args.clone()).await?;
    assert_eq!(value(&empty)?["messages"], json!([]));
    invoke(
        &runtime,
        "sender",
        "send",
        "send_jobs",
        json!({"message_key": "new", "payload": "arrived"}),
    )
    .await?;
    let replay = invoke(&runtime, "receiver", "poll-1", "receive_jobs", args.clone()).await?;
    assert_eq!(value(&replay)?["messages"], json!([]));
    assert_eq!(
        serde_json::to_value(replay.receipt)?,
        serde_json::to_value(empty.receipt)?
    );
    let fresh = invoke(&runtime, "receiver", "poll-2", "receive_jobs", args).await?;
    assert_eq!(value(&fresh)?["messages"][0]["payload"], "arrived");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn capacity_serializes_across_independent_database_connections() -> Result {
    let directory = tempfile::tempdir()?;
    let kernel = kernel(directory.path())?;
    let first = Arc::new(MailboxServer::open(
        directory.path().join("mailboxes.db"),
        &kernel,
        config(),
    )?);
    let second = Arc::new(MailboxServer::open(
        directory.path().join("mailboxes.db"),
        &kernel,
        config(),
    )?);
    let barrier = Arc::new(tokio::sync::Barrier::new(8));
    let mut tasks = Vec::new();
    for number in 0..8 {
        let server = if number % 2 == 0 {
            first.clone()
        } else {
            second.clone()
        };
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            server.invoke("send_jobs", json!({"message_key": format!("worker-{number}"), "payload": {"number": number}}), None).await
        }));
    }
    let mut sent = 0;
    for task in tasks {
        let result = task.await??;
        if result["status"] == "sent" {
            sent += 1;
        } else {
            assert_eq!(result["status"], "full");
        }
    }
    assert_eq!(sent, 1);
    let mut changed = config();
    changed[0].limits.max_messages += 1;
    assert!(MailboxServer::open(directory.path().join("mailboxes.db"), &kernel, changed).is_err());
    let other_directory = tempfile::tempdir()?;
    let other_kernel = support::kernel(other_directory.path(), Box::new(Unused))?;
    assert!(MailboxServer::open(
        directory.path().join("mailboxes.db"),
        &other_kernel,
        config()
    )
    .is_err());
    Ok(())
}

#[tokio::test]
async fn attesting_hosts_record_the_kernel_selected_sender_and_bind_keys_to_it() -> Result {
    let directory = tempfile::tempdir()?;
    // A payload claiming another sender changes nothing: identity comes from the kernel.
    let send = json!({"message_key": "review", "payload": {"text": "ready", "sender": "receiver"}});
    let receive = json!({"after_sequence": "0", "limit": 2});
    {
        let kernel = attesting_kernel(directory.path())?;
        let runtime = processes(directory.path(), kernel)?;
        let sent = invoke(&runtime, "sender", "send", "send_jobs", send.clone()).await?;
        assert_eq!(value(&sent)?, json!({"status": "sent", "sequence": "1"}));
        let read = invoke(
            &runtime,
            "receiver",
            "read",
            "receive_jobs",
            receive.clone(),
        )
        .await?;
        assert_eq!(
            value(&read)?["messages"],
            json!([{"sequence": "1", "payload": {"text": "ready", "sender": "receiver"}, "sender": "sender"}])
        );
        // The root holds the same send grant, but the key already belongs to "sender".
        let taken = invoke(&runtime, "root", "reuse", "send_jobs", send.clone()).await?;
        assert_eq!(taken.verdict, Verdict::Deny);
        let replay = invoke(&runtime, "sender", "replay", "send_jobs", send.clone()).await?;
        assert_eq!(value(&replay)?, json!({"status": "sent", "sequence": "1"}));
    }
    let kernel = attesting_kernel(directory.path())?;
    let runtime = ProcessRuntime::open(directory.path().join("process.db"), kernel)?;
    let read = invoke(&runtime, "receiver", "later", "receive_jobs", receive).await?;
    assert_eq!(value(&read)?["messages"][0]["sender"], "sender");
    Ok(())
}

#[tokio::test]
async fn attesting_servers_refuse_sends_without_a_kernel_caller() -> Result {
    let directory = tempfile::tempdir()?;
    let kernel = support::kernel(directory.path(), Box::new(Unused))?;
    let registry = ProcessRegistry::open(directory.path().join("process.db"), &kernel)?;
    let server = MailboxServer::open(directory.path().join("mailboxes.db"), &kernel, config())?
        .attest_senders(registry);
    let send = json!({"message_key": "review", "payload": {"text": "ready"}});
    assert!(server.invoke("send_jobs", send, None).await.is_err());
    let receive = json!({"after_sequence": "0", "limit": 1});
    assert_eq!(
        server.invoke("receive_jobs", receive, None).await?["messages"],
        json!([])
    );
    Ok(())
}

fn sequences(response: &ToolCallResponse) -> Result<Vec<(String, String)>> {
    let messages = value(response)?["messages"].clone();
    let messages = messages
        .as_array()
        .ok_or("claim returned no message array")?;
    Ok(messages
        .iter()
        .map(|message| {
            (
                message["sequence"].as_str().unwrap_or_default().to_owned(),
                message["claim"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect())
}

async fn send_three_jobs(runtime: &ProcessRuntime) -> Result<()> {
    for number in 1..=3 {
        let sent = invoke(
            runtime,
            "sender",
            &format!("send-{number}"),
            "send_jobs",
            json!({"message_key": format!("job-{number}"), "payload": {"job": number}}),
        )
        .await?;
        assert_eq!(value(&sent)?["sequence"], number.to_string());
    }
    Ok(())
}

/// Two workers claim disjoint messages; the first completes one of its two.
async fn first_claims(runtime: &ProcessRuntime, claim: &Value) -> Result<ToolCallResponse> {
    let first = invoke(runtime, "worker_a", "claim-1", "claim_jobs", claim.clone()).await?;
    assert_eq!(
        sequences(&first)?,
        vec![
            ("1".to_owned(), "1".to_owned()),
            ("2".to_owned(), "1".to_owned())
        ]
    );
    let message = &value(&first)?["messages"][0];
    assert_eq!(message["payload"], json!({"job": 1}));
    assert_eq!(message["sender"], "sender");
    assert!(message["lease_expires_at_ms"].as_u64().is_some());
    let second = invoke(runtime, "worker_b", "claim-1", "claim_jobs", claim.clone()).await?;
    assert_eq!(sequences(&second)?, vec![("3".to_owned(), "1".to_owned())]);
    // Claims consume nothing: every message is still pending for readers.
    let read = invoke(
        runtime,
        "receiver",
        "read",
        "receive_jobs",
        json!({"after_sequence": "0", "limit": 16}),
    )
    .await?;
    assert_eq!(value(&read)?["messages"].as_array().map(Vec::len), Some(3));
    let done = invoke(
        runtime,
        "worker_a",
        "complete-1",
        "complete_jobs",
        json!({"sequence": "1", "claim": "1"}),
    )
    .await?;
    assert_eq!(
        value(&done)?,
        json!({"status": "completed", "sequence": "1"})
    );
    let again = invoke(
        runtime,
        "worker_a",
        "complete-1-again",
        "complete_jobs",
        json!({"sequence": "1", "claim": "1"}),
    )
    .await?;
    assert_eq!(value(&again)?["status"], "completed");
    Ok(first)
}

async fn refused_completions_and_claims(runtime: &ProcessRuntime) -> Result<()> {
    for (id, key, args) in [
        (
            "worker_b",
            "not-mine",
            json!({"sequence": "2", "claim": "1"}),
        ),
        (
            "worker_a",
            "wrong-claim",
            json!({"sequence": "2", "claim": "2"}),
        ),
        (
            "worker_a",
            "unclaimed",
            json!({"sequence": "4", "claim": "1"}),
        ),
        (
            "worker_a",
            "no-message",
            json!({"sequence": "9", "claim": "1"}),
        ),
        (
            "worker_a",
            "zero-claim",
            json!({"sequence": "2", "claim": "0"}),
        ),
    ] {
        assert_eq!(
            invoke(runtime, id, key, "complete_jobs", args)
                .await?
                .verdict,
            Verdict::Deny,
            "{key}"
        );
    }
    for (key, args) in [
        ("short-lease", json!({"limit": 1, "lease_ms": 999})),
        ("long-lease", json!({"limit": 1, "lease_ms": 300001})),
        ("no-limit", json!({"limit": 0, "lease_ms": 1000})),
        ("wide-limit", json!({"limit": 17, "lease_ms": 1000})),
    ] {
        assert_eq!(
            invoke(runtime, "worker_a", key, "claim_jobs", args)
                .await?
                .verdict,
            Verdict::Deny,
            "{key}"
        );
    }
    Ok(())
}

/// Both leases expire: the pool hands the messages out again under a new
/// generation, and the earlier holder can no longer complete them.
async fn reclaim_and_drain(runtime: &ProcessRuntime, claim: &Value) -> Result<()> {
    let reclaimed = invoke(runtime, "worker_b", "claim-2", "claim_jobs", claim.clone()).await?;
    assert_eq!(
        sequences(&reclaimed)?,
        vec![
            ("2".to_owned(), "2".to_owned()),
            ("3".to_owned(), "2".to_owned())
        ]
    );
    let stale = invoke(
        runtime,
        "worker_a",
        "complete-2",
        "complete_jobs",
        json!({"sequence": "2", "claim": "1"}),
    )
    .await?;
    assert_eq!(stale.verdict, Verdict::Deny);
    for sequence in ["2", "3"] {
        let done = invoke(
            runtime,
            "worker_b",
            &format!("complete-{sequence}"),
            "complete_jobs",
            json!({"sequence": sequence, "claim": "2"}),
        )
        .await?;
        assert_eq!(value(&done)?["status"], "completed");
    }
    let drained = invoke(
        runtime,
        "receiver",
        "read-drained",
        "receive_jobs",
        json!({"after_sequence": "0", "limit": 16}),
    )
    .await?;
    assert_eq!(value(&drained)?["messages"], json!([]));
    let empty = invoke(
        runtime,
        "worker_a",
        "claim-empty",
        "claim_jobs",
        claim.clone(),
    )
    .await?;
    assert_eq!(value(&empty)?, json!({"status": "claimed", "messages": []}));
    Ok(())
}

#[tokio::test]
async fn competing_consumers_claim_disjoint_messages_under_fenced_leases() -> Result {
    let directory = tempfile::tempdir()?;
    let mut channels = config();
    channels[0].limits = MailboxLimits {
        max_pending_messages: 4,
        max_pending_bytes: 1024,
        max_message_bytes: 128,
        max_messages: 8,
    };
    let claim = json!({"limit": 2, "lease_ms": 300_000});
    // Each stage is boxed: together their futures exceed a test thread's stack
    // in a debug build.
    let first_claim = {
        let kernel = attesting_kernel_with(directory.path(), channels.clone())?;
        let runtime = processes(directory.path(), kernel)?;
        Box::pin(send_three_jobs(&runtime)).await?;
        let first = Box::pin(first_claims(&runtime, &claim)).await?;
        Box::pin(refused_completions_and_claims(&runtime)).await?;
        first
    };
    // Seed expired leases while the host is stopped. Store tests exercise
    // the exact clock boundary; durable kernel calls must not race a short lease.
    rusqlite::Connection::open(directory.path().join("mailboxes.db"))?.execute(
        "UPDATE mailbox_messages SET lease_expires_at = 1 WHERE claimant IS NOT NULL",
        [],
    )?;
    let kernel = attesting_kernel_with(directory.path(), channels)?;
    let runtime = ProcessRuntime::open(directory.path().join("process.db"), kernel)?;
    Box::pin(reclaim_and_drain(&runtime, &claim)).await?;
    let replayed = invoke(&runtime, "worker_a", "claim-1", "claim_jobs", claim).await?;
    assert_eq!(
        serde_json::to_value(replayed.receipt)?,
        serde_json::to_value(first_claim.receipt)?
    );
    assert_eq!(replayed.output, first_claim.output);
    Ok(())
}

#[tokio::test]
async fn claims_require_an_attested_caller() -> Result {
    let directory = tempfile::tempdir()?;
    let kernel = support::kernel(directory.path(), Box::new(Unused))?;
    let unattested = MailboxServer::open(directory.path().join("plain.db"), &kernel, config())?;
    let registry = ProcessRegistry::open(directory.path().join("process.db"), &kernel)?;
    let attesting = MailboxServer::open(directory.path().join("mailboxes.db"), &kernel, config())?
        .attest_senders(registry);
    for server in [&unattested, &attesting] {
        assert!(server
            .invoke("claim_jobs", json!({"limit": 1, "lease_ms": 1000}), None)
            .await
            .is_err());
        assert!(server
            .invoke(
                "complete_jobs",
                json!({"sequence": "1", "claim": "1"}),
                None
            )
            .await
            .is_err());
    }
    Ok(())
}

#[tokio::test]
async fn receive_waits_for_a_send_within_its_bound() -> Result {
    let directory = tempfile::tempdir()?;
    let kernel = attesting_kernel(directory.path())?;
    let runtime = processes(directory.path(), kernel)?;
    let started = Instant::now();
    let empty = invoke(
        &runtime,
        "receiver",
        "wait-empty",
        "receive_jobs",
        json!({"after_sequence": "0", "limit": 1, "wait_ms": 300}),
    )
    .await?;
    assert_eq!(value(&empty)?["messages"], json!([]));
    assert!(started.elapsed() >= Duration::from_millis(300));
    let started = Instant::now();
    let (sent, received) = tokio::join!(
        async {
            tokio::time::sleep(Duration::from_millis(400)).await;
            invoke(
                &runtime,
                "sender",
                "send",
                "send_jobs",
                json!({"message_key": "job", "payload": {"text": "ready"}}),
            )
            .await
        },
        invoke(
            &runtime,
            "receiver",
            "wait-ready",
            "receive_jobs",
            json!({"after_sequence": "0", "limit": 1, "wait_ms": 10_000}),
        ),
    );
    assert_eq!(value(&sent?)?["status"], "sent");
    let received = received?;
    assert_eq!(
        value(&received)?["messages"][0]["payload"],
        json!({"text": "ready"})
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    let too_long = invoke(
        &runtime,
        "receiver",
        "wait-long",
        "receive_jobs",
        json!({"after_sequence": "0", "limit": 1, "wait_ms": 30_001}),
    )
    .await?;
    assert_eq!(too_long.verdict, Verdict::Deny);
    Ok(())
}
