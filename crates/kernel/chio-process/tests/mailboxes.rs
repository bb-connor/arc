#![cfg(feature = "mailboxes")]

mod support;

use std::path::Path;
use std::sync::Arc;

use chio_core_types::capability::attenuation::scope_hash;
use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core_types::crypto::Keypair;
use chio_kernel::{
    ChioKernel, KernelError, NestedFlowBridge, ToolCallOutput, ToolCallResponse,
    ToolServerConnection, Verdict,
};
use chio_process::mailboxes::{MailboxConfig, MailboxLimits, MailboxServer, SERVER_ID};
use chio_process::{ProcessError, ProcessRuntime};
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

fn config() -> Vec<MailboxConfig> {
    ["jobs", "other"]
        .into_iter()
        .map(|id| MailboxConfig {
            id: id.into(),
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

fn processes(path: &Path, kernel: Arc<ChioKernel>) -> Result<ProcessRuntime> {
    let runtime = ProcessRuntime::open(path.join("process.db"), kernel.clone())?;
    let parent = kernel.issue_capability(
        &support::parent_key().public_key(),
        scope(&[
            "send_jobs",
            "receive_jobs",
            "ack_jobs",
            "send_other",
            "receive_other",
            "ack_other",
        ]),
        3600,
    )?;
    runtime.create_root("root", &parent, support::limits(100))?;
    for (id, names) in [
        ("sender", vec!["send_jobs"]),
        ("receiver", vec!["receive_jobs", "ack_jobs"]),
        ("outsider", vec!["receive_other"]),
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
            json!([{"sequence": "1", "payload": {"text": "ready"}}])
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
