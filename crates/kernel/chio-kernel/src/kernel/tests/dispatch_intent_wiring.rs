// Dispatch-intent journal wiring across the evaluator paths.
//
// Included by `src/kernel/tests.rs`. Shares helper items from
// `tests/support.rs` via the surrounding `include!`s.
//
// These tests anchor the crash-window contract at the evaluation level:
//   * the tenant recorded on a journaled intent always equals the tenant the
//     terminal receipt resolves for the same request, so the consuming append
//     can never strand an intent behind a tenant mismatch;
//   * a scope guard left alive by a sibling task on the resuming worker
//     thread never leaks its tenant into another request's intent or receipt.

/// Guard that parks the named request on the blocking pool until released,
/// creating a deterministic suspension point between the evaluation's
/// tenant-scope install and its dispatch-intent write. Every other request
/// passes straight through.
struct HoldRequestGuard {
    request_id: String,
    entered: std::sync::mpsc::Sender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

impl Guard for HoldRequestGuard {
    fn name(&self) -> &str {
        "hold-request"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        if ctx.request.request_id == self.request_id {
            let _ = self.entered.send(());
            if let Ok(release) = self.release.lock() {
                let _ = release.recv_timeout(std::time::Duration::from_secs(30));
            }
        }
        Ok(GuardDecision::allow())
    }
}

/// (open-intent count, journaled tenant) pairs observed from inside a tool
/// invocation.
type ObservedIntentJournal = std::sync::Arc<Mutex<Vec<(i64, Option<String>)>>>;

/// Tool server that inspects the dispatch-intent journal from INSIDE
/// `invoke`, capturing the number of open rows and the journaled tenant for
/// its own request at the moment the effect runs. Reads the store file over
/// its own connection so it observes exactly what would survive a crash.
struct IntentProbeServer {
    id: String,
    tools: Vec<String>,
    db_path: PathBuf,
    seen: ObservedIntentJournal,
}

#[async_trait::async_trait]
impl ToolServerConnection for IntentProbeServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        let connection = Connection::open(&self.db_path)
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        let open: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM chio_dispatch_intents WHERE state = 'open'",
                [],
                |row| row.get(0),
            )
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        let tenant: Option<String> = connection
            .query_row(
                "SELECT tenant_id FROM chio_dispatch_intents WHERE state = 'open' LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| KernelError::Internal(error.to_string()))?
            .flatten();
        if let Ok(mut seen) = self.seen.lock() {
            seen.push((open, tenant));
        }
        Ok(serde_json::json!({"status": "ok"}))
    }
}

#[test]
fn nested_flow_dispatch_journals_a_durable_intent_and_consumes_it_on_allow(
) -> Result<(), Box<dyn std::error::Error>> {
    // The nested-flow evaluator shares the crash-window contract with the
    // top-level path: a side-effecting nested dispatch must observe its own
    // durable intent (written before the tool runs, tagged with the
    // request-scoped tenant) and the terminal allow receipt must consume it.
    let path = unique_receipt_db_path("chio-intent-nested-journal");
    let mut config = make_config();
    config.dispatch_intent_journal = crate::DispatchIntentJournalMode::SideEffecting;
    let mut kernel = make_kernel(config);
    let store = std::sync::Arc::new(SqliteReceiptStore::open(&path)?);
    kernel.set_receipt_store_handle(
        std::sync::Arc::clone(&store) as std::sync::Arc<dyn crate::receipt_store::ReceiptStore>
    )?;

    let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
    kernel.register_tool_server(Box::new(IntentProbeServer {
        id: "srv-nested".to_string(),
        tools: vec!["destructive_update".to_string()],
        db_path: path.clone(),
        seen: std::sync::Arc::clone(&seen),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-nested", "destructive_update")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.set_session_auth_context(&session_id, oauth_auth_with_enterprise_tenant("tenant-A"))?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-nested-intent",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request("req-nested-intent", &cap, "destructive_update", "srv-nested");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let response = rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    })?;

    assert!(
        matches!(response.verdict, Verdict::Allow),
        "expected Allow, got {:?}: {:?}",
        response.verdict,
        response.reason
    );
    let seen = seen.lock().map_err(|_| "probe lock poisoned")?.clone();
    assert_eq!(
        seen,
        vec![(1, Some("tenant-A".to_string()))],
        "the nested dispatch must observe its own durable intent, tagged \
         with the session tenant"
    );
    assert_eq!(
        response.receipt.tenant_id.as_deref(),
        Some("tenant-A"),
        "the nested terminal receipt carries the request-scoped tenant"
    );
    assert_eq!(
        ReceiptStore::open_dispatch_intent_count(store.as_ref())?,
        0,
        "the nested allow receipt consumed the intent"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Minimal append-only store whose boot reconciliation always fails.
struct ReconcileFailingStore;

impl crate::receipt_store::ReceiptStore for ReconcileFailingStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn reconcile_dispatch_intents(
        &self,
        _reconciler: &dyn crate::receipt_store::DispatchIntentReconciler,
    ) -> Result<crate::receipt_store::DispatchIntentReconcileReport, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "boot reconciliation failed".to_string(),
        ))
    }
}

#[test]
fn failed_boot_reconciliation_leaves_no_store_attached() -> Result<(), Box<dyn std::error::Error>>
{
    // Boot reconciliation must complete BEFORE the store serves: if it
    // fails, the attach is refused and the kernel keeps no store handle, so
    // no new dispatch can interleave with (or run ahead of) an incomplete
    // reconcile pass.
    let mut kernel = make_kernel(make_config());
    let result = kernel.set_receipt_store_handle(std::sync::Arc::new(ReconcileFailingStore));
    assert!(
        result.is_err(),
        "a failed boot reconcile must refuse the attach"
    );
    assert!(
        kernel.with_receipt_store(|_| Ok(()))?.is_none(),
        "the store must not serve after a failed boot reconciliation"
    );
    Ok(())
}

/// Tool server whose dispatch always requires URL elicitations, so the
/// evaluation returns to the caller WITHOUT any tool side effect and without
/// recording a terminal receipt.
struct UrlElicitingServer {
    id: String,
    tools: Vec<String>,
}

#[async_trait::async_trait]
impl ToolServerConnection for UrlElicitingServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::UrlElicitationsRequired {
            message: "URL elicitation required before dispatch side effect".to_string(),
            elicitations: Vec::new(),
        })
    }
}

fn url_elicitation_journal_kernel(
    db_path: &Path,
) -> Result<(ChioKernel, std::sync::Arc<SqliteReceiptStore>), Box<dyn std::error::Error>> {
    let mut config = make_config();
    config.dispatch_intent_journal = crate::DispatchIntentJournalMode::SideEffecting;
    let mut kernel = make_kernel(config);
    let store = std::sync::Arc::new(SqliteReceiptStore::open(db_path)?);
    kernel.set_receipt_store_handle(
        std::sync::Arc::clone(&store) as std::sync::Arc<dyn crate::receipt_store::ReceiptStore>
    )?;
    kernel.register_tool_server(Box::new(UrlElicitingServer {
        id: "srv-elicit".to_string(),
        tools: vec!["write_file".to_string()],
    }));
    Ok((kernel, store))
}

#[test]
fn url_elicitation_exit_clears_the_journaled_intent(
) -> Result<(), Box<dyn std::error::Error>> {
    // UrlElicitationsRequired precedes any tool side effect and records no
    // terminal receipt, so the pre-dispatch intent must be cleared on this
    // exit: an intent left open would dead-letter as a false orphan at the
    // next boot even though nothing executed.
    let path = unique_receipt_db_path("chio-intent-elicitation-clear");
    let (kernel, store) = url_elicitation_journal_kernel(&path)?;

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-elicit", "write_file")]),
        300,
    );
    let request = make_request("req-elicit-clear", &cap, "write_file", "srv-elicit");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(kernel.evaluate_tool_call(&request));
    assert!(
        matches!(result, Err(KernelError::UrlElicitationsRequired { .. })),
        "the elicitation error must propagate to the caller"
    );
    assert_eq!(
        ReceiptStore::open_dispatch_intent_count(store.as_ref())?,
        0,
        "a non-dispatch elicitation exit must not leave an open intent"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn nested_flow_url_elicitation_exit_clears_the_journaled_intent(
) -> Result<(), Box<dyn std::error::Error>> {
    // Same contract on the nested-flow evaluator: its elicitation arm also
    // returns without dispatching or recording a terminal receipt, so it
    // must clear the intent it journaled.
    let path = unique_receipt_db_path("chio-intent-elicitation-clear-nested");
    let (kernel, store) = url_elicitation_journal_kernel(&path)?;

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-elicit", "write_file")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-elicit-clear-nested",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request("req-elicit-clear-nested", &cap, "write_file", "srv-elicit");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    });
    assert!(
        matches!(result, Err(KernelError::UrlElicitationsRequired { .. })),
        "the elicitation error must propagate to the caller"
    );
    assert_eq!(
        ReceiptStore::open_dispatch_intent_count(store.as_ref())?,
        0,
        "a nested non-dispatch elicitation exit must not leave an open intent"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn intent_and_receipt_tenant_ignore_a_foreign_thread_scope(
) -> Result<(), Box<dyn std::error::Error>> {
    // A tenant-scoped sibling task can hold its thread-local scope guard
    // across an await, so the worker that resumes THIS evaluation after its
    // guard-pipeline suspension may carry a foreign tenant in the thread
    // local. The request-scoped tenant resolution must win on both the
    // intent write and the terminal receipt: a sessionless call stays
    // untagged and its intent is consumed by its receipt.
    let path = unique_receipt_db_path("chio-intent-tenant-isolation");
    let mut config = make_config();
    config.dispatch_intent_journal = crate::DispatchIntentJournalMode::SideEffecting;
    // Force the guard pipeline onto the blocking pool so the evaluation
    // genuinely suspends (and can resume under a foreign scope) even on a
    // current-thread runtime.
    config.deadlines.always_offload_guards = true;
    let mut kernel = make_kernel(config);
    let store = std::sync::Arc::new(SqliteReceiptStore::open(&path)?);
    kernel.set_receipt_store_handle(
        std::sync::Arc::clone(&store) as std::sync::Arc<dyn crate::receipt_store::ReceiptStore>
    )?;
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["write_file"])));

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    kernel.add_guard(Box::new(HoldRequestGuard {
        request_id: "req-tenant-isolated".to_string(),
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-a", "write_file")]),
        300,
    );
    let request = make_request("req-tenant-isolated", &cap, "write_file", "srv-a");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let response: Result<_, Box<dyn std::error::Error>> = rt.block_on(async {
        let evaluation = kernel.evaluate_tool_call(&request);
        tokio::pin!(evaluation);
        // Drive the evaluation until it parks inside its guard on the
        // blocking pool; the entered signal proves it suspended after
        // installing its own (empty) tenant scopes.
        let entered = tokio::task::spawn_blocking(move || entered_rx.recv());
        tokio::pin!(entered);
        tokio::select! {
            _ = &mut evaluation => panic!("the evaluation must park in the guard"),
            joined = &mut entered => {
                joined??;
            }
        }
        // Model the sibling task: a foreign tenant scope alive on the very
        // thread that resumes the parked evaluation.
        let _foreign = scope_receipt_tenant_id(Some("tenant-foreign".to_string()));
        release_tx.send(())?;
        evaluation.await.map_err(Into::into)
    });
    let response = response?;

    assert!(
        matches!(response.verdict, Verdict::Allow),
        "expected Allow, got {:?}: {:?}",
        response.verdict,
        response.reason
    );
    assert!(
        response.receipt.tenant_id.is_none(),
        "a sessionless call must not adopt a foreign task's tenant scope \
         (got {:?})",
        response.receipt.tenant_id
    );
    store.flush_receipt_writes()?;
    assert_eq!(
        store.open_dispatch_intent_count()?,
        0,
        "the terminal receipt consumed the intent under the same tenant"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}
