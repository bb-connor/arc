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
