use super::*;
use chio_kernel::{KernelError, ToolServerConnection};
use std::future::Future;

pub(super) fn create_effect_store(path: &Path) -> TestResult {
    let raw = rusqlite::Connection::open(path.join("effects.sqlite3"))?;
    raw.execute_batch(
        "PRAGMA synchronous = FULL;
         CREATE TABLE invocations (id INTEGER PRIMARY KEY);
         CREATE TABLE effects (id INTEGER PRIMARY KEY);
         CREATE TABLE accounts (closed INTEGER NOT NULL);
         INSERT INTO accounts VALUES (0);",
    )?;
    Ok(())
}

pub(super) fn effects(path: &Path) -> TestResult<(i64, i64, bool)> {
    let raw = rusqlite::Connection::open_with_flags(
        path.join("effects.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    Ok(raw.query_row(
        "SELECT (SELECT count(*) FROM invocations), (SELECT count(*) FROM effects), closed
         FROM accounts",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?)
}

pub(super) struct DurableEffectTool {
    pub(super) path: PathBuf,
    pub(super) entered: Arc<AtomicU64>,
    pub(super) cut: Option<Cut>,
}

impl DurableEffectTool {
    fn record_entry_and_effect(&self) -> TestResult {
        let mut raw = rusqlite::Connection::open(self.path.join("effects.sqlite3"))?;
        raw.execute_batch("PRAGMA synchronous = FULL;")?;
        let transaction = raw.transaction()?;
        transaction.execute("INSERT INTO invocations DEFAULT VALUES", [])?;
        if self.cut != Some(Cut::DispatchEntered) {
            transaction.execute("INSERT INTO effects DEFAULT VALUES", [])?;
            transaction.execute("UPDATE accounts SET closed = 1", [])?;
        }
        transaction.commit()?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for DurableEffectTool {
    fn server_id(&self) -> &str {
        "vendor-ledger"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["close_account".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.record_entry_and_effect()
            .map_err(|error| KernelError::Internal(format!("crash fixture effect: {error}")))?;
        self.entered.fetch_add(1, Ordering::SeqCst);
        if self.cut.is_some() {
            std::future::pending::<()>().await;
        }
        Ok(serde_json::json!({"closed": true}))
    }
}

pub(super) fn run(path: &Path, cut: Cut) -> TestResult {
    let state = harness::load_state(path)?;
    let fixture = state.open(path)?;
    let parked = Arc::new(AtomicU64::new(0));
    let mut kernel = if cut == Cut::ClaimBeforeDispatch {
        fixture.kernel(faults::FaultHook::new(
            fixture.hook()?,
            path.join("runtime.sqlite3"),
            faults::Fault::Park(parked.clone()),
        ))?
    } else {
        fixture.kernel(fixture.hook()?)?
    };
    kernel.register_tool_server(Box::new(DurableEffectTool {
        path: path.to_owned(),
        entered: parked.clone(),
        cut: Some(cut),
    }));
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut invocation = Box::pin(kernel.evaluate_tool_call_with_metadata(
                &fixture.inner.request,
                Some(swarm_route_metadata()),
            ));
            std::future::poll_fn(|cx| {
                let result = invocation.as_mut().poll(cx);
                assert!(
                    result.is_pending(),
                    "worker call completed before crash cut: {result:?}"
                );
                if parked.load(Ordering::SeqCst) > 0 {
                    std::task::Poll::Ready(())
                } else {
                    std::task::Poll::Pending
                }
            })
            .await;
            harness::write_json(
                &path.join("parked.pending"),
                &fixture.inner.authority.mutation_fence(),
            )?;
            std::fs::rename(path.join("parked.pending"), path.join("parked.json"))?;
            // Keep the live evaluation, coordinator, store and receipt log in
            // memory. Only the parent's SIGKILL ends this pending worker.
            std::future::pending::<()>().await;
            drop(invocation);
            Ok(())
        })
}
