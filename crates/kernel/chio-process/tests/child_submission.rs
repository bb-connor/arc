mod support;

use std::sync::{Arc, Mutex, OnceLock};

use chio_core_types::crypto::Keypair;
use chio_kernel::{
    KernelError, NestedFlowBridge, ToolInvocationContext, ToolServerConnection, Verdict,
};
use chio_process::{ChildSubmission, ProcessError, ProcessRegistry, ProcessRuntime};
use serde_json::{json, Value};
use support::Result;

struct Probe(Arc<Mutex<Vec<ToolInvocationContext>>>);

#[async_trait::async_trait]
impl ToolServerConnection for Probe {
    fn server_id(&self) -> &str {
        "tools"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["append".to_owned(), "read".to_owned()]
    }
    async fn invoke(
        &self,
        _: &str,
        _: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        Err(KernelError::Internal("context required".to_owned()))
    }
    async fn invoke_with_context(
        &self,
        context: &ToolInvocationContext,
        _: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        self.0
            .lock()
            .map_err(|_| KernelError::Internal("probe poisoned".to_owned()))?
            .push(context.clone());
        Ok(json!({"bound": true}))
    }
}

fn submit(
    registry: &ProcessRegistry,
    context: &ToolInvocationContext,
    input: &Value,
) -> std::result::Result<chio_process::ChildWork, ProcessError> {
    registry.submit_child(
        ChildSubmission {
            context,
            template: "read",
            input,
            budget_share_bps: 1000,
            max_submissions: 128,
        },
        |parent, signer, subject| {
            support::child(
                parent,
                signer,
                &uuid::Uuid::new_v4().to_string(),
                subject,
                support::scope(&["read"]),
            )
            .map_err(|_| ProcessError::Invalid("test issuance failed"))
        },
    )
}

#[tokio::test]
async fn child_key_work_and_call_binding_commit_together_and_cannot_be_rebound() -> Result {
    let directory = tempfile::tempdir()?;
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let kernel = support::kernel(directory.path(), Box::new(Probe(contexts.clone())))?;
    let runtime = ProcessRuntime::open(directory.path().join("process.db"), kernel.clone())?;
    support::root(&runtime, &kernel, 20)?;
    let registry = runtime.registry();
    registry.provision_signers(&[("root".to_owned(), &support::parent_key())])?;
    assert!(registry
        .provision_signers(&[("root".to_owned(), &Keypair::generate())])
        .is_err());
    for key in ["first", "rollback", "third"] {
        let request = runtime.tool_request(
            "root",
            key,
            "tools",
            "append",
            json!({"parent_id": "forged"}),
        )?;
        assert_eq!(
            runtime.invoke("root", key, &request).await?.verdict,
            Verdict::Allow
        );
    }
    let contexts = contexts.lock().map_err(|_| "poisoned")?.clone();
    let first = submit(&registry, &contexts[0], &json!({"task": 1}))?;
    assert_eq!(first.parent, "root");
    assert_eq!(first.process, "dyn_1");
    assert_eq!(
        submit(&registry, &contexts[0], &json!({"task": 1}))?.process,
        first.process
    );
    assert!(matches!(
        submit(&registry, &contexts[0], &json!({"task": 2})),
        Err(ProcessError::Conflict)
    ));
    let failed = registry.submit_child(
        ChildSubmission {
            context: &contexts[1],
            template: "read",
            input: &Value::Null,
            budget_share_bps: 1000,
            max_submissions: 128,
        },
        |_, _, _| Err(ProcessError::Invalid("issuance fault")),
    );
    assert!(failed.is_err());
    assert_eq!(registry.child_work()?.len(), 1);
    let db = rusqlite::Connection::open(directory.path().join("process.db"))?;
    assert_eq!(
        db.query_row("SELECT count(*) FROM process_delegation_keys", [], |r| r
            .get::<_, u32>(0))?,
        2
    );
    // Fail after the process and key inserts to exercise SQL transaction rollback.
    db.execute_batch("CREATE TRIGGER fail_child_work BEFORE INSERT ON process_child_work BEGIN SELECT RAISE(ABORT,'test work commit fault'); END;")?;
    assert!(submit(&registry, &contexts[1], &json!({"task": 2})).is_err());
    assert_eq!(
        db.query_row("SELECT count(*) FROM processes", [], |r| r.get::<_, u32>(0))?,
        2
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM process_delegation_keys", [], |r| r
            .get::<_, u32>(0))?,
        2
    );
    db.execute_batch("DROP TRIGGER fail_child_work")?;
    let second = submit(&registry, &contexts[1], &json!({"task": 2}))?;
    assert_eq!(second.process, "dyn_2");
    registry.wait_for_children(
        &contexts[0],
        std::slice::from_ref(&first.process),
        |_, _| Ok(()),
    )?;
    assert!(registry
        .wait_for_children(
            &contexts[0],
            std::slice::from_ref(&second.process),
            |_, _| Err(ProcessError::Invalid("cycle"))
        )
        .is_err());
    assert_eq!(
        registry.worker_waits()?.get("root"),
        Some(&vec![first.process])
    );
    runtime.cancel("root")?;
    assert!(matches!(
        submit(&registry, &contexts[2], &Value::Null),
        Err(ProcessError::Cancelled(_))
    ));
    assert_eq!(registry.child_work()?.len(), 2);
    Ok(())
}

struct CrashServer {
    registry: Arc<OnceLock<ProcessRegistry>>,
    crash: bool,
}

#[tokio::test]
async fn the_same_capability_attached_to_two_processes_is_not_a_parent_selector() -> Result {
    let directory = tempfile::tempdir()?;
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let kernel = support::kernel(directory.path(), Box::new(Probe(contexts.clone())))?;
    let runtime = ProcessRuntime::open(directory.path().join("process.db"), kernel.clone())?;
    let capability = support::root(&runtime, &kernel, 5)?;
    runtime.create_root("alias", &capability, support::limits(5))?;
    let request = runtime.tool_request(
        "root",
        "ambiguous",
        "tools",
        "append",
        json!({"parent_id": "root"}),
    )?;
    assert_eq!(
        runtime.invoke("root", "ambiguous", &request).await?.verdict,
        Verdict::Allow
    );
    let contexts = contexts.lock().map_err(|_| "poisoned")?;
    assert!(matches!(
        runtime.registry().caller(&contexts[0]),
        Err(ProcessError::Conflict)
    ));
    assert!(matches!(
        submit(&runtime.registry(), &contexts[0], &Value::Null),
        Err(ProcessError::Conflict)
    ));
    assert!(runtime.registry().child_work()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn independent_registries_serialize_duplicate_submission_and_cancellation() -> Result {
    let directory = tempfile::tempdir()?;
    let contexts = Arc::new(Mutex::new(Vec::new()));
    let kernel = support::kernel(directory.path(), Box::new(Probe(contexts.clone())))?;
    let runtime = ProcessRuntime::open(directory.path().join("process.db"), kernel.clone())?;
    support::root(&runtime, &kernel, 5)?;
    runtime
        .registry()
        .provision_signers(&[("root".to_owned(), &support::parent_key())])?;
    for key in ["duplicate", "cancel-race"] {
        let request = runtime.tool_request("root", key, "tools", "append", Value::Null)?;
        assert_eq!(
            runtime.invoke("root", key, &request).await?.verdict,
            Verdict::Allow
        );
    }
    let contexts = contexts.lock().map_err(|_| "poisoned")?.clone();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let mut submissions = Vec::new();
    for _ in 0..2 {
        let registry = ProcessRegistry::open(directory.path().join("process.db"), &kernel)?;
        let context = contexts[0].clone();
        let barrier = barrier.clone();
        submissions.push(std::thread::spawn(move || {
            barrier.wait();
            submit(&registry, &context, &Value::Null)
        }));
    }
    for submission in submissions {
        assert_eq!(
            submission
                .join()
                .map_err(|_| "submission panicked")??
                .process,
            "dyn_1"
        );
    }
    assert_eq!(runtime.registry().child_work()?.len(), 1);
    let registry = ProcessRegistry::open(directory.path().join("process.db"), &kernel)?;
    let context = contexts[1].clone();
    let other_barrier = barrier.clone();
    let submission = std::thread::spawn(move || {
        other_barrier.wait();
        submit(&registry, &context, &Value::Null)
    });
    barrier.wait();
    runtime.cancel("root")?;
    match submission.join().map_err(|_| "submission panicked")? {
        Ok(child) => assert_eq!(
            runtime.process(&child.process)?.state,
            chio_process::ProcessState::Cancelled
        ),
        Err(failure) => assert!(matches!(failure, ProcessError::Cancelled(_))),
    }
    for child in runtime.registry().child_work()? {
        assert_eq!(
            runtime.process(&child.process)?.state,
            chio_process::ProcessState::Cancelled
        );
    }
    Ok(())
}

#[async_trait::async_trait]
impl ToolServerConnection for CrashServer {
    fn server_id(&self) -> &str {
        "tools"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["append".to_owned()]
    }
    async fn invoke(
        &self,
        _: &str,
        _: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        Err(KernelError::Internal("context required".to_owned()))
    }
    async fn invoke_with_context(
        &self,
        context: &ToolInvocationContext,
        arguments: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        let registry = self
            .registry
            .get()
            .ok_or_else(|| KernelError::Internal("not provisioned".to_owned()))?;
        let child = submit(registry, context, &arguments)
            .map_err(|_| KernelError::Internal("submission failed".to_owned()))?;
        if self.crash {
            std::process::exit(73);
        }
        Ok(json!({"process": child.process}))
    }
}

#[test]
fn child_committed_before_host_death_is_not_redispatched_when_kernel_outcome_is_unknown() -> Result
{
    let directory = tempfile::tempdir()?;
    for (phase, expected) in [("crash", Some(73)), ("recover", Some(0))] {
        let status = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "subprocess_child_worker", "--nocapture"])
            .env("CHIO_CHILD_TEST_DIRECTORY", directory.path())
            .env("CHIO_CHILD_TEST_PHASE", phase)
            .status()?;
        assert_eq!(status.code(), expected);
    }
    Ok(())
}

#[tokio::test]
async fn subprocess_child_worker() -> Result {
    let Some(directory) = std::env::var_os("CHIO_CHILD_TEST_DIRECTORY") else {
        return Ok(());
    };
    let directory = std::path::PathBuf::from(directory);
    let crash = std::env::var("CHIO_CHILD_TEST_PHASE")? == "crash";
    let holder = Arc::new(OnceLock::new());
    let kernel = support::kernel(
        &directory,
        Box::new(CrashServer {
            registry: holder.clone(),
            crash,
        }),
    )?;
    let runtime = ProcessRuntime::open(directory.join("process.db"), kernel.clone())?;
    if crash {
        support::root(&runtime, &kernel, 1)?;
        runtime
            .registry()
            .provision_signers(&[("root".to_owned(), &support::parent_key())])?;
    }
    holder
        .set(runtime.registry())
        .map_err(|_| "already initialized")?;
    let request = runtime.tool_request("root", "spawn", "tools", "append", json!({"task": 1}))?;
    let response = runtime.invoke("root", "spawn", &request).await?;
    assert!(!crash);
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert!(response
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("OutcomeUnknownAfterDispatch"));
    assert!(response.receipt.verify_signature()?);
    assert_eq!(runtime.registry().child_work()?.len(), 1);
    assert_eq!(runtime.process("root")?.tree_calls, 1);
    assert_eq!(runtime.process("dyn_1")?.parent_id.as_deref(), Some("root"));
    Ok(())
}
