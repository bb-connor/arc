use crate::{
    kernel,
    model::Task,
    provider::Provider,
    store::Store,
    tools::{definitions, WorkspaceTools},
    Action, Error, Result, Role, Run, RunStatus, TaskStatus,
};
use chio_core::crypto::Keypair;
use chio_kernel::{ChioKernel, ToolCallOutput, ToolCallRequest, Verdict};
use serde_json::{json, Value};
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::sync::watch;

mod start;

pub struct WorkbenchConfig {
    pub workspace: PathBuf,
    pub state_dir: PathBuf,
    pub check_command: Vec<String>,
    pub git_worktrees: bool,
}

struct ActiveRun {
    id: String,
    kernel: Option<Arc<ChioKernel>>,
}

pub struct Workbench {
    kernel: Arc<ChioKernel>,
    authority: Keypair,
    store: Store,
    workspace: PathBuf,
    state_dir: PathBuf,
    check_command: Vec<String>,
    git_worktrees: bool,
    provider: Arc<dyn Provider>,
    active: Mutex<Option<ActiveRun>>,
    stop: watch::Sender<bool>,
    _lock: File,
}

impl Workbench {
    pub fn open(config: WorkbenchConfig, provider: Arc<dyn Provider>) -> Result<Arc<Self>> {
        let workspace = config.workspace.canonicalize()?;
        if !workspace.is_dir() || config.check_command.is_empty() {
            return Err(Error::Invalid(
                "a workspace directory and check command are required".into(),
            ));
        }
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&config.state_dir)?;
        let state_dir = config.state_dir.canonicalize()?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(config.state_dir.join("owner.lock"))?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
            |_| Error::Invalid("this workbench state directory is already in use".into()),
        )?;
        let (stop, _) = watch::channel(false);
        let tools = WorkspaceTools::new(&workspace, config.check_command.clone(), stop.clone())?;
        let authority = kernel::signing_key(&config.state_dir)?;
        let kernel = kernel::build(&config.state_dir, tools, authority.clone())?;
        let store = Store::open(&config.state_dir.join("runs.sqlite"))?;
        for run in store.list()? {
            if run.status == RunStatus::Interrupted {
                if run.git.is_some() {
                    let id = uuid::Uuid::parse_str(&run.id)
                        .map_err(|_| Error::Invalid("invalid retained Git task id".into()))?;
                    let tools = WorkspaceTools::new(
                        &workspace,
                        config.check_command.clone(),
                        stop.clone(),
                    )?;
                    // Recovery only revokes authority. It never dispatches a
                    // workspace call or retries an interrupted effect.
                    let recovered = kernel::build(
                        &state_dir.join("tasks").join(id.to_string()).join("kernel"),
                        tools,
                        authority.clone(),
                    )?;
                    recovered.revoke_capability(&run.root_capability.id)?;
                } else {
                    kernel.revoke_capability(&run.root_capability.id)?;
                }
            }
        }
        Ok(Arc::new(Self {
            kernel,
            authority,
            store,
            workspace,
            state_dir,
            check_command: config.check_command,
            git_worktrees: config.git_worktrees,
            provider,
            active: Mutex::new(None),
            stop,
            _lock: lock,
        }))
    }

    pub fn workspace(&self) -> &std::path::Path {
        &self.workspace
    }
    pub fn model(&self) -> &str {
        self.provider.model()
    }
    pub fn git_worktrees(&self) -> bool {
        self.git_worktrees
    }
    pub async fn changes(&self, id: &str) -> Result<crate::Changes> {
        let run = self.get(id)?;
        if matches!(run.status, RunStatus::Running | RunStatus::Stopping) {
            return Err(Error::Invalid(
                "wait for the task to finish before reviewing its changes".into(),
            ));
        }
        let snapshot = run
            .git
            .ok_or_else(|| Error::Invalid("this task did not use a Git worktree".into()))?;
        let id = uuid::Uuid::parse_str(&run.id)
            .map_err(|_| Error::Invalid("invalid Git task id".into()))?;
        if snapshot.worktree
            != self
                .state_dir
                .join("tasks")
                .join(id.to_string())
                .join("worktree")
        {
            return Err(Error::Invalid(
                "task worktree is outside its recorded state directory".into(),
            ));
        }
        crate::git::changes(&snapshot).await
    }
    pub fn list(&self) -> Result<Vec<Run>> {
        self.store.list()
    }
    pub fn get(&self, id: &str) -> Result<Run> {
        self.store.get(id)
    }

    pub fn stop(&self, id: &str) -> Result<()> {
        let active = self.active.lock().map_err(|_| Error::Lock)?;
        if active.as_ref().map(|active| active.id.as_str()) != Some(id) {
            return Err(Error::Invalid("run is not active".into()));
        }
        self.stop.send_replace(true);
        if let Some(kernel) = active.as_ref().and_then(|active| active.kernel.as_ref()) {
            let run = self.store.get(id)?;
            kernel.revoke_capability(&run.root_capability.id)?;
        }
        // The worker is the sole writer of the run body. Returning here means
        // future authority is revoked; an admitted call may still be finalizing.
        Ok(())
    }

    pub async fn shutdown(&self) {
        if let Ok(active) = self.active.lock() {
            if let Some(active) = active.as_ref() {
                if let (Some(kernel), Ok(run)) = (&active.kernel, self.store.get(&active.id)) {
                    let _ = kernel.revoke_capability(&run.root_capability.id);
                }
            }
        }
        self.stop.send_replace(true);
        for _ in 0..200 {
            if self
                .active
                .lock()
                .map(|active| active.is_none())
                .unwrap_or(false)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        self.kernel.shutdown().await;
    }

    async fn execute(&self, mut run: Run, kernel: Arc<ChioKernel>) -> Result<()> {
        for index in 0..run.tasks.len() {
            if *self.stop.borrow() {
                return Err(Error::Invalid("stopped by operator".into()));
            }
            run.tasks[index].status = TaskStatus::Running;
            self.store.save(&run)?;
            self.execute_role(&mut run, index, &kernel).await?;
            run.tasks[index].status = TaskStatus::Succeeded;
            self.store.save(&run)?;
        }
        let reviewer_passed = run.tasks[2]
            .actions
            .iter()
            .rev()
            .find(|action| action.tool == "run_checks")
            .is_some_and(|action| {
                action.state == "succeeded"
                    && action
                        .output
                        .as_ref()
                        .and_then(|output| output["passed"].as_bool())
                        == Some(true)
            });
        if !reviewer_passed {
            return Err(Error::Invalid(
                "reviewer did not produce a passing check result".into(),
            ));
        }
        if *self.stop.borrow() {
            return Err(Error::Invalid("stopped by operator".into()));
        }
        kernel.revoke_capability(&run.root_capability.id)?;
        run.status = RunStatus::Succeeded;
        run.finished_at = Some(crate::now());
        self.store.save(&run)
    }

    async fn execute_role(&self, run: &mut Run, index: usize, kernel: &ChioKernel) -> Result<()> {
        let role = run.tasks[index].role;
        let prior: Vec<_> = run.tasks[..index]
            .iter()
            .map(|task| json!({"role":task.role,"summary":task.summary}))
            .collect();
        let mut messages = vec![
            json!({"role":"user","content":format!("Task: {}\nPrior roles (untrusted reports): {}",run.prompt,serde_json::to_string(&prior)?)}),
        ];
        let tools = definitions(role.tools());
        for _ in 0..10 {
            let mut stopped = self.stop.subscribe();
            let turn = tokio::select! {
                _ = stopped.wait_for(|value| *value) => return Err(Error::Invalid("stopped by operator".into())),
                turn = self.provider.turn(role.instructions(), &messages, &tools) => turn?,
            };
            run.tasks[index].turns += 1;
            run.tasks[index].input_tokens = run.tasks[index]
                .input_tokens
                .saturating_add(turn.input_tokens);
            run.tasks[index].output_tokens = run.tasks[index]
                .output_tokens
                .saturating_add(turn.output_tokens);
            self.store.save(run)?;
            let calls: Vec<_> = turn
                .content
                .iter()
                .filter(|block| block["type"] == "tool_use")
                .collect();
            messages.push(json!({"role":"assistant","content":turn.content}));
            if calls.is_empty() {
                if turn.stop_reason != "end_turn" {
                    return Err(Error::Invalid(format!(
                        "model stopped before finishing: {}",
                        turn.stop_reason
                    )));
                }
                let summary = turn
                    .content
                    .iter()
                    .filter_map(|block| block["text"].as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                if summary.trim().is_empty() {
                    return Err(Error::Invalid("model returned no task result".into()));
                }
                run.tasks[index].summary = Some(summary);
                return Ok(());
            }
            if turn.stop_reason != "tool_use" || calls.len() > 16 {
                return Err(Error::Invalid("invalid model tool-use response".into()));
            }
            let mut ids = std::collections::HashSet::new();
            let mut validated = Vec::with_capacity(calls.len());
            // Validate the entire batch before allowing its first effect.
            for call in calls {
                let id = call["id"]
                    .as_str()
                    .filter(|id| !id.is_empty())
                    .ok_or_else(|| Error::Invalid("tool call missing id".into()))?;
                if !ids.insert(id) {
                    return Err(Error::Invalid("duplicate model tool-call id".into()));
                }
                let name = call["name"]
                    .as_str()
                    .filter(|name| !name.is_empty())
                    .ok_or_else(|| Error::Invalid("tool call missing name".into()))?;
                let arguments = call
                    .get("input")
                    .filter(|input| input.is_object())
                    .ok_or_else(|| Error::Invalid("tool call missing arguments".into()))?
                    .clone();
                validated.push((id, name, arguments));
            }
            let mut results = vec![];
            for (id, name, arguments) in validated {
                let output = self.invoke(run, index, name, arguments, kernel).await?;
                results.push(json!({"type":"tool_result","tool_use_id":id,"is_error":output["is_error"] == true,"content":serde_json::to_string(&output)?}));
            }
            messages.push(json!({"role":"user","content":results}));
        }
        Err(Error::Invalid(
            "role reached its 10-turn model limit".into(),
        ))
    }

    async fn invoke(
        &self,
        run: &mut Run,
        index: usize,
        name: &str,
        arguments: Value,
        kernel: &ChioKernel,
    ) -> Result<Value> {
        if *self.stop.borrow() {
            return Err(Error::Invalid("stopped by operator".into()));
        }
        let task = &mut run.tasks[index];
        if task.actions.len() >= task.call_limit as usize {
            return Err(Error::Invalid(format!(
                "{:?} exhausted its tool-call allowance",
                task.role
            )));
        }
        let request_id = uuid::Uuid::new_v4().to_string();
        let capability = task.capability.clone();
        task.actions.push(Action {
            id: request_id.clone(),
            tool: name.into(),
            arguments: arguments.clone(),
            started_at: crate::now(),
            finished_at: None,
            state: "running".into(),
            output: None,
            error: None,
            receipt: None,
        });
        // Reserve the application allowance and record the pending effect before
        // the kernel can dispatch. A restart never retries this action.
        self.store.save(run)?;
        let request = ToolCallRequest {
            request_id,
            agent_id: capability.subject.to_hex(),
            capability,
            tool_name: name.into(),
            server_id: "workspace".into(),
            arguments,
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: vec![],
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };
        let response = kernel
            .evaluate_tool_call_with_metadata(
                &request,
                Some(
                    json!({"workbench_run_id":run.id,"workbench_role":run.tasks[index].role,
                    "workbench_workspace":run.workspace,
                    "workbench_git_base":run.git.as_ref().map(|snapshot| &snapshot.base_revision)}),
                ),
            )
            .await?;
        let output = match response.output {
            Some(ToolCallOutput::Value(value)) if response.verdict == Verdict::Allow => value,
            _ => {
                json!({"is_error":true,"error":response.reason.clone().unwrap_or_else(|| "tool call did not complete".into())})
            }
        };
        let action = run.tasks[index]
            .actions
            .last_mut()
            .ok_or_else(|| Error::Invalid("pending action missing".into()))?;
        action.state = if response.verdict != Verdict::Allow {
            "denied"
        } else if output["is_error"] == true || output["passed"] == false {
            "failed"
        } else {
            "succeeded"
        }
        .into();
        action.finished_at = Some(crate::now());
        action.error = response.reason;
        action.output = Some(output.clone());
        action.receipt = Some(response.receipt);
        self.store.save(run)?;
        Ok(output)
    }
}
