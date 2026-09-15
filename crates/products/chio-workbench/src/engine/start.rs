use super::*;

struct Reservation {
    owner: Arc<Workbench>,
    id: String,
    committed: bool,
}

impl Reservation {
    fn new(owner: &Arc<Workbench>) -> Result<Self> {
        let mut active = owner.active.lock().map_err(|_| Error::Lock)?;
        if active.is_some() {
            return Err(Error::Busy);
        }
        if owner.store.list()?.len() >= 100 {
            return Err(Error::Invalid(
                "this state directory has 100 runs; archive it and choose a new directory".into(),
            ));
        }
        let id = uuid::Uuid::new_v4().to_string();
        owner.stop.send_replace(false);
        *active = Some(ActiveRun {
            id: id.clone(),
            kernel: None,
        });
        Ok(Self {
            owner: Arc::clone(owner),
            id,
            committed: false,
        })
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.committed {
            if let Ok(mut active) = self.owner.active.lock() {
                if active.as_ref().is_some_and(|active| active.id == self.id) {
                    *active = None;
                }
            }
        }
    }
}

impl Workbench {
    pub async fn start(self: &Arc<Self>, prompt: String, call_limit: u32) -> Result<String> {
        if prompt.trim().is_empty() || prompt.len() > 16000 || !(6..=120).contains(&call_limit) {
            return Err(Error::Invalid(
                "provide a task up to 16000 bytes and a tool-call allowance between 6 and 120"
                    .into(),
            ));
        }
        let mut reservation = Reservation::new(self)?;
        let (run_kernel, workspace, git) = if self.git_worktrees {
            let tasks = self.state_dir.join("tasks");
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&tasks)?;
            let task = tasks.join(&reservation.id);
            std::fs::DirBuilder::new().mode(0o700).create(&task)?;
            let (workspace, snapshot) = crate::git::prepare(
                &self.workspace,
                &task.join("worktree"),
                &self.state_dir,
                self.stop.subscribe(),
            )
            .await
            .map_err(|error| {
                Error::Invalid(format!("{error}; task directory: {}", task.display()))
            })?;
            let tools =
                WorkspaceTools::new(&workspace, self.check_command.clone(), self.stop.clone())?;
            (
                kernel::build(&task.join("kernel"), tools, self.authority.clone())?,
                workspace,
                Some(snapshot),
            )
        } else {
            (Arc::clone(&self.kernel), self.workspace.clone(), None)
        };
        if *self.stop.borrow() {
            return Err(Error::Invalid("task preparation was stopped".into()));
        }
        let key = Keypair::generate();
        let root = run_kernel.issue_capability(
            &key.public_key(),
            kernel::scope(Role::Editor, call_limit, true),
            3600,
        )?;
        run_kernel.set_capability_trust_root(
            self.authority.public_key(),
            chio_core::capability::attenuation::scope_hash(&root.scope)
                .map_err(|error| Error::Invalid(error.to_string()))?,
        );
        run_kernel
            .register_budget_parent(root.id.clone(), 10_000)
            .map_err(|error| Error::Invalid(error.to_string()))?;
        let quarter = call_limit / 4;
        let tasks = [
            (Role::Investigator, quarter),
            (Role::Editor, call_limit - 2 * quarter),
            (Role::Reviewer, quarter),
        ]
        .into_iter()
        .map(|(role, calls)| {
            Ok(Task {
                role,
                status: TaskStatus::Queued,
                capability: kernel::child(&root, &key, &self.authority, role, calls)?,
                call_limit: calls,
                turns: 0,
                input_tokens: 0,
                output_tokens: 0,
                summary: None,
                actions: vec![],
            })
        })
        .collect::<Result<Vec<_>>>()?;
        let run = Run {
            id: reservation.id.clone(),
            prompt,
            workspace: workspace.display().to_string(),
            git,
            model: self.provider.model().into(),
            status: RunStatus::Running,
            started_at: crate::now(),
            finished_at: None,
            call_limit,
            root_capability: root,
            tasks,
            error: None,
        };
        self.store.save(&run)?;
        let id = run.id.clone();
        self.active
            .lock()
            .map_err(|_| Error::Lock)?
            .as_mut()
            .ok_or_else(|| Error::Invalid("task reservation disappeared".into()))?
            .kernel = Some(Arc::clone(&run_kernel));
        let owner = Arc::clone(self);
        tokio::spawn(async move {
            // Join the worker so a panic cannot silently occupy the active slot.
            let worker = Arc::clone(&owner);
            let work = run.clone();
            let worker_kernel = Arc::clone(&run_kernel);
            let outcome =
                tokio::spawn(async move { worker.execute(work, worker_kernel).await }).await;
            let failure = match outcome {
                Ok(Ok(())) => None,
                Ok(Err(error)) => Some(error.to_string()),
                Err(_) => Some("task worker interrupted; review pending effects".into()),
            };
            if let Some(error) = failure {
                let _ = run_kernel.revoke_capability(&run.root_capability.id);
                if let Ok(mut current) = owner.store.get(&run.id) {
                    current.status = if *owner.stop.borrow() {
                        RunStatus::Stopped
                    } else {
                        RunStatus::Failed
                    };
                    current.error = Some(error);
                    current.finished_at = Some(crate::now());
                    for task in &mut current.tasks {
                        if matches!(task.status, TaskStatus::Running | TaskStatus::Queued) {
                            task.status = if current.status == RunStatus::Stopped {
                                TaskStatus::Stopped
                            } else {
                                TaskStatus::Failed
                            };
                        }
                        for action in &mut task.actions {
                            if action.state == "running" {
                                action.state = "unknown".into();
                            }
                        }
                    }
                    if let Err(error) = owner.store.save(&current) {
                        eprintln!("workbench could not persist terminal task state: {error}");
                    }
                }
            }
            run_kernel.evict_budget_parent(&run.root_capability.id);
            if run.git.is_some() {
                run_kernel.shutdown().await;
            }
            if let Ok(mut active) = owner.active.lock() {
                *active = None;
            }
        });
        reservation.committed = true;
        Ok(id)
    }
}
