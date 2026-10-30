use super::*;

impl Service {
    pub(super) fn settle(
        &self,
        context: &ToolInvocationContext,
        arguments: Value,
        active: &ActiveRun,
        parent: &str,
    ) -> Result<Value, ProcessError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wait {
            children: Vec<String>,
        }
        let wait: Wait = serde_json::from_value(arguments)?;
        let work = self.registry.child_work()?;
        if wait.children.iter().any(|id| {
            !work
                .iter()
                .any(|child| child.process == *id && child.parent == parent)
        }) {
            return Err(ProcessError::Invalid(
                "settlement requires your direct dynamically spawned children",
            ));
        }
        // Acquire no runner write transaction while holding the process store.
        // Wait ownership, cancellation and cycles are checked atomically there.
        let journal = SqliteRunJournal::open_existing(&self.journal, Access::Write)?;
        require_running(&journal, parent)?;
        self.registry
            .wait_for_settled_children(context, &wait.children, |_, proposed| {
                validate_wait(active, proposed)
            })?;
        // A recorded settlement is a committed tool effect, not a claim about
        // response delivery.
        let outcomes = journal
            .settle_children(parent, &wait.children, context.request_id())
            .map_err(journal_error)?;
        let complete = outcomes.iter().all(|o| o.state.is_terminal());
        Ok(json!({
            "complete": complete,
            "successful": outcomes.iter().all(|o| o.state == WorkerState::Completed),
            "children": wait.children,
            "outcomes": outcomes,
        }))
    }
}
