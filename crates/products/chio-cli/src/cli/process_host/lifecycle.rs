use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use chio_core_types::crypto::Keypair;
use chio_kernel::{
    KernelError, NestedFlowBridge, ToolInvocationContext, ToolInvocationCost, ToolServerConnection,
};
use chio_manifest::{ToolDefinition, ToolManifest};
use chio_process::{ChildSubmission, ProcessError, ProcessRegistry};
use rusqlite::{Connection as SqliteConnection, OpenFlags, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};

use super::state::{Child, SpawnTemplate};

pub(super) const SERVER_ID: &str = "chio-process";

pub(super) struct Service {
    registry: ProcessRegistry,
    templates: Vec<SpawnTemplate>,
    issuer: Keypair,
    manifests: Vec<ToolManifest>,
    journal: PathBuf,
    active: Mutex<Option<ActiveRun>>,
}

struct ActiveRun {
    dependencies: BTreeMap<String, Vec<String>>,
    max_submissions: u32,
}

impl Service {
    pub fn new(
        registry: ProcessRegistry,
        templates: Vec<SpawnTemplate>,
        issuer: Keypair,
        manifests: Vec<ToolManifest>,
        journal: PathBuf,
    ) -> Self {
        Self {
            registry,
            templates,
            issuer,
            manifests,
            journal,
            active: Mutex::new(None),
        }
    }

    /// Only the native runner activates delegation after validating and binding
    /// its executable plan. A serving-only host keeps these tools disabled.
    #[cfg(target_os = "linux")]
    pub fn activate(
        &self,
        dependencies: BTreeMap<String, Vec<String>>,
    ) -> Result<(), ProcessError> {
        let max_submissions = 128_u32
            .checked_sub(dependencies.len() as u32)
            .ok_or(ProcessError::Limit("run workers"))?;
        let mut active = self
            .active
            .lock()
            .map_err(|_| ProcessError::StorePoisoned)?;
        if active.is_some() {
            return Err(ProcessError::Conflict);
        }
        *active = Some(ActiveRun {
            dependencies,
            max_submissions,
        });
        Ok(())
    }

    fn dispatch(
        &self,
        context: &ToolInvocationContext,
        arguments: Value,
    ) -> Result<Value, ProcessError> {
        if context.server_id() != SERVER_ID {
            return Err(ProcessError::Unauthenticated);
        }
        let active = self
            .active
            .lock()
            .map_err(|_| ProcessError::StorePoisoned)?;
        let active = active.as_ref().ok_or(ProcessError::Configuration(
            "delegation requires an active native run",
        ))?;
        let caller = self.registry.caller(context)?;
        let db =
            SqliteConnection::open_with_flags(&self.journal, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        if worker_state(&db, &caller.id)?.as_deref() != Some("running") {
            return Err(ProcessError::Invalid(
                "caller has no running worker attempt",
            ));
        }
        if context.tool_name() == "wait_children" {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Wait {
                children: Vec<String>,
            }
            let wait: Wait = serde_json::from_value(arguments)?;
            self.registry
                .wait_for_children(context, &wait.children, |_, proposed| {
                    let mut graph = active.dependencies.clone();
                    for (id, children) in proposed {
                        graph
                            .entry(id.clone())
                            .or_default()
                            .extend(children.iter().cloned());
                        for child in children {
                            if !child.starts_with("dyn_")
                                && !active.dependencies.contains_key(child)
                            {
                                return Err(ProcessError::Invalid(
                                    "wait target is not scheduled by this plan",
                                ));
                            }
                            graph.entry(child.clone()).or_default();
                        }
                    }
                    acyclic(graph)
                })?;
            let mut complete = true;
            for child in &wait.children {
                match worker_state(&db, child)?.as_deref() {
                    Some("completed") => {}
                    Some("failed") => return Err(ProcessError::Invalid("child worker failed")),
                    _ => complete = false,
                }
            }
            return Ok(json!({"complete": complete, "children": wait.children}));
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Spawn {
            input: Value,
            budget_share_bps: u16,
        }
        let input: Spawn = serde_json::from_value(arguments)?;
        let template = context
            .tool_name()
            .strip_prefix("spawn_")
            .and_then(|id| self.templates.iter().find(|template| template.id == id))
            .ok_or(ProcessError::Invalid("unknown spawn template"))?;
        if input.budget_share_bps > template.max_budget_share_bps {
            return Err(ProcessError::Limit("template budget share"));
        }
        let child = self.registry.submit_child(
            ChildSubmission {
                context,
                template: &template.id,
                input: &input.input,
                budget_share_bps: input.budget_share_bps,
                max_submissions: active.max_submissions,
            },
            |parent, signer, subject| {
                let child = Child {
                    id: String::new(),
                    parent: caller.id.clone(),
                    tools: template.tools.clone(),
                    budget_share_bps: input.budget_share_bps,
                };
                super::provision::child_capability(
                    parent,
                    signer,
                    &child,
                    subject,
                    &self.issuer,
                    &self.manifests,
                )
                .map_err(|_| {
                    ProcessError::Invalid("template cannot attenuate this caller's authority")
                })
            },
        )?;
        Ok(json!({"process": child.process}))
    }
}

fn worker_state(db: &SqliteConnection, id: &str) -> Result<Option<String>, ProcessError> {
    Ok(db
        .query_row(
            "SELECT state FROM run_workers WHERE process=?1",
            [id],
            |r| r.get(0),
        )
        .optional()?)
}

fn acyclic(mut graph: BTreeMap<String, Vec<String>>) -> Result<(), ProcessError> {
    while !graph.is_empty() {
        let ready: BTreeSet<_> = graph
            .iter()
            .filter(|(_, deps)| deps.is_empty())
            .map(|(id, _)| id.clone())
            .collect();
        if ready.is_empty() {
            return Err(ProcessError::Invalid("worker dependency cycle"));
        }
        graph.retain(|id, _| !ready.contains(id));
        for deps in graph.values_mut() {
            deps.retain(|id| !ready.contains(id));
        }
    }
    Ok(())
}

pub(super) fn manifest(templates: &[SpawnTemplate], public_key: &str) -> ToolManifest {
    let mut tools: Vec<_> = templates.iter().map(|template| ToolDefinition {
        name: format!("spawn_{}", template.id),
        description: "Start child work with this configured template and narrower authority. Keep a stable operation key when recovering.".to_owned(),
        input_schema: json!({"type":"object", "additionalProperties":false, "required":["input","budget_share_bps"],
            "properties":{"input":{}, "budget_share_bps":{"type":"integer","minimum":1,"maximum":template.max_budget_share_bps}}}),
        output_schema: None, pricing: None, has_side_effects: true, latency_hint: None,
    }).collect();
    tools.push(ToolDefinition {
        name: "wait_children".to_owned(),
        description: "Join direct children. If incomplete, checkpoint and exit 75 to release your worker slot. Use a new poll key after resumption.".to_owned(),
        input_schema: json!({"type":"object", "additionalProperties":false,"required":["children"],
            "properties":{"children":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":128,"uniqueItems":true}}}),
        output_schema: None, pricing: None, has_side_effects: true, latency_hint: None,
    });
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    ToolManifest {
        schema: "chio.manifest.v1".to_owned(),
        server_id: SERVER_ID.to_owned(),
        name: "Chio child processes".to_owned(),
        description: Some("Native delegation and cooperative joins".to_owned()),
        version: "1".to_owned(),
        tools,
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: public_key.to_owned(),
    }
}

pub(super) struct Connection(pub Arc<Service>);

#[async_trait::async_trait]
impl ToolServerConnection for Connection {
    fn server_id(&self) -> &str {
        SERVER_ID
    }
    fn tool_names(&self) -> Vec<String> {
        manifest(&self.0.templates, "")
            .tools
            .into_iter()
            .map(|tool| tool.name)
            .collect()
    }
    async fn invoke(
        &self,
        _: &str,
        _: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Err(KernelError::ToolServerError(
            "kernel caller context required".to_owned(),
        ))
    }
    async fn invoke_with_context(
        &self,
        context: &ToolInvocationContext,
        arguments: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.0.dispatch(context, arguments).map_err(|failure| {
            let reason = match failure {
                ProcessError::Invalid(reason)
                | ProcessError::Configuration(reason)
                | ProcessError::Limit(reason) => reason,
                ProcessError::Conflict => "child submission conflicts with existing state",
                ProcessError::Unauthenticated | ProcessError::Cancelled(_) => {
                    "caller is unavailable"
                }
                ProcessError::Json(_) => "invalid child operation arguments",
                _ => "child operation storage failed",
            };
            KernelError::ToolServerError(reason.to_owned())
        })
    }
    async fn invoke_with_cost_and_context(
        &self,
        context: &ToolInvocationContext,
        arguments: Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(Value, Option<ToolInvocationCost>), KernelError> {
        Ok((
            self.invoke_with_context(context, arguments, bridge).await?,
            None,
        ))
    }
}
