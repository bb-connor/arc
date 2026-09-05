//! Claude Code transports model proposals with its own workspace tools disabled.

use super::{parse_turn, Provider, Turn};
use crate::{Error, Result};
use serde_json::{json, Value};
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::{io::AsyncWriteExt, process::Command};

mod process;

const MAX_INPUT: usize = 1024 * 1024;
const MAX_OUTPUT: usize = 256 * 1024;

pub struct ClaudeCode {
    command: PathBuf,
    selection: String,
    model: String,
    budget: f64,
    timeout: Duration,
}

impl ClaudeCode {
    pub fn new(command: PathBuf, model: String, turn_budget_usd: f64) -> Result<Self> {
        if command.as_os_str().is_empty() || model.trim().is_empty() {
            return Err(Error::Invalid(
                "a Claude Code executable and model are required".into(),
            ));
        }
        if !turn_budget_usd.is_finite() || turn_budget_usd <= 0.0 {
            return Err(Error::Invalid(
                "Claude Code turn budget must be positive and finite".into(),
            ));
        }
        Ok(Self {
            command,
            model: format!("claude-code:{model}"),
            selection: model,
            budget: turn_budget_usd,
            timeout: Duration::from_secs(120),
        })
    }
}

fn response_schema(tools: &[Value]) -> Value {
    let mut blocks = vec![json!({
        "type":"object", "properties":{"type":{"const":"text"},"text":{"type":"string"}},
        "required":["type","text"], "additionalProperties":false,
    })];
    for tool in tools {
        blocks.push(json!({
            "type":"object", "properties":{
                "type":{"const":"tool_use"}, "id":{"type":"string"},
                "name":{"const":tool["name"]}, "input":tool["input_schema"],
            }, "required":["type","id","name","input"], "additionalProperties":false,
        }));
    }
    json!({
        "type":"object", "properties":{
            "content":{"type":"array","items":{"anyOf":blocks},"minItems":1,"maxItems":32},
            "stop_reason":{"enum":["end_turn","tool_use"]},
        }, "required":["content","stop_reason"], "additionalProperties":false,
    })
}

pub(super) fn parse_result(value: &Value) -> Result<Turn> {
    if value["type"] != "result" || value["subtype"] != "success" || value["is_error"] != false {
        return Err(Error::Invalid(
            "Claude Code did not complete a model turn successfully".into(),
        ));
    }
    if value
        .get("permission_denials")
        .is_some_and(|denials| denials.as_array().is_none_or(|items| !items.is_empty()))
    {
        return Err(Error::Invalid(
            "Claude Code reported an unexpected permission request".into(),
        ));
    }
    let proposal = &value["structured_output"];
    parse_turn(&json!({
        "content":proposal["content"], "stop_reason":proposal["stop_reason"], "usage":value["usage"],
    }))
}

#[async_trait::async_trait]
impl Provider for ClaudeCode {
    fn model(&self) -> &str {
        &self.model
    }

    async fn turn(&self, system: &str, messages: &[Value], tools: &[Value]) -> Result<Turn> {
        let input = serde_json::to_vec(&json!({"messages":messages,"tools":tools}))?;
        if input.len() > MAX_INPUT {
            return Err(Error::Invalid(
                "Claude Code model context exceeded 1 MiB".into(),
            ));
        }
        let directory = tempfile::Builder::new().prefix("chio-model-").tempdir()?;
        let instructions = format!(
            "{system}\nYou are the model component of Chio Workbench. The input is a JSON envelope of conversation messages and available Chio tool definitions. Produce exactly the next assistant turn as structured output. Propose tool calls using tool_use blocks with unique nonempty ids and stop_reason tool_use. Chio will execute them and supply their results in the next request. Never pretend to execute a tool. To finish this role, return a text summary and stop_reason end_turn. Claude Code's own tools are disabled."
        );
        let mut command = Command::new(&self.command);
        command
            .args([
                "--print",
                "--output-format",
                "json",
                "--no-session-persistence",
                "--safe-mode",
                "--restricted",
                "--setting-sources",
                "",
                "--strict-mcp-config",
                "--mcp-config",
                "{\"mcpServers\":{}}",
                "--tools",
                "",
                "--settings",
                "{\"disableAllHooks\":true}",
                "--max-turns",
                "3",
                "--model",
                &self.selection,
                "--max-budget-usd",
                &self.budget.to_string(),
                "--system-prompt",
                &instructions,
                "--json-schema",
                &response_schema(tools).to_string(),
            ])
            .current_dir(directory.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        // The trusted CLI uses its normal authentication. No credentials are
        // extracted or passed into the workspace tools.
        let mut child = command.spawn()?;
        let group = process::Group::new(&child)?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::Invalid("model stdin unavailable".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::Invalid("model stdout unavailable".into()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| Error::Invalid("model stderr unavailable".into()))?;
        let execution = async {
            let (status, (), output, _) = tokio::try_join!(
                child.wait(),
                async move {
                    stdin.write_all(&input).await?;
                    stdin.shutdown().await
                },
                process::read(stdout, MAX_OUTPUT),
                process::read(stderr, 64 * 1024),
            )?;
            Ok::<_, std::io::Error>((status, output))
        };
        let outcome = tokio::time::timeout(self.timeout, execution).await;
        // This guard also kills descendants when the turn future is cancelled.
        drop(group);
        let (status, output) = match outcome {
            Ok(Ok(value)) => value,
            failure => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(match failure {
                    Ok(Err(error)) => error.into(),
                    _ => Error::Invalid("Claude Code model request exceeded 120 seconds".into()),
                });
            }
        };
        if !status.success() {
            return Err(Error::Invalid("Claude Code request failed; check authentication, model, CLI version, and per-turn budget".into()));
        }
        parse_result(&serde_json::from_slice(&output)?)
    }
}

#[cfg(test)]
mod tests;
