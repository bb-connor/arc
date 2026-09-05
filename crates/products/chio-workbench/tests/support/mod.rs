use chio_workbench::{
    provider::{Provider, Turn},
    Error, Result, WorkbenchConfig,
};
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

pub struct Scripted(pub Mutex<VecDeque<Turn>>);
#[async_trait::async_trait]
impl Provider for Scripted {
    fn model(&self) -> &str {
        "scripted-test-provider"
    }
    async fn turn(&self, _system: &str, _messages: &[Value], _tools: &[Value]) -> Result<Turn> {
        self.0
            .lock()
            .map_err(|_| Error::Lock)?
            .pop_front()
            .ok_or_else(|| Error::Invalid("script exhausted".into()))
    }
}
pub fn calls(calls: &[(&str, Value)]) -> Turn {
    Turn { content: calls.iter().enumerate().map(|(id,(name,input))|json!({"type":"tool_use","id":format!("call-{id}"),"name":name,"input":input})).collect(), stop_reason:"tool_use".into(), input_tokens:20, output_tokens:10 }
}
pub fn done() -> Turn {
    Turn {
        content: vec![
            json!({"type":"text","text":format!("Task role finished.\nFixture digest: {}", "f".repeat(128))}),
        ],
        stop_reason: "end_turn".into(),
        input_tokens: 10,
        output_tokens: 5,
    }
}
pub fn repair_script() -> Arc<dyn Provider> {
    Arc::new(Scripted(Mutex::new(VecDeque::from([
        calls(&[
            ("read_file", json!({"path":"calc.py"})),
            ("run_checks", json!({})),
        ]),
        done(),
        calls(&[
            ("read_file", json!({"path":"calc.py"})),
            (
                "replace_text",
                json!({"path":"calc.py","old_text":"return a - b","new_text":"return a + b"}),
            ),
            ("run_checks", json!({})),
        ]),
        done(),
        calls(&[
            ("read_file", json!({"path":"calc.py"})),
            ("run_checks", json!({})),
        ]),
        done(),
    ]))))
}

pub fn config(root: &std::path::Path) -> Result<WorkbenchConfig> {
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&workspace)?;
    if !workspace.join("calc.py").exists() {
        std::fs::write(
            workspace.join("calc.py"),
            "def add(a, b):\n    return a - b\n",
        )?;
    }
    Ok(WorkbenchConfig {
        workspace,
        state_dir: root.join("state"),
        check_command: vec![
            "python3".into(),
            "-I".into(),
            "-c".into(),
            "import runpy; module = runpy.run_path('calc.py'); assert module['add'](2, 3) == 5"
                .into(),
        ],
    })
}
