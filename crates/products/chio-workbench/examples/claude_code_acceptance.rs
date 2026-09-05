//! Opt-in live model acceptance. Generates a private arithmetic repair fixture.
#[cfg(unix)]
use chio_workbench::{provider::ClaudeCode, Role, RunStatus, Workbench, WorkbenchConfig};
#[cfg(unix)]
use clap::Parser;
#[cfg(unix)]
use serde_json::json;
#[cfg(unix)]
use std::{os::unix::fs::DirBuilderExt, path::PathBuf, sync::Arc, time::Duration};

#[cfg(unix)]
#[derive(Parser)]
struct Args {
    /// New private directory for the fixture, state, and evidence.
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    model: String,
    #[arg(long, default_value = "claude")]
    claude_command: PathBuf,
    #[arg(long, default_value_t = 0.25)]
    turn_budget_usd: f64,
}

#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&args.output)?;
    let output = args.output.canonicalize()?;
    let workspace = output.join("workspace");
    std::fs::create_dir(&workspace)?;
    std::fs::write(
        workspace.join("calc.py"),
        "def add(a, b):\n    return a - b\n",
    )?;
    // The check lives outside model-editable files and tests several inputs.
    let check = "import runpy; f = runpy.run_path('calc.py')['add']; assert all(f(a,b) == a+b for a,b in [(2,3),(-2,3),(0,1),(-3,-4)])";
    let config = WorkbenchConfig {
        workspace: workspace.clone(),
        state_dir: output.join("state"),
        check_command: vec!["python3".into(), "-I".into(), "-c".into(), check.into()],
    };
    let workbench = Workbench::open(
        config,
        Arc::new(ClaudeCode::new(
            args.claude_command,
            args.model,
            args.turn_budget_usd,
        )?),
    )?;
    let id = workbench.start("Fix the addition bug in calc.py. Establish the failing checks, make a focused correction, and have the reviewer inspect the change and run checks independently.".into(), 36)?;
    let completion = tokio::time::timeout(Duration::from_secs(600), async {
        loop {
            let run = workbench.get(&id)?;
            if !matches!(run.status, RunStatus::Running | RunStatus::Stopping) {
                return Ok::<_, chio_workbench::Error>(run);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await;
    workbench.shutdown().await;
    let run = completion??;
    std::fs::write(output.join("run.json"), serde_json::to_vec_pretty(&run)?)?;
    if run.status != RunStatus::Succeeded {
        return Err(format!("live task failed; inspect {}", output.display()).into());
    }
    let failed_before = run.tasks[0].actions.iter().any(|action| {
        action.tool == "run_checks"
            && action
                .output
                .as_ref()
                .is_some_and(|value| value["passed"] == false)
    });
    let edited = run.tasks[1]
        .actions
        .iter()
        .any(|action| action.tool == "replace_text" && action.state == "succeeded");
    let passed_after = run.tasks[2].actions.iter().any(|action| {
        action.tool == "run_checks"
            && action
                .output
                .as_ref()
                .is_some_and(|value| value["passed"] == true)
    });
    if !failed_before || !edited || !passed_after {
        return Err(
            "live task did not exercise failing checks, an edit, and independent passing review"
                .into(),
        );
    }
    let mut receipts = 0;
    for task in &run.tasks {
        if !task.capability.verify_signature()?
            || !task
                .capability
                .scope
                .is_subset_of(&run.root_capability.scope)
            || task
                .capability
                .delegation_chain
                .first()
                .is_none_or(|entry| entry.capability_id != run.root_capability.id)
        {
            return Err("invalid live role delegation".into());
        }
        for action in &task.actions {
            if action.tool == "replace_text" && task.role != Role::Editor {
                return Err("a non-editor proposed a write during the acceptance task".into());
            }
            let receipt = action
                .receipt
                .as_ref()
                .ok_or("live action has no receipt")?;
            if !receipt.verify_signature()? || receipt.capability_id != task.capability.id {
                return Err("invalid live action receipt".into());
            }
            receipts += 1;
        }
    }
    let independent = std::process::Command::new("python3")
        .args(["-I", "-c", check])
        .current_dir(&workspace)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .status()?;
    if !independent.success() {
        return Err("operator verification of the repaired file failed".into());
    }
    let evidence = json!({
        "kind":"chio.workbench-live-acceptance.v1", "run_id":id, "model":run.model,
        "roles":run.tasks.len(), "verified_receipts":receipts,
        "failed_checks_before_edit":failed_before, "editor_changed_file":edited,
        "reviewer_checks_passed":passed_after, "operator_checks_passed":true,
        "delegation_verified":true, "release_qualified":false,
        "input_tokens":run.tasks.iter().map(|task| task.input_tokens).sum::<u64>(),
        "output_tokens":run.tasks.iter().map(|task| task.output_tokens).sum::<u64>(),
    });
    std::fs::write(
        output.join("acceptance.json"),
        serde_json::to_vec_pretty(&evidence)?,
    )?;
    println!("{}", serde_json::to_string_pretty(&evidence)?);
    Ok(())
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("The live workbench acceptance profile requires Linux.");
    std::process::ExitCode::FAILURE
}
