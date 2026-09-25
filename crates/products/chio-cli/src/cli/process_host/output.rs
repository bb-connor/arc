//! Human summaries are opt-in in pipes and the default at an interactive terminal.

use serde_json::Value;
use std::path::Path;

pub(super) fn initialized(json: bool, state: &Path, processes: usize, key: &str) {
    if json {
        println!(
            "{}",
            serde_json::json!({"initialized": true, "processes": processes, "kernel_key": key})
        );
    } else {
        println!("Initialized {} ({processes} processes)", state.display());
        println!("Public key: {}", state.join("kernel.pub").display());
    }
}

pub(super) fn run(json: bool, state: &Path, report: &Value) {
    if json {
        println!("{report}");
        return;
    }
    println!(
        "{}",
        if report["complete"] == true {
            "Run complete"
        } else {
            "Run incomplete"
        }
    );
    workers(report);
    if report["complete"] != true {
        println!("Inspect: chio process status --state {}", shell_path(state));
    }
}

pub(super) fn status(json: bool, state: &Path, report: &Value) {
    if json {
        println!("{report}");
        return;
    }
    println!(
        "Host: {} ({})",
        state.display(),
        if report["host_lock_held"] == true {
            "active"
        } else {
            "stopped"
        }
    );
    if report["run"].is_null() {
        println!("No run recorded");
    } else {
        workers(&report["run"]);
    }
}

fn workers(report: &Value) {
    if let Some(workers) = report["workers"].as_array() {
        println!("{:<24} {:<12} Attempts", "Worker", "State");
        for worker in workers {
            println!(
                "{:<24} {:<12} {}",
                worker["process"].as_str().unwrap_or("?"),
                worker["state"].as_str().unwrap_or("unknown"),
                worker["attempts"]
            );
        }
    }
}

fn shell_path(path: &Path) -> String {
    let text = path.to_string_lossy();
    if text
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
    {
        text.into_owned()
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}
