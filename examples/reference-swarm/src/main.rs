//! An orchestrator and two workers driving the reference tools
//! through three Chio edges.
//!
//! The orchestrator signs a swarm task graph that delegates a narrower scope
//! to each worker, verifies the bundle with the swarm authority before any
//! worker starts, runs seven scenarios the runtime must allow or refuse,
//! then releases the budget pool and signs the terminal receipt. Every tool
//! call leaves a receipt in trust-control; the run writes the bundle and a
//! scenario report for the evidence export that follows.

mod authority;
mod edge;
mod scenarios;
mod trust;

use std::error::Error;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use serde_json::json;

use authority::{build_plan, now_unix_ms, WorkerGrant};
use edge::EdgeTarget;
use scenarios::{BudgetLedger, Context};
use trust::TrustClient;

type Fallible<T> = Result<T, Box<dyn Error>>;

#[derive(Parser, Debug)]
#[command(about = "Run the reference swarm against three Chio edges and a trust-control service")]
struct Args {
    #[arg(long, value_name = "URL")]
    control_url: String,
    /// Trust-control service bearer, for receipt queries.
    #[arg(long, env = "CHIO_SERVICE_TOKEN", hide_env_values = true)]
    service_token: String,
    /// Bearer the workers present to every edge.
    #[arg(long, env = "CHIO_AUTH_TOKEN", hide_env_values = true)]
    session_token: String,
    /// Bearer for the edges' admin routes.
    #[arg(long, env = "CHIO_ADMIN_TOKEN", hide_env_values = true)]
    admin_token: String,
    #[arg(long, value_name = "URL")]
    reader_url: String,
    #[arg(long, value_name = "URL")]
    writer_url: String,
    #[arg(long, value_name = "URL")]
    digest_url: String,
    #[arg(long, default_value = "reference-reader")]
    reader_server_id: String,
    #[arg(long, default_value = "reference-writer")]
    writer_server_id: String,
    #[arg(long, default_value = "reference-digest")]
    digest_server_id: String,
    /// The pre-created artifact the writer edge wraps.
    #[arg(long, value_name = "PATH")]
    artifact: PathBuf,
    /// Directory that receives the bundle and the run report.
    #[arg(long, value_name = "PATH")]
    output: PathBuf,
    /// Script that restarts the reader edge in place, for the recovery scenario.
    #[arg(long, value_name = "PATH")]
    restart_hook: Option<PathBuf>,
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("reference-swarm: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Fallible<bool> {
    std::fs::create_dir_all(&args.output)?;
    let trust = TrustClient::new(&args.control_url, &args.service_token);
    if !trust.healthy() {
        return Err(format!(
            "trust-control at {} does not answer its health route",
            args.control_url
        )
        .into());
    }
    let reader = EdgeTarget {
        name: "reader".to_string(),
        base_url: args.reader_url.clone(),
        server_id: args.reader_server_id.clone(),
    };
    let writer = EdgeTarget {
        name: "writer".to_string(),
        base_url: args.writer_url.clone(),
        server_id: args.writer_server_id.clone(),
    };
    let digest = EdgeTarget {
        name: "digest".to_string(),
        base_url: args.digest_url.clone(),
        server_id: args.digest_server_id.clone(),
    };
    let run_id = format!("{:x}", now_unix_ms());
    let workers = [
        WorkerGrant {
            task_id: "task-reader".to_string(),
            server_id: reader.server_id.clone(),
            tools: ["list_directory", "read_file", "stat"]
                .map(str::to_string)
                .to_vec(),
            route_target: reader.base_url.clone(),
        },
        WorkerGrant {
            task_id: "task-writer".to_string(),
            server_id: writer.server_id.clone(),
            tools: ["write_file", "read_file", "stat"]
                .map(str::to_string)
                .to_vec(),
            route_target: writer.base_url.clone(),
        },
    ];
    let mut plan = build_plan(&run_id, &workers)?;
    let admission = plan.verify()?;
    println!(
        "swarm {run_id}: {} ({} tasks, {} continuations, {} joins, {} routes)",
        admission.verdict,
        admission.task_count,
        admission.continuation_count,
        admission.join_count,
        admission.route_count
    );

    let context = Context {
        reader,
        writer,
        digest,
        session_bearer: args.session_token.clone(),
        admin_bearer: args.admin_token.clone(),
        trust,
        artifact: args.artifact.clone(),
        restart_hook: args.restart_hook.clone(),
    };
    let ledger = BudgetLedger::new(&plan);
    let mut reports = vec![
        scenarios::success(&context, &ledger),
        scenarios::file_denial(&context, &ledger),
        scenarios::scope_widening(&context, &plan),
        scenarios::sensitive_output(&context, &ledger),
        scenarios::budget_exhaustion(&context, &plan),
        scenarios::restart_recovery(&context, &ledger),
    ];
    reports.push(scenarios::revocation(&context, &mut plan));

    let result_digest = scenarios::result_digest(&reports);
    plan.complete(&["task-writer".to_string()], &result_digest)?;
    let closing = match plan.verify() {
        Ok(verdict) => format!(
            "bundle verifies after the run despite the revoked reader: {}",
            verdict.verdict
        ),
        Err(error) => {
            format!("bundle refused after the run, as the reader's task is revoked: {error}")
        }
    };
    println!("{closing}");

    let passed = reports.iter().all(|report| report.passed);
    for report in &reports {
        println!(
            "{:<20} {}",
            report.name,
            if report.passed { "passed" } else { "FAILED" }
        );
        for observation in &report.observations {
            println!("  {observation}");
        }
    }
    std::fs::write(
        args.output.join("swarm-bundle.json"),
        serde_json::to_vec_pretty(&plan.bundle)?,
    )?;
    std::fs::write(
        args.output.join("run-report.json"),
        serde_json::to_vec_pretty(&json!({
            "schema": "chio.reference-swarm.run-report.v1",
            "qualification": "integration-only",
            "taskCapabilityBindingEnforced": false,
            "confinementEvidenceCollected": false,
            "runId": run_id,
            "admissionVerdict": admission.verdict.to_string(),
            "closing": closing,
            "resultDigest": result_digest,
            "passed": passed,
            "scenarios": reports,
        }))?,
    )?;
    Ok(passed)
}
