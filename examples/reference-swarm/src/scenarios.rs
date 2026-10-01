//! The seven scenarios, each a worker doing one thing the runtime must
//! allow or refuse, observed through the edge's answer, the kernel's denial
//! events, the trust-control receipts and the swarm authority's verdicts.

use std::collections::BTreeMap;
use std::error::Error;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;

use serde::Serialize;
use serde_json::{json, Value};

use crate::authority::{SwarmPlan, CALLS_PER_WORKER};
use crate::edge::{CallOutcome, EdgeAdmin, EdgeSession, EdgeTarget};
use crate::trust::TrustClient;

mod budget_receipts;

type Fallible<T> = Result<T, Box<dyn Error>>;

/// Everything the scenarios need from the deployment.
pub struct Context {
    pub reader: EdgeTarget,
    pub writer: EdgeTarget,
    pub digest: EdgeTarget,
    pub session_bearer: String,
    pub admin_bearer: String,
    pub trust: TrustClient,
    pub artifact: PathBuf,
    pub restart_hook: Option<PathBuf>,
}

/// What one scenario expected and saw.
#[derive(Debug, Serialize)]
pub struct ScenarioReport {
    pub name: &'static str,
    pub expectation: &'static str,
    pub passed: bool,
    pub observations: Vec<String>,
    pub capability_ids: Vec<String>,
}

impl ScenarioReport {
    fn new(name: &'static str, expectation: &'static str) -> Self {
        Self {
            name,
            expectation,
            passed: true,
            observations: Vec::new(),
            capability_ids: Vec::new(),
        }
    }

    fn check(&mut self, condition: bool, observation: impl Into<String>) {
        let observation = observation.into();
        if condition {
            self.observations.push(format!("ok: {observation}"));
        } else {
            self.passed = false;
            self.observations.push(format!("FAILED: {observation}"));
        }
    }

    fn fail(&mut self, error: impl std::fmt::Display) {
        self.passed = false;
        self.observations.push(format!("FAILED: {error}"));
    }
}

/// The orchestrator's ledger of the budget pool: one unit per call, per
/// worker, shared by every worker thread.
pub struct BudgetLedger {
    remaining: Mutex<BTreeMap<String, u64>>,
}

impl BudgetLedger {
    pub fn new(plan: &SwarmPlan) -> Self {
        Self {
            remaining: Mutex::new(
                plan.bundle
                    .budget_pool
                    .allocations
                    .iter()
                    .map(|allocation| (allocation.task_id.clone(), allocation.active_units))
                    .collect(),
            ),
        }
    }

    /// Take one unit for `task_id`; `false` when its allocation is spent.
    pub fn charge(&self, task_id: &str) -> bool {
        let Ok(mut remaining) = self.remaining.lock() else {
            return false;
        };
        match remaining.get_mut(task_id) {
            Some(units) if *units > 0 => {
                *units -= 1;
                true
            }
            _ => false,
        }
    }
}

fn describe(outcome: &CallOutcome) -> String {
    match &outcome.event {
        Some(event) => format!(
            "event {event}, error {}: {}",
            outcome.is_error, outcome.text
        ),
        None => format!("error {}: {}", outcome.is_error, outcome.text),
    }
}

fn record_capability(
    report: &mut ScenarioReport,
    admin: &EdgeAdmin,
    session: &EdgeSession,
) -> Option<String> {
    let Some(session_id) = session.session_id() else {
        report.fail("the edge assigned no session id");
        return None;
    };
    match admin.session_capability_id(session_id) {
        Ok(capability_id) => {
            report.capability_ids.push(capability_id.clone());
            Some(capability_id)
        }
        Err(error) => {
            report.fail(format!("session capability: {error}"));
            None
        }
    }
}

fn receipts_for(
    report: &mut ScenarioReport,
    trust: &TrustClient,
    capability_id: &str,
    at_least: usize,
) {
    match trust.receipts(capability_id) {
        Ok(receipts) => report.check(
            receipts.len() >= at_least,
            format!("trust-control holds {} receipts for {capability_id} (expected at least {at_least})", receipts.len()),
        ),
        Err(error) => report.fail(format!("receipt query: {error}")),
    }
}

pub fn success(context: &Context, ledger: &BudgetLedger) -> ScenarioReport {
    let mut report = ScenarioReport::new(
        "success",
        "the reader lists and reads, the writer writes and reads back, the orchestrator digests the result, every call leaves a receipt",
    );
    let run = |report: &mut ScenarioReport| -> Fallible<()> {
        let admin_reader = EdgeAdmin::new(&context.reader, &context.admin_bearer);
        let mut reader = EdgeSession::connect(&context.reader, &context.session_bearer)?;
        let reader_capability = record_capability(report, &admin_reader, &reader);
        let surface = reader.list_tools()?;
        report.check(
            surface.iter().any(|tool| tool == "read_file"),
            format!("reader edge advertises {surface:?}"),
        );
        report.check(
            ledger.charge("task-reader"),
            "reader charged one unit for list_directory",
        );
        let listing = reader.call("list_directory", json!({ "path": "." }))?;
        let names: Vec<String> = listing.structured["entries"]
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| entry["name"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        report.check(
            !listing.is_error && names.iter().any(|name| name == "README.md"),
            format!("reader listed the repository: {names:?}"),
        );
        report.check(
            ledger.charge("task-reader"),
            "reader charged one unit for read_file",
        );
        let readme = reader.call("read_file", json!({ "path": "README.md" }))?;
        let content = readme.structured["content"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        report.check(
            !readme.is_error && content.starts_with('#'),
            format!("reader read README.md ({} bytes)", content.len()),
        );
        reader.close();

        let admin_writer = EdgeAdmin::new(&context.writer, &context.admin_bearer);
        let mut writer = EdgeSession::connect(&context.writer, &context.session_bearer)?;
        let writer_capability = record_capability(report, &admin_writer, &writer);
        let artifact = context.artifact.to_string_lossy().into_owned();
        let body = format!("reference swarm report\nreadme_bytes={}\n", content.len());
        report.check(
            ledger.charge("task-writer"),
            "writer charged one unit for write_file",
        );
        let written = writer.call("write_file", json!({ "path": artifact, "content": body }))?;
        report.check(
            !written.is_error && written.event.is_none(),
            format!("writer wrote the artifact: {}", describe(&written)),
        );
        report.check(
            ledger.charge("task-writer"),
            "writer charged one unit for read_file",
        );
        let read_back = writer.call("read_file", json!({ "path": artifact }))?;
        report.check(
            read_back.structured["content"].as_str() == Some(body.as_str()),
            "writer read back exactly what it wrote",
        );
        writer.close();

        let admin_digest = EdgeAdmin::new(&context.digest, &context.admin_bearer);
        let mut digest = EdgeSession::connect(&context.digest, &context.session_bearer)?;
        let digest_capability = record_capability(report, &admin_digest, &digest);
        let hashed = digest.call("sha256", json!({ "text": body }))?;
        let hex = hashed.structured["sha256"].as_str().unwrap_or_default();
        report.check(
            !hashed.is_error && hex.len() == 64,
            format!("orchestrator digested the report: {hex}"),
        );
        digest.close();

        for (capability, calls) in [
            (reader_capability, 2),
            (writer_capability, 2),
            (digest_capability, 1),
        ] {
            if let Some(capability) = capability {
                receipts_for(report, &context.trust, &capability, calls);
            }
        }
        Ok(())
    };
    if let Err(error) = run(&mut report) {
        report.fail(error);
    }
    report
}

pub fn file_denial(context: &Context, ledger: &BudgetLedger) -> ScenarioReport {
    let mut report = ScenarioReport::new(
        "file_denial",
        "a path outside the reader's root is refused by the tool, and a forbidden system file is denied by the edge before the tool sees it",
    );
    let run = |report: &mut ScenarioReport| -> Fallible<()> {
        let admin = EdgeAdmin::new(&context.reader, &context.admin_bearer);
        let mut reader = EdgeSession::connect(&context.reader, &context.session_bearer)?;
        record_capability(report, &admin, &reader);
        report.check(
            ledger.charge("task-reader"),
            "reader charged one unit for the escape attempt",
        );
        let escape = reader.call("read_file", json!({ "path": "../outside" }))?;
        report.check(
            escape.is_error && escape.text.contains("refused"),
            format!("../outside: {}", describe(&escape)),
        );
        report.check(
            ledger.charge("task-reader"),
            "reader charged one unit for the forbidden path",
        );
        let forbidden = reader.call("read_file", json!({ "path": "/etc/passwd" }))?;
        report.check(
            forbidden.guard_denied(),
            format!("/etc/passwd: {}", describe(&forbidden)),
        );
        reader.close();
        Ok(())
    };
    if let Err(error) = run(&mut report) {
        report.fail(error);
    }
    report
}

pub fn scope_widening(context: &Context, plan: &SwarmPlan) -> ScenarioReport {
    let mut report = ScenarioReport::new(
        "scope_widening",
        "a tool outside the digest edge's grant is denied by the edge, and no delegation witness exists for a scope wider than the orchestrator's",
    );
    let run = |report: &mut ScenarioReport| -> Fallible<()> {
        let admin = EdgeAdmin::new(&context.digest, &context.admin_bearer);
        let mut digest = EdgeSession::connect(&context.digest, &context.session_bearer)?;
        record_capability(report, &admin, &digest);
        let widened = digest.call("canonical_json", json!({ "value": { "a": 1 } }))?;
        report.check(
            widened.denied(),
            format!("canonical_json: {}", describe(&widened)),
        );
        digest.close();
        report.check(
            plan.widening_is_refused(&context.digest.server_id, "canonical_json"),
            "no attenuation witness for a worker scope that adds canonical_json",
        );
        Ok(())
    };
    if let Err(error) = run(&mut report) {
        report.fail(error);
    }
    report
}

pub fn budget_exhaustion(context: &Context, plan: &SwarmPlan) -> ScenarioReport {
    let mut report = ScenarioReport::new(
        "budget_exhaustion",
        "two workers send every attempted call concurrently, including overruns; the kernel must allow six stat calls per grant and refuse the next two",
    );
    let attempts = CALLS_PER_WORKER + 2;
    let workers = [
        (
            "task-reader",
            &context.reader,
            "stat",
            json!({ "path": "README.md" }),
        ),
        (
            "task-writer",
            &context.writer,
            "stat",
            json!({ "path": context.artifact.to_string_lossy() }),
        ),
    ];
    let outcome: Result<Vec<(String, u64, u64, String)>, String> = std::thread::scope(|scope| {
        let handles: Vec<_> = workers
            .iter()
            .map(|(task_id, target, tool, arguments)| {
                let bearer = context.session_bearer.clone();
                let admin_bearer = context.admin_bearer.clone();
                scope.spawn(move || -> Result<(String, u64, u64, String), String> {
                    let mut session =
                        EdgeSession::connect(target, &bearer).map_err(|error| error.to_string())?;
                    let session_id = session.session_id().ok_or("missing worker session")?;
                    let capability = EdgeAdmin::new(target, &admin_bearer)
                        .session_capability_id(session_id)
                        .map_err(|error| error.to_string())?;
                    let mut granted = 0;
                    let mut refused = 0;
                    for attempt in 0..attempts {
                        let outcome = session
                            .call(tool, arguments.clone())
                            .map_err(|error| error.to_string())?;
                        // Neither local accounting nor retrying under a fresh
                        // request identity may turn an authority fault into a pass.
                        if attempt < CALLS_PER_WORKER && !outcome.is_error && !outcome.denied() {
                            granted += 1;
                        } else if attempt >= CALLS_PER_WORKER
                            && outcome.budget_exhausted(&capability)
                        {
                            refused += 1;
                        } else {
                            return Err(format!(
                                "{task_id}: unexpected outcome on attempt {attempt}: {}",
                                describe(&outcome)
                            ));
                        }
                    }
                    session.close();
                    Ok(((*task_id).to_string(), granted, refused, capability))
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .map_err(|_| "worker thread panicked".to_string())?
            })
            .collect()
    });
    match outcome {
        Ok(results) => {
            for (task_id, granted, refused, capability) in results {
                report.check(
                    granted == CALLS_PER_WORKER && refused == 2,
                    format!("{task_id}: {granted} calls allowed, {refused} refused by the kernel's invocation budget"),
                );
                let server = if task_id == "task-reader" {
                    &context.reader.server_id
                } else {
                    &context.writer.server_id
                };
                match context.trust.receipts(&capability).and_then(|receipts| budget_receipts::verify_counts(receipts, &capability, server)) {
                    Ok((allowed, denied)) => report.check(
                        allowed == CALLS_PER_WORKER as usize && denied == 2,
                        format!("{task_id}: signed receipts confirm {allowed} allows and {denied} kernel budget denials"),
                    ),
                    Err(error) => report.fail(format!("{task_id}: budget receipt verification: {error}")),
                }
                report.capability_ids.push(capability);
            }
        }
        Err(error) => report.fail(error),
    }
    report.check(
        plan.oversubscription_is_refused(),
        "reserving the whole pool for every worker is refused by the authority",
    );
    report
}

pub fn revocation(context: &Context, plan: &mut SwarmPlan) -> ScenarioReport {
    let mut report = ScenarioReport::new(
        "revocation",
        "after the orchestrator revokes a worker's capability mid-run, the edge denies the next call and the swarm bundle no longer verifies for that task",
    );
    let mut run = |report: &mut ScenarioReport| -> Fallible<()> {
        let admin = EdgeAdmin::new(&context.reader, &context.admin_bearer);
        let mut reader = EdgeSession::connect(&context.reader, &context.session_bearer)?;
        let Some(capability_id) = record_capability(report, &admin, &reader) else {
            return Ok(());
        };
        let before = reader.call("stat", json!({ "path": "README.md" }))?;
        report.check(
            !before.is_error && before.event.is_none(),
            format!("before revocation: {}", describe(&before)),
        );
        let newly = admin.revoke(&capability_id)?;
        report.check(newly, format!("revoked {capability_id}"));
        let after = reader.call("stat", json!({ "path": "README.md" }))?;
        report.check(
            after.revoked(),
            format!("after revocation: {}", describe(&after)),
        );
        reader.close();
        plan.revoke_task("task-reader")?;
        match plan.verify() {
            Ok(verdict) => report.check(
                false,
                format!(
                    "bundle still verifies after revoking task-reader: {}",
                    verdict.verdict
                ),
            ),
            Err(error) => report.check(
                true,
                format!("bundle refused after revoking task-reader: {error}"),
            ),
        }
        Ok(())
    };
    if let Err(error) = run(&mut report) {
        report.fail(error);
    }
    report
}

pub fn sensitive_output(context: &Context, ledger: &BudgetLedger) -> ScenarioReport {
    let mut report = ScenarioReport::new(
        "sensitive_output",
        "a write carrying a credential pattern is denied by the edge's secret-leak guard and the artifact is left untouched",
    );
    let run = |report: &mut ScenarioReport| -> Fallible<()> {
        let admin = EdgeAdmin::new(&context.writer, &context.admin_bearer);
        let mut writer = EdgeSession::connect(&context.writer, &context.session_bearer)?;
        record_capability(report, &admin, &writer);
        let artifact = context.artifact.to_string_lossy().into_owned();
        report.check(
            ledger.charge("task-writer"),
            "writer charged one unit for the leaking write",
        );
        let before = writer.call("read_file", json!({ "path": artifact }))?;
        let previous = before.structured["content"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let leaking = format!("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n{previous}");
        let denied = writer.call(
            "write_file",
            json!({ "path": artifact, "content": leaking }),
        )?;
        report.check(
            denied.guard_denied(),
            format!("leaking write: {}", describe(&denied)),
        );
        let after = writer.call("read_file", json!({ "path": artifact }))?;
        report.check(
            after.structured["content"].as_str() == Some(previous.as_str()),
            "the artifact still holds the previous content",
        );
        writer.close();
        Ok(())
    };
    if let Err(error) = run(&mut report) {
        report.fail(error);
    }
    report
}

pub fn restart_recovery(context: &Context, ledger: &BudgetLedger) -> ScenarioReport {
    let mut report = ScenarioReport::new(
        "restart_recovery",
        "after the reader edge restarts, the worker continues its session by id without a new handshake",
    );
    let Some(hook) = &context.restart_hook else {
        report.check(
            false,
            "restart recovery requires a restart hook; it was not exercised",
        );
        return report;
    };
    let run = |report: &mut ScenarioReport| -> Fallible<()> {
        let admin = EdgeAdmin::new(&context.reader, &context.admin_bearer);
        let mut reader = EdgeSession::connect(&context.reader, &context.session_bearer)?;
        record_capability(report, &admin, &reader);
        let Some(session_id) = reader.session_id().map(str::to_string) else {
            return Err("the edge assigned no session id".into());
        };
        report.check(
            ledger.charge("task-reader"),
            "reader charged one unit before the restart",
        );
        let before = reader.call("stat", json!({ "path": "README.md" }))?;
        report.check(
            !before.is_error,
            format!("before restart: {}", describe(&before)),
        );
        let status = Command::new(hook).status()?;
        report.check(
            status.success(),
            format!("restart hook {} exited {status}", hook.display()),
        );
        report.check(
            admin.healthy(),
            "the reader edge answers its health route again",
        );
        let mut resumed =
            EdgeSession::resume(&context.reader, &context.session_bearer, &session_id);
        report.check(
            ledger.charge("task-reader"),
            "reader charged one unit after the restart",
        );
        let after = resumed.call("read_file", json!({ "path": "README.md" }))?;
        report.check(
            !after.is_error && after.event.is_none(),
            format!("after restart, session {session_id}: {}", describe(&after)),
        );
        resumed.close();
        Ok(())
    };
    if let Err(error) = run(&mut report) {
        report.fail(error);
    }
    report
}

/// The result digest the terminal receipt carries: over every scenario's
/// name and verdict, so the receipt binds what actually happened.
pub fn result_digest(reports: &[ScenarioReport]) -> String {
    let summary: Vec<Value> = reports
        .iter()
        .map(|report| json!({ "name": report.name, "passed": report.passed }))
        .collect();
    chio_core_types::crypto::sha256_hex(Value::Array(summary).to_string().as_bytes())
}
