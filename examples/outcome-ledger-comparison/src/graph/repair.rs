//! A real repository repair checked through observed Git effects. Candidate
//! Python runs without authority or access to the separate check repositories.
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair};
use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection, Verdict};
use chio_runtime_core::outcome_continuation::{
    OutcomeEffectArguments, OutcomeEffectRequest, OutcomeEffectRule, OutcomeEffectSlot,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::model::{hash, outcome, Delivery};
use crate::{Gate, Result, BACKENDS, NOW};

#[path = "repair_receiver_check.rs"]
mod receiver_check;
pub use receiver_check::compare as compare_receiver_check;

#[path = "repair_git.rs"]
pub mod git_recovery;

#[path = "repair_work.rs"]
pub mod work_reuse;

#[path = "repair_exchange.rs"]
pub mod exchange;

const FILES: [&str; 2] = [
    "sdks/python/chio-adapter-base/src/chio_adapter_base/security.py",
    "sdks/python/chio-hermes/src/chio_hermes/executors.py",
];
const HOOKS: [&str; 5] = [
    "pre-commit",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "reference-transaction",
];
const DRIVER: &str = include_str!("repair_driver.py");
const MESSAGE: &str = "test: checked repository repair";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Repair {
    base_sha256: BTreeMap<String, String>,
    files: BTreeMap<String, String>,
}

fn sources(root: &Path) -> Result<BTreeMap<String, String>> {
    FILES
        .into_iter()
        .map(|name| {
            let mut contents = String::new();
            std::fs::File::open(root.join(name))?
                .take(256 * 1024 + 1)
                .read_to_string(&mut contents)?;
            if contents.len() > 256 * 1024 {
                return Err("repair source exceeds limit".into());
            }
            Ok((name.into(), contents))
        })
        .collect()
}

fn requests() -> Value {
    let tail = ["commit", "--allow-empty", "-m", MESSAGE];
    let prefixes: [&[&str]; 5] = [
        &[],
        &[],
        &["-c", "core.hooksPath=/work/hooks"],
        &[
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.hooksPath=/work/hooks",
        ],
        &["--config-env=core.hooksPath=HOOK_TEST_PATH"],
    ];
    let mut rows = Vec::new();
    for (index, prefix) in prefixes.iter().enumerate() {
        let mut argv = vec!["git"];
        argv.extend_from_slice(prefix);
        argv.extend_from_slice(&tail);
        if index == 1 {
            argv.push("--no-verify");
        }
        rows.push(json!({"entrypoint":"helper","argv":argv,"message":MESSAGE}));
    }
    rows.push(json!({"entrypoint":"commit","message":MESSAGE}));
    rows.push(json!({"entrypoint":"git_run","command":format!("commit -m '{MESSAGE}'"),"message":MESSAGE}));
    json!(rows)
}

struct OwnedChild(std::process::Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn capture(mut command: Command) -> Result<Value> {
    let mut child = OwnedChild(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    let stdout = child.0.stdout.take().ok_or("stdout missing")?;
    let stderr = child.0.stderr.take().ok_or("stderr missing")?;
    let (sender, receiver) = std::sync::mpsc::channel();
    for (name, mut stream) in [
        ("stdout", Box::new(stdout) as Box<dyn Read + Send>),
        ("stderr", Box::new(stderr) as Box<dyn Read + Send>),
    ] {
        let sender = sender.clone();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stream
                .by_ref()
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes);
            let _ = sender.send((name, result));
        });
    }
    drop(sender);
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            return Err("repair subprocess exceeded deadline".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let mut result = json!({"success":status.success(),"exit":status.to_string()});
    for _ in 0..2 {
        let (name, bytes) = receiver.recv_timeout(Duration::from_secs(5))?;
        let bytes = bytes?;
        if bytes.len() > 1024 * 1024 {
            return Err("repair subprocess output exceeds bound".into());
        }
        result[name] = Value::String(String::from_utf8(bytes)?);
    }
    Ok(result)
}

fn candidate_argv(directory: &Path, repair: &Repair) -> Result<Value> {
    std::fs::write(directory.join("driver.py"), DRIVER)?;
    std::fs::write(
        directory.join("requests.json"),
        canonical_json_bytes(&requests())?,
    )?;
    std::fs::create_dir_all(directory.join("empty-work/.git"))?;
    let mut command = super::isolation::base_command()?;
    command.args(["--ro-bind", "/usr/bin/python3.12", "/app/python"]);
    for (name, contents) in FILES.iter().zip(["security.py", "executors.py"]) {
        std::fs::write(
            directory.join(contents),
            repair.files.get(*name).ok_or("repair source absent")?,
        )?;
        command
            .arg("--ro-bind")
            .arg(directory.join(contents))
            .arg(format!("/{contents}"));
    }
    for name in ["driver.py", "requests.json"] {
        command
            .arg("--ro-bind")
            .arg(directory.join(name))
            .arg(format!("/{name}"));
    }
    command
        .arg("--ro-bind")
        .arg(directory.join("empty-work"))
        .arg("/work");
    command.args(["--", "/app/python", "-I", "-S", "-B", "/driver.py"]);
    capture(command)
}

fn git(directory: &Path, argv: &[String]) -> Result<Value> {
    if argv.first().map(String::as_str) != Some("git")
        || argv.len() > 64
        || argv
            .iter()
            .any(|arg| arg.len() > 4096 || arg.contains('\0'))
    {
        return Err("candidate returned an invalid Git invocation".into());
    }
    let mut command = super::isolation::base_command()?;
    command.args([
        "--ro-bind",
        "/usr/bin/git",
        "/usr/bin/git",
        "--ro-bind",
        "/usr/bin/dash",
        "/usr/bin/sh",
        "--symlink",
        "usr/bin",
        "/bin",
    ]);
    command
        .arg("--bind")
        .arg(directory)
        .arg("/work")
        .args(["--chdir", "/work"]);
    for (name, value) in [
        ("PATH", "/usr/bin"),
        ("HOME", "/tmp"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_AUTHOR_NAME", "Chio repair checker"),
        ("GIT_AUTHOR_EMAIL", "test@example.invalid"),
        ("GIT_COMMITTER_NAME", "Chio repair checker"),
        ("GIT_COMMITTER_EMAIL", "test@example.invalid"),
        ("HOOK_TEST_PATH", "/work/hooks"),
    ] {
        command.args(["--setenv", name, value]);
    }
    command.args(["--", "/usr/bin/git"]).args(&argv[1..]);
    capture(command)
}

fn git_ok(directory: &Path, args: &[&str]) -> Result<Value> {
    let argv = std::iter::once("git")
        .chain(args.iter().copied())
        .map(String::from)
        .collect::<Vec<_>>();
    let output = git(directory, &argv)?;
    if output["success"] != true {
        return Err(format!("checker Git setup failed: {output}").into());
    }
    Ok(output)
}

// Candidate output cannot add shell aliases, hooks, alternate programs or
// arbitrary Git operations to the checker's process. It may only add the
// hook-disabling override and --no-verify to the exact requested commit.
fn validate_commit(index: usize, argv: &[String]) -> Result<()> {
    fn normalized(argv: &[String]) -> Vec<String> {
        let mut result = Vec::new();
        let mut cursor = 0;
        let mut commit = false;
        while cursor < argv.len() {
            if !commit
                && argv[cursor] == "-c"
                && argv.get(cursor + 1).map(String::as_str) == Some("core.hooksPath=/dev/null")
            {
                cursor += 2;
                continue;
            }
            if argv[cursor] == "commit" {
                commit = true;
            }
            if !(commit && argv[cursor] == "--no-verify") {
                result.push(argv[cursor].clone());
            }
            cursor += 1;
        }
        result
    }
    let expected: Vec<String> = if index < 5 {
        serde_json::from_value(requests()[index]["argv"].clone())?
    } else {
        [
            "git",
            "-C",
            "/work",
            "--git-dir",
            "/work/.git",
            "--work-tree",
            "/work",
            "commit",
            "-m",
            MESSAGE,
        ]
        .into_iter()
        .map(String::from)
        .collect()
    };
    if normalized(argv) != normalized(&expected) {
        return Err(
            "candidate changed the requested commit beyond the permitted hook policy".into(),
        );
    }
    Ok(())
}

fn repository(directory: &Path) -> Result<()> {
    std::fs::create_dir(directory)?;
    git_ok(directory, &["init", "-q"])?;
    // Initial state and callbacks are chosen by the checker, outside the
    // candidate process. It sees only an empty read-only /work placeholder.
    std::fs::write(directory.join("change.txt"), "checked change\n")?;
    git_ok(directory, &["add", "change.txt"])?;
    std::fs::create_dir(directory.join("hooks"))?;
    for name in HOOKS {
        use std::os::unix::fs::PermissionsExt;
        let path = directory.join("hooks").join(name);
        std::fs::write(
            &path,
            format!("#!/bin/sh\nprintf ran >> /work/{name}.observed\n"),
        )?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    git_ok(directory, &["config", "core.hooksPath", "/work/hooks"])?;
    Ok(())
}

fn check(directory: &Path, repair: &Repair) -> Result<Value> {
    std::fs::create_dir_all(directory)?;
    let invocation = candidate_argv(directory, repair)?;
    std::fs::write(
        directory.join("candidate-process.json"),
        serde_json::to_vec_pretty(&invocation)?,
    )?;
    if invocation["success"] != true {
        return Err("candidate process failed".into());
    }
    let calls: Vec<Vec<String>> = serde_json::from_str(
        invocation["stdout"]
            .as_str()
            .ok_or("candidate output absent")?,
    )?;
    if calls.len() != 7 {
        return Err("candidate invocation count differs from owner contract".into());
    }
    let mut rows = Vec::new();
    for (index, argv) in calls.iter().enumerate() {
        validate_commit(index, argv)?;
        let work = directory.join(format!("case-{index}"));
        repository(&work)?;
        let output = git(&work, argv)?;
        let hooks: Vec<_> = HOOKS
            .into_iter()
            .filter(|name| work.join(format!("{name}.observed")).exists())
            .collect();
        let readback = git(
            &work,
            &[
                "git".into(),
                "log".into(),
                "-1".into(),
                "--format=%s".into(),
            ],
        )?;
        let committed_file = git(
            &work,
            &["git".into(), "show".into(), "HEAD:change.txt".into()],
        )?;
        let passed = output["success"] == true
            && hooks.is_empty()
            && readback["success"] == true
            && readback["stdout"].as_str().map(str::trim) == Some(MESSAGE)
            && committed_file["stdout"] == "checked change\n";
        rows.push(json!({"case":index,"argv":argv,"execution":output,"hooksObserved":hooks,"commitReadback":readback,"committedFile":committed_file,"passed":passed}));
    }
    let report = json!({"passed":rows.iter().all(|row|row["passed"]==true),"cases":rows});
    std::fs::write(
        directory.join("checks.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(report)
}

struct Verifier {
    directory: PathBuf,
    rule: OutcomeEffectRule,
    base: BTreeMap<String, String>,
    key: Keypair,
}

fn check_owned_artifact(
    directory: &Path,
    base: &BTreeMap<String, String>,
    artifact: &Value,
) -> Result<()> {
    let repair: Repair = serde_json::from_value(artifact.clone())?;
    if repair.base_sha256 != *base
        || repair.files.len() != 2
        || !FILES.iter().all(|name| repair.files.contains_key(*name))
        || repair.files.values().any(|text| text.len() > 256 * 1024)
    {
        return Err("repair differs from owner path, base or size contract".into());
    }
    let directory = directory.join(Keypair::generate().public_key().to_hex());
    let report = check(&directory, &repair)?;
    if report["passed"] != true {
        return Err("observed Git effects violate owner contract".into());
    }
    Ok(())
}

#[async_trait::async_trait]
impl ToolServerConnection for Verifier {
    fn server_id(&self) -> &str {
        "repair-verifier"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["verify".into()]
    }
    async fn invoke(
        &self,
        _tool: &str,
        artifact: Value,
        _bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        let result = (|| -> Result<Value> {
            check_owned_artifact(&self.directory, &self.base, &artifact)?;
            Ok(serde_json::to_value(Delivery {
                evidence: outcome(&self.rule, &artifact, &self.key)?,
                artifact,
            })?)
        })();
        result.map_err(|error| KernelError::ToolServerError(error.to_string()))
    }
}

struct Publisher {
    gate: Arc<Gate>,
    rule: OutcomeEffectRule,
    directory: PathBuf,
    local_check: Option<LocalCheck>,
}

// Installed by the receiver owner, never deserialized from a request. The
// local gate's signer is the receiver itself after successful re-execution.
struct LocalCheck {
    base: BTreeMap<String, String>,
    key: Keypair,
}

#[async_trait::async_trait]
impl ToolServerConnection for Publisher {
    fn server_id(&self) -> &str {
        "repair-review-queue"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["publish".into()]
    }
    async fn invoke(
        &self,
        _tool: &str,
        arguments: Value,
        _bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        let result = (|| -> Result<Value> {
            let delivery: Delivery = if let Some(local) = &self.local_check {
                if self.gate.status(&self.rule)?.0 != "waiting" {
                    return Err(
                        "logical publication is already claimed; no candidate re-execution".into(),
                    );
                }
                check_owned_artifact(
                    &self.directory.join("local-checks"),
                    &local.base,
                    &arguments,
                )?;
                Delivery {
                    evidence: outcome(&self.rule, &arguments, &local.key)?,
                    artifact: arguments,
                }
            } else {
                serde_json::from_value(arguments)?
            };
            let repair: Repair = serde_json::from_value(delivery.artifact.clone())?;
            let request = OutcomeEffectRequest {
                evidence: delivery.evidence,
                arguments: OutcomeEffectArguments {
                    artifact_sha256: hash(&delivery.artifact)?,
                    resource: self.rule.resource.clone(),
                },
            };
            let prepared = self
                .gate
                .prepare(&request, self.server_id(), "publish", NOW)?;
            let permit = self
                .gate
                .claim(&prepared, self.server_id(), "publish", NOW)?;
            let mut log = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.directory.join("effects.log"))?;
            writeln!(log, "{}", request.arguments.artifact_sha256)?;
            log.sync_all()?;
            for name in FILES {
                let path = self.directory.join("approved").join(name);
                std::fs::create_dir_all(path.parent().ok_or("approved parent absent")?)?;
                let mut file = std::fs::File::create(path)?;
                file.write_all(
                    repair
                        .files
                        .get(name)
                        .ok_or("approved source absent")?
                        .as_bytes(),
                )?;
                file.sync_all()?;
            }
            let result = json!({"artifactSha256":request.arguments.artifact_sha256,"publishedForReview":true});
            self.gate.complete(permit, &result)?;
            Ok(result)
        })();
        result.map_err(|error| KernelError::ToolServerError(error.to_string()))
    }
}

fn response(
    directory: &Path,
    name: &str,
    reply: &chio_kernel::ToolCallResponse,
) -> Result<Option<Value>> {
    assert!(reply.receipt.verify_signature()?);
    let output = match &reply.output {
        Some(chio_kernel::ToolCallOutput::Value(value)) => Some(value.clone()),
        _ => None,
    };
    if reply.verdict == Verdict::Allow {
        assert_eq!(
            reply.receipt.content_hash,
            hash(output.as_ref().ok_or("allowed output absent")?)?
        );
    }
    std::fs::write(
        directory.join(format!("{name}.json")),
        serde_json::to_vec_pretty(
            &json!({"receipt":reply.receipt,"allowed":reply.verdict==Verdict::Allow,"reason":reply.reason,"output":output}),
        )?,
    )?;
    Ok(output)
}

pub fn compare(root: &Path, baseline: &Path, candidate: &Path) -> Result<Value> {
    let root = std::fs::canonicalize(root)?;
    let old = sources(baseline)?;
    let base = old
        .iter()
        .map(|(name, text)| (name.clone(), sha256_hex(text.as_bytes())))
        .collect::<BTreeMap<_, _>>();
    let repair = Repair {
        base_sha256: base.clone(),
        files: sources(candidate)?,
    };
    let artifact = serde_json::to_value(&repair)?;
    let original = serde_json::to_value(Repair {
        base_sha256: base.clone(),
        files: old,
    })?;
    let contract = json!({"schema":"git-hook-repair-contract.experimental.v1","baseSha256":base,"paths":FILES,"requests":requests(),"hooks":HOOKS,"driverSha256":sha256_hex(DRIVER.as_bytes()),"checkerSha256":sha256_hex(include_bytes!("repair.rs")),"isolationPolicySha256":sha256_hex(include_bytes!("isolation.rs")),"required":"Each command creates the expected commit and file without executing any configured hook"});
    std::fs::write(
        root.join("contract.json"),
        serde_json::to_vec_pretty(&contract)?,
    )?;
    std::fs::write(
        root.join("candidate.json"),
        serde_json::to_vec_pretty(&artifact)?,
    )?;
    std::fs::write(
        root.join("baseline.json"),
        serde_json::to_vec_pretty(&original)?,
    )?;
    let mut observations = Vec::new();
    for backend in BACKENDS {
        let directory = root.join(backend);
        std::fs::create_dir(&directory)?;
        let verifier_key = Keypair::generate();
        let publisher_key = Keypair::generate();
        let rule = OutcomeEffectRule {
            slot: OutcomeEffectSlot {
                receiver_id: publisher_key.public_key().to_hex(),
                workflow_id: "disable-git-commit-hooks".into(),
                step_id: "publish-reviewed-repair".into(),
            },
            predecessor_step_id: "check-git-effects".into(),
            verifier_key: verifier_key.public_key(),
            contract_sha256: hash(&contract)?,
            server_id: "repair-review-queue".into(),
            tool_name: "publish".into(),
            resource: "reviewed-source-files".into(),
            valid_from_unix_ms: NOW - 1000,
            valid_until_unix_ms: NOW + 1000,
        };
        std::fs::write(
            directory.join("owner-rule.json"),
            serde_json::to_vec_pretty(&rule)?,
        )?;
        let verify_dir = directory.join("verifier");
        std::fs::create_dir(&verify_dir)?;
        let mut verifier = crate::workload::configured_kernel(&verify_dir, verifier_key.clone())?;
        verifier.register_tool_server(Box::new(Verifier {
            directory: verify_dir.clone(),
            rule: rule.clone(),
            base: base.clone(),
            key: verifier_key.clone(),
        }));
        for (name, bad) in [
            ("baseline", original.clone()),
            ("helper_only_fix", {
                let mut value = artifact.clone();
                value["files"][FILES[1]] = original["files"][FILES[1]].clone();
                value
            }),
            ("self_asserted_pass", {
                let mut value = artifact.clone();
                value["files"][FILES[0]] =
                    json!("print('{\"passed\":true}'); raise SystemExit(0)\n");
                value
            }),
            ("no_commit", {
                let mut value = artifact.clone();
                value["files"][FILES[0]] = json!(
                    "import json; print(json.dumps([['git','status']]*7)); raise SystemExit(0)\n"
                );
                value
            }),
            ("erase_hook_evidence", {
                let commands = json!(vec![vec![
                    "git".to_string(), "-c".to_string(),
                    format!("alias.forge=!git commit --no-verify --allow-empty -m '{MESSAGE}'; rm -f /work/*.observed"),
                    "forge".to_string(),
                ]; 7]);
                let mut value = artifact.clone();
                value["files"][FILES[0]] = json!(format!(
                    "print({:?}); raise SystemExit(0)\n",
                    commands.to_string()
                ));
                value
            }),
            ("wrong_base", {
                let mut value = artifact.clone();
                value["baseSha256"][FILES[0]] = json!("00".repeat(32));
                value
            }),
        ] {
            let denied = crate::workload::invoke_authorized(
                &verifier,
                &verifier_key,
                "repair-verifier",
                "verify",
                bad,
                name,
            )?;
            response(&directory, name, &denied)?;
            assert_ne!(denied.verdict, Verdict::Allow, "{backend} {name}");
            if name == "baseline" || name == "helper_only_fix" {
                assert!(
                    denied
                        .reason
                        .as_deref()
                        .unwrap_or_default()
                        .contains("observed Git effects"),
                    "{backend} {name} did not reach the behavioral regression: {:?}",
                    denied.reason
                );
            }
            if name == "erase_hook_evidence" {
                assert!(
                    denied
                        .reason
                        .as_deref()
                        .unwrap_or_default()
                        .contains("beyond the permitted hook policy"),
                    "checker did not reject executable Git configuration before dispatch: {:?}",
                    denied.reason
                );
            }
        }
        let verified = crate::workload::invoke_authorized(
            &verifier,
            &verifier_key,
            "repair-verifier",
            "verify",
            artifact.clone(),
            "candidate",
        )?;
        let delivery =
            response(&directory, "verified-repair", &verified)?.ok_or("verified repair missing")?;
        assert_eq!(
            verified.verdict,
            Verdict::Allow,
            "{backend}: {:?}",
            verified.reason
        );
        let gate = Arc::new(Gate::open(backend, &directory, &rule)?);
        let mut publisher = crate::workload::configured_kernel(&directory, publisher_key.clone())?;
        publisher.register_tool_server(Box::new(Publisher {
            gate: gate.clone(),
            rule: rule.clone(),
            directory: directory.clone(),
            local_check: None,
        }));
        let mut substituted = delivery.clone();
        substituted["artifact"]["files"][FILES[0]] = json!("print('unverified replacement')\n");
        let denied = crate::workload::invoke_authorized(
            &publisher,
            &publisher_key,
            "repair-review-queue",
            "publish",
            substituted,
            "substituted",
        )?;
        response(&directory, "substitution-denied", &denied)?;
        assert_ne!(denied.verdict, Verdict::Allow);
        assert_eq!(crate::count(&directory)?, 0);
        let accepted = crate::workload::invoke_authorized(
            &publisher,
            &publisher_key,
            "repair-review-queue",
            "publish",
            delivery.clone(),
            "publish",
        )?;
        response(&directory, "publication", &accepted)?;
        assert_eq!(accepted.verdict, Verdict::Allow);
        assert_eq!(crate::count(&directory)?, 1);
        drop(publisher);
        drop(gate);
        let reopened = Arc::new(Gate::open(backend, &directory, &rule)?);
        let mut replacement =
            crate::workload::configured_kernel(&directory, publisher_key.clone())?;
        replacement.register_tool_server(Box::new(Publisher {
            gate: reopened.clone(),
            rule: rule.clone(),
            directory: directory.clone(),
            local_check: None,
        }));
        let repeated = crate::workload::invoke_authorized(
            &replacement,
            &publisher_key,
            "repair-review-queue",
            "publish",
            delivery,
            "replacement",
        )?;
        response(&directory, "replacement-denied", &repeated)?;
        assert_ne!(repeated.verdict, Verdict::Allow);
        assert_eq!(crate::count(&directory)?, 1);
        for name in FILES {
            assert_eq!(
                std::fs::read_to_string(directory.join("approved").join(name))?,
                repair.files[name]
            );
        }
        observations.push(json!({"baselineRejected":true,"helperOnlyFixRejected":true,"selfAssertedPassRejected":true,"noCommitRejected":true,"evidenceErasureRejected":true,"wrongBaseRejected":true,"substitutionRejected":true,"replacementRejected":true,"checkedCommitCases":7,"publishedEffects":1,"artifactSha256":hash(&artifact)?,"state":reopened.status(&rule)?.0}));
    }
    assert_eq!(observations[0], observations[1]);
    let report = json!({"experiment":"isolated-code-repair","chio":observations[0],"ledger":observations[1],"separationObserved":false,"limits":["Finite black-box regression contract, not universal code correctness","Trusted host checker, kernel, operator, libraries and Git; candidate Python and Git checks run in separate sandboxes","No aggregate resource quotas, remote administration, live model or deployment activation","Sources published into a new review directory; operator checkout is not changed by this workflow"]});
    std::fs::write(
        root.join("repair-comparison.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(report)
}
