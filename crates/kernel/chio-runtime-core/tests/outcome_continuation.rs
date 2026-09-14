use std::error::Error;
use std::io::{BufRead, Write};
use std::process::{Child, Command, Stdio};

use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_runtime_core::outcome_continuation::{
    ArtifactOutcome, OutcomeEffectArguments, OutcomeEffectRequest, OutcomeEffectRule,
    OutcomeEffectSlot, OutcomeEffectState, SignedArtifactOutcome, ARTIFACT_OUTCOME_SCHEMA,
};
use chio_runtime_core::SqliteRuntimeOrchestrationStore;

type TestResult = Result<(), Box<dyn Error>>;
const NOW: u64 = 1_800_000_000_000;

fn rule() -> OutcomeEffectRule {
    OutcomeEffectRule {
        slot: OutcomeEffectSlot {
            receiver_id: "release-owner".into(),
            workflow_id: "repair-quote-rounding".into(),
            step_id: "publish-approved-artifact".into(),
        },
        predecessor_step_id: "independent-contract-check".into(),
        verifier_key: Keypair::from_seed(&[19; 32]).public_key(),
        contract_sha256: sha256_hex(b"owner-selected-contract"),
        server_id: "artifact-registry".into(),
        tool_name: "publish".into(),
        resource: "release-candidate-queue".into(),
        valid_from_unix_ms: NOW - 1_000,
        valid_until_unix_ms: NOW + 1_000,
    }
}

fn request(rule: &OutcomeEffectRule) -> Result<OutcomeEffectRequest, Box<dyn Error>> {
    let body = ArtifactOutcome {
        schema: ARTIFACT_OUTCOME_SCHEMA.into(),
        slot: rule.slot.clone(),
        predecessor_step_id: rule.predecessor_step_id.clone(),
        contract_sha256: rule.contract_sha256.clone(),
        artifact_sha256: sha256_hex(b"verified artifact"),
        passed: true,
        verified_at_unix_ms: NOW,
    };
    Ok(OutcomeEffectRequest {
        arguments: OutcomeEffectArguments {
            artifact_sha256: body.artifact_sha256.clone(),
            resource: rule.resource.clone(),
        },
        evidence: SignedArtifactOutcome::sign(body, &Keypair::from_seed(&[19; 32]))?,
    })
}

#[test]
fn receiver_rule_binds_every_effect_and_outcome_input_without_burning_the_slot() -> TestResult {
    for mutation in [
        "key",
        "contract",
        "predecessor",
        "receiver",
        "workflow",
        "step",
        "artifact",
        "resource",
        "failed",
        "future",
        "old",
        "server",
        "tool",
        "unsigned",
        "schema",
    ] {
        let dir = tempfile::tempdir()?;
        let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("receiver.db"))?;
        let rule = rule();
        store.activate_outcome_effect(&rule)?;
        let baseline = request(&rule)?;
        let mut changed = baseline.clone();
        let mut signing_key = Keypair::from_seed(&[19; 32]);
        let mut server = rule.server_id.as_str();
        let mut tool = rule.tool_name.as_str();
        match mutation {
            "key" => signing_key = Keypair::from_seed(&[20; 32]),
            "contract" => changed.evidence.body.contract_sha256 = sha256_hex(b"easier contract"),
            "predecessor" => {
                changed.evidence.body.predecessor_step_id = "unverified-proposal".into()
            }
            "receiver" => changed.evidence.body.slot.receiver_id = "different-owner".into(),
            "workflow" => changed.evidence.body.slot.workflow_id = "fresh-workflow".into(),
            "step" => changed.evidence.body.slot.step_id = "fresh-step".into(),
            "artifact" => changed.arguments.artifact_sha256 = sha256_hex(b"untested artifact"),
            "resource" => changed.arguments.resource = "production".into(),
            "failed" => changed.evidence.body.passed = false,
            "future" => changed.evidence.body.verified_at_unix_ms = NOW + 1,
            "old" => changed.evidence.body.verified_at_unix_ms = NOW - 1_001,
            "server" => server = "other-server",
            "tool" => tool = "delete",
            "unsigned" | "schema" => {}
            _ => return Err("unhandled mutation".into()),
        }
        changed.evidence = SignedArtifactOutcome::sign(changed.evidence.body, &signing_key)?;
        if mutation == "unsigned" {
            changed.evidence.body.artifact_sha256 = sha256_hex(b"unsigned rewrite");
            changed.arguments.artifact_sha256 = changed.evidence.body.artifact_sha256.clone();
        }
        if mutation == "schema" {
            changed.evidence.body.schema = "different-protocol".into();
        }
        assert!(
            store
                .claim_outcome_effect(&changed, server, tool, "host-request", NOW)
                .is_err(),
            "{mutation}"
        );
        assert!(
            matches!(
                store.outcome_effect_status(&rule.slot)?.state,
                OutcomeEffectState::Waiting
            ),
            "{mutation}"
        );
        let permit = store.claim_outcome_effect(
            &baseline,
            &rule.server_id,
            &rule.tool_name,
            "retry-valid",
            NOW,
        )?;
        store.complete_outcome_effect(permit, &serde_json::json!({"published": true}))?;
    }
    Ok(())
}

#[test]
fn fresh_evidence_attempt_and_artifact_cannot_recreate_consumed_authority() -> TestResult {
    let dir = tempfile::tempdir()?;
    let database = dir.path().join("receiver.db");
    let rule = rule();
    {
        let store = SqliteRuntimeOrchestrationStore::open(&database)?;
        store.activate_outcome_effect(&rule)?;
        let permit = store.claim_outcome_effect(
            &request(&rule)?,
            &rule.server_id,
            &rule.tool_name,
            "agent-1-request",
            NOW,
        )?;
        store.complete_outcome_effect(permit, &serde_json::json!({"artifact": "published"}))?;
    }
    let store = SqliteRuntimeOrchestrationStore::open(&database)?;
    store.activate_outcome_effect(&rule)?;
    for replace_artifact in [false, true] {
        let mut fresh = request(&rule)?;
        fresh.evidence.body.verified_at_unix_ms = NOW + 1;
        if replace_artifact {
            fresh.evidence.body.artifact_sha256 =
                sha256_hex(b"another genuinely verified artifact");
            fresh.arguments.artifact_sha256 = fresh.evidence.body.artifact_sha256.clone();
        }
        fresh.evidence =
            SignedArtifactOutcome::sign(fresh.evidence.body, &Keypair::from_seed(&[19; 32]))?;
        let error = store
            .claim_outcome_effect(
                &fresh,
                &rule.server_id,
                &rule.tool_name,
                "replacement-agent-fresh-request",
                NOW + 1,
            )
            .err()
            .ok_or("duplicate claim was admitted")?;
        assert_eq!(error.code(), "outcome_effect_already_claimed");
    }
    assert!(matches!(
        store.outcome_effect_status(&rule.slot)?.state,
        OutcomeEffectState::Completed { .. }
    ));
    Ok(())
}

#[test]
fn revocation_and_expiry_are_rechecked_at_claim_time() -> TestResult {
    for expiry in [false, true] {
        let dir = tempfile::tempdir()?;
        let database = dir.path().join("receiver.db");
        let rule = rule();
        let store = SqliteRuntimeOrchestrationStore::open(&database)?;
        store.activate_outcome_effect(&rule)?;
        let request = request(&rule)?;
        store.preview_outcome_effect(&request, &rule.server_id, &rule.tool_name, NOW)?;
        let now = if expiry {
            rule.valid_until_unix_ms
        } else {
            store.revoke_outcome_effect(&rule.slot)?;
            NOW
        };
        drop(store);
        let reopened = SqliteRuntimeOrchestrationStore::open(&database)?;
        reopened.activate_outcome_effect(&rule)?;
        let error = reopened
            .claim_outcome_effect(
                &request,
                &rule.server_id,
                &rule.tool_name,
                "after-preview",
                now,
            )
            .err()
            .ok_or("stale preview authorized a claim")?;
        assert_eq!(
            error.code(),
            if expiry {
                "outcome_effect_expired"
            } else {
                "outcome_effect_revoked"
            }
        );
        assert!(matches!(
            reopened.outcome_effect_status(&rule.slot)?.state,
            OutcomeEffectState::Waiting
        ));
    }
    Ok(())
}

#[test]
fn activation_is_immutable_and_has_no_new_token_reset_path() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("receiver.db"))?;
    let rule = rule();
    store.activate_outcome_effect(&rule)?;
    let mut different = rule.clone();
    different.valid_until_unix_ms += 1;
    assert_eq!(
        store
            .activate_outcome_effect(&different)
            .err()
            .ok_or("rule changed")?
            .code(),
        "outcome_rule_conflict"
    );
    let _permit = store.claim_outcome_effect(
        &request(&rule)?,
        &rule.server_id,
        &rule.tool_name,
        "ambiguous-dispatch",
        NOW,
    )?;
    store.activate_outcome_effect(&rule)?;
    store.revoke_outcome_effect(&rule.slot)?;
    store.activate_outcome_effect(&rule)?;
    let status = store.outcome_effect_status(&rule.slot)?;
    assert!(status.revoked);
    assert!(matches!(
        status.state,
        OutcomeEffectState::DispatchClaimed { .. }
    ));
    Ok(())
}

/// Ensure a test panic cannot leave an owned crash-probe process running.
struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn child(directory: &std::path::Path, mode: &str) -> Result<OwnedChild, Box<dyn Error>> {
    Ok(OwnedChild(
        Command::new(std::env::current_exe()?)
            .args(["--exact", "outcome_claim_subprocess_worker", "--nocapture"])
            .env("CHIO_OUTCOME_TEST_DIRECTORY", directory)
            .env("CHIO_OUTCOME_TEST_MODE", mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    ))
}

#[test]
fn competing_receiver_processes_spend_exactly_one_effect_slot() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("receiver.db"))?;
    store.activate_outcome_effect(&rule())?;
    let mut children = (0..8)
        .map(|_| child(dir.path(), "compete"))
        .collect::<Result<Vec<_>, _>>()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !children
        .iter()
        .all(|child| dir.path().join(format!("ready-{}", child.0.id())).exists())
    {
        if std::time::Instant::now() >= deadline {
            return Err("receiver processes did not reach the race barrier".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    std::fs::write(dir.path().join("start-race"), b"go")?;
    for child in &mut children {
        assert!(child.0.wait()?.success());
    }
    let effects = std::fs::read_to_string(dir.path().join("effects.log"))?;
    assert_eq!(effects.lines().count(), 1);
    println!(
        "CHIO_OUTCOME_RACE contenders={} physical_effects={}",
        children.len(),
        effects.lines().count()
    );
    assert!(matches!(
        store.outcome_effect_status(&rule().slot)?.state,
        OutcomeEffectState::Completed { .. }
    ));
    Ok(())
}

#[test]
fn killed_dispatchers_preserve_uncertainty_before_and_after_the_external_effect() -> TestResult {
    for (mode, expected_effects) in [("crash_after_claim", 0), ("crash_after_effect", 1)] {
        let dir = tempfile::tempdir()?;
        let store = SqliteRuntimeOrchestrationStore::open(dir.path().join("receiver.db"))?;
        store.activate_outcome_effect(&rule())?;
        let mut child = child(dir.path(), mode)?;
        let stdout = child.0.stdout.take().ok_or("child stdout missing")?;
        let mut checkpoint_seen = false;
        for line in std::io::BufReader::new(stdout).lines() {
            if line? == "CHIO_OUTCOME_CRASH_CHECKPOINT" {
                checkpoint_seen = true;
                break;
            }
        }
        assert!(
            checkpoint_seen,
            "owned process did not reach the requested crash boundary"
        );
        child.0.kill()?;
        let exit_status = child.0.wait()?;
        assert!(!exit_status.success());
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(exit_status.signal(), Some(9));
        }
        drop(store);
        let reopened = SqliteRuntimeOrchestrationStore::open(dir.path().join("receiver.db"))?;
        assert!(matches!(
            reopened.outcome_effect_status(&rule().slot)?.state,
            OutcomeEffectState::DispatchClaimed { .. }
        ));
        let mut replacement = self::child(dir.path(), "complete")?;
        assert!(replacement.0.wait()?.success());
        let effects = match std::fs::read_to_string(dir.path().join("effects.log")) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error.into()),
        };
        assert_eq!(effects.lines().count(), expected_effects, "{mode}");
        println!("CHIO_OUTCOME_KILL boundary={mode} exit={exit_status} physical_effects={} state=DispatchClaimed replacement_effects=0", effects.lines().count());
    }
    Ok(())
}

#[test]
fn outcome_claim_subprocess_worker() -> TestResult {
    let Some(directory) = std::env::var_os("CHIO_OUTCOME_TEST_DIRECTORY") else {
        return Ok(());
    };
    let directory = std::path::PathBuf::from(directory);
    let mode = std::env::var("CHIO_OUTCOME_TEST_MODE")?;
    let store = SqliteRuntimeOrchestrationStore::open(directory.join("receiver.db"))?;
    let rule = rule();
    if mode == "compete" {
        std::fs::write(
            directory.join(format!("ready-{}", std::process::id())),
            b"ready",
        )?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !directory.join("start-race").exists() {
            if std::time::Instant::now() >= deadline {
                return Err("race barrier was not released".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    let permit = match store.claim_outcome_effect(
        &request(&rule)?,
        &rule.server_id,
        &rule.tool_name,
        &format!("process-{}", std::process::id()),
        NOW,
    ) {
        Ok(permit) => permit,
        Err(error) if error.code() == "outcome_effect_already_claimed" => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if mode != "crash_after_claim" {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(directory.join("effects.log"))?;
        writeln!(file, "{}", permit.claim().arguments.artifact_sha256)?;
        file.sync_all()?;
    }
    if mode.starts_with("crash_after_") {
        println!("CHIO_OUTCOME_CRASH_CHECKPOINT");
        std::io::stdout().flush()?;
        loop {
            std::thread::park();
        }
    }
    assert!(matches!(mode.as_str(), "complete" | "compete"));
    store.complete_outcome_effect(permit, &serde_json::json!({"published": true}))?;
    Ok(())
}
