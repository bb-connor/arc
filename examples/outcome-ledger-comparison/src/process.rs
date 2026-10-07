use std::io::{BufRead, Write};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::{append_effect, count, fixture, Gate, Result, BACKENDS, NOW};

struct OwnedChild(Child);
impl OwnedChild {
    fn wait(&mut self) -> Result<ExitStatus> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.0.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err("owned worker did not exit before deadline".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(backend: &str, directory: &Path, mode: &str) -> Result<OwnedChild> {
    Ok(OwnedChild(
        Command::new(std::env::current_exe()?)
            .arg("--worker")
            .arg(backend)
            .arg(directory)
            .arg(mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    ))
}

fn checkpoint() -> ! {
    println!("OBSERVED_DISPATCH_CHECKPOINT");
    let _ = std::io::stdout().flush();
    loop {
        std::thread::park();
    }
}

pub fn worker(backend: &str, directory: &Path, mode: &str) -> Result<()> {
    let (rule, request, _) = fixture()?;
    let gate = Gate::open(backend, directory, &rule)?;
    let prepared = match gate.prepare(&request, &rule.server_id, &rule.tool_name, NOW) {
        Ok(prepared) => prepared,
        Err(error) => {
            if matches!(gate.status(&rule)?.0.as_str(), "claimed" | "completed") {
                return Ok(());
            }
            return Err(error);
        }
    };
    if mode == "race" {
        std::fs::write(
            directory.join(format!("ready-{}", std::process::id())),
            b"ready",
        )?;
        let deadline = Instant::now() + Duration::from_secs(15);
        while !directory.join("start").exists() {
            if Instant::now() >= deadline {
                return Err("race not released".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    if mode == "before_claim" {
        checkpoint();
    }
    let permit = match gate.claim(&prepared, &rule.server_id, &rule.tool_name, NOW) {
        Ok(permit) => permit,
        Err(error) => {
            if matches!(gate.status(&rule)?.0.as_str(), "claimed" | "completed") {
                return Ok(());
            }
            return Err(error);
        }
    };
    if mode == "after_claim" {
        checkpoint();
    }
    let result = append_effect(directory)?;
    if mode == "after_effect" {
        checkpoint();
    }
    gate.complete(permit, &result)?;
    if mode == "after_complete" {
        checkpoint();
    }
    if !matches!(mode, "race" | "complete") {
        return Err("unknown worker phase".into());
    }
    Ok(())
}

pub fn compare(root: &Path) -> Result<Value> {
    let mut rows = Vec::new();
    for mode in [
        "race",
        "before_claim",
        "after_claim",
        "after_effect",
        "after_complete",
    ] {
        let mut observations = Vec::new();
        for backend in BACKENDS {
            let directory = root.join("faults").join(mode).join(backend);
            let (rule, _, _) = fixture()?;
            drop(Gate::open(backend, &directory, &rule)?);
            let killed = if mode == "race" {
                let mut children = (0..8)
                    .map(|_| spawn(backend, &directory, mode))
                    .collect::<Result<Vec<_>>>()?;
                let deadline = Instant::now() + Duration::from_secs(15);
                while !children
                    .iter()
                    .all(|child| directory.join(format!("ready-{}", child.0.id())).exists())
                {
                    if Instant::now() >= deadline {
                        return Err("contenders did not reach race barrier".into());
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                std::fs::write(directory.join("start"), b"go")?;
                for child in &mut children {
                    assert!(child.wait()?.success(), "{backend} race worker failed");
                }
                false
            } else {
                let mut child = spawn(backend, &directory, mode)?;
                let stdout = child.0.stdout.take().ok_or("child stdout absent")?;
                let (sender, receiver) = std::sync::mpsc::sync_channel(1);
                std::thread::spawn(move || {
                    for line in std::io::BufReader::new(stdout).lines() {
                        match line {
                            Ok(line) if line == "OBSERVED_DISPATCH_CHECKPOINT" => {
                                let _ = sender.send(true);
                                return;
                            }
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                    let _ = sender.send(false);
                });
                let observed = receiver.recv_timeout(Duration::from_secs(15))?;
                assert!(observed, "{backend} {mode} checkpoint missing");
                child.0.kill()?;
                let status = child.wait()?;
                assert!(!status.success());
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    assert_eq!(status.signal(), Some(9));
                }
                eprintln!("MATCHED_KILL backend={backend} boundary={mode} exit={status}");
                true
            };
            let reopened = Gate::open(backend, &directory, &rule)?;
            let before_state = reopened.status(&rule)?.0;
            let before_effects = count(&directory)?;
            let expected_state = match mode {
                "before_claim" => "waiting",
                "after_claim" | "after_effect" => "claimed",
                _ => "completed",
            };
            assert_eq!(before_state, expected_state);
            assert_eq!(
                before_effects,
                usize::from(matches!(mode, "race" | "after_effect" | "after_complete"))
            );
            let mut replacement = spawn(backend, &directory, "complete")?;
            assert!(replacement.wait()?.success());
            let (after_state, result) = reopened.status(&rule)?;
            let after_effects = count(&directory)?;
            assert_eq!(after_effects, usize::from(mode != "after_claim"));
            assert_eq!(
                result.is_some(),
                matches!(mode, "race" | "before_claim" | "after_complete")
            );
            observations.push(json!({"killed":killed,"stateAtRestart":before_state,"effectsAtRestart":before_effects,"stateAfterReplacement":after_state,"effectsAfterReplacement":after_effects,"resultRetained":result.is_some()}));
        }
        assert_eq!(observations[0], observations[1], "{mode}");
        rows.push(json!({"case":mode,"chio":observations[0],"ledger":observations[1]}));
    }
    Ok(json!(rows))
}
