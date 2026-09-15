//! Domain-specific recovery for one receiver-owned Git reference. The generic
//! gate is never reset, and a lost dispatch permit is never reconstructed.
use super::*;
use std::os::unix::process::ExitStatusExt;

#[path = "repair_git_audit.rs"]
pub mod audit;

const REFERENCE: &str = "refs/heads/verified-repair";
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Intent {
    reference: String,
    expected_old: String,
    target_commit: String,
    repair: Repair,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Owner {
    backend: String,
    rule: OutcomeEffectRule,
    request: OutcomeEffectRequest,
    intent: Intent,
}

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err("Git publication input exceeds one MiB".into());
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_once(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path.parent().ok_or("intent parent absent")?;
    let bytes = canonical_json_bytes(value)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    if let Err(error) = file.persist_noclobber(path) {
        if error.error.kind() != std::io::ErrorKind::AlreadyExists || std::fs::read(path)? != bytes
        {
            return Err("immutable publication record conflicts".into());
        }
    }
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn trusted_git(repo: &Path, args: &[&str]) -> Result<String> {
    let mut command = vec![
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsync=all",
        "-c",
        "core.fsyncMethod=fsync",
    ];
    command.extend_from_slice(args);
    let result = git_ok(repo, &command)?;
    Ok(result["stdout"]
        .as_str()
        .ok_or("Git stdout missing")?
        .to_string())
}

fn oid(value: &str) -> Result<&str> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("expected a literal SHA-256 Git object identifier".into());
    }
    Ok(value)
}

fn prepare_repository(repo: &Path, repair: &Repair) -> Result<Intent> {
    std::fs::create_dir(repo)?;
    trusted_git(repo, &["init", "--quiet", "--object-format=sha256"])?;
    for (name, text) in &repair.files {
        let path = repo.join(name);
        std::fs::create_dir_all(path.parent().ok_or("source parent missing")?)?;
        std::fs::write(path, text)?;
    }
    trusted_git(repo, &["add", "--", FILES[0], FILES[1]])?;
    let tree = trusted_git(repo, &["write-tree"])?;
    let commit = trusted_git(
        repo,
        &[
            "commit-tree",
            oid(tree.trim())?,
            "-m",
            "fix: publish checked Git hook repair",
        ],
    )?;
    let intent = Intent {
        reference: REFERENCE.into(),
        expected_old: ZERO.into(),
        target_commit: oid(commit.trim())?.into(),
        repair: repair.clone(),
    };
    verify_tree(repo, &intent)?;
    assert!(current_ref(repo)?.is_none());
    Ok(intent)
}

fn verify_tree(repo: &Path, intent: &Intent) -> Result<()> {
    if intent.reference != REFERENCE || intent.expected_old != ZERO {
        return Err("Git adapter only creates its fixed, initially absent reference".into());
    }
    let target = oid(&intent.target_commit)?;
    if trusted_git(repo, &["cat-file", "-t", target])?.trim() != "commit" {
        return Err("publication target is not a commit".into());
    }
    let files = trusted_git(
        repo,
        &[
            "ls-tree",
            "-r",
            "--full-tree",
            "--format=%(objectmode) %(objecttype) %(path)",
            target,
        ],
    )?;
    let expected = FILES
        .iter()
        .map(|name| format!("100644 blob {name}\n"))
        .collect::<String>();
    if files != expected || intent.repair.files.len() != FILES.len() {
        return Err("commit tree differs from the fixed regular-file contract".into());
    }
    for name in FILES {
        let stored = trusted_git(repo, &["show", &format!("{target}:{name}")])?;
        if Some(&stored) != intent.repair.files.get(name) {
            return Err("published Git bytes differ from checked source".into());
        }
    }
    Ok(())
}

fn current_ref(repo: &Path) -> Result<Option<String>> {
    let symbolic = git(
        repo,
        &[
            "git".into(),
            "symbolic-ref".into(),
            "-q".into(),
            REFERENCE.into(),
        ],
    )?;
    if symbolic["success"] == true {
        return Err("publication reference became symbolic".into());
    }
    if symbolic["exit"] != "exit status: 1" {
        return Err(format!("cannot inspect reference kind: {symbolic}").into());
    }
    let value = git(
        repo,
        &[
            "git".into(),
            "rev-parse".into(),
            "--verify".into(),
            "--quiet".into(),
            REFERENCE.into(),
        ],
    )?;
    if value["success"] == true {
        Ok(Some(
            oid(value["stdout"].as_str().ok_or("ref output missing")?.trim())?.into(),
        ))
    } else if value["exit"] == "exit status: 1" {
        Ok(None)
    } else {
        Err(format!("cannot inspect publication reference: {value}").into())
    }
}

fn checkpoint(mode: &str, phase: &str) {
    if mode == phase {
        println!("GIT_PUBLICATION_CHECKPOINT {phase}");
        let _ = std::io::stdout().flush();
        loop {
            std::thread::park();
        }
    }
}

struct GitPublisher {
    owner: Owner,
    gate: Gate,
    directory: PathBuf,
    mode: String,
}

impl GitPublisher {
    fn publish(&self, arguments: Value) -> Result<Value> {
        let intent: Intent = serde_json::from_value(arguments)?;
        if hash(&intent)? != hash(&self.owner.intent)?
            || self.owner.request.arguments.artifact_sha256 != hash(&intent)?
            || self.owner.request.arguments.resource != self.owner.rule.resource
        {
            return Err("request changed the receiver's immutable Git intent".into());
        }
        let repo = self.directory.join("review-repo");
        verify_tree(&repo, &intent)?;
        // Reconcile only this fixed CAS, with exactly the authorization that
        // was consumed. Read-only claim state cannot dispatch an append tool.
        let permit = if self.gate.claimed_matches(&self.owner.request)? {
            None
        } else {
            let prepared = self.gate.prepare(
                &self.owner.request,
                &self.owner.rule.server_id,
                &self.owner.rule.tool_name,
                NOW,
            )?;
            checkpoint(&self.mode, "before_claim");
            let permit = self.gate.claim(
                &prepared,
                &self.owner.rule.server_id,
                &self.owner.rule.tool_name,
                NOW,
            )?;
            checkpoint(&self.mode, "after_claim");
            Some(permit)
        };
        match current_ref(&repo)? {
            Some(current) if current == intent.target_commit => {}
            Some(_) => {
                return Err(
                    "publication reference has an unexpected commit; refusing overwrite".into(),
                )
            }
            None => {
                // --no-deref prevents a concurrent symbolic-ref replacement
                // from redirecting this write to another branch. Expected-old
                // zero makes every attempt a conditional creation, not append.
                let attempted = trusted_git(
                    &repo,
                    &[
                        "update-ref",
                        "--no-deref",
                        "--create-reflog",
                        "-m",
                        "checked-repair-publication",
                        REFERENCE,
                        &intent.target_commit,
                        ZERO,
                    ],
                );
                if attempted.is_err()
                    && current_ref(&repo)?.as_deref() != Some(&intent.target_commit)
                {
                    return Err("Git compare-and-swap did not publish the selected commit".into());
                }
            }
        }
        checkpoint(&self.mode, "after_ref");
        // Completion comes from current Git state and exact tree bytes, never
        // from a caller claim or the existence of a prior result file.
        if current_ref(&repo)?.as_deref() != Some(&intent.target_commit) {
            return Err("publication changed before observation".into());
        }
        verify_tree(&repo, &intent)?;
        let result = json!({"schema":"observed-git-publication.experimental.v1","intentSha256":hash(&intent)?,"artifactSha256":hash(&intent.repair)?,"reference":REFERENCE,"commit":intent.target_commit,"observedPublished":true});
        write_once(&self.directory.join("git-observation.json"), &result)?;
        if let Some(permit) = permit {
            self.gate.complete(permit, &result)?;
        }
        checkpoint(&self.mode, "after_complete");
        Ok(result)
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for GitPublisher {
    fn server_id(&self) -> &str {
        "checked-git-publication"
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
        self.publish(arguments)
            .map_err(|error| KernelError::ToolServerError(error.to_string()))
    }
}

pub fn worker(directory: &Path, mode: &str) -> Result<()> {
    if !matches!(
        mode,
        "finish" | "before_claim" | "after_claim" | "after_ref" | "after_complete" | "race"
    ) {
        return Err("unknown Git publication worker mode".into());
    }
    let owner: Owner = read(&directory.join("owner.json"))?;
    let key = Keypair::from_seed_hex(&std::fs::read_to_string(directory.join("key.seed"))?)?;
    let gate = Gate::open(&owner.backend, directory, &owner.rule)?;
    let arguments = read(&directory.join("input.json"))?;
    let host = directory.join(format!("worker-{}", std::process::id()));
    std::fs::create_dir(&host)?;
    let mut kernel = crate::workload::configured_kernel(&host, key.clone())?;
    kernel.register_tool_server(Box::new(GitPublisher {
        owner,
        gate,
        directory: directory.into(),
        mode: mode.into(),
    }));
    if mode == "race" {
        std::fs::write(host.join("ready"), b"ready")?;
        let deadline = Instant::now() + Duration::from_secs(20);
        while !directory.join("start").exists() {
            if Instant::now() >= deadline {
                return Err("Git race not released".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let reply = crate::workload::invoke_authorized(
        &kernel,
        &key,
        "checked-git-publication",
        "publish",
        arguments,
        "git-publication",
    )?;
    response(&host, "reply", &reply)?;
    if reply.verdict != Verdict::Allow {
        return Err(format!("Git publication denied: {:?}", reply.reason).into());
    }
    Ok(())
}

fn launch(directory: &Path, mode: &str) -> Result<OwnedChild> {
    Ok(OwnedChild(
        Command::new(std::env::current_exe()?)
            .arg("--git-repair-worker")
            .arg(directory)
            .arg(mode)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    ))
}

fn kill_at(directory: &Path, phase: &str) -> Result<()> {
    use std::io::BufRead;
    let mut child = launch(directory, phase)?;
    let stdout = child.0.stdout.take().ok_or("worker stdout missing")?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let expected = format!("GIT_PUBLICATION_CHECKPOINT {phase}");
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            if matches!(line, Ok(ref line) if line == &expected) {
                let _ = sender.send(());
                break;
            }
        }
    });
    receiver.recv_timeout(Duration::from_secs(30))?;
    child.0.kill()?;
    let status = child.0.wait()?;
    assert_eq!(status.signal(), Some(9));
    eprintln!("GIT_PUBLICATION_KILL pid={} phase={phase}", child.0.id());
    Ok(())
}

fn finish(directory: &Path, admitted: bool) -> Result<()> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .arg("--git-repair-worker")
        .arg(directory)
        .arg("finish");
    let output = capture(command)?;
    assert_eq!(output["success"], admitted, "Git worker: {output}");
    Ok(())
}

fn publications(repo: &Path) -> Result<usize> {
    let path = repo.join(".git/logs").join(REFERENCE);
    match std::fs::read_to_string(path) {
        Ok(log) => Ok(log
            .lines()
            .filter(|line| line.ends_with("\tchecked-repair-publication"))
            .count()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}

fn provision(directory: &Path, backend: &str, repair: &Repair, contract: &Value) -> Result<Owner> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(directory)?;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    let intent = prepare_repository(&directory.join("review-repo"), repair)?;
    let key = Keypair::generate();
    std::fs::write(directory.join("key.seed"), key.seed_hex())?;
    std::fs::set_permissions(
        directory.join("key.seed"),
        std::fs::Permissions::from_mode(0o600),
    )?;
    let rule = OutcomeEffectRule {
        slot: OutcomeEffectSlot {
            receiver_id: key.public_key().to_hex(),
            workflow_id: "recover-checked-git-repair".into(),
            step_id: "publish".into(),
        },
        predecessor_step_id: "receiver-source-check".into(),
        verifier_key: key.public_key(),
        contract_sha256: hash(contract)?,
        server_id: "checked-git-publication".into(),
        tool_name: "publish".into(),
        resource: REFERENCE.into(),
        valid_from_unix_ms: NOW - 1000,
        valid_until_unix_ms: NOW + 1000,
    };
    let request = OutcomeEffectRequest {
        evidence: outcome(&rule, &serde_json::to_value(&intent)?, &key)?,
        arguments: OutcomeEffectArguments {
            artifact_sha256: hash(&intent)?,
            resource: REFERENCE.into(),
        },
    };
    let owner = Owner {
        backend: backend.into(),
        rule,
        request,
        intent,
    };
    write_once(&directory.join("owner.json"), &owner)?;
    std::fs::write(
        directory.join("input.json"),
        canonical_json_bytes(&owner.intent)?,
    )?;
    drop(Gate::open(backend, directory, &owner.rule)?);
    Ok(owner)
}

pub fn compare(root: &Path, baseline: &Path, candidate: &Path) -> Result<Value> {
    let root = std::fs::canonicalize(root)?;
    let base = sources(baseline)?
        .into_iter()
        .map(|(name, text)| (name, sha256_hex(text.as_bytes())))
        .collect();
    let repair = Repair {
        base_sha256: base,
        files: sources(candidate)?,
    };
    let contract = json!({"schema":"checked-git-recovery.experimental.v1","paths":FILES,"baseSha256":repair.base_sha256,"requests":requests(),"hooks":HOOKS,"reference":REFERENCE,"expectedOld":ZERO,"checkerSha256":sha256_hex(include_bytes!("repair.rs")),"driverSha256":sha256_hex(DRIVER.as_bytes()),"adapterSha256":sha256_hex(include_bytes!("repair_git.rs")),"isolationSha256":sha256_hex(include_bytes!("isolation.rs")),"recovery":"Reconcile only the already-claimed immutable Git creation; do not reconstruct a generic permit"});
    write_once(&root.join("contract.json"), &contract)?;
    write_once(&root.join("candidate.json"), &repair)?;
    let cases = [
        "before_claim",
        "after_claim",
        "after_ref",
        "after_complete",
        "race_after_claim",
        "revoked_after_claim",
        "changed_source",
        "changed_target",
        "conflicting_ref",
        "symbolic_ref",
        "missing_object",
        "revoked_before_claim",
    ];
    let mut rows = Vec::new();
    // Receiver checking occurs before trusted provisioning. Reuse only the
    // exact checked bytes across crash scenarios; candidate code has no access
    // to these receiver directories or any signing key.
    for backend in BACKENDS {
        check_owned_artifact(
            &root.join("checks").join(backend),
            &repair.base_sha256,
            &serde_json::to_value(&repair)?,
        )?;
    }
    for case in cases {
        let mut observations = Vec::new();
        for backend in BACKENDS {
            let directory = root.join(case).join(backend);
            let owner = provision(&directory, backend, &repair, &contract)?;
            let repo = directory.join("review-repo");
            let gate = Gate::open(backend, &directory, &owner.rule)?;
            assert!(!gate.claimed_matches(&owner.request)?);
            if case == "revoked_before_claim" {
                gate.revoke(&owner.rule)?;
            } else {
                kill_at(
                    &directory,
                    if matches!(case, "before_claim" | "after_ref" | "after_complete") {
                        case
                    } else {
                        "after_claim"
                    },
                )?;
            }
            let initial = publications(&repo)?;
            let initial_state = gate.status(&owner.rule)?.0;
            if case == "revoked_after_claim" {
                // Claim commits the fixed domain operation. Later revocation
                // prevents fresh claims, but cannot cancel this accepted CAS.
                gate.revoke(&owner.rule)?;
            }
            if initial_state != "waiting" {
                assert!(gate.claimed_matches(&owner.request)?);
                let mut other = owner.request.clone();
                other.arguments.artifact_sha256 = sha256_hex(b"unclaimed artifact");
                assert!(!gate.claimed_matches(&other)?);
                other = owner.request.clone();
                other.evidence.signature = Keypair::generate().sign(b"different evidence");
                assert!(!gate.claimed_matches(&other)?);
            }
            match case {
                "changed_source" => {
                    let mut changed = owner.intent.clone();
                    changed
                        .repair
                        .files
                        .insert(FILES[0].into(), "print('not checked')\n".into());
                    std::fs::write(
                        directory.join("input.json"),
                        canonical_json_bytes(&changed)?,
                    )?;
                }
                "changed_target" => {
                    let mut changed = owner.intent.clone();
                    changed.target_commit = ZERO.into();
                    std::fs::write(
                        directory.join("input.json"),
                        canonical_json_bytes(&changed)?,
                    )?;
                }
                "conflicting_ref" | "symbolic_ref" => {
                    let tree = trusted_git(
                        &repo,
                        &[
                            "rev-parse",
                            &format!("{}^{{tree}}", owner.intent.target_commit),
                        ],
                    )?;
                    let other = trusted_git(
                        &repo,
                        &[
                            "commit-tree",
                            tree.trim(),
                            "-m",
                            "test: unrelated operator commit",
                        ],
                    )?;
                    trusted_git(
                        &repo,
                        &[
                            "update-ref",
                            "--create-reflog",
                            "-m",
                            "operator",
                            if case == "symbolic_ref" {
                                "refs/heads/operator"
                            } else {
                                REFERENCE
                            },
                            other.trim(),
                            ZERO,
                        ],
                    )?;
                    if case == "symbolic_ref" {
                        trusted_git(&repo, &["symbolic-ref", REFERENCE, "refs/heads/operator"])?;
                    }
                }
                "missing_object" => {
                    let target = &owner.intent.target_commit;
                    std::fs::rename(
                        repo.join(".git/objects")
                            .join(&target[..2])
                            .join(&target[2..]),
                        directory.join("withheld-commit-object"),
                    )?;
                }
                _ => {}
            }
            let admitted = matches!(
                case,
                "before_claim"
                    | "after_claim"
                    | "after_ref"
                    | "after_complete"
                    | "race_after_claim"
                    | "revoked_after_claim"
            );
            let refs_before = trusted_git(
                &repo,
                &[
                    "for-each-ref",
                    "--format=%(refname) %(objectname) %(symref)",
                ],
            )?;
            if case == "race_after_claim" {
                let mut children = (0..8)
                    .map(|_| launch(&directory, "race"))
                    .collect::<Result<Vec<_>>>()?;
                let deadline = Instant::now() + Duration::from_secs(20);
                while !children.iter().all(|child| {
                    directory
                        .join(format!("worker-{}", child.0.id()))
                        .join("ready")
                        .exists()
                }) {
                    if Instant::now() >= deadline {
                        return Err("Git contenders not ready".into());
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                std::fs::write(directory.join("start"), b"go")?;
                for child in &mut children {
                    while child.0.try_wait()?.is_none() {
                        if Instant::now() >= deadline {
                            return Err("Git contender did not finish".into());
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    assert!(child.0.wait()?.success());
                }
            } else {
                finish(&directory, admitted)?;
            }
            let final_state = gate.status(&owner.rule)?.0;
            if admitted {
                assert_eq!(
                    current_ref(&repo)?.as_deref(),
                    Some(owner.intent.target_commit.as_str())
                );
                verify_tree(&repo, &owner.intent)?;
                assert!(directory.join("git-observation.json").exists());
                finish(&directory, true)?;
            } else {
                assert!(!directory.join("git-observation.json").exists());
                // Compare complete ref inventory so denial cannot silently
                // redirect the symbolic reference's unrelated destination.
                let before = trusted_git(
                    &repo,
                    &[
                        "for-each-ref",
                        "--format=%(refname) %(objectname) %(symref)",
                    ],
                )?;
                assert_eq!(refs_before, before, "denial changed another reference");
                finish(&directory, false)?;
                assert_eq!(
                    before,
                    trusted_git(
                        &repo,
                        &[
                            "for-each-ref",
                            "--format=%(refname) %(objectname) %(symref)"
                        ]
                    )?
                );
            }
            assert_eq!(publications(&repo)?, usize::from(admitted));
            assert_eq!(
                final_state,
                if matches!(case, "before_claim" | "after_complete") {
                    "completed"
                } else if case == "revoked_before_claim" {
                    "waiting"
                } else {
                    "claimed"
                }
            );
            observations.push(json!({"accepted":admitted,"initialPublications":initial,"finalPublications":publications(&repo)?,"initialGateState":initial_state,"finalGateState":final_state,"observedPublished":directory.join("git-observation.json").exists(),"repeatPreservedState":gate.status(&owner.rule)?.0==final_state,"claimIdentitySubstitutionsRejected":initial_state!="waiting"}));
        }
        assert_eq!(observations[0], observations[1], "{case}");
        rows.push(json!({"case":case,"chio":observations[0],"ledger":observations[1]}));
    }
    let report = json!({"experiment":"receiver-checked-git-publication-recovery","pairedScenarios":rows,"receiverChecks":2,"checkedCommitCases":14,"sigkills":22,"recoveryRacersPerBackend":8,"gateSeparationObserved":false,"genericPermitReconstructed":false,"limits":["Receiver, checker, adapter, store and host are trusted","One exclusive receiver-owned SHA-256 Git reference; no reset, rollback or ABA guarantee","Generic gate remains claimed after permit loss; Git observation is a separate domain result","Revocation prevents new claims but does not cancel the fixed CAS already accepted by a claim","Process kills at observed boundaries, not power loss or interruption inside Git ref transactions","No arbitrary-effect exactly-once claim, remote Git push, deployment or integration-effort advantage"]});
    write_once(&root.join("git-repair-comparison.json"), &report)?;
    Ok(report)
}
