//! Local contingent-delivery experiment with an explicitly trusted checker and
//! settlement operator. The credit and key transition is one SQLite transaction.
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};

const WORKER: &str = include_str!("repair_exchange.py");
static LOG_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

fn write(path: &Path, value: &impl Serialize) -> Result<()> {
    std::fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn command(root: &Path, directory: &Path, action: &str, args: &[&str]) -> Command {
    let mut command = Command::new("/usr/bin/python3.12");
    command
        .env_clear()
        .arg("-I")
        .arg("-B")
        .arg(root.join("exchange-worker.py"))
        .arg(action)
        .arg(directory)
        .args(args);
    command
}

fn run(root: &Path, directory: &Path, action: &str, args: &[&str]) -> Result<Value> {
    let result = capture(command(root, directory, action, args))?;
    let sequence = LOG_SEQUENCE.fetch_add(1, Ordering::SeqCst);
    write(
        &directory.join(format!("process-{sequence}-{action}.json")),
        &result,
    )?;
    Ok(result)
}

fn successful(result: Value) -> Result<Value> {
    if result["success"] != true {
        return Err(format!("exchange worker failed: {}", result["stderr"]).into());
    }
    Ok(serde_json::from_str(
        result["stdout"].as_str().ok_or("worker output absent")?,
    )?)
}

fn make_offer(
    root: &Path,
    directory: &Path,
    name: &str,
    contract: &Value,
    artifact: &Repair,
) -> Result<Value> {
    std::fs::create_dir_all(directory)?;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    let terms = json!({"schema":"checked-repair-trade.experimental.v1","tradeId":name,"contractSha256":hash(contract)?,"buyer":"buyer","seller":"seller","price":10,"deadline":NOW+1000});
    write(&directory.join("terms.json"), &terms)?;
    std::fs::write(
        directory.join("private-artifact.json"),
        canonical_json_bytes(artifact)?,
    )?;
    successful(run(root, directory, "seal", &[])?)?;
    let offer: Value = serde_json::from_slice(&std::fs::read(directory.join("offer.json"))?)?;
    assert_eq!(offer["terms"], terms);
    assert_eq!(offer["artifactSha256"], hash(artifact)?);
    Ok(offer)
}

fn view(root: &Path, directory: &Path) -> Result<Value> {
    let snapshot = successful(run(root, directory, "view", &[])?)?;
    write(&directory.join("settlement-view.json"), &snapshot)?;
    Ok(snapshot)
}

fn check_opening(
    root: &Path,
    directory: &Path,
    selected: &Value,
    checked: &Repair,
) -> Result<Value> {
    let offer: Value = serde_json::from_slice(&std::fs::read(directory.join("offer.json"))?)?;
    if &offer != selected {
        return Err("offer differs from selected trade".into());
    }
    let opened = successful(run(root, directory, "check-open", &[])?)?;
    if opened["decryptedSha256"] != hash(checked)?
        || std::fs::read(directory.join("checker-artifact.json"))? != canonical_json_bytes(checked)?
    {
        return Err("opening is absent from the native-checked artifact cache".into());
    }
    Ok(offer)
}

fn receive(root: &Path, directory: &Path, expected: &Repair) -> Result<()> {
    let result = successful(run(root, directory, "receive", &[])?)?;
    assert_eq!(result["receivedSha256"], hash(expected)?);
    assert_eq!(
        std::fs::read(directory.join("buyer-artifact.json"))?,
        canonical_json_bytes(expected)?
    );
    Ok(())
}

fn rule(key: &Keypair, name: &str, contract: &Value) -> Result<OutcomeEffectRule> {
    Ok(OutcomeEffectRule {
        slot: OutcomeEffectSlot {
            receiver_id: key.public_key().to_hex(),
            workflow_id: name.into(),
            step_id: "settle".into(),
        },
        predecessor_step_id: "check-encrypted-repair".into(),
        verifier_key: key.public_key(),
        contract_sha256: hash(contract)?,
        server_id: "local-repair-exchange".into(),
        tool_name: "settle".into(),
        resource: "funded-trade".into(),
        valid_from_unix_ms: NOW - 1000,
        valid_until_unix_ms: NOW + 1000,
    })
}

pub fn compare(root: &Path, baseline: &Path, candidate: &Path) -> Result<Value> {
    let root = std::fs::canonicalize(root)?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    std::fs::write(root.join("exchange-worker.py"), WORKER)?;
    let old = sources(baseline)?;
    let base = old
        .iter()
        .map(|(name, source)| (name.clone(), sha256_hex(source.as_bytes())))
        .collect::<BTreeMap<_, _>>();
    let good = Repair {
        base_sha256: base.clone(),
        files: sources(candidate)?,
    };
    let bad = Repair {
        base_sha256: base.clone(),
        files: old,
    };
    let contract = json!({"schema":"repair-exchange-check.experimental.v1","baseSha256":base,"paths":FILES,"requests":requests(),"hooks":HOOKS,"checkerSha256":sha256_hex(include_bytes!("repair.rs")),"driverSha256":sha256_hex(DRIVER.as_bytes()),"exchangeSha256":sha256_hex(include_bytes!("repair_exchange.rs")),"settlementWorkerSha256":sha256_hex(WORKER.as_bytes()),"isolationSha256":sha256_hex(include_bytes!("isolation.rs")),"settlementAssumption":"Trusted local checker and SQLite operator; 100 test credits, no external payment rail"});
    write(&root.join("contract.json"), &contract)?;

    // The plain receiver already has usable bytes when it decides whether to pay.
    let plaintext = root.join("plaintext-buyer-aborts");
    std::fs::create_dir(&plaintext)?;
    std::fs::write(
        plaintext.join("buyer-artifact.json"),
        canonical_json_bytes(&good)?,
    )?;
    check_owned_artifact(
        &plaintext.join("native-check"),
        &base,
        &serde_json::to_value(&good)?,
    )?;
    assert!(check_owned_artifact(
        &root.join("buggy-native-check"),
        &base,
        &serde_json::to_value(&bad)?
    )
    .is_err());

    // A correct key and authenticated ciphertext can still contain the bad repair.
    let hashlock = root.join("bare-hashlock-buggy-repair");
    let bad_offer = make_offer(&root, &hashlock, "bare-hashlock", &contract, &bad)?;
    successful(run(&root, &hashlock, "fund", &[])?)?;
    let now = NOW.to_string();
    let after = (NOW + 1000).to_string();
    successful(run(&root, &hashlock, "settle", &[&now, "private-key.bin"])?)?;
    let bad_paid = view(&root, &hashlock)?;
    assert_eq!(bad_paid["balances"]["seller"], 10);
    receive(&root, &hashlock, &bad)?;

    // Check the ciphertext opening, then reuse the native check only for exact
    // previously checked artifact bytes. Offer signatures bind every trade term.
    let rejected = check_opening(&root, &hashlock, &bad_offer, &good);
    assert!(rejected.is_err());
    write(
        &hashlock.join("trusted-checker-denial.json"),
        &json!({"approved":false,"reason":rejected.err().ok_or("missing checker error")?.to_string()}),
    )?;
    let mut cases = Vec::new();
    for case in [
        "honest",
        "buyer_aborts_after_funding",
        "seller_withholds",
        "before_commit_crash",
        "after_commit_crash",
        "concurrent_retries",
        "wrong_key",
        "offer_substitution",
    ] {
        let mut observations = Vec::new();
        for backend in BACKENDS {
            let name = format!("{backend}-{case}");
            let directory = root.join(backend).join(case);
            let offer = make_offer(&root, &directory, &name, &contract, &good)?;
            let offer = check_opening(&root, &directory, &offer, &good)?;
            let key = Keypair::generate();
            let rule = rule(&key, &name, &contract)?;
            let gate = Gate::open(backend, &directory.join("gate"), &rule)?;
            let request = OutcomeEffectRequest {
                evidence: outcome(&rule, &offer, &key)?,
                arguments: OutcomeEffectArguments {
                    artifact_sha256: hash(&offer)?,
                    resource: rule.resource.clone(),
                },
            };
            write(&directory.join("gate-rule.json"), &rule)?;
            write(&directory.join("gate-request.json"), &request)?;
            successful(run(&root, &directory, "fund", &[])?)?;
            let initial = view(&root, &directory)?;
            write(&directory.join("after-funding.json"), &initial)?;
            assert_eq!(initial["balances"]["seller"], 0);
            assert_eq!(initial["locked"], 10);
            assert!(initial["releasedKey"].is_null());
            assert_eq!(run(&root, &directory, "receive", &[])?["success"], false);
            assert_eq!(run(&root, &directory, "refund", &[&now])?["success"], false);
            let mut killed = 0;
            let mut workers = 0;
            if case == "seller_withholds" {
                successful(run(&root, &directory, "refund", &[&after])?)?;
                assert_eq!(
                    run(&root, &directory, "settle", &[&after, "private-key.bin"])?["success"],
                    false
                );
                assert_eq!(
                    run(&root, &directory, "refund", &[&after])?["success"],
                    false
                );
            } else {
                let prepared = gate.prepare(&request, &rule.server_id, &rule.tool_name, NOW)?;
                let permit = gate.claim(&prepared, &rule.server_id, &rule.tool_name, NOW)?;
                if case == "wrong_key" {
                    std::fs::write(directory.join("wrong-key.bin"), [0u8; 32])?;
                    assert_eq!(
                        run(&root, &directory, "settle", &[&now, "wrong-key.bin"])?["success"],
                        false
                    );
                    assert_eq!(view(&root, &directory)?, initial);
                }
                if case == "offer_substitution" {
                    for field in ["price", "seller", "tradeId", "contractSha256"] {
                        let mut changed = offer.clone();
                        changed["terms"][field] = if field == "price" {
                            json!(99)
                        } else {
                            json!("substituted")
                        };
                        write(&directory.join("offer.json"), &changed)?;
                        assert_eq!(
                            run(&root, &directory, "settle", &[&now, "private-key.bin"])?
                                ["success"],
                            false
                        );
                        assert_eq!(view(&root, &directory)?, initial);
                    }
                    write(&directory.join("offer.json"), &offer)?;
                }
                if matches!(case, "before_commit_crash" | "after_commit_crash") {
                    let fault = if case == "before_commit_crash" {
                        "after_credit_before_commit"
                    } else {
                        "after_commit_before_reply"
                    };
                    let result = run(
                        &root,
                        &directory,
                        "settle",
                        &[&now, "private-key.bin", fault],
                    )?;
                    assert_eq!(result["success"], false);
                    assert!(result["exit"]
                        .as_str()
                        .ok_or("exit missing")?
                        .contains("SIGKILL"));
                    eprintln!("EXCHANGE_WORKER_KILLED {backend} {fault}");
                    killed = 1;
                    let intermediate = view(&root, &directory)?;
                    write(&directory.join("after-crash.json"), &intermediate)?;
                    assert_eq!(
                        intermediate["state"],
                        if case == "before_commit_crash" {
                            "funded"
                        } else {
                            "settled"
                        }
                    );
                }
                if case == "concurrent_retries" {
                    let mut handles = Vec::new();
                    for _ in 0..8 {
                        let root = root.clone();
                        let directory = directory.clone();
                        let now = now.clone();
                        handles.push(std::thread::spawn(move || {
                            run(&root, &directory, "settle", &[&now, "private-key.bin"])
                                .map_err(|e| e.to_string())
                        }));
                    }
                    for handle in handles {
                        successful(
                            handle
                                .join()
                                .map_err(|_| "exchange worker thread panicked")??,
                        )?;
                    }
                    workers = 8;
                } else {
                    successful(run(
                        &root,
                        &directory,
                        "settle",
                        &[&now, "private-key.bin"],
                    )?)?;
                    workers = 1;
                }
                let completed = view(&root, &directory)?;
                gate.complete(permit, &completed)?;
                assert!(gate
                    .prepare(&request, &rule.server_id, &rule.tool_name, NOW)
                    .and_then(|p| gate.claim(&p, &rule.server_id, &rule.tool_name, NOW))
                    .is_err());
                successful(run(
                    &root,
                    &directory,
                    "settle",
                    &[&now, "private-key.bin"],
                )?)?;
                assert_eq!(view(&root, &directory)?, completed);
                assert_eq!(
                    run(&root, &directory, "refund", &[&after])?["success"],
                    false
                );
            }
            let final_view = view(&root, &directory)?;
            let settled = case != "seller_withholds";
            assert_eq!(
                final_view["balances"]["buyer"],
                if settled { 90 } else { 100 }
            );
            assert_eq!(
                final_view["balances"]["seller"],
                if settled { 10 } else { 0 }
            );
            assert_eq!(final_view["locked"], 0);
            assert_eq!(final_view["settlementEvents"], 1);
            if settled {
                receive(&root, &directory, &good)?;
            } else {
                assert!(final_view["releasedKey"].is_null());
                assert_eq!(run(&root, &directory, "receive", &[])?["success"], false);
            }
            drop(gate);
            let reopened = Gate::open(backend, &directory.join("gate"), &rule)?;
            assert_eq!(
                reopened.status(&rule)?.0,
                if settled { "completed" } else { "waiting" }
            );
            observations.push(json!({"settled":settled,"buyerReceivedCheckedArtifact":settled,"sellerCredits":final_view["balances"]["seller"],"buyerCredits":final_view["balances"]["buyer"],"lockedCredits":0,"terminalEvents":1,"keyReleased":settled,"gateStateAfterReopen":reopened.status(&rule)?.0,"killedSettlementWorkers":killed,"concurrentOrRecoveryWorkers":workers}));
        }
        assert_eq!(observations[0], observations[1]);
        cases.push(json!({"case":case,"chio":observations[0],"ledger":observations[1]}));
    }
    let report = json!({"experiment":"checked-repair-for-local-credits","plaintextBuyerAbort":{"buyerHasValidRepair":true,"sellerCredits":0},"bareHashlock":{"sellerCredits":10,"buyerHasValidRepair":false,"validKeyRevealed":true},"trustedCheckerRejectsBuggyOpening":true,"pairedScenarios":cases,"nativeCheckerRuns":2,"actualGitCommitCases":14,"gateSeparationObserved":false,"zeroKnowledgeProofImplemented":false,"externalPaymentExecuted":false,"limits":["Trusted native checker, local settlement operator and host; all roles run under one administrative account","Test credits have no monetary value; no blockchain, bank, payment provider or deployed market integration","The operator sees plaintext and the key before settlement; no trustless fair exchange or zero-knowledge proof","Buyer delivery reads only the funded offer and committed key view, but this is not a new cross-user filesystem isolation test","The already-public repository repair is a reproducible fixture, not a secrecy experiment with an unknown valuable good","Native checking is reused only for identical artifact bytes; the seven-case contract is not general correctness","Four settlement children are SIGKILLed, while the trusted controller retains its gate permits; no controller-loss, power-loss or dishonest-operator guarantee","Payment and key release are atomic only because they share one SQLite transaction; moving either to an external system invalidates that argument"]});
    write(&root.join("repair-exchange-comparison.json"), &report)?;
    Ok(report)
}
