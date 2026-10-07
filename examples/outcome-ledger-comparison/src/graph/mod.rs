//! A replaceable courier carries outcomes between three separately restarted
//! kernel processes. Receiver state determines recovery and admissible work.
mod isolation;
mod model;
mod receiver;
pub mod repair;
mod transport;

use std::io::Write;
use std::path::Path;

use chio_core_types::crypto::{canonical_json_bytes, Keypair};
use serde_json::{json, Value};

use crate::{count, scope, Result, BACKENDS};
use model::{hash, provision, Delivery, PublicJob};
use transport::{allowed, invoke, Attempt};

pub use isolation::probe;
pub use receiver::worker;

fn state(job: &PublicJob, index: usize) -> Result<Value> {
    allowed(
        &job.endpoints[index],
        "status",
        json!({"artifactSha256":hash(&job.artifact)?}),
    )
}

fn resume(job: &PublicJob, checkpoint: bool) -> Result<Value> {
    let archive = state(job, 2)?;
    if archive["state"] == "completed" {
        return Ok(
            json!({"state":"completed","artifactSha256":archive["result"]["artifactSha256"]}),
        );
    }
    if archive["state"] == "claimed" {
        return Ok(json!({"state":"uncertain","receiver":"archive"}));
    }
    let publisher = state(job, 1)?;
    let published = if publisher["state"] == "completed" {
        publisher["result"].clone()
    } else if publisher["state"] == "claimed" {
        return Ok(json!({"state":"uncertain","receiver":"publisher"}));
    } else {
        let verifier = state(job, 0)?;
        let verified = if verifier["state"] == "completed" {
            verifier["result"].clone()
        } else {
            allowed(&job.endpoints[0], "verify", job.artifact.clone())?
        };
        allowed(&job.endpoints[1], "apply", verified)?
    };
    if checkpoint {
        println!("GRAPH_COURIER_CHECKPOINT");
        std::io::stdout().flush()?;
        loop {
            std::thread::park();
        }
    }
    let archived = allowed(&job.endpoints[2], "apply", published)?;
    Ok(json!({"state":"completed","artifactSha256":archived["artifactSha256"]}))
}

pub fn courier(path: &Path, mode: &str) -> Result<()> {
    if !matches!(mode, "none" | "after_publisher") {
        return Err("unknown courier mode".into());
    }
    let job: PublicJob = serde_json::from_slice(&std::fs::read(path)?)?;
    println!(
        "{}",
        serde_json::to_string(&resume(&job, mode == "after_publisher")?)?
    );
    Ok(())
}

fn job(
    root: &Path,
    backend: &str,
    isolated: bool,
) -> Result<(PublicJob, std::path::PathBuf, Option<isolation::Brokers>)> {
    let mut job = PublicJob {
        endpoints: provision(root, backend)?,
        artifact: serde_json::to_value(scope("source-checkout", "read"))?,
    };
    let brokers = if isolated {
        Some(isolation::Brokers::start(root, &mut job)?)
    } else {
        None
    };
    let path = root.join("public-job.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&job)?)?;
    Ok((job, path, brokers))
}

fn run_courier(
    path: &Path,
    brokers: Option<&isolation::Brokers>,
    kill: bool,
) -> Result<Option<Value>> {
    if let Some(brokers) = brokers {
        brokers.courier(path, kill)
    } else {
        transport::courier(path, kill)
    }
}

fn verify_completion(job: &PublicJob, result: &Value) -> Result<()> {
    assert_eq!(result["state"], "completed");
    assert_eq!(result["artifactSha256"], hash(&job.artifact)?);
    for endpoint in &job.endpoints[1..] {
        assert_eq!(count(&endpoint.directory)?, 1);
        assert_eq!(
            std::fs::read(endpoint.directory.join("approved.scope.json"))?,
            canonical_json_bytes(&job.artifact)?
        );
    }
    Ok(())
}

pub fn compare(root: &Path) -> Result<Value> {
    compare_mode(root, false)
}

pub fn compare_isolated(root: &Path) -> Result<Value> {
    compare_mode(root, true)
}

fn compare_mode(root: &Path, isolated: bool) -> Result<Value> {
    let mut rows = Vec::new();
    let mut isolation_reports = Vec::new();
    let scenarios = [
        ("normal", 0, "none"),
        ("verifier_response_lost", 0, "after_complete"),
        ("publisher_response_lost", 1, "after_complete"),
        ("archive_response_lost", 2, "after_complete"),
        ("publisher_before_claim", 1, "before_claim"),
        ("archive_before_claim", 2, "before_claim"),
        ("publisher_after_claim", 1, "after_claim"),
        ("publisher_after_effect", 1, "after_effect"),
        ("archive_after_claim", 2, "after_claim"),
        ("archive_after_effect", 2, "after_effect"),
        ("courier_replaced", 0, "courier"),
    ];
    for (name, index, phase) in scenarios {
        let mut observations = Vec::new();
        for backend in BACKENDS {
            let directory = root.join(name).join(backend);
            let (job, path, brokers) = job(&directory, backend, isolated)?;
            if name == "normal" {
                if let Some(brokers) = &brokers {
                    isolation_reports.push(json!({"backend":backend,"probes":brokers.probe_boundaries(&directory, &path, &job)?}));
                }
            }
            if phase == "courier" {
                assert!(run_courier(&path, brokers.as_ref(), true)?.is_none());
                assert_eq!(count(&job.endpoints[1].directory)?, 1);
                assert_eq!(count(&job.endpoints[2].directory)?, 0);
            } else if phase != "none" {
                let mut payload = job.artifact.clone();
                if index >= 1 {
                    payload = allowed(&job.endpoints[0], "verify", payload)?;
                }
                if index >= 2 {
                    payload = allowed(&job.endpoints[1], "apply", payload)?;
                }
                let tool = if index == 0 { "verify" } else { "apply" };
                let attempt = if isolated {
                    transport::call_process(
                        &job.endpoints[index],
                        model::Rpc {
                            tool: tool.into(),
                            arguments: payload,
                        },
                        phase,
                        true,
                    )?
                } else {
                    transport::call(&job.endpoints[index], tool, payload, phase)?
                };
                assert!(matches!(attempt, Attempt::Killed));
            }
            let result = run_courier(&path, brokers.as_ref(), false)?
                .ok_or("replacement courier missing")?;
            let uncertain = matches!(phase, "after_claim" | "after_effect");
            if uncertain {
                assert_eq!(
                    result,
                    json!({"state":"uncertain","receiver":job.endpoints[index].role})
                );
                let stored = state(&job, index)?;
                assert_eq!(stored["state"], "claimed");
                assert!(
                    stored["result"].is_null(),
                    "uncertainty must not export success evidence"
                );
                let expected_publisher = usize::from(index == 2 || phase == "after_effect");
                let expected_archive = usize::from(index == 2 && phase == "after_effect");
                assert_eq!(count(&job.endpoints[1].directory)?, expected_publisher);
                assert_eq!(count(&job.endpoints[2].directory)?, expected_archive);
            } else {
                verify_completion(&job, &result)?;
            }
            let before = [
                count(&job.endpoints[1].directory)?,
                count(&job.endpoints[2].directory)?,
            ];
            // Another fresh courier has no prior in-memory execution state.
            let repeated =
                run_courier(&path, brokers.as_ref(), false)?.ok_or("second courier missing")?;
            assert_eq!(repeated, result);
            assert_eq!(
                before,
                [
                    count(&job.endpoints[1].directory)?,
                    count(&job.endpoints[2].directory)?
                ]
            );
            observations.push(json!({"result":result,"publisherEffects":before[0],"archiveEffects":before[1],"replacementPreservedResult":true}));
        }
        assert_eq!(observations[0], observations[1], "graph {name}");
        rows.push(json!({"case":name,"chio":observations[0],"ledger":observations[1]}));
    }
    let attacks = attacks(root, isolated)?;
    let report = json!({"experiment":"receiver-owned-outcome-graph","pairedScenarios":rows,"pairedAttacks":attacks,"separationObserved":false,
        "isolated":isolated,"isolationProbes":isolation_reports,
        "scope":"Three distinct keys, stores and kernel processes on one host; shared implementation around the two independent gates",
        "limits":[if isolated {"Linux namespaces with explicit mounts; shared host kernel and operator; no independently administered remote deployment"} else {"No OS isolation between same-user processes or independent remote administration"},"Static native policy artifact; no live model or arbitrary code execution","Unknown external effects require intervention; completion recovery does not replay them","No integration-cost or latency advantage measured"]});
    std::fs::write(
        root.join("graph-comparison.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(report)
}

fn attacks(root: &Path, isolated: bool) -> Result<Value> {
    let mut rows = Vec::new();
    for case in [
        "overbroad_candidate",
        "skip_publisher",
        "artifact_substitution",
        "forged_completion",
        "foreign_workflow",
        "duplicate_delivery",
    ] {
        let mut observations = Vec::new();
        for backend in BACKENDS {
            let (job, path, brokers) = job(
                &root.join("attacks").join(case).join(backend),
                backend,
                isolated,
            )?;
            let reply = if case == "overbroad_candidate" {
                invoke(
                    &job.endpoints[0],
                    "verify",
                    serde_json::to_value(scope("source-checkout", "delete"))?,
                )?
            } else {
                let verified = allowed(&job.endpoints[0], "verify", job.artifact.clone())?;
                if case == "skip_publisher" {
                    invoke(&job.endpoints[2], "apply", verified)?
                } else {
                    let published = allowed(&job.endpoints[1], "apply", verified)?;
                    if case == "duplicate_delivery" {
                        allowed(&job.endpoints[2], "apply", published.clone())?;
                    }
                    let mut delivery: Delivery = serde_json::from_value(published)?;
                    match case {
                        "artifact_substitution" => {
                            delivery.artifact =
                                serde_json::to_value(scope("source-checkout", "delete"))?
                        }
                        "forged_completion" => {
                            delivery.evidence.signature = Keypair::generate()
                                .sign(&canonical_json_bytes(&delivery.evidence.body)?)
                        }
                        "foreign_workflow" => {
                            delivery.evidence.body.slot.workflow_id = "another-owner-job".into()
                        }
                        "duplicate_delivery" => {}
                        _ => return Err("unknown graph attack".into()),
                    }
                    invoke(&job.endpoints[2], "apply", serde_json::to_value(delivery)?)?
                }
            };
            assert!(!reply.allowed, "{case} {backend}");
            let initial_archive = count(&job.endpoints[2].directory)?;
            assert_eq!(initial_archive, usize::from(case == "duplicate_delivery"));
            let recovered = run_courier(&path, brokers.as_ref(), false)?
                .ok_or("valid follow-up courier absent")?;
            verify_completion(&job, &recovered)?;
            observations.push(json!({"attackAllowed":false,"archiveEffectsAfterAttack":initial_archive,"validFollowupCompleted":true,"publisherEffects":1,"archiveEffects":1}));
        }
        assert_eq!(observations[0], observations[1]);
        rows.push(json!({"case":case,"chio":observations[0],"ledger":observations[1]}));
    }
    Ok(json!(rows))
}
