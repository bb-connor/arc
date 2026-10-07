//! Compare trusting an upstream attestation with receiver-owned re-execution.
//! Both gate backends receive identical checking code and owner assumptions.
use super::*;

fn publisher(
    directory: &Path,
    rule: &OutcomeEffectRule,
    key: &Keypair,
    gate: Arc<Gate>,
    base: &BTreeMap<String, String>,
    local: bool,
) -> Result<chio_kernel::ChioKernel> {
    let mut kernel = crate::workload::configured_kernel(directory, key.clone())?;
    kernel.register_tool_server(Box::new(Publisher {
        gate,
        rule: rule.clone(),
        directory: directory.into(),
        local_check: local.then(|| LocalCheck {
            base: base.clone(),
            key: key.clone(),
        }),
    }));
    Ok(kernel)
}

fn call(
    kernel: &chio_kernel::ChioKernel,
    key: &Keypair,
    directory: &Path,
    name: &str,
    artifact: Value,
    admitted: bool,
) -> Result<chio_kernel::ToolCallResponse> {
    let reply = crate::workload::invoke_authorized(
        kernel,
        key,
        "repair-review-queue",
        "publish",
        artifact,
        name,
    )?;
    response(directory, name, &reply)?;
    assert_eq!(
        reply.verdict == Verdict::Allow,
        admitted,
        "{name}: {:?}",
        reply.reason
    );
    Ok(reply)
}

pub fn compare(root: &Path, baseline: &Path, candidate: &Path) -> Result<Value> {
    let root = std::fs::canonicalize(root)?;
    let old = sources(baseline)?;
    let base = old
        .iter()
        .map(|(name, text)| (name.clone(), sha256_hex(text.as_bytes())))
        .collect::<BTreeMap<_, _>>();
    let good = serde_json::to_value(Repair {
        base_sha256: base.clone(),
        files: sources(candidate)?,
    })?;
    let bad = serde_json::to_value(Repair {
        base_sha256: base.clone(),
        files: old,
    })?;
    std::fs::write(
        root.join("candidate.json"),
        serde_json::to_vec_pretty(&good)?,
    )?;
    std::fs::write(root.join("baseline.json"), serde_json::to_vec_pretty(&bad)?)?;
    let mut profiles = Vec::new();
    for local in [false, true] {
        let profile = if local {
            "receiver_checked"
        } else {
            "upstream_attested"
        };
        let contract = json!({"schema":"repair-receiver-check.experimental.v1","profile":profile,"baseSha256":base,"paths":FILES,"requests":requests(),"hooks":HOOKS,
            "checkerSha256":sha256_hex(include_bytes!("repair.rs")),"experimentSha256":sha256_hex(include_bytes!("repair_receiver_check.rs")),"driverSha256":sha256_hex(DRIVER.as_bytes()),"isolationPolicySha256":sha256_hex(include_bytes!("isolation.rs")),
            "input":if local {"Source artifact without an upstream signature"} else {"Source artifact with an upstream signed outcome"}});
        std::fs::create_dir(root.join(profile))?;
        std::fs::write(
            root.join(profile).join("contract.json"),
            serde_json::to_vec_pretty(&contract)?,
        )?;
        let mut rows = Vec::new();
        for backend in BACKENDS {
            let directory = root.join(profile).join(backend);
            std::fs::create_dir(&directory)?;
            let receiver_key = Keypair::generate();
            let upstream_key = Keypair::generate();
            let rule = OutcomeEffectRule {
                slot: OutcomeEffectSlot {
                    receiver_id: receiver_key.public_key().to_hex(),
                    workflow_id: "checked-git-hook-repair".into(),
                    step_id: "publish-repair".into(),
                },
                predecessor_step_id: if local {
                    "receiver-local-check".into()
                } else {
                    "upstream-check".into()
                },
                verifier_key: if local {
                    receiver_key.public_key()
                } else {
                    upstream_key.public_key()
                },
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
            // The actual selected upstream key lies about the original buggy
            // source. This is an explicit violation of that profile's trust
            // assumption, not a forged signature or an unsigned mutation.
            let lie = serde_json::to_value(Delivery {
                artifact: bad.clone(),
                evidence: outcome(&rule, &bad, &upstream_key)?,
            })?;
            assert!(upstream_key.public_key().verify_strict(
                &canonical_json_bytes(
                    &serde_json::from_value::<Delivery>(lie.clone())?
                        .evidence
                        .body
                )?,
                &serde_json::from_value::<Delivery>(lie.clone())?
                    .evidence
                    .signature
            ));
            std::fs::write(
                directory.join("dishonest-upstream-delivery.json"),
                serde_json::to_vec_pretty(&lie)?,
            )?;
            let gate = Arc::new(Gate::open(backend, &directory, &rule)?);
            let kernel = publisher(&directory, &rule, &receiver_key, gate.clone(), &base, local)?;
            if local {
                call(
                    &kernel,
                    &receiver_key,
                    &directory,
                    "upstream-envelope-cannot-select-profile",
                    lie,
                    false,
                )?;
                assert_eq!(gate.status(&rule)?.0, "waiting");
                let rejected = call(
                    &kernel,
                    &receiver_key,
                    &directory,
                    "bad-source-checked-locally",
                    bad.clone(),
                    false,
                )?;
                assert!(rejected
                    .reason
                    .as_deref()
                    .unwrap_or_default()
                    .contains("observed Git effects"));
                assert_eq!(gate.status(&rule)?.0, "waiting");
                assert_eq!(crate::count(&directory)?, 0);
                let mut wrong_base = good.clone();
                wrong_base["baseSha256"][FILES[0]] = json!("00".repeat(32));
                call(
                    &kernel,
                    &receiver_key,
                    &directory,
                    "wrong-base",
                    wrong_base,
                    false,
                )?;
                call(
                    &kernel,
                    &receiver_key,
                    &directory,
                    "unsigned-valid-source",
                    good.clone(),
                    true,
                )?;
                assert_eq!(crate::count(&directory)?, 1);
                for name in FILES {
                    assert_eq!(
                        std::fs::read_to_string(directory.join("approved").join(name))?,
                        good["files"][name]
                            .as_str()
                            .ok_or("candidate file absent")?
                    );
                }
            } else {
                call(
                    &kernel,
                    &receiver_key,
                    &directory,
                    "unsigned-source-not-an-attestation",
                    good.clone(),
                    false,
                )?;
                call(
                    &kernel,
                    &receiver_key,
                    &directory,
                    "dishonest-signed-source",
                    lie,
                    true,
                )?;
                assert_eq!(crate::count(&directory)?, 1);
                for name in FILES {
                    assert_eq!(
                        std::fs::read_to_string(directory.join("approved").join(name))?,
                        bad["files"][name].as_str().ok_or("baseline file absent")?
                    );
                }
            }
            drop(kernel);
            drop(gate);
            let reopened = Arc::new(Gate::open(backend, &directory, &rule)?);
            let replacement = publisher(
                &directory,
                &rule,
                &receiver_key,
                reopened.clone(),
                &base,
                local,
            )?;
            let repeat = if local {
                good.clone()
            } else {
                serde_json::to_value(Delivery {
                    artifact: good.clone(),
                    evidence: outcome(&rule, &good, &upstream_key)?,
                })?
            };
            call(
                &replacement,
                &receiver_key,
                &directory,
                "fresh-capability-after-reopen",
                repeat,
                false,
            )?;
            assert_eq!(crate::count(&directory)?, 1);
            let checks = if local {
                std::fs::read_dir(directory.join("local-checks"))?.count()
            } else {
                0
            };
            assert_eq!(checks, if local { 2 } else { 0 });
            rows.push(json!({"acceptedArtifact":if local {"repaired-source"} else {"buggy-source-signed-by-trusted-upstream"},"artifactSha256":hash(if local {&good} else {&bad})?,"publicationEffects":1,"sourceChecks":checks,
                "upstreamVerificationCalls":0,"upstreamSignatureRequired":!local,"upstreamHonestyRequired":!local,"receiverCheckerTrusted":local,
                "reopenedRepeatDenied":true,"repeatDidNotExecuteCandidate":true,"state":reopened.status(&rule)?.0}));
        }
        assert_eq!(rows[0], rows[1], "profile {profile}");
        profiles.push(json!({"profile":profile,"chio":rows[0],"ledger":rows[1]}));
    }
    let report = json!({"experiment":"repair-upstream-trust-comparison","profiles":profiles,"gateSeparationObserved":false,
        "limits":["The attested counterexample deliberately violates upstream-verifier honesty, an explicit assumption of that profile","Receiver checking repeats the finite Git regression contract locally; this is not a succinct proof, zero-knowledge proof or general program-correctness proof","Receiver, checker, runtime, store, operator and host kernel remain trusted","Local checking removes the need for an upstream signature but requires receiver compute and the checker runtime","No remote administration, independent benchmark, deployment activation or new cryptographic mechanism demonstrated"]});
    std::fs::write(
        root.join("receiver-check-comparison.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(report)
}
