//! Falsification of artifact-counting as a scarce-work metric. This is not a
//! deployed consensus protocol or an attack on the existing local effect gate.
use super::*;
use chio_core_types::crypto::{PublicKey, Signature};
use chio_runtime_core::outcome_continuation::SignedArtifactOutcome;
use std::collections::BTreeSet;

const COUNT: usize = 6;
const JOB: &str = "repair-git-hook-policy";
const SCHEMA: &str = "candidate-work-claim.experimental.v1";
const AST_SCRIPT: &str = include_str!("repair_ast.py");

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClaimBody {
    schema: String,
    job_id: String,
    contract_sha256: String,
    challenge: String,
    artifact_sha256: String,
    producer: PublicKey,
    claim_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Claim {
    body: ClaimBody,
    signature: Signature,
}

fn verify_claim(claim: &Claim, artifact: &Repair, contract: &str, challenge: &str) -> Result<()> {
    if claim.body.schema != SCHEMA
        || claim.body.job_id != JOB
        || claim.body.contract_sha256 != contract
        || claim.body.challenge != challenge
        || claim.body.artifact_sha256 != hash(artifact)?
        || claim.body.claim_id.is_empty()
        || !claim
            .body
            .producer
            .verify_strict(&canonical_json_bytes(&claim.body)?, &claim.signature)
    {
        return Err("candidate work claim failed signature or binding".into());
    }
    Ok(())
}

fn fingerprint(directory: &Path, artifact: &Repair) -> Result<String> {
    std::fs::create_dir_all(directory)?;
    std::fs::write(
        directory.join("artifact.json"),
        canonical_json_bytes(artifact)?,
    )?;
    std::fs::write(directory.join("fingerprint.py"), AST_SCRIPT)?;
    let mut command = crate::graph::isolation::base_command()?;
    command
        .args(["--ro-bind", "/usr/bin/python3.12", "/app/python"])
        .arg("--ro-bind")
        .arg(directory.join("artifact.json"))
        .arg("/artifact.json")
        .arg("--ro-bind")
        .arg(directory.join("fingerprint.py"))
        .arg("/fingerprint.py")
        .args(["--", "/app/python", "-I", "-S", "-B", "/fingerprint.py"]);
    let process = capture(command)?;
    std::fs::write(
        directory.join("fingerprint-process.json"),
        serde_json::to_vec_pretty(&process)?,
    )?;
    if process["success"] != true {
        return Err("trusted syntax parser failed".into());
    }
    let parsed: Value = serde_json::from_str(
        process["stdout"]
            .as_str()
            .ok_or("syntax fingerprint absent")?,
    )?;
    let digest = parsed["astSha256"].as_str().ok_or("syntax digest absent")?;
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid syntax digest".into());
    }
    Ok(digest.into())
}

fn protect_one_job(root: &Path, contract: &Value, artifacts: &[Repair]) -> Result<Value> {
    let mut observations = Vec::new();
    for backend in BACKENDS {
        let directory = root.join("protected-job").join(backend);
        let key = Keypair::generate();
        let rule = OutcomeEffectRule {
            slot: OutcomeEffectSlot {
                receiver_id: key.public_key().to_hex(),
                workflow_id: JOB.into(),
                step_id: "publish".into(),
            },
            predecessor_step_id: "receiver-check".into(),
            verifier_key: key.public_key(),
            contract_sha256: hash(contract)?,
            server_id: "repair-review-queue".into(),
            tool_name: "publish".into(),
            resource: "reviewed-source-files".into(),
            valid_from_unix_ms: NOW - 1000,
            valid_until_unix_ms: NOW + 1000,
        };
        let gate = Gate::open(backend, &directory, &rule)?;
        std::fs::write(
            directory.join("owner-rule.json"),
            serde_json::to_vec_pretty(&rule)?,
        )?;
        let mut rows = Vec::new();
        for (index, artifact) in artifacts.iter().enumerate() {
            let mut evidence = outcome(&rule, &serde_json::to_value(artifact)?, &key)?;
            evidence.body.verified_at_unix_ms = NOW + index as u64;
            evidence = SignedArtifactOutcome::sign(evidence.body, &key)?;
            let request = OutcomeEffectRequest {
                evidence,
                arguments: OutcomeEffectArguments {
                    artifact_sha256: hash(artifact)?,
                    resource: rule.resource.clone(),
                },
            };
            let permit = gate
                .prepare(
                    &request,
                    &rule.server_id,
                    &rule.tool_name,
                    NOW + index as u64,
                )
                .and_then(|prepared| {
                    gate.claim(
                        &prepared,
                        &rule.server_id,
                        &rule.tool_name,
                        NOW + index as u64,
                    )
                });
            let accepted = permit.is_ok();
            if let Ok(permit) = permit {
                let mut log = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(directory.join("effects.log"))?;
                writeln!(log, "{}", request.arguments.artifact_sha256)?;
                log.sync_all()?;
                gate.complete(permit,&json!({"artifactSha256":request.arguments.artifact_sha256,"recordedOnce":true}))?;
            }
            assert_eq!(accepted, index == 0);
            rows.push(json!({"request":request,"accepted":accepted}));
        }
        drop(gate);
        let reopened = Gate::open(backend, &directory, &rule)?;
        assert_eq!(crate::count(&directory)?, 1);
        assert_eq!(reopened.status(&rule)?.0, "completed");
        std::fs::write(
            directory.join("attempts.json"),
            serde_json::to_vec_pretty(&rows)?,
        )?;
        observations.push(json!({"attempts":artifacts.len(),"accepted":1,"effects":1,"stateAfterReopen":"completed"}));
    }
    assert_eq!(observations[0], observations[1]);
    Ok(json!({"chio":observations[0],"ledger":observations[1]}))
}

pub fn compare(root: &Path, baseline: &Path, candidate: &Path) -> Result<Value> {
    let root = std::fs::canonicalize(root)?;
    let old = sources(baseline)?;
    let base = old
        .iter()
        .map(|(name, text)| (name.clone(), sha256_hex(text.as_bytes())))
        .collect::<BTreeMap<_, _>>();
    let cached = Repair {
        base_sha256: base.clone(),
        files: sources(candidate)?,
    };
    let bad = Repair {
        base_sha256: base.clone(),
        files: old,
    };
    let contract = json!({"schema":"repair-work-reuse.experimental.v1","job":JOB,"baseSha256":base,"paths":FILES,"requests":requests(),"hooks":HOOKS,"checkerSha256":sha256_hex(include_bytes!("repair.rs")),"driverSha256":sha256_hex(DRIVER.as_bytes()),"experimentSha256":sha256_hex(include_bytes!("repair_work.rs")),"syntaxParserSha256":sha256_hex(AST_SCRIPT.as_bytes()),"isolationSha256":sha256_hex(include_bytes!("isolation.rs")),"scope":"Finite artifact validity and illustrative counting metrics, without a resource-hardness or consensus claim"});
    let contract_sha = hash(&contract)?;
    std::fs::write(
        root.join("contract.json"),
        serde_json::to_vec_pretty(&contract)?,
    )?;
    assert!(check_owned_artifact(
        &root.join("buggy-check"),
        &base,
        &serde_json::to_value(&bad)?
    )
    .is_err());
    check_owned_artifact(
        &root.join("cached-check"),
        &base,
        &serde_json::to_value(&cached)?,
    )?;
    let cached_ast = fingerprint(&root.join("cached-syntax"), &cached)?;
    let fixed_challenge = sha256_hex(Keypair::generate().public_key().to_hex().as_bytes());
    let mut checked = BTreeMap::from([(hash(&cached)?, cached_ast.clone())]);
    let mut artifacts = Vec::new();
    let mut groups = Vec::new();
    let mut all_producers = BTreeSet::new();
    let mut all_artifacts = BTreeSet::new();
    let mut all_syntax = BTreeSet::new();
    let mut all_challenges = BTreeSet::new();
    for family in [
        "new_identities",
        "comments",
        "dead_branches",
        "fresh_challenges",
    ] {
        let mut rows = Vec::new();
        let mut artifact_ids = BTreeSet::new();
        let mut syntax_ids = BTreeSet::new();
        let mut challenges = BTreeSet::new();
        for index in 0..COUNT {
            let directory = root.join(family).join(index.to_string());
            std::fs::create_dir_all(&directory)?;
            let challenge = if family == "fresh_challenges" {
                sha256_hex(Keypair::generate().public_key().to_hex().as_bytes())
            } else {
                fixed_challenge.clone()
            };
            // The cached repair is loaded before these fresh challenges exist.
            // Construct every candidate by copying it and appending inert text.
            let suffix = match family {
                "new_identities" => String::new(),
                "comments" => format!("\n# reused repair variant {index}\n"),
                "dead_branches" => {
                    format!("\nif False:\n    _unused_work_marker_{index} = {index}\n")
                }
                "fresh_challenges" => format!("\n# current challenge: {challenge}\n"),
                _ => return Err("unknown artifact family".into()),
            };
            let mut artifact = cached.clone();
            for (name, source) in &mut artifact.files {
                source.push_str(&suffix);
                assert_eq!(
                    &source[..source.len() - suffix.len()],
                    cached.files.get(name).ok_or("cached source absent")?
                );
            }
            let artifact_sha = hash(&artifact)?;
            std::fs::write(
                directory.join("artifact.json"),
                canonical_json_bytes(&artifact)?,
            )?;
            let syntax = if let Some(syntax) = checked.get(&artifact_sha) {
                syntax.clone()
            } else {
                check_owned_artifact(
                    &directory.join("checks"),
                    &base,
                    &serde_json::to_value(&artifact)?,
                )?;
                let syntax = fingerprint(&directory.join("syntax"), &artifact)?;
                checked.insert(artifact_sha.clone(), syntax.clone());
                syntax
            };
            assert_eq!(syntax == cached_ast, family != "dead_branches");
            let producer = Keypair::generate();
            let body = ClaimBody {
                schema: SCHEMA.into(),
                job_id: JOB.into(),
                contract_sha256: contract_sha.clone(),
                challenge: challenge.clone(),
                artifact_sha256: artifact_sha.clone(),
                producer: producer.public_key(),
                claim_id: format!("{family}-{index}"),
            };
            let claim = Claim {
                signature: producer.sign(&canonical_json_bytes(&body)?),
                body,
            };
            verify_claim(&claim, &artifact, &contract_sha, &challenge)?;
            assert!(verify_claim(
                &claim,
                &artifact,
                &contract_sha,
                &sha256_hex(b"wrong challenge")
            )
            .is_err());
            assert!(verify_claim(&claim, &bad, &contract_sha, &challenge).is_err());
            let mut unsigned = claim.clone();
            unsigned.body.claim_id.push_str("-mutated");
            assert!(verify_claim(&unsigned, &artifact, &contract_sha, &challenge).is_err());
            std::fs::write(
                directory.join("claim.json"),
                serde_json::to_vec_pretty(&claim)?,
            )?;
            artifact_ids.insert(artifact_sha.clone());
            syntax_ids.insert(syntax.clone());
            challenges.insert(challenge.clone());
            all_artifacts.insert(artifact_sha.clone());
            all_syntax.insert(syntax.clone());
            all_challenges.insert(challenge.clone());
            all_producers.insert(producer.public_key().to_hex());
            rows.push(json!({"claimSha256":hash(&claim)?,"artifactSha256":artifact_sha,"astSha256":syntax,"challenge":challenge,"sourcePrefixEqualsCachedRepair":true,"appendedBytesPerFile":suffix.len(),"signatureAndBindingsValid":true,"artifactPassed":true,"syntaxMatchesCachedRepair":syntax==cached_ast}));
            artifacts.push(artifact);
        }
        assert_eq!(
            artifact_ids.len(),
            if family == "new_identities" { 1 } else { COUNT }
        );
        assert_eq!(
            syntax_ids.len(),
            if family == "dead_branches" { COUNT } else { 1 }
        );
        groups.push(json!({"family":family,"claims":rows,"acceptedClaims":COUNT,"distinctArtifactHashes":artifact_ids.len(),"distinctSyntaxHashes":syntax_ids.len(),"distinctChallenges":challenges.len(),"distinctLogicalJobs":1}));
    }
    assert_eq!(checked.len(), 19);
    let protected = protect_one_job(&root, &contract, &artifacts)?;
    let report = json!({"experiment":"checked-artifact-reuse-is-not-scarce-work","families":groups,"totals":{"acceptedSignedClaims":artifacts.len(),"distinctProducerKeys":all_producers.len(),"distinctArtifactHashes":all_artifacts.len(),"distinctSyntaxHashes":all_syntax.len(),"distinctChallenges":all_challenges.len(),"distinctLogicalJobs":1,"validArtifactsBehaviorChecked":checked.len(),"totalBehaviorCheckerRuns":checked.len()+1,"actualGitCommitCases":(checked.len()+1)*7},"protectedLogicalJob":protected,"synthesisMethod":"Load one existing repair, then copy it and append comments or unreachable branches; no new repair search or model invocation","consensusImplemented":false,"resourceHardnessEstablished":false,"limits":["Illustrative claim, byte-hash and syntax-hash counting metrics, not a deployed consensus algorithm or an attack on existing Chio admission","Syntax fingerprints are not semantic equivalence proofs; all variants meet only the selected seven-case contract","No timing advantage, compute lower bound, energy measurement or result about all useful-work protocols","Stable receiver-owned job budgets stop repeated effects for both gates; independent scarce-resource and membership assumptions remain unspecified"]});
    std::fs::write(
        root.join("work-reuse-comparison.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(report)
}
