#[test]
fn outcome_gates_match_under_substitution_reissue_crash_and_kernel_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("comparison");
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_chio-outcome-ledger-comparison"))
        .arg(&output)
        .output()?;
    assert!(
        result.status.success(),
        "comparison failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output.join("comparison.json"))?)?;
    assert_eq!(
        report["commonSubstitutionCases"]
            .as_array()
            .ok_or("substitution cases missing")?
            .len(),
        16
    );
    assert_eq!(
        report["commonTransitionCases"]
            .as_array()
            .ok_or("transition cases missing")?
            .len(),
        6
    );
    assert_eq!(
        report["processFaults"]
            .as_array()
            .ok_or("fault cases missing")?
            .len(),
        5
    );
    assert_eq!(
        report["kernelArtifactWorkflows"]["chio"],
        report["kernelArtifactWorkflows"]["ledger"]
    );
    assert_eq!(report["ledgerHandleChecks"]["freshHandlesObserved"], true);
    assert_eq!(report["ledgerHandleChecks"]["forgedHandleRejected"], true);
    assert_eq!(report["separationObserved"], false);
    Ok(())
}

#[test]
fn independent_receiver_processes_recover_completed_graph_outputs_without_repeating_effects(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("graph");
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_chio-outcome-ledger-comparison"))
        .arg("--graph")
        .arg(&output)
        .output()?;
    assert!(
        result.status.success(),
        "graph failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output.join("graph-comparison.json"))?)?;
    assert_eq!(
        report["pairedScenarios"]
            .as_array()
            .ok_or("scenarios absent")?
            .len(),
        11
    );
    assert_eq!(
        report["pairedAttacks"]
            .as_array()
            .ok_or("attacks absent")?
            .len(),
        6
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with("GRAPH_KILL "))
            .count(),
        18
    );
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with("GRAPH_COURIER_KILL "))
            .count(),
        2
    );
    assert_eq!(report["separationObserved"], false);
    Ok(())
}

#[test]
fn isolated_couriers_cannot_read_receiver_keys_and_preserve_graph_recovery(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("isolated-graph");
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_chio-outcome-ledger-comparison"))
        .arg("--isolated-graph")
        .arg(&output)
        .output()?;
    assert!(
        result.status.success(),
        "isolated graph failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output.join("graph-comparison.json"))?)?;
    assert_eq!(report["isolated"], true);
    assert_eq!(
        report["pairedScenarios"]
            .as_array()
            .ok_or("scenarios absent")?
            .len(),
        11
    );
    assert_eq!(
        report["pairedAttacks"]
            .as_array()
            .ok_or("attacks absent")?
            .len(),
        6
    );
    let probes = report["isolationProbes"]
        .as_array()
        .ok_or("isolation probes absent")?;
    assert_eq!(probes.len(), 2);
    for backend in probes {
        let roles = backend["probes"].as_array().ok_or("role probes absent")?;
        assert_eq!(roles.len(), 4);
        for role in roles {
            assert_eq!(
                role["report"]["deniedPaths"]
                    .as_array()
                    .ok_or("private path probes absent")?
                    .len(),
                9
            );
            assert_eq!(role["report"]["hostLoopbackDenied"], true);
            assert_eq!(role["report"]["procRootDenied"], true);
            assert_eq!(role["report"]["symlinkEscapeDenied"], true);
        }
    }
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with("GRAPH_KILL "))
            .count(),
        18
    );
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with("GRAPH_COURIER_KILL "))
            .count(),
        2
    );
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with("ISOLATION_CHILDREN_TERMINATED "))
            .count(),
        20
    );
    assert_eq!(report["separationObserved"], false);
    Ok(())
}
#[test]
fn repaired_repository_sources_require_observed_effects_before_publication(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let package = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = directory.path().join("repair");
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_chio-outcome-ledger-comparison"))
        .arg("--repair")
        .arg(package.join("fixtures/git-hook-repair/base"))
        .arg(package.join("../.."))
        .arg(&output)
        .output()?;
    assert!(
        result.status.success(),
        "repair failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output.join("repair-comparison.json"))?)?;
    assert_eq!(report["chio"], report["ledger"]);
    assert_eq!(report["separationObserved"], false);
    for backend in ["chio", "ledger"] {
        assert_eq!(report[backend]["checkedCommitCases"], 7);
        assert_eq!(report[backend]["publishedEffects"], 1);
        for field in [
            "baselineRejected",
            "helperOnlyFixRejected",
            "selfAssertedPassRejected",
            "noCommitRejected",
            "evidenceErasureRejected",
            "wrongBaseRejected",
            "substitutionRejected",
            "replacementRejected",
        ] {
            assert_eq!(report[backend][field], true, "{backend} {field}");
        }
    }
    Ok(())
}
#[test]
fn receiver_checking_rejects_a_dishonest_attestation_and_accepts_unsigned_valid_work(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let package = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = directory.path().join("receiver-check");
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_chio-outcome-ledger-comparison"))
        .arg("--repair-receiver-check")
        .arg(package.join("fixtures/git-hook-repair/base"))
        .arg(package.join("../.."))
        .arg(&output)
        .output()?;
    assert!(
        result.status.success(),
        "receiver check failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(
        output.join("receiver-check-comparison.json"),
    )?)?;
    assert_eq!(report["gateSeparationObserved"], false);
    let profiles = report["profiles"].as_array().ok_or("profiles absent")?;
    assert_eq!(profiles.len(), 2);
    for profile in profiles {
        assert_eq!(profile["chio"], profile["ledger"]);
        let local = profile["profile"] == "receiver_checked";
        let row = &profile["chio"];
        assert_eq!(row["upstreamSignatureRequired"], !local);
        assert_eq!(row["upstreamHonestyRequired"], !local);
        assert_eq!(row["sourceChecks"], if local { 2 } else { 0 });
        assert_eq!(
            row["acceptedArtifact"],
            if local {
                "repaired-source"
            } else {
                "buggy-source-signed-by-trusted-upstream"
            }
        );
        assert_eq!(row["publicationEffects"], 1);
        assert_eq!(row["reopenedRepeatDenied"], true);
        assert_eq!(row["repeatDidNotExecuteCandidate"], true);
    }
    Ok(())
}

#[test]
fn git_publication_recovers_the_bound_commit_without_reconstructing_dispatch_permits(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let package = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = directory.path().join("git-recovery");
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_chio-outcome-ledger-comparison"))
        .arg("--repair-git-recovery")
        .arg(package.join("fixtures/git-hook-repair/base"))
        .arg(package.join("../.."))
        .arg(&output)
        .output()?;
    assert!(
        result.status.success(),
        "Git recovery failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output.join("git-repair-comparison.json"))?)?;
    assert_eq!(report["gateSeparationObserved"], false);
    assert_eq!(report["genericPermitReconstructed"], false);
    assert_eq!(report["checkedCommitCases"], 14);
    assert_eq!(
        String::from_utf8_lossy(&result.stderr)
            .lines()
            .filter(|line| line.starts_with("GIT_PUBLICATION_KILL "))
            .count(),
        22
    );
    let cases = report["pairedScenarios"]
        .as_array()
        .ok_or("Git scenarios missing")?;
    assert_eq!(cases.len(), 12);
    for case in cases {
        assert_eq!(case["chio"], case["ledger"]);
        let name = case["case"].as_str().ok_or("case name missing")?;
        let accepted = matches!(
            name,
            "before_claim"
                | "after_claim"
                | "after_ref"
                | "after_complete"
                | "race_after_claim"
                | "revoked_after_claim"
        );
        assert_eq!(case["chio"]["accepted"], accepted);
        assert_eq!(case["chio"]["finalPublications"], usize::from(accepted));
        assert_eq!(case["chio"]["observedPublished"], accepted);
        assert_eq!(case["chio"]["repeatPreservedState"], true);
        if matches!(
            name,
            "after_claim" | "after_ref" | "race_after_claim" | "revoked_after_claim"
        ) {
            assert_eq!(case["chio"]["finalGateState"], "claimed");
        }
    }
    Ok(())
}

#[test]
fn portable_artifact_checking_rejects_buggy_signed_work_without_claiming_private_history(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let package = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let base = package.join("fixtures/git-hook-repair/base");
    let output = directory.path().join("artifact-audit");
    let binary = env!("CARGO_BIN_EXE_chio-outcome-ledger-comparison");
    let result = std::process::Command::new(binary)
        .arg("--repair-artifact-audit")
        .arg(&base)
        .arg(package.join("../.."))
        .arg(&output)
        .output()?;
    assert!(
        result.status.success(),
        "artifact comparison failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(
        output.join("artifact-audit-comparison.json"),
    )?)?;
    assert_eq!(report["chio"], report["ledger"]);
    assert_eq!(report["gateSeparationObserved"], false);
    assert_eq!(report["auditorNeedsReceiverKeyOrStore"], false);
    let cases = report["chio"]
        .as_array()
        .ok_or("artifact scenarios absent")?;
    assert_eq!(cases.len(), 10);
    for case in cases {
        let name = case["case"].as_str().ok_or("case name absent")?;
        assert_eq!(
            case["artifactAccepted"],
            matches!(
                name,
                "honest_published" | "signed_unpublished" | "unsigned_valid"
            )
        );
        assert_eq!(case["publicationHistoryVerified"], false);
        assert_eq!(case["receiverStatePathsDenied"], 9);
        assert_eq!(case["packetReadOnly"], true);
        if name == "signed_unpublished" {
            assert_eq!(case["receiverClaimSignatureValid"], true);
            assert_eq!(case["publicationActuallyOccurred"], false);
        }
        if name == "unsigned_valid" {
            assert_eq!(case["receiverClaimSignatureValid"], false);
        }
    }
    // Exercise the consumer-facing CLI with only its own base and an unsigned
    // packet. No receiver database, key, intent or receipt is supplied.
    let audit_output = directory.path().join("standalone-audit");
    let result = std::process::Command::new(binary)
        .arg("--audit-repair-bundle")
        .arg(&base)
        .arg(output.join("chio/packets/unsigned_valid"))
        .arg(&audit_output)
        .output()?;
    assert!(
        result.status.success(),
        "standalone auditor failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let checked: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit_output.join("checked-artifact.json"))?)?;
    assert_eq!(checked["artifactPassed"], true);
    assert_eq!(checked["checkedCommitCases"], 7);
    assert_eq!(checked["publicationHistoryVerified"], false);
    assert_eq!(checked["receiverSignatureRequired"], false);
    Ok(())
}

#[test]
fn artifact_reuse_inflates_counting_metrics_but_cannot_refill_a_protected_job(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let package = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = directory.path().join("work-reuse");
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_chio-outcome-ledger-comparison"))
        .arg("--repair-work-reuse")
        .arg(package.join("fixtures/git-hook-repair/base"))
        .arg(package.join("../.."))
        .arg(&output)
        .output()?;
    assert!(
        result.status.success(),
        "work reuse comparison failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output.join("work-reuse-comparison.json"))?)?;
    let totals = &report["totals"];
    for (name, count) in [
        ("acceptedSignedClaims", 24),
        ("distinctProducerKeys", 24),
        ("distinctArtifactHashes", 19),
        ("distinctSyntaxHashes", 7),
        ("distinctChallenges", 7),
        ("distinctLogicalJobs", 1),
        ("validArtifactsBehaviorChecked", 19),
        ("actualGitCommitCases", 140),
    ] {
        assert_eq!(totals[name], count, "{name}");
    }
    let groups = report["families"].as_array().ok_or("families missing")?;
    assert_eq!(groups.len(), 4);
    for group in groups {
        let name = group["family"].as_str().ok_or("family name missing")?;
        assert_eq!(group["acceptedClaims"], 6);
        assert_eq!(group["distinctLogicalJobs"], 1);
        assert_eq!(
            group["distinctArtifactHashes"],
            if name == "new_identities" { 1 } else { 6 }
        );
        assert_eq!(
            group["distinctSyntaxHashes"],
            if name == "dead_branches" { 6 } else { 1 }
        );
        assert_eq!(
            group["distinctChallenges"],
            if name == "fresh_challenges" { 6 } else { 1 }
        );
    }
    assert_eq!(
        report["protectedLogicalJob"]["chio"],
        report["protectedLogicalJob"]["ledger"]
    );
    assert_eq!(report["protectedLogicalJob"]["chio"]["accepted"], 1);
    assert_eq!(report["protectedLogicalJob"]["chio"]["effects"], 1);
    assert_eq!(report["consensusImplemented"], false);
    assert_eq!(report["resourceHardnessEstablished"], false);
    Ok(())
}
#[test]
fn checked_repair_exchange_binds_delivery_to_atomic_local_credit_settlement(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let package = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = directory.path().join("exchange");
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_chio-outcome-ledger-comparison"))
        .arg("--repair-exchange")
        .arg(package.join("fixtures/git-hook-repair/base"))
        .arg(package.join("../.."))
        .arg(&output)
        .output()?;
    assert!(
        result.status.success(),
        "exchange failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(
        output.join("repair-exchange-comparison.json"),
    )?)?;
    assert_eq!(report["plaintextBuyerAbort"]["buyerHasValidRepair"], true);
    assert_eq!(report["plaintextBuyerAbort"]["sellerCredits"], 0);
    assert_eq!(report["bareHashlock"]["buyerHasValidRepair"], false);
    assert_eq!(report["bareHashlock"]["sellerCredits"], 10);
    assert_eq!(report["trustedCheckerRejectsBuggyOpening"], true);
    let cases = report["pairedScenarios"]
        .as_array()
        .ok_or("exchange cases absent")?;
    assert_eq!(cases.len(), 8);
    for case in cases {
        assert_eq!(case["chio"], case["ledger"]);
        assert_eq!(case["chio"]["terminalEvents"], 1);
        assert_eq!(case["chio"]["lockedCredits"], 0);
        let settled = case["case"] != "seller_withholds";
        assert_eq!(case["chio"]["settled"], settled);
        assert_eq!(case["chio"]["buyerReceivedCheckedArtifact"], settled);
        assert_eq!(case["chio"]["sellerCredits"], if settled { 10 } else { 0 });
        assert_eq!(case["chio"]["buyerCredits"], if settled { 90 } else { 100 });
    }
    assert_eq!(
        String::from_utf8_lossy(&result.stderr)
            .lines()
            .filter(|line| line.starts_with("EXCHANGE_WORKER_KILLED "))
            .count(),
        4
    );
    assert_eq!(report["actualGitCommitCases"], 14);
    assert_eq!(report["zeroKnowledgeProofImplemented"], false);
    assert_eq!(report["externalPaymentExecuted"], false);
    Ok(())
}
