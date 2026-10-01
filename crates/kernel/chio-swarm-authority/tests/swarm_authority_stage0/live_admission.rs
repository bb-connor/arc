//! Live authorization must not require evidence of future task completion.
use super::*;
use chio_swarm_authority::verify_swarm_authority_for_admission;

#[test]
fn fanout_admission_does_not_claim_future_join_or_terminal_results() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    bundle.join_receipts.clear();
    bundle.terminal_receipts.clear();
    let report = verify_swarm_authority_for_admission(&bundle, &trusted_witness_keys())?;
    assert_eq!(report.verdict, "verified");
    assert_eq!(report.continuation_count, 2);
    assert_eq!(report.join_count, 0);
    for claim in [
        CLAIM_SWARM_TASK_GRAPH_BOUND,
        CLAIM_SWARM_BUDGET_POOL_BOUND,
        CLAIM_SWARM_CONTINUATION_FRESH,
        CLAIM_SWARM_ATTENUATION_WITNESS_CHAIN_BOUND,
    ] {
        assert!(report.verified_claims.iter().any(|value| value == claim));
    }
    for claim in [
        CLAIM_SWARM_JOIN_RECEIPT_BOUND,
        CLAIM_SWARM_TERMINAL_GRAPH_RECEIPT_BOUND,
    ] {
        assert!(!report.verified_claims.iter().any(|value| value == claim));
    }
    // The complete-artifact verifier must remain strict.
    assert!(verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()).is_err());
    Ok(())
}

#[test]
fn admission_checks_supplied_results_instead_of_ignoring_them() -> Result<(), Box<dyn Error>> {
    let mut bundle = sample_swarm_bundle()?;
    let complete = verify_swarm_authority_bundle(&bundle, &trusted_witness_keys())?;
    assert_eq!(
        verify_swarm_authority_for_admission(&bundle, &trusted_witness_keys())?,
        complete
    );
    bundle.terminal_receipts.clear();
    let report = verify_swarm_authority_for_admission(&bundle, &trusted_witness_keys())?;
    assert!(report
        .verified_claims
        .iter()
        .any(|claim| claim == CLAIM_SWARM_JOIN_RECEIPT_BOUND));
    assert!(!report
        .verified_claims
        .iter()
        .any(|claim| claim == CLAIM_SWARM_TERMINAL_GRAPH_RECEIPT_BOUND));
    assert!(verify_swarm_authority_bundle(&bundle, &trusted_witness_keys()).is_err());
    bundle.join_receipts[0].signature = "00".repeat(64);
    assert!(verify_swarm_authority_for_admission(&bundle, &trusted_witness_keys()).is_err());
    let mut bundle = sample_swarm_bundle()?;
    bundle.terminal_receipts[0].signature = "00".repeat(64);
    assert!(verify_swarm_authority_for_admission(&bundle, &trusted_witness_keys()).is_err());
    // A terminal receipt cannot hide missing graph joins even during admission.
    let mut bundle = sample_swarm_bundle()?;
    bundle.join_receipts.clear();
    assert!(verify_swarm_authority_for_admission(&bundle, &trusted_witness_keys()).is_err());
    Ok(())
}

#[test]
fn admission_still_requires_selected_join_and_all_authority() -> Result<(), Box<dyn Error>> {
    for mutation in ["join", "signature", "budget", "expired", "witness", "trust"] {
        let mut bundle = sample_swarm_bundle()?;
        bundle.join_receipts.clear();
        bundle.terminal_receipts.clear();
        let mut trusted = trusted_witness_keys();
        match mutation {
            "join" => {
                let token = &mut bundle.continuation_tokens[0];
                token.parent_task_id = None;
                token.join_receipt_id = Some("join-child-results".into());
                token.signature = sign_swarm_continuation_token(token, &witness_keypair())?;
            }
            "signature" => bundle.task_graph.signature = "00".repeat(64),
            "budget" => bundle.budget_pool.total_units = 0,
            "expired" => bundle.now_unix_ms = bundle.task_graph.expires_at_unix_ms,
            "witness" => bundle.witness_chains.clear(),
            "trust" => trusted.clear(),
            _ => unreachable!(),
        }
        assert!(
            verify_swarm_authority_for_admission(&bundle, &trusted).is_err(),
            "{mutation}"
        );
    }
    Ok(())
}
