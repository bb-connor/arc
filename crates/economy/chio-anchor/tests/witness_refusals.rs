#![cfg(feature = "web3")]

use chio_anchor::{
    batch_body_hash, build_anchor_batch, build_anchor_batch_body,
    build_ots_inclusion_proof_with_forged_digest, evaluate_witness_policy,
    evaluate_witness_policy_with_verifier, verify_anchor_batch_with_witness_policy,
    verify_anchor_batch_with_witness_policy_async, AnchorBatch, AnchorBatchWitness,
    AnchorBatchWitnessKind, AnchorError, AnchorWitnessClient, AnchorWitnessError, OtsClient,
    VerifiedWitnessCache, WitnessPolicy, WitnessPolicyError, WitnessReceipt, WitnessState,
};
use chio_core::hashing::{sha256, Hash};
use chio_core::Keypair;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn loopback_contract(endpoint: &str) -> chio_egress_contract::HttpEgressContract {
    chio_egress_contract::HttpEgressContract::permissive_for_tests(
        endpoint.trim_start_matches("http://"),
    )
}

const ISSUED_AT: u64 = 1_700_000_000;
const NOW: i64 = 1_700_000_100;

fn witness_descriptor() -> AnchorBatchWitness {
    AnchorBatchWitness {
        kind: AnchorBatchWitnessKind::Rekor,
        witness_id: "rekor:pending".to_owned(),
        root: Hash::zero(),
        observed_at: Some(ISSUED_AT),
    }
}

fn sample_batch() -> Result<AnchorBatch, Box<dyn std::error::Error>> {
    let signer = Keypair::from_seed(&[3; 32]);
    Ok(build_anchor_batch(
        vec!["ck-1".to_owned(), "ck-2".to_owned()],
        witness_descriptor(),
        ISSUED_AT,
        &signer,
    )?)
}

fn witnessed_state(batch: &AnchorBatch) -> Result<WitnessState, Box<dyn std::error::Error>> {
    Ok(WitnessState::Witnessed {
        receipt: WitnessReceipt {
            kind: AnchorBatchWitnessKind::Rekor,
            external_uuid: "entry-1".to_owned(),
            published_at: 1_700_000_010,
            inclusion_proof: Vec::new(),
            witness_root: batch.body.tree_root,
            body_hash: batch_body_hash(batch)?,
        },
        observed_at: 1_700_000_010,
    })
}

fn stale_state() -> WitnessState {
    WitnessState::Stale {
        last_verified: ISSUED_AT as i64,
        error: "lane down".to_owned(),
    }
}

#[tokio::test]
async fn load_bearing_witnessed_without_a_verifier_is_refused() -> TestResult {
    let batch = sample_batch()?;
    let state = witnessed_state(&batch)?;
    let result = evaluate_witness_policy_with_verifier(
        &batch,
        &state,
        &WitnessPolicy::require_public_witness(),
        NOW,
        None,
        &VerifiedWitnessCache::new(),
    )
    .await;
    assert!(matches!(result, Err(WitnessPolicyError::VerifierRequired)));
    Ok(())
}

#[tokio::test]
async fn async_entry_surfaces_the_missing_verifier_refusal() -> TestResult {
    let signer = Keypair::from_seed(&[3; 32]);
    let mut body = build_anchor_batch_body(
        vec!["ck-1".to_owned()],
        witness_descriptor(),
        ISSUED_AT,
        signer.public_key(),
    )?;
    let unwitnessed = AnchorBatch::sign(body.clone(), &signer)?;
    body.witness_state = witnessed_state(&unwitnessed)?;
    let batch = AnchorBatch::sign(body, &signer)?;
    let result = verify_anchor_batch_with_witness_policy_async(
        &batch,
        &WitnessPolicy::require_public_witness(),
        NOW,
        None,
        &VerifiedWitnessCache::new(),
    )
    .await;
    match result {
        Err(AnchorError::Verification(message)) => assert_eq!(
            message,
            format!(
                "witness policy violation: {}",
                WitnessPolicyError::VerifierRequired
            )
        ),
        other => panic!("expected Verification carrying VerifierRequired, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn stale_cache_entry_from_the_future_is_refused_with_both_timestamps() -> TestResult {
    let batch = sample_batch()?;
    let mut cache = VerifiedWitnessCache::new();
    cache.insert(batch_body_hash(&batch)?, NOW + 1);
    let result = evaluate_witness_policy_with_verifier(
        &batch,
        &stale_state(),
        &WitnessPolicy::require_public_witness(),
        NOW,
        None,
        &cache,
    )
    .await;
    match result {
        Err(WitnessPolicyError::StaleVerifierCacheInFuture { verified_at, now }) => {
            assert_eq!(verified_at, NOW + 1);
            assert_eq!(now, NOW);
        }
        other => panic!("expected StaleVerifierCacheInFuture, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn stale_cache_entry_at_the_verifier_clock_is_admitted() -> TestResult {
    let batch = sample_batch()?;
    let mut cache = VerifiedWitnessCache::new();
    cache.insert(batch_body_hash(&batch)?, NOW);
    evaluate_witness_policy_with_verifier(
        &batch,
        &stale_state(),
        &WitnessPolicy::require_public_witness(),
        NOW,
        None,
        &cache,
    )
    .await?;
    Ok(())
}

#[test]
fn tampered_receipt_body_hash_is_refused_with_both_digests() -> TestResult {
    let batch = sample_batch()?;
    let forged = sha256(b"forged-batch-body");
    let state = match witnessed_state(&batch)? {
        WitnessState::Witnessed {
            mut receipt,
            observed_at,
        } => {
            receipt.body_hash = forged;
            WitnessState::Witnessed {
                receipt,
                observed_at,
            }
        }
        other => panic!("expected Witnessed, got {other:?}"),
    };
    let result = evaluate_witness_policy(&batch, &state, &WitnessPolicy::advisory(), NOW);
    match result {
        Err(WitnessPolicyError::WitnessReceiptBodyHashMismatch {
            receipt_hash,
            batch_hash,
        }) => {
            assert_eq!(receipt_hash, forged.to_hex_prefixed());
            assert_eq!(batch_hash, batch_body_hash(&batch)?.to_hex_prefixed());
        }
        other => panic!("expected WitnessReceiptBodyHashMismatch, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn tampered_receipt_body_hash_never_reaches_the_live_verifier() -> TestResult {
    struct PanickingClient;
    #[async_trait::async_trait]
    impl AnchorWitnessClient for PanickingClient {
        async fn publish(&self, _: &AnchorBatch) -> Result<WitnessReceipt, AnchorWitnessError> {
            panic!("publish must not be called");
        }
        async fn verify_inclusion(&self, _: &WitnessReceipt) -> Result<(), AnchorWitnessError> {
            panic!("verify_inclusion must not be called");
        }
    }
    let batch = sample_batch()?;
    let forged = sha256(b"forged-batch-body");
    let state = match witnessed_state(&batch)? {
        WitnessState::Witnessed {
            mut receipt,
            observed_at,
        } => {
            receipt.body_hash = forged;
            WitnessState::Witnessed {
                receipt,
                observed_at,
            }
        }
        other => panic!("expected Witnessed, got {other:?}"),
    };
    let result = evaluate_witness_policy_with_verifier(
        &batch,
        &state,
        &WitnessPolicy::require_public_witness(),
        NOW,
        Some(&PanickingClient),
        &VerifiedWitnessCache::new(),
    )
    .await;
    assert!(matches!(
        result,
        Err(WitnessPolicyError::WitnessReceiptBodyHashMismatch { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn ots_proof_committing_to_another_digest_reports_both_digests() -> TestResult {
    let committed = sha256(b"digest-the-calendar-stamped");
    let expected = sha256(b"digest-the-batch-hashes-to");
    let receipt = WitnessReceipt {
        kind: AnchorBatchWitnessKind::Ots,
        external_uuid: "ots:calendar".to_owned(),
        published_at: 1_700_000_010,
        inclusion_proof: build_ots_inclusion_proof_with_forged_digest(&committed, 900_000)?,
        witness_root: Hash::zero(),
        body_hash: expected,
    };
    let client = OtsClient::new(
        "http://127.0.0.1:9",
        &loopback_contract("http://127.0.0.1:9"),
        0,
    )?;
    match client.verify_inclusion(&receipt).await {
        Err(AnchorWitnessError::BodyHashMismatch { lane, batch }) => {
            assert_eq!(lane, committed.to_hex());
            assert_eq!(batch, expected.to_hex());
        }
        other => panic!("expected BodyHashMismatch, got {other:?}"),
    }
    Ok(())
}

#[test]
fn sync_route_under_load_bearing_policy_is_refused_before_verification() -> TestResult {
    let mut batch = sample_batch()?;
    batch.body.issued_at += 1;
    let result = verify_anchor_batch_with_witness_policy(
        &batch,
        &WitnessPolicy::require_public_witness(),
        NOW,
    );
    assert!(matches!(
        result,
        Err(AnchorError::SyncRouteRequiresAdvisoryPolicy)
    ));
    Ok(())
}

#[test]
fn sync_route_under_advisory_policy_still_verifies_the_batch() -> TestResult {
    let batch = sample_batch()?;
    verify_anchor_batch_with_witness_policy(&batch, &WitnessPolicy::advisory(), NOW)?;
    let mut tampered = sample_batch()?;
    tampered.body.issued_at += 1;
    let result =
        verify_anchor_batch_with_witness_policy(&tampered, &WitnessPolicy::advisory(), NOW);
    assert!(matches!(result, Err(AnchorError::Verification(_))));
    Ok(())
}
