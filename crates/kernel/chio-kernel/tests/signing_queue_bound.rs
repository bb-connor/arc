//! Byte-bound enforcement for the async receipt-signing queue (BAC-539).
//!
//! Each queued [`signing_task::SignRequest`] owns the full canonical-content
//! preimage. The bounded mpsc channel limits the queue by request *count* but
//! not by *bytes*; without a per-request byte cap a burst of large value/stream
//! receipts under signer backpressure could retain hundreds of full preimages
//! in memory. These tests assert the fail-closed byte cap:
//!
//! - a request at or under the cap still signs, and
//! - an oversized request is refused before it is enqueued (never truncated,
//!   which would break the WYSIWYS recompute), via both the awaiting [`sign`]
//!   path and the non-blocking [`try_sign`] path.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::TrustLevel,
};
// `signing_task.rs` is included below via `#[path]`; its `use crate::{...}`
// resolves against this test binary's crate root, so re-export the symbols it
// needs (including `DEFAULT_MAX_STREAM_TOTAL_BYTES`) here.
use chio_kernel::{KernelError, DEFAULT_MAX_STREAM_TOTAL_BYTES};
use serde_json::json;

#[allow(dead_code)]
#[path = "../src/kernel/signing_task.rs"]
mod signing_task;

use signing_task::{SigningTaskHandle, DEFAULT_MAX_SIGNING_CONTENT_BYTES};

/// Small explicit byte budget for the cap-enforcement tests so they exercise the
/// fail-closed boundary without allocating the 256 MiB default budget.
const TEST_BUDGET: usize = 4 * 1024;

const KERNEL_SEED: [u8; 32] = [
    0x77, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F,
];

/// Build a signable body whose `content_hash` is the sha256 of the given
/// canonical-content preimage, so the signing-task WYSIWYS recompute accepts it.
fn body_for_content(kernel_key: &Keypair, canonical_content: &[u8]) -> ChioReceiptBody {
    let action =
        ToolCallAction::from_parameters(json!({"tool": "echo"})).expect("payload canonicalises");
    ChioReceiptBody {
        id: "rcpt-queue-bound".to_string(),
        timestamp: 1_700_200_000,
        capability_id: "cap-queue-bound".to_string(),
        tool_server: "tool.example".to_string(),
        tool_name: "echo".to_string(),
        action,
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: sha256_hex(canonical_content),
        policy_hash: sha256_hex(b"policy:queue-bound"),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: kernel_key.public_key(),
        bbs_projection_version: None,
    }
}

/// Build a handle whose per-request byte budget is the small [`TEST_BUDGET`] so
/// the cap-enforcement tests stay cheap.
fn small_budget_handle(keypair: &Keypair) -> SigningTaskHandle {
    SigningTaskHandle::with_capacity_and_max_content_bytes(
        keypair.clone(),
        /* capacity */ 256,
        TEST_BUDGET,
    )
}

#[tokio::test(flavor = "current_thread")]
async fn sign_accepts_content_at_the_byte_budget() {
    let keypair = Keypair::from_seed(&KERNEL_SEED);
    let handle = small_budget_handle(&keypair);

    // Exactly at the budget must be accepted.
    let content = vec![0xABu8; TEST_BUDGET];
    let body = body_for_content(&keypair, &content);

    let receipt = handle
        .sign(body, content)
        .await
        .expect("content at the budget should sign");
    assert!(receipt.verify_signature().expect("signature verifies"));

    handle.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn sign_refuses_oversized_content_fail_closed() {
    let keypair = Keypair::from_seed(&KERNEL_SEED);
    let handle = small_budget_handle(&keypair);

    // One byte over the budget must be refused before it is ever enqueued.
    let content = vec![0xABu8; TEST_BUDGET + 1];
    let body = body_for_content(&keypair, &content);

    let err = handle
        .sign(body, content)
        .await
        .expect_err("oversized content must be refused");
    match err {
        KernelError::ReceiptSigningFailed(message) => {
            assert!(
                message.contains("over the"),
                "error should explain the queue byte budget: {message}"
            );
        }
        other => panic!("expected ReceiptSigningFailed, got {other:?}"),
    }

    // The task must remain usable: a normal request still signs afterwards.
    let small = b"small-content".to_vec();
    let body = body_for_content(&keypair, &small);
    let receipt = handle
        .sign(body, small)
        .await
        .expect("normal request still signs after an oversized rejection");
    assert!(receipt.verify_signature().expect("signature verifies"));

    handle.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn try_sign_returns_oversized_content_unsent() {
    let keypair = Keypair::from_seed(&KERNEL_SEED);
    let handle = small_budget_handle(&keypair);

    let content = vec![0xABu8; TEST_BUDGET + 1];
    let body = body_for_content(&keypair, &content);

    let outcome = handle.try_sign(body, content.clone());
    match outcome {
        Err((_body, returned_content)) => {
            assert_eq!(
                returned_content.len(),
                content.len(),
                "oversized content is returned unsent, not enqueued"
            );
        }
        Ok(_) => panic!("oversized content must not be enqueued"),
    }

    handle.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn default_budget_admits_large_async_receipts_above_one_mib() {
    // BAC-539 round-4: the default per-request budget is aligned to the kernel's
    // configured stream/output max (256 MiB), not a fixed 1 MiB hard-reject. A
    // legitimate large async receipt above 1 MiB must sign through the async
    // queue, since it is the documented off-critical-path signer. The budget is
    // still BOUNDED: it equals the configured stream max.
    assert_eq!(
        DEFAULT_MAX_SIGNING_CONTENT_BYTES,
        usize::try_from(DEFAULT_MAX_STREAM_TOTAL_BYTES).unwrap(),
        "default signing budget must track the configured stream/output max"
    );
    assert!(
        DEFAULT_MAX_SIGNING_CONTENT_BYTES > 1024 * 1024,
        "default budget must exceed the old 1 MiB hard-reject"
    );

    let keypair = Keypair::from_seed(&KERNEL_SEED);
    let handle = SigningTaskHandle::spawn(keypair.clone());

    // 2 MiB: comfortably over the retired 1 MiB cap, well under the default budget.
    let content = vec![0xCDu8; 2 * 1024 * 1024];
    let body = body_for_content(&keypair, &content);

    let receipt = handle
        .sign(body, content)
        .await
        .expect("a 2 MiB async receipt must sign under the configured-stream-max budget");
    assert!(receipt.verify_signature().expect("signature verifies"));

    handle.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn zero_per_request_cap_admits_large_receipts_unlimited() {
    // BAC-539 round-5 (issue 2): a per-request cap of 0 means UNLIMITED (matching
    // the inline signer), NOT a 1-byte cap. The kernel wires a `0` cap when
    // `max_stream_total_bytes == 0` ("unlimited stream") flows through, so the
    // async path must admit a large receipt rather than rejecting it as "1 byte
    // over". Without the fix, `max_content_bytes.max(1)` turned 0 into 1 and this
    // 64 KiB preimage would be refused fail-closed.
    let keypair = Keypair::from_seed(&KERNEL_SEED);
    // Per-request cap = 0 (unlimited); aggregate budget large enough to admit the
    // single request so we isolate the per-request-cap behaviour.
    let handle = SigningTaskHandle::with_capacity_max_content_and_queued_bytes(
        keypair.clone(),
        /* capacity */ 256,
        /* per-request cap */ 0,
        /* aggregate budget */ 1024 * 1024,
    );

    // A preimage far larger than the retired 1-byte cap the `max(1)` bug imposed.
    let content = vec![0x5Au8; 64 * 1024];
    let body = body_for_content(&keypair, &content);

    let receipt = handle.sign(body, content).await.expect(
        "a 0 (unlimited) per-request cap must admit a 64 KiB receipt, not reject as 1-over",
    );
    assert!(receipt.verify_signature().expect("signature verifies"));

    handle.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn aggregate_byte_budget_backpressures_even_with_channel_room() {
    // BAC-539 round-5 (issue 1): the AGGREGATE byte budget bounds the SUM of
    // in-flight queued preimage bytes independently of channel COUNT capacity.
    // On a current-thread runtime the spawned signing task does not run until we
    // `.await` it, so permits acquired by `try_sign` stay held; this lets us
    // assert deterministically that a second request is refused purely by the
    // aggregate byte budget while the channel still has count capacity.
    let keypair = Keypair::from_seed(&KERNEL_SEED);
    // Generous channel capacity (count) but a tiny 4-byte aggregate budget. Per
    // request cap is unlimited so the ONLY thing that can block the second send
    // is the aggregate byte budget.
    let handle = SigningTaskHandle::with_capacity_max_content_and_queued_bytes(
        keypair.clone(),
        /* capacity */ 256,
        /* per-request cap */ 0,
        /* aggregate budget */ 4,
    );

    // First request consumes the whole 4-byte aggregate budget and enqueues
    // (channel has plenty of count capacity). The task has not run yet, so the
    // permit is still held.
    let first_content = vec![0x11u8; 4];
    let first_body = body_for_content(&keypair, &first_content);
    let first = handle.try_sign(first_body, first_content);
    let first_rx = match first {
        Ok(rx) => rx,
        Err(_) => panic!("first request must enqueue: budget and channel both have room"),
    };

    // Second request: 1 byte. The channel still has count capacity, but the
    // aggregate byte budget is exhausted, so it MUST be refused (returned unsent)
    // rather than enqueued. This proves total queued bytes are bounded by the
    // aggregate budget, not just by channel count.
    let second_content = vec![0x22u8; 1];
    let second_body = body_for_content(&keypair, &second_content);
    match handle.try_sign(second_body, second_content) {
        Err((_body, returned)) => {
            assert_eq!(
                returned.len(),
                1,
                "second request returned unsent by aggregate byte budget backpressure"
            );
        }
        Ok(_) => panic!("aggregate byte budget exhausted: second request must not enqueue"),
    }

    // Drain: signing the first request releases its permit, so after shutdown the
    // task processes it and the first reply resolves. This also proves the budget
    // is RELEASED (not leaked) once a request is signed.
    drop(first_rx);
    handle.shutdown().await;

    // After the budget frees, a fresh request fits again, confirming the budget
    // is a recoverable bound, not a one-shot exhaustion.
    let handle =
        SigningTaskHandle::with_capacity_max_content_and_queued_bytes(keypair.clone(), 256, 0, 4);
    let content = vec![0x33u8; 4];
    let body = body_for_content(&keypair, &content);
    let receipt = handle
        .sign(body, content)
        .await
        .expect("a request within the aggregate budget signs");
    assert!(receipt.verify_signature().expect("signature verifies"));
    handle.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn shutdown_during_permit_wait_rejects_stalled_request() {
    // BAC-539 round-6: a producer stalled on the aggregate-permit `.await` when
    // `shutdown()` runs MUST be rejected, not enqueued. The fix is that `sign`
    // does NOT hold a sender clone across the permit wait; it re-clones the
    // sender (and re-checks the `closed` flag) AFTER the await. Without the fix,
    // the stalled producer's pre-await sender clone would keep the receiver open
    // while shutdown drained queued work, then enqueue a request that had not
    // reached the channel before shutdown began -- which shutdown would then
    // sign/await.
    //
    // Determinism: a tiny 4-byte aggregate budget on a current-thread runtime.
    // The first request is enqueued via `try_sign`, which holds the whole budget
    // and does not run the signing task. A second request submitted via `sign`
    // therefore parks on `acquire_aggregate_permit`. We drive that `sign` future
    // to its park point by polling it DIRECTLY (via `poll_fn`) rather than
    // `yield_now`/`spawn`, so the signing task never gets a scheduler slot to
    // drain the first request early and release the budget before shutdown.
    // `shutdown` then latches `closed`, drops the canonical sender, and joins the
    // task; joining drains the first request, releases the budget, and wakes the
    // stalled producer, whose post-await re-check observes `closed` and rejects.
    use std::future::poll_fn;
    use std::future::Future;
    use std::pin::pin;
    use std::task::Poll;

    let keypair = Keypair::from_seed(&KERNEL_SEED);
    let handle = SigningTaskHandle::with_capacity_max_content_and_queued_bytes(
        keypair.clone(),
        /* capacity */ 256,
        /* per-request cap */ 0,
        /* aggregate budget */ 4,
    );

    // First request consumes the entire 4-byte aggregate budget and enqueues
    // (channel has count capacity). The task has not run, so the permit is held.
    let first_content = vec![0x11u8; 4];
    let first_body = body_for_content(&keypair, &first_content);
    let _first_rx = handle
        .try_sign(first_body, first_content)
        .expect("first request enqueues and holds the whole aggregate budget");

    // Second request: build the `sign` future and poll it directly until it parks
    // on the exhausted aggregate budget. Polling directly (no scheduler yield)
    // guarantees the signing task does not drain the first request and release
    // the budget before shutdown.
    let second_content = vec![0x22u8; 1];
    let second_body = body_for_content(&keypair, &second_content);
    let mut sign_future = pin!(handle.sign(second_body, second_content));
    poll_fn(|cx| {
        // One poll is enough to reach the parked `acquire_aggregate_permit`
        // await; it must be Pending because the budget is exhausted.
        match sign_future.as_mut().poll(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(other) => {
                panic!("sign must park on the exhausted aggregate budget, got {other:?}")
            }
        }
    })
    .await;

    // Shutdown while the producer is parked on the permit, then resume the
    // parked `sign` future. With the fix, shutdown's join drains the first queued
    // request (the parked producer holds no sender clone, so the channel closes),
    // the budget frees, the producer's permit acquisition succeeds, and its
    // post-await re-check observes `closed` and rejects. Without the fix, the
    // parked producer's pre-await sender clone keeps the channel open, so
    // shutdown's join would hang; the timeout converts that regression into a
    // deterministic failure instead of a hung suite.
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        handle.shutdown().await;
        sign_future.await
    })
    .await
    .expect("shutdown + resume must not hang (a hang means a stalled sender clone kept the channel open)");
    match result {
        Err(KernelError::Internal(message)) => {
            assert!(
                message.contains("already shut down"),
                "stalled request must be rejected as shut down, got: {message}"
            );
        }
        Err(other) => panic!("expected shut-down rejection, got {other:?}"),
        Ok(_) => panic!(
            "a request stalled on the permit when shutdown began must be rejected, \
             not signed (it had not reached the channel before shutdown)"
        ),
    }
}
