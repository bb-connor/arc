//! Timing-leak dudect harness for the strict bilateral invocation DSSE
//! envelope verifier.
//!
//! Gated behind the `dudect` Cargo feature so default `cargo test -p
//! chio-federation` is unaffected; opt in via:
//!
//! ```bash
//! cargo test -p chio-federation --features dudect --release --test dudect_bilateral_dsse_verify
//! ```
//!
//! # What this harness measures
//!
//! [`verify_chio_bilateral_dsse_envelope`] matches the two DSSE signature
//! entries to Org A and Org B by `keyid`, not by array position, and the
//! envelope profile states that the array order carries no security
//! meaning. Both input classes are the same co-signed envelope with the
//! same single-byte corruption of Org B's signature, so both run every
//! structural gate, verify Org A's Ed25519 signature, and then fail closed
//! at the Org B check (`signature.server_b_invalid`). They differ only in
//! the order of the two entries in the `signatures` array:
//!
//! - `Class::Left`: entries in emitted order, Org A first.
//! - `Class::Right`: the same two entries, Org B first.
//!
//! The elliptic-curve work is byte-identical across the classes: the same
//! payload, the same two public keys and the same two signature blobs are
//! consumed in both. What varies is the data the verifier itself walks -
//! the keyid uniqueness scan and the two `keyid` lookups - so the t-test
//! isolates this verifier's own handling rather than the timing profile of
//! the underlying Ed25519 primitive. A distinguishable pair of
//! distributions means the rejection time reveals which array slot held
//! which signer, or that a positional fast path crept in ahead of the
//! signature checks.
//!
//! The classes deliberately do not differ by which signer was tampered or
//! by which signature byte was flipped. Either choice changes the scalars
//! that `ed25519-dalek`'s variable-time verification consumes (and the
//! first also changes the number of verifications performed), so the t-test
//! would report the cost of that primitive instead of a property of this
//! verifier.
//!
//! The CI lane `.github/workflows/dudect.yml` runs this harness nightly with
//! the two-consecutive-runs `t < 4.5` pass rule.

#![cfg(feature = "dudect")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::OnceLock;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chio_core_types::crypto::{sha256_hex, Keypair, PublicKey};
use chio_core_types::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::TrustLevel,
};
use chio_federation::bilateral_dsse::{
    sign_chio_bilateral_dsse_envelope, verify_chio_bilateral_dsse_envelope,
    BilateralPredicateExtensions, CapabilityLeaseRef, DsseEnvelope, GovernanceReceiptRef,
    HashRecord, Keyid, PolicyEvaluationSummary, PolicyVerdict, TreatyBindingRef,
};
use dudect_bencher::rand::RngExt;
use dudect_bencher::{ctbench_main, BenchRng, Class, CtRunner};

/// Deterministic Org A signer seed. Identical to the libFuzzer entry in
/// `fuzz/src/entries.rs` so the two tools exercise the same key material.
const DUDECT_ORG_A_SEED: [u8; 32] = [
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
];

/// Deterministic Org B signer seed; see [`DUDECT_ORG_A_SEED`].
const DUDECT_ORG_B_SEED: [u8; 32] = [
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
];

/// Number of class draws per harness invocation. Matches the sibling
/// harnesses; the runner re-invokes the closure per draw.
const SAMPLES_PER_RUN: usize = 100_000;

/// Prebuilt inputs shared by every draw so the measured closure contains
/// only the verifier call.
struct Fixture {
    org_a: PublicKey,
    org_b: PublicKey,
    /// Co-signed envelope whose Org B signature carries a single flipped
    /// byte. Entries are in the order `sign_chio_bilateral_dsse_envelope`
    /// emits them, Org A first.
    tampered: DsseEnvelope,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(build_fixture)
}

fn build_fixture() -> Fixture {
    let org_a = Keypair::from_seed(&DUDECT_ORG_A_SEED);
    let org_b = Keypair::from_seed(&DUDECT_ORG_B_SEED);
    let receipt = sample_receipt(&org_b);
    let envelope = sign_chio_bilateral_dsse_envelope(
        &receipt,
        &org_a,
        &org_b,
        "kernel.org-a",
        "kernel.org-b",
        "file_read",
        1_734_000_000_000,
        treaty_extensions(&receipt),
    )
    .expect("fixture envelope signs and self-verifies");
    let org_b_keyid = Keyid::from_public_key(&org_b.public_key());
    Fixture {
        org_a: org_a.public_key(),
        org_b: org_b.public_key(),
        tampered: with_signature_byte_flipped(&envelope, org_b_keyid.as_str()),
    }
}

/// Flip the low bit of the first signature byte of the entry carrying
/// `keyid`. Byte 0 sits inside the 32-byte `R` component, so the `s` scalar
/// stays canonical and the verifier runs the full hash-and-recompute check
/// before rejecting rather than bailing out of the scalar decode. The keyid
/// is untouched so the lookup succeeds and only the Ed25519 check fails.
fn with_signature_byte_flipped(envelope: &DsseEnvelope, keyid: &str) -> DsseEnvelope {
    let mut tampered = envelope.clone();
    let entry = tampered
        .signatures
        .iter_mut()
        .find(|signature| signature.keyid == keyid)
        .expect("fixture envelope carries the requested keyid");
    let mut bytes = BASE64_STANDARD
        .decode(&entry.sig)
        .expect("fixture signature is base64");
    let first = bytes.first_mut().expect("Ed25519 signature is 64 bytes");
    *first ^= 0x01;
    entry.sig = BASE64_STANDARD.encode(bytes);
    tampered
}

fn sample_receipt(kernel: &Keypair) -> ChioReceipt {
    let body = ChioReceiptBody {
        id: "rcpt-bilateral-dudect".to_string(),
        timestamp: 1_734_000_000,
        capability_id: "cap-bilateral-dudect".to_string(),
        tool_server: "srv-orgb-files".to_string(),
        tool_name: "file_read".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"k": "v"}))
            .expect("fixture action hashes"),
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: sha256_hex(b"{}"),
        policy_hash: "pol".to_string(),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: kernel.public_key(),
        bbs_projection_version: None,
    };
    ChioReceipt::sign(body, kernel).expect("fixture receipt signs")
}

fn treaty_extensions(receipt: &ChioReceipt) -> BilateralPredicateExtensions {
    let receipt_canonical = chio_core_types::canonical::canonical_json_bytes(receipt)
        .expect("fixture receipt canonicalises");
    BilateralPredicateExtensions {
        capability_lease_ref: Some(CapabilityLeaseRef {
            lease_id: "lease-bilateral".to_string(),
            issuer: "kernel.org-a".to_string(),
            expires_at_unix_ms: 1_734_000_060_000,
            scope_digest: None,
        }),
        policy_evaluation_summary: Some(PolicyEvaluationSummary {
            server_a_verdict: PolicyVerdict {
                verdict: "allow".to_string(),
                policy_id: "policy-a".to_string(),
                policy_version: "v1".to_string(),
                rationale_code: None,
            },
            server_b_verdict: PolicyVerdict {
                verdict: "allow".to_string(),
                policy_id: "policy-b".to_string(),
                policy_version: "v1".to_string(),
                rationale_code: None,
            },
            joint_disposition: Some("allow".to_string()),
        }),
        governance_receipt_ref: Some(GovernanceReceiptRef {
            receipt_id: "gov-receipt-1".to_string(),
            kernel_id: "kernel.org-b".to_string(),
            digest: HashRecord {
                alg: "sha256".to_string(),
                value: "d".repeat(64),
            },
        }),
        consistency_anchor: Some("anchor-live".to_string()),
        consistency_model: Some("totally-ordered".to_string()),
        cross_org_visibility: Some("treaty_only".to_string()),
        treaty_binding_ref: Some(TreatyBindingRef {
            treaty_id: "treaty-buyer-vendor".to_string(),
            treaty_scope_sha256: "1".repeat(64),
            ladder_intersection_sha256: "2".repeat(64),
            admission_report_sha256: "3".repeat(64),
            continuation_sha256: "4".repeat(64),
            lineage_bundle_sha256: "5".repeat(64),
            action_class_id: "workflow.destructive.vendor_call".to_string(),
            consistency_model: "totally-ordered".to_string(),
            request_sha256: receipt.action.parameter_hash.clone(),
            outcome_sha256: receipt.content_hash.clone(),
            local_receipt_sha256: "8".repeat(64),
            remote_receipt_sha256: sha256_hex(&receipt_canonical),
            lease_refs: vec!["lease-bilateral".to_string()],
            governance_refs: vec!["gov-receipt-1".to_string()],
            signer_kernel_ids: vec!["kernel.org-a".to_string(), "kernel.org-b".to_string()],
        }),
    }
}

/// Dudect harness for `verify_chio_bilateral_dsse_envelope`.
///
/// - `Class::Left`: Org B's signature corrupted, entries in emitted order.
/// - `Class::Right`: the same envelope with the two entries reversed.
///
/// Both classes fail closed at the Org B Ed25519 check after the same two
/// verifications over the same bytes. The t-test asks whether the time
/// taken to fail depends on where in the array each signer's entry sits.
fn bilateral_dsse_verify_bench(runner: &mut CtRunner, rng: &mut BenchRng) {
    let fixture = fixture();

    // Draw the class sequence up front so the per-iteration work measured by
    // `run_one` contains only the verifier call.
    let classes: Vec<Class> = (0..SAMPLES_PER_RUN)
        .map(|_| {
            if rng.random::<bool>() {
                Class::Left
            } else {
                Class::Right
            }
        })
        .collect();

    // One envelope value serves both classes, swapped in place between
    // draws. Two separately built envelopes would differ in heap layout as
    // well as in order, and the t-test would pick up the allocator rather
    // than the verifier.
    let mut envelope = fixture.tampered.clone();
    for class in classes {
        let reversed = matches!(class, Class::Right);
        if reversed {
            envelope.signatures.swap(0, 1);
        }
        {
            let probe = &envelope;
            runner.run_one(class, || {
                // The verdict is always `Err` by construction. Return the
                // outcome so `run_one`'s `black_box` keeps the verifier call
                // in the optimized binary.
                verify_chio_bilateral_dsse_envelope(probe, &fixture.org_a, &fixture.org_b).is_err()
            });
        }
        if reversed {
            envelope.signatures.swap(0, 1);
        }
    }
}

ctbench_main!(bilateral_dsse_verify_bench);
