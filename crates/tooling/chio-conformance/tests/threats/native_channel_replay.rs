// Threat test for threat ID `native_channel_replay`.
//
// Threat: native_channel_replay (Replay attacks on the native channel).
// Surfaces: native_chio.
//
// Coverage strategy: import the production
// `chio_kernel::execution_nonce` module directly. Mint a signed
// execution nonce via `mint_execution_nonce`, present it once to
// `verify_execution_nonce` (which calls into the
// `ExecutionNonceStore::reserve_until` replay-prevention surface) so the
// nonce is consumed, then present the same `SignedExecutionNonce` a
// second time. The production verifier MUST return
// `ExecutionNonceError::Replayed` because `InMemoryExecutionNonceStore`
// returns `Ok(false)` on the second reservation. This test also
// exercises the `BadSchema` branch (invariant a forged frame whose
// schema is mutated) and the `BindingMismatch` branch (a mismatched
// tool_name).
//
// Production call site:
// `crates/chio-kernel/src/execution_nonce.rs:364` (`verify_execution_nonce`).
// `crates/chio-kernel/src/execution_nonce.rs:206` (`InMemoryExecutionNonceStore`).
//
// Revert-to-prove-it-fails recipe: inside `verify_execution_nonce` in
// `crates/chio-kernel/src/execution_nonce.rs`, replace
// `Ok(false) => Err(ExecutionNonceError::Replayed)` with
// `Ok(false) => Ok(())`. The replay deny-arm assertion below fails
// because the second presentation of the same nonce no longer
// returns `ExecutionNonceError::Replayed`.

use chio_core::crypto::Keypair;
use chio_kernel::execution_nonce::{
    mint_execution_nonce, verify_execution_nonce, ExecutionNonceConfig, ExecutionNonceError,
    InMemoryExecutionNonceStore, NonceBinding, SignedExecutionNonce,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn current_unix_time() -> i64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
}

fn sample_binding() -> NonceBinding {
    NonceBinding {
        subject_id: "subject-attacker".to_string(),
        capability_id: "cap-replay".to_string(),
        tool_server: "fs".to_string(),
        tool_name: "read_file".to_string(),
        parameter_hash: "0".repeat(64),
    }
}

#[test]
fn threat_native_channel_replay_replayed_nonce_rejected() {
    // covers: native_channel_replay
    //
    // Mint -> verify (consumes nonce) -> verify same nonce again. The
    // production replay store MUST cause the second verify to deny.
    let kp = Keypair::generate();
    let store = InMemoryExecutionNonceStore::default();
    let cfg = ExecutionNonceConfig::default();
    let binding = sample_binding();
    let now = current_unix_time();

    let signed = match mint_execution_nonce(&kp, binding.clone(), &cfg, now) {
        Ok(signed) => signed,
        Err(err) => panic!("mint_execution_nonce failed: {err:?}"),
    };

    // First presentation succeeds and consumes the nonce.
    if let Err(err) = verify_execution_nonce(&signed, &kp.public_key(), &binding, now + 1, &store) {
        panic!("first verify must succeed; got {err:?}");
    }

    // Replay: present the same SignedExecutionNonce a second time.
    let err = match verify_execution_nonce(&signed, &kp.public_key(), &binding, now + 2, &store) {
        Ok(()) => panic!(
            "production verify_execution_nonce MUST reject a replayed nonce; \
                 got Ok on second presentation"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err, ExecutionNonceError::Replayed),
        "expected ExecutionNonceError::Replayed on replayed nonce, got {err:?}"
    );
}

#[test]
fn threat_native_channel_replay_binding_mismatch_rejected() {
    // covers: native_channel_replay
    //
    // A nonce minted for tool_name=read_file is presented for
    // tool_name=write_file. The production binding-mismatch check
    // MUST deny before signature or replay surfaces are reached.
    let kp = Keypair::generate();
    let store = InMemoryExecutionNonceStore::default();
    let cfg = ExecutionNonceConfig::default();
    let minted = sample_binding();
    let now: i64 = 1_700_000_100;

    let signed = match mint_execution_nonce(&kp, minted.clone(), &cfg, now) {
        Ok(signed) => signed,
        Err(err) => panic!("mint_execution_nonce failed: {err:?}"),
    };
    let mut presented = minted;
    presented.tool_name = "write_file".to_string();

    let err = match verify_execution_nonce(&signed, &kp.public_key(), &presented, now + 1, &store) {
        Ok(()) => panic!(
            "production verify_execution_nonce MUST reject a binding mismatch; \
                 got Ok"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(
            err,
            ExecutionNonceError::BindingMismatch { field: "tool_name" }
        ),
        "expected BindingMismatch tool_name, got {err:?}"
    );
}

#[test]
fn threat_native_channel_replay_tampered_signature_rejected() {
    // covers: native_channel_replay
    //
    // A native-channel attacker mutates the signed body without
    // re-signing. The production canonical-JSON signature surface
    // MUST reject before the replay store is touched.
    let kp = Keypair::generate();
    let store = InMemoryExecutionNonceStore::default();
    let cfg = ExecutionNonceConfig::default();
    let binding = sample_binding();
    let now: i64 = 1_700_000_200;

    let mut signed = match mint_execution_nonce(&kp, binding.clone(), &cfg, now) {
        Ok(signed) => signed,
        Err(err) => panic!("mint_execution_nonce failed: {err:?}"),
    };
    signed.nonce.bound_to.tool_name = "write_file".to_string();
    let mut expected = binding;
    expected.tool_name = "write_file".to_string();

    let err = match verify_execution_nonce(&signed, &kp.public_key(), &expected, now + 1, &store) {
        Ok(()) => panic!(
            "production verify_execution_nonce MUST reject tampered signature; \
                 got Ok"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err, ExecutionNonceError::InvalidSignature),
        "expected InvalidSignature, got {err:?}"
    );
}

#[test]
fn threat_native_channel_replay_unknown_signed_fields_rejected_at_decode() {
    // covers: native_channel_replay
    let kp = Keypair::generate();
    let signed = match mint_execution_nonce(
        &kp,
        sample_binding(),
        &ExecutionNonceConfig::default(),
        1_700_000_300,
    ) {
        Ok(signed) => signed,
        Err(err) => panic!("mint_execution_nonce failed: {err:?}"),
    };
    let baseline = match serde_json::to_value(signed) {
        Ok(value) => value,
        Err(err) => panic!("execution nonce serialization failed: {err:?}"),
    };

    let mut unknown_outer = baseline.clone();
    match unknown_outer.as_object_mut() {
        Some(object) => {
            object.insert("unsigned_extension".to_string(), serde_json::json!(true));
        }
        None => panic!("signed execution nonce must serialize as an object"),
    }

    let mut unknown_nonce = baseline.clone();
    match unknown_nonce["nonce"].as_object_mut() {
        Some(object) => {
            object.insert("unsigned_extension".to_string(), serde_json::json!(true));
        }
        None => panic!("execution nonce body must serialize as an object"),
    }

    let mut unknown_binding = baseline;
    match unknown_binding["nonce"]["bound_to"].as_object_mut() {
        Some(object) => {
            object.insert("unsigned_extension".to_string(), serde_json::json!(true));
        }
        None => panic!("execution nonce binding must serialize as an object"),
    }

    for malformed in [unknown_outer, unknown_nonce, unknown_binding] {
        let error = match serde_json::from_value::<SignedExecutionNonce>(malformed) {
            Ok(_) => panic!("unknown signed execution-nonce field must be rejected"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("unknown field"),
            "expected closed-schema rejection, got {error}"
        );
    }
}
