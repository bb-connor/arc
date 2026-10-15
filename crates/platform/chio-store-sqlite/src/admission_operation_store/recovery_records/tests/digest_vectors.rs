//! Known answers computed independently from the canonical JSON arrays.

use super::super::digest::{event_digest, record_digest, EventDigestInput, RecordDigestInput};
use super::super::{NativeIdentity, RecordKind};
use super::fixture::{TestResult, SCOPE};

const NON_ASCII_KEY: &str = "workflow:é漢🙂\"q\\";

/// `["chio.recovery.protected-record.v1","deployment:a",SCOPE,"deployment",1,
/// sha256_hex(b"{\"v\":1}"),null,null]`
#[test]
fn record_digest_matches_its_canonical_array() -> TestResult {
    let digest = record_digest(&RecordDigestInput {
        key: "deployment:a",
        scope: SCOPE,
        kind: RecordKind::Deployment,
        version: 1,
        payload: br#"{"v":1}"#,
        native: None,
    })?;
    assert_eq!(
        digest,
        "16803a52b65706127064478895f9bdfdd2883edccd1e53d284284d069e3acc64"
    );
    Ok(())
}

/// A non-ASCII, quote and backslash bearing key with a native identity:
/// `[..,"workflow",7,sha256_hex(b"{}"),"cd" * 32,"request-ü"]`.
#[test]
fn record_digest_binds_non_ascii_identity_and_native_request() -> TestResult {
    let native = NativeIdentity {
        namespace: "cd".repeat(32),
        request: "request-ü".to_owned(),
    };
    let digest = record_digest(&RecordDigestInput {
        key: NON_ASCII_KEY,
        scope: SCOPE,
        kind: RecordKind::Workflow,
        version: 7,
        payload: b"{}",
        native: Some(&native),
    })?;
    assert_eq!(
        digest,
        "0d9c24d438cdd9cff6de9a4f257f79cd0439b4ec3ac4f7a63cf952dc6d2f6dc8"
    );
    Ok(())
}

/// `["chio.recovery.store-event.v1",3,NON_ASCII_KEY,7,record,"1" * 64,1792000000000]`.
#[test]
fn event_digest_matches_its_canonical_array() -> TestResult {
    let previous = "1".repeat(64);
    let digest = event_digest(&EventDigestInput {
        sequence: 3,
        key: NON_ASCII_KEY,
        version: 7,
        record_digest: "0d9c24d438cdd9cff6de9a4f257f79cd0439b4ec3ac4f7a63cf952dc6d2f6dc8",
        previous_digest: &previous,
        observed_at: 1_792_000_000_000,
    })?;
    assert_eq!(
        digest,
        "9ec8cb28135a9cb20bc116fff71019c04688662223ef30e6363307cfe651124c"
    );
    Ok(())
}
