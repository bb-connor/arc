// Threat test for threat ID `resource_exhaustion_dos`.
//
// Threat: resource_exhaustion_dos (Resource exhaustion denial of service).
// Surfaces: native_chio, hosted_mcp, trust_control, kernel_to_tool.
//
// Coverage strategy: drive the production native-kernel transport's
// length-prefixed frame reader. The reader must reject a declared body
// above its 16 MiB ceiling before allocating or waiting for that body.
// A bounded-frame round trip is the positive control, preventing an
// implementation that rejects all traffic from satisfying this test.
//
// Production call site:
//   `crates/kernel/chio-kernel/src/transport.rs:79` (`read_frame`).
//
// Revert-to-prove-it-fails recipe:
// In `crates/kernel/chio-kernel/src/transport.rs`, invert the
// `len > MAX_MESSAGE_SIZE` predicate in `read_frame`. Re-run
// `cargo test -p chio-conformance --test threats -- resource_exhaustion_dos`.
// The oversized-frame assertion MUST fail because the transport no longer
// returns `TransportError::MessageTooLarge` before reading the body.

use std::io::Cursor;

use chio_kernel::transport::{read_frame, write_frame, TransportError};

const KERNEL_MAX_MESSAGE_SIZE: u32 = 16 * 1024 * 1024;

#[test]
fn threat_resource_exhaustion_dos_oversized_native_frame_is_rejected_before_body_read() {
    // covers: resource_exhaustion_dos
    //
    // Attacker scenario: a native peer declares a body larger than the
    // transport ceiling but withholds the body. Production must reject from
    // the prefix alone, without allocating the declared length or blocking
    // for attacker-controlled bytes.
    let declared = KERNEL_MAX_MESSAGE_SIZE + 1;
    let mut frame = Cursor::new(declared.to_be_bytes());

    match read_frame(&mut frame) {
        Err(TransportError::MessageTooLarge { size, max }) => {
            assert_eq!(size, declared);
            assert_eq!(max, KERNEL_MAX_MESSAGE_SIZE);
        }
        Err(other) => panic!("expected MessageTooLarge before body read, got {other:?}"),
        Ok(body) => panic!(
            "oversized native frame MUST be rejected before body read; got {} bytes",
            body.len()
        ),
    }
}

#[test]
fn threat_resource_exhaustion_dos_bounded_native_frame_round_trips() {
    // covers: resource_exhaustion_dos (sanity)
    //
    // Positive control: ordinary bounded traffic must remain usable so an
    // over-rejecting transport cannot masquerade as a DoS defense.
    let body = br#"{"jsonrpc":"2.0"}"#;
    let mut encoded = Vec::new();
    if let Err(error) = write_frame(&mut encoded, body) {
        panic!("bounded native frame MUST encode: {error}");
    }
    let decoded = match read_frame(&mut Cursor::new(encoded)) {
        Ok(decoded) => decoded,
        Err(error) => panic!("bounded native frame MUST decode: {error}"),
    };
    assert_eq!(decoded, body);
}
