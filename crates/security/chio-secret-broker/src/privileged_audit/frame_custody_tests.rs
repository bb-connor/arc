//! Synthetic frame custody checks; no freed-memory or total-erasure claim.
use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LegacyFrameFixture {
    reference_commitment_salt: String,
    reference_request_head: Vec<u8>,
    reference_request_body: Vec<u8>,
}

impl Drop for LegacyFrameFixture {
    fn drop(&mut self) {
        self.reference_commitment_salt.zeroize();
        self.reference_request_head.zeroize();
        self.reference_request_body.zeroize();
    }
}

#[test]
fn f053_audit_partial_body_is_wiped_before_body_error_returns() -> TestResult {
    let mut bytes = Zeroizing::new(vec![0xaa; 32]);
    let mut partial = b"fixture-audit-secret".as_slice();
    let error = read_audit_frame_body(&mut partial, &mut bytes)
        .err()
        .ok_or("partial body was accepted")?;
    assert!(matches!(error, BrokerError::InvalidRequest(message)
        if message.starts_with("privileged audit frame body failed:")));
    assert!(
        bytes.is_empty(),
        "the original body reader returned its error with a retained partial body"
    );
    Ok(())
}

#[test]
fn f053_audit_secret_encoding_is_canonical_and_uses_counted_output() -> TestResult {
    let mut head = b"POST /private HTTP/1.1\r\nAuthorization: Bearer ".to_vec();
    head.extend_from_slice(&vec![b'x'; 16_385]);
    head.extend_from_slice(b"\r\n\r\n");
    let fixture = LegacyFrameFixture {
        reference_commitment_salt: "a".repeat(64),
        reference_request_head: head,
        reference_request_body: vec![b'y'; 4_099],
    };
    // Use the native public encoder as the compatibility oracle, not a second
    // implementation of JCS. All bytes here are disposable synthetic fixtures.
    let expected = Zeroizing::new(canonical_json_bytes(&fixture)?);
    assert!(expected.len() > 32_768);
    assert!(
        !expected.len().is_power_of_two(),
        "fixture must expose growth slack"
    );
    let encoded = encode_audit_frame(&fixture)?;
    assert!(
        encoded.as_slice() == expected.as_slice(),
        "the private transport encoding changed canonical bytes"
    );
    assert_eq!(
        encoded.capacity(),
        encoded.len(),
        "the original transport encoder grew its buffer before zeroizing custody"
    );
    Ok(())
}

#[test]
fn f053_audit_frame_preserves_prefix_length_and_complete_body() -> TestResult {
    let bytes = b"fixture-only";
    let mut frame = Vec::new();
    write_frame(&mut frame, bytes, 32)?;
    let mut expected = u32::try_from(bytes.len())?.to_be_bytes().to_vec();
    expected.extend_from_slice(bytes);
    assert_eq!(frame, expected);
    let mut input = frame.as_slice();
    let decoded = read_frame(&mut input, 32)?;
    assert_eq!(decoded.as_slice(), bytes);
    assert!(input.is_empty());
    Ok(())
}

#[test]
fn f053_audit_frame_preserves_native_bounds_and_truncation_errors() -> TestResult {
    for length in [0, u32::try_from(MAX_AUDIT_CONTROL_FRAME_BYTES + 1)?] {
        let prefix = length.to_be_bytes();
        let mut input = prefix.as_slice();
        assert!(
            matches!(read_frame(&mut input, MAX_AUDIT_CONTROL_FRAME_BYTES),
            Err(BrokerError::InvalidRequest(message))
                if message == "privileged audit frame is empty or oversized")
        );
    }
    let short_prefix = [0_u8, 0];
    let mut prefix = short_prefix.as_slice();
    assert!(matches!(read_frame(&mut prefix, 32),
        Err(BrokerError::InvalidRequest(message))
            if message.starts_with("privileged audit frame prefix failed:")));
    let mut frame = 3_u32.to_be_bytes().to_vec();
    frame.extend_from_slice(b"ab");
    let mut partial = frame.as_slice();
    assert!(matches!(read_frame(&mut partial, 32),
        Err(BrokerError::InvalidRequest(message))
            if message.starts_with("privileged audit frame body failed:")));
    Ok(())
}
