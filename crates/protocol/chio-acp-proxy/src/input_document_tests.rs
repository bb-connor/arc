use super::*;
use chio_core::{
    capability::{scope::ChioScope, token::CapabilityToken, token::CapabilityTokenBody},
    crypto::Keypair,
};
use std::io::{BufReader, Cursor};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn unsigned_envelope_accepts_producer_decimal_spellings() -> TestResult {
    for (number, expected) in [
        ("0.50", 0.5),
        ("1e-05", 0.00001),
        ("1e+16", 1e16),
        ("18446744073709551616", 18446744073709551616.0),
    ] {
        let bytes = format!(
            r#"{{"jsonrpc":"2.0","method":"session/update","params":{{"sessionId":"s1","update":{{"rawInput":{{"score":{number}}}}}}}}}"#
        );
        let message = AcpMessage::decode(bytes.as_bytes())?;
        assert_eq!(
            message.as_value()["params"]["update"]["rawInput"]["score"].as_f64(),
            Some(expected)
        );
    }
    Ok(())
}

#[test]
fn producer_decimal_frame_keeps_later_frames_readable() -> TestResult {
    let bytes = b"{\"jsonrpc\":\"2.0\",\"method\":\"session/update\",\"params\":{\"usage\":1e-05}}\n{\"jsonrpc\":\"2.0\",\"id\":18446744073709551615,\"result\":{}}\n";
    let mut reader = AcpFrameReader::new(BufReader::with_capacity(7, Cursor::new(bytes)));
    let first = reader.recv()?.ok_or("missing first frame")?;
    assert_eq!(first.as_value()["params"]["usage"].as_f64(), Some(0.00001));
    let next = reader.recv()?.ok_or("missing second frame")?;
    assert_eq!(next.as_value()["id"].as_u64(), Some(u64::MAX));
    assert!(reader.recv()?.is_none());
    Ok(())
}

fn signed_token() -> Result<CapabilityToken, chio_core::error::Error> {
    let issuer = Keypair::from_seed(&[73; 32]);
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: "original-byte-capability".into(),
            issuer: issuer.public_key(),
            subject: Keypair::from_seed(&[74; 32]).public_key(),
            scope: ChioScope::default(),
            issued_at: 9_007_199_254_740_993,
            expires_at: u64::MAX,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )
}

fn authority_message(field: &str, raw: &str, nested: bool) -> String {
    let params = if nested {
        format!(r#"{{"chio":{{"{field}":{raw}}}}}"#)
    } else {
        format!(r#"{{"{field}":{raw}}}"#)
    };
    format!(r#"{{"jsonrpc":"2.0","method":"initialize","params":{params}}}"#)
}

fn signed_nonce() -> Result<chio_kernel::SignedExecutionNonce, chio_core::error::Error> {
    let key = Keypair::from_seed(&[75; 32]);
    let nonce = chio_kernel::ExecutionNonce {
        schema: chio_kernel::EXECUTION_NONCE_SCHEMA.into(),
        nonce_id: "original-byte-nonce".into(),
        issued_at: 9_007_199_254_740_993,
        expires_at: i64::MAX,
        bound_to: chio_kernel::NonceBinding {
            subject_id: "subject".into(),
            request_id: "request".into(),
            capability_id: "capability".into(),
            tool_server: "server".into(),
            tool_name: "tool".into(),
            parameter_hash: "a".repeat(64),
        },
        reserved_hold_id: None,
        reserving_request_id: None,
    };
    let (signature, _) = key.sign_canonical(&nonce)?;
    Ok(chio_kernel::SignedExecutionNonce { nonce, signature })
}

#[test]
fn original_capability_objects_keep_full_width_signed_integers() -> TestResult {
    let token = signed_token()?;
    let raw = serde_json::to_string(&token)?;
    for nested in [false, true] {
        for field in ["capabilityToken", "capability_token"] {
            let bytes = authority_message(field, &raw, nested);
            let message = AcpMessage::decode(bytes.as_bytes())?;
            let text = crate::extract_capability_token(&message.as_value()["params"])
                .ok_or("missing object-form token")?;
            let decoded: CapabilityToken =
                UntrustedJsonText::from_wire(text.as_bytes(), MAX_CAPABILITY_BYTES)?
                    .decode_signed()?;
            assert_eq!(decoded.issued_at, 9_007_199_254_740_993);
            assert_eq!(decoded.expires_at, u64::MAX);
            assert!(decoded.verify_signature()?);
        }
    }
    Ok(())
}

#[test]
fn original_authority_objects_reject_lossy_number_spellings() -> TestResult {
    let token = serde_json::to_string(&signed_token()?)?;
    let nonce = serde_json::to_string(&signed_nonce()?)?;
    for nested in [false, true] {
        for field in [
            "capabilityToken",
            "capability_token",
            "executionNonce",
            "execution_nonce",
        ] {
            let original = if field.starts_with("execution") {
                &nonce
            } else {
                &token
            };
            // The signed reader preserves its native 1e+16 spelling. The
            // redundant exponent zero below is discarded by document projection.
            for number in ["0.50", "1e-05", "1e+016", "18446744073709551616"] {
                let raw = format!(r#"{{"private_marker":{number},{}"#, &original[1..]);
                let bytes = authority_message(field, &raw, nested);
                let error = match AcpMessage::decode(bytes.as_bytes()) {
                    Err(error) => error,
                    Ok(_) => panic!("original {field} spelling admitted: {number}"),
                };
                assert!(matches!(error, AcpProxyError::UntrustedInput(_)));
                assert!(std::error::Error::source(&error).is_some());
                assert!(!format!("{error:?} {error}").contains("private_marker"));
            }
        }
    }
    Ok(())
}

#[test]
fn original_nonce_objects_keep_full_width_signed_integers() -> TestResult {
    let nonce = signed_nonce()?;
    let raw = serde_json::to_string(&nonce)?;
    let key = Keypair::from_seed(&[75; 32]);
    for nested in [false, true] {
        for field in ["executionNonce", "execution_nonce"] {
            let bytes = authority_message(field, &raw, nested);
            let message = AcpMessage::decode(bytes.as_bytes())?;
            let decoded = crate::extract_execution_nonce(&message.as_value()["params"])?
                .ok_or("missing object-form nonce")?;
            assert_eq!(decoded.nonce.issued_at, 9_007_199_254_740_993);
            assert_eq!(decoded.nonce.expires_at, i64::MAX);
            assert!(key
                .public_key()
                .verify_canonical(&decoded.nonce, &decoded.signature)?);
        }
    }
    Ok(())
}

#[test]
fn encoded_capability_text_still_uses_its_strict_signed_reader() -> TestResult {
    let token = serde_json::to_string(&signed_token()?)?;
    let raw = format!(r#"{{"private_marker":0.50,{}"#, &token[1..]);
    let encoded = serde_json::to_string(&raw)?;
    let bytes = authority_message("capabilityToken", &encoded, true);
    let message = AcpMessage::decode(bytes.as_bytes())?;
    let text = crate::extract_capability_token(&message.as_value()["params"])
        .ok_or("missing token text")?;
    assert_eq!(text, raw);
    assert!(matches!(
        UntrustedJsonText::from_wire(text.as_bytes(), MAX_CAPABILITY_BYTES)?
            .decode_signed::<CapabilityToken>(),
        Err(UntrustedJsonError::SignedInput(_))
    ));
    Ok(())
}

#[test]
fn document_envelope_rejects_duplicate_keys_inside_ignored_extensions() {
    let bytes = br#"{"jsonrpc":"2.0","method":"initialize","ignored":{"secret_marker":0.50,"secret_marker":1e-05}}"#;
    let error = match AcpMessage::decode(bytes) {
        Err(error) => error,
        Ok(_) => panic!("ignored extension duplicate admitted"),
    };
    assert!(matches!(error, AcpProxyError::UntrustedInput(_)));
    assert!(std::error::Error::source(&error).is_some());
    assert!(!format!("{error:?} {error}").contains("secret_marker"));
}
