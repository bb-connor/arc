//! Finite compatibility and owner controls for the actual audit request path.
use super::*;
use crate::private_request_wire::{
    caller_drop_observation, canonical_execute_bytes, canonical_header_bytes,
    reset_caller_drop_observer,
};
use crate::privileged_audit::{
    decode_open_wire, encode_open_wire, BrokerPrivilegedAuditOpenRequest,
};
use zeroize::Zeroizing;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn audit_open(
) -> std::result::Result<(Fixture, BrokerPrivilegedAuditOpenRequest), Box<dyn std::error::Error>> {
    let fixture = fixture(1, false, false);
    let (request, _) = execution(&fixture, 882, 1);
    let (head, body) = audit_reference_parts(&fixture, &request, true);
    let commitment = crate::audit::BrokerAuditReferencePrecommitment::generate(&head, &body)?;
    let open = BrokerPrivilegedAuditOpenRequest::new(
        "f053-contract".to_owned(),
        "legacy-provider-observation".to_owned(),
        "combined-authority".to_owned(),
        request,
        head,
        body,
        &commitment,
    )?;
    Ok((fixture, open))
}

fn native_eof(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut cause = Some(error);
    for _ in 0..16 {
        let Some(current) = cause else { return false };
        if current
            .downcast_ref::<serde_json::Error>()
            .is_some_and(serde_json::Error::is_eof)
        {
            return true;
        }
        cause = current.source();
    }
    false
}

#[test]
fn f053_contract_legacy_outer_sequence_keeps_noncanonical_category() -> TestResult {
    let (_, open) = audit_open()?;
    let sequence = Zeroizing::new(chio_core_types::canonical_json_bytes(&(
        &open.schema,
        &open.audit_id,
        &open.reference_source,
        &open.revocation_authority_domain,
        &open.request,
        &open.reference_commitment_salt,
        &open.reference_commitment_sha256,
        &open.reference_request_head,
        &open.reference_request_body,
    ))?);
    let native =
        chio_core_types::canonical::UntrustedJsonText::from_wire(&sequence, 16 * 1_048_576)?
            .decode_canonical::<BrokerPrivilegedAuditOpenRequest>();
    assert!(matches!(
        native,
        Err(chio_core_types::canonical::UntrustedJsonError::NonCanonical)
    ));
    let repaired = decode_open_wire(&sequence);
    assert!(matches!(
        repaired,
        Err(BrokerError::UntrustedInput(
            chio_core_types::canonical::UntrustedJsonError::NonCanonical
        ))
    ));
    Ok(())
}

#[test]
fn f053_contract_nested_request_bytes_keep_bounded_owned_storage() -> TestResult {
    let (_, mut open) = audit_open()?;
    open.request.request.headers = vec![crate::protocol::HeaderField::normalized(
        "content-type",
        b"application/json",
    )?];
    open.request.request.body = (0_u8..=255).cycle().take(4099).collect();
    let Some(header) = open.request.request.headers.first_mut() else {
        panic!("fixture caller header")
    };
    header.value = vec![b'k'; 4099];
    let encoded = encode_open_wire(&open)?;
    let decoded = decode_open_wire(&encoded)?;
    assert_eq!(decoded.request.request.body, open.request.request.body);
    assert_eq!(decoded.request.request.body.capacity(), 524_288);
    assert_eq!(
        decoded.request.request.headers,
        open.request.request.headers
    );
    let Some(header) = decoded.request.request.headers.first() else {
        panic!("decoded caller header")
    };
    assert_eq!(header.value.capacity(), 8192);
    Ok(())
}

#[test]
fn f053_contract_late_unknown_error_drops_nested_body_and_headers() -> TestResult {
    let (_, mut open) = audit_open()?;
    open.reference_request_head.clear();
    open.reference_request_body.clear();
    let owners = open.request.request.headers.len() + 1;
    let mut encoded = encode_open_wire(&open)?;
    assert_eq!(encoded.pop(), Some(b'}'));
    encoded.extend_from_slice(b",\"unknownAfterPrivate\":1}");
    reset_sensitive_drop_observer();
    let Err(error) = decode_open_wire(&encoded) else {
        panic!("unknown field must fail")
    };
    assert_eq!(error.diagnostic_code(), "signed_json_invalid_shape");
    assert!(std::error::Error::source(&error).is_some());
    assert!(!error.is_service_fault());
    assert!(sensitive_drop_observation().0 >= owners);
    Ok(())
}

#[test]
fn f053_contract_partial_header_keeps_native_eof_and_cleans_prefix() -> TestResult {
    let (fixture, mut open) = audit_open()?;
    open.request.request.headers = vec![crate::protocol::HeaderField::normalized(
        "content-type",
        b"application/json",
    )?];
    open.reference_request_head.clear();
    open.reference_request_body.clear();
    open.request.request.body.clear();
    let mut encoded = encode_open_wire(&open)?;
    let marker = b"\"value\":[";
    let Some(start) = encoded
        .windows(marker.len())
        .position(|part| part == marker)
    else {
        panic!("header marker")
    };
    let suffix = encoded.get(start + marker.len()..).ok_or("header suffix")?;
    let Some(comma) = suffix.iter().position(|byte| *byte == b',') else {
        panic!("header byte delimiter")
    };
    encoded.truncate(start + marker.len() + comma + 1);
    reset_sensitive_drop_observer();
    let before = fixture.live_authority_calls.load(Ordering::SeqCst);
    let Err(error) = decode_open_wire(&encoded) else {
        panic!("partial header must fail")
    };
    assert_eq!(error.diagnostic_code(), "signed_json_invalid_shape");
    assert!(native_eof(&error));
    assert!(sensitive_drop_observation().0 >= 1);
    assert_eq!(fixture.live_authority_calls.load(Ordering::SeqCst), before);
    assert_eq!(fixture.resolver_calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn f053_contract_direct_private_bytes_preserve_digest_inputs_and_domains() -> TestResult {
    let (_, mut open) = audit_open()?;
    let raw = vec![crate::protocol::HeaderField {
        name: "x-private".to_owned(),
        value: (0_u8..=255).collect(),
    }];
    let encoded = canonical_header_bytes(&raw)?;
    assert_eq!(
        encoded.as_slice(),
        chio_core_types::canonical_json_bytes(&raw)?.as_slice()
    );
    let mut digest = Sha256::new();
    digest.update(b"chio.broker-caller-headers.v1\0");
    digest.update(encoded.as_slice());
    assert_eq!(
        crate::proof::caller_header_digest(&raw)?,
        hex::encode(digest.finalize())
    );
    for preview in [None, Some("a".repeat(64))] {
        open.request.request.approved_preview_sha256 = preview;
        open.request.request.body = (0_u8..=255).cycle().take(4099).collect();
        let encoded = canonical_execute_bytes(&open.request)?;
        assert_eq!(
            encoded.as_slice(),
            chio_core_types::canonical_json_bytes(&open.request)?.as_slice()
        );
        let mut digest = Sha256::new();
        digest.update(b"chio.broker-execute-request-registration.v1\0");
        digest.update(encoded.as_slice());
        assert_eq!(
            crate::registration::broker_execute_request_registration_digest(&open.request)?,
            hex::encode(digest.finalize())
        );
    }
    Ok(())
}

#[test]
fn f053_contract_actual_prepared_and_audit_caller_owners_run_cleanup() -> TestResult {
    let (fixture, open) = audit_open()?;
    let credential = fixture
        .backend
        .materialize(&open.request.capability.body.credential)?;
    reset_caller_drop_observer();
    let prepared = fixture.provider.prepare(
        &open.request.request,
        &open.request.capability.body.constraints,
        &credential,
    )?;
    assert_eq!(prepared.caller.body, open.request.request.body);
    assert_eq!(prepared.caller.headers, open.request.request.headers);
    drop(prepared);
    let reference = crate::audit::BrokerAuditReferenceRequest::new_with_precommitment(
        open.reference_request_head.clone(),
        open.reference_request_body.clone(),
    )?
    .0;
    let salt = crate::audit::BrokerAuditComparisonSalt::generate()?;
    let comparison = fixture.https.compare_prepared_request_for_audit(
        fixture.provider.as_ref(),
        &open.request.request,
        &open.request.capability.body.constraints,
        &credential,
        &salt,
        reference,
    )?;
    assert!(comparison.projections_equal);
    drop(open);
    let [opened, provider, pinned] = caller_drop_observation();
    assert_eq!(opened, 1);
    assert_eq!(provider, 1);
    assert_eq!(pinned, 1);
    Ok(())
}

#[test]
fn f053_contract_borrowed_header_validation_preserves_error_order() -> TestResult {
    let (_, mut open) = audit_open()?;
    open.request.request.headers = vec![crate::protocol::HeaderField::normalized(
        "content-type",
        b"application/json",
    )?];
    let original = open.request.request.headers.clone();
    let Some(header) = open.request.request.headers.first_mut() else {
        panic!("fixture caller header")
    };
    header.name = "Content-Type".to_owned();
    header.value = vec![0];
    let Err(error) = open.request.request.validate_bounds() else {
        panic!("bad value")
    };
    assert!(
        matches!(&error, BrokerError::InvalidRequest(message) if message == "header value is invalid or oversized")
    );
    let Some(header) = open.request.request.headers.first_mut() else {
        panic!("fixture caller header")
    };
    header.value = b"application/json".to_vec();
    let Err(error) = open.request.request.validate_bounds() else {
        panic!("uppercase name")
    };
    assert!(
        matches!(&error, BrokerError::InvalidRequest(message) if message == "caller headers must use normalized comparison form")
    );
    open.request.request.headers = original;
    open.request.request.validate_bounds()?;
    let Some(header) = open.request.request.headers.first().cloned() else {
        panic!("fixture caller header")
    };
    open.request.request.headers.push(header);
    let Err(error) = open.request.request.validate_bounds() else {
        panic!("duplicate name")
    };
    assert!(
        matches!(&error, BrokerError::InvalidRequest(message) if message == "caller headers must be strictly sorted without duplicates")
    );
    Ok(())
}

#[test]
fn f053_contract_nested_private_exact_and_one_over_limits() -> TestResult {
    let (_, mut open) = audit_open()?;
    open.request.request.body = vec![b'b'; 524_288];
    open.request.request.headers = (0..64)
        .map(|index| crate::protocol::HeaderField {
            name: format!("x-{index:03}"),
            value: vec![b'v'; 8192],
        })
        .collect();
    let encoded = encode_open_wire(&open)?;
    let decoded = decode_open_wire(&encoded)?;
    assert_eq!(decoded.request.request.body.len(), 524_288);
    assert_eq!(decoded.request.request.headers.len(), 64);
    assert!(decoded
        .request
        .request
        .headers
        .iter()
        .all(|header| header.value.len() == 8192));
    for boundary in 0..3 {
        open.request.request.body = vec![b'b'; 524_288];
        open.request.request.headers = (0..64)
            .map(|index| crate::protocol::HeaderField {
                name: format!("x-{index:03}"),
                value: vec![b'v'; 8192],
            })
            .collect();
        match boundary {
            0 => open.request.request.body.push(b'b'),
            1 => {
                let Some(header) = open.request.request.headers.first_mut() else {
                    panic!("fixture header")
                };
                header.value.push(b'v');
            }
            _ => open
                .request
                .request
                .headers
                .push(crate::protocol::HeaderField {
                    name: "x-064".to_owned(),
                    value: vec![b'v'; 8192],
                }),
        }
        let encoded = encode_open_wire(&open)?;
        let Err(error) = decode_open_wire(&encoded) else {
            panic!("one-over private bound must fail")
        };
        assert_eq!(error.diagnostic_code(), "invalid_request");
        assert!(!error.is_service_fault());
        assert!(matches!(error, BrokerError::InvalidRequest(_)));
    }
    Ok(())
}

fn salt_wire(
    open: &BrokerPrivilegedAuditOpenRequest,
    token: &[u8],
    complete: bool,
) -> std::result::Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    let encoded = encode_open_wire(open)?;
    let marker = b"\"referenceCommitmentSalt\":";
    let start = encoded
        .windows(marker.len())
        .position(|part| part == marker)
        .ok_or("salt marker")?
        + marker.len();
    assert_eq!(encoded.get(start), Some(&b'"'));
    let end = start + open.reference_commitment_salt.len() + 2;
    let mut result = Zeroizing::new(Vec::with_capacity(encoded.len() + token.len()));
    result.extend_from_slice(encoded.get(..start).ok_or("salt prefix")?);
    result.extend_from_slice(token);
    if complete {
        result.extend_from_slice(encoded.get(end..).ok_or("salt suffix")?);
    }
    Ok(result)
}

#[test]
fn f053_contract_salt_lone_surrogates_keep_invalid_shape_without_string_rerun() -> TestResult {
    let (_, open) = audit_open()?;
    for token in [
        br#""\uD800""#.as_slice(),
        br#""\uDC00""#,
        br#""\uD800x""#,
        br#""\uD800\u0041""#,
    ] {
        let encoded = salt_wire(&open, token, true)?;
        let Err(native) =
            chio_core_types::canonical::UntrustedJsonText::from_wire(&encoded, 16 * 1_048_576)?
                .decode_canonical::<BrokerPrivilegedAuditOpenRequest>()
        else {
            panic!("native lone surrogate must fail")
        };
        assert_eq!(
            BrokerError::UntrustedInput(native).diagnostic_code(),
            "signed_json_invalid_shape"
        );
        let Err(error) = decode_open_wire(&encoded) else {
            panic!("lone surrogate must fail")
        };
        assert_eq!(error.diagnostic_code(), "signed_json_invalid_shape");
        assert!(std::error::Error::source(&error).is_some());
        assert!(!error.is_service_fault());
    }
    Ok(())
}

#[test]
fn f053_contract_salt_valid_alternate_escapes_and_partial_eof_keep_categories() -> TestResult {
    let (_, open) = audit_open()?;
    for token in [br#""\u006b""#.as_slice(), br#""\uD83D\uDE00""#, br#""\/""#] {
        let encoded = salt_wire(&open, token, true)?;
        let Err(native) =
            chio_core_types::canonical::UntrustedJsonText::from_wire(&encoded, 16 * 1_048_576)?
                .decode_canonical::<BrokerPrivilegedAuditOpenRequest>()
        else {
            panic!("native alternate salt is noncanonical")
        };
        assert_eq!(
            BrokerError::UntrustedInput(native).diagnostic_code(),
            "signed_json_noncanonical"
        );
        let Err(error) = decode_open_wire(&encoded) else {
            panic!("alternate salt is noncanonical")
        };
        assert_eq!(error.diagnostic_code(), "signed_json_noncanonical");
    }
    let encoded = salt_wire(&open, br#""private-prefix\uD80"#, false)?;
    let Err(native) =
        chio_core_types::canonical::UntrustedJsonText::from_wire(&encoded, 16 * 1_048_576)?
            .decode_canonical::<BrokerPrivilegedAuditOpenRequest>()
    else {
        panic!("native partial salt must fail")
    };
    assert!(native_eof(&native));
    let Err(error) = decode_open_wire(&encoded) else {
        panic!("partial salt must fail")
    };
    assert_eq!(error.diagnostic_code(), "signed_json_invalid_shape");
    assert!(native_eof(&error));
    Ok(())
}

#[test]
fn f053_contract_canonical_salt_unicode_and_control_bytes_match_native() -> TestResult {
    let (_, mut open) = audit_open()?;
    open.reference_commitment_salt = "salt\"\\\n\u{001f}é😀".to_owned();
    let encoded = encode_open_wire(&open)?;
    assert_eq!(
        encoded.as_slice(),
        chio_core_types::canonical_json_bytes(&open)?.as_slice()
    );
    let native =
        chio_core_types::canonical::UntrustedJsonText::from_wire(&encoded, 16 * 1_048_576)?
            .decode_canonical::<BrokerPrivilegedAuditOpenRequest>()?;
    let decoded = decode_open_wire(&encoded)?;
    assert_eq!(
        decoded.reference_commitment_salt,
        native.reference_commitment_salt
    );
    assert_eq!(
        decoded.reference_request_head,
        native.reference_request_head
    );
    Ok(())
}
