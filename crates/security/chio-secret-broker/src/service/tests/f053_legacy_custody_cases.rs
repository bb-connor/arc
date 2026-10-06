//! Real audit decoding and transport controls with synthetic private bytes.
use super::*;
use crate::privileged_audit::{
    decode_open_wire, encode_open_wire, private_byte_serialization_observation,
    reset_private_byte_serialization_observer, BrokerPrivilegedAuditOpenRequest,
};
use chio_core_types::canonical::UntrustedJsonError;
use zeroize::Zeroizing;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
const HEAD_BYTES: usize = 1_048_576;
const BODY_BYTES: usize = 524_288;

fn open_fixture(
    long_reference: bool,
) -> std::result::Result<(Fixture, BrokerPrivilegedAuditOpenRequest), Box<dyn std::error::Error>> {
    let fixture = fixture(1, false, false);
    let (request, _) = execution(&fixture, 881, 1);
    let (mut head, body) = audit_reference_parts(&fixture, &request, true);
    if long_reference {
        head = b"POST /v1 HTTP/1.1\r\nAuthorization: Bearer ".to_vec();
        head.extend_from_slice(&vec![b'k'; 4_099]);
        head.extend_from_slice(b"\r\n\r\n");
    }
    let commitment = crate::audit::BrokerAuditReferencePrecommitment::generate(&head, &body)?;
    let open = BrokerPrivilegedAuditOpenRequest::new(
        "f053-legacy-owned".to_owned(),
        "legacy-provider-observation".to_owned(),
        "combined-authority".to_owned(),
        request,
        head,
        body,
        &commitment,
    )?;
    Ok((fixture, open))
}

fn wire(
    open: &BrokerPrivilegedAuditOpenRequest,
) -> std::result::Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    Ok(Zeroizing::new(chio_core_types::canonical_json_bytes(open)?))
}

#[test]
fn f053_legacy_open_long_credential_uses_bounded_custody_before_copy() -> TestResult {
    let (_, open) = open_fixture(true)?;
    let bytes = wire(&open)?;
    let decoded = decode_open_wire(&bytes)?;
    assert_eq!(decoded.reference_request_head, open.reference_request_head);
    assert_eq!(
        decoded.reference_request_head.capacity(),
        HEAD_BYTES,
        "original audit head used growing serde storage instead of its bounded owner"
    );
    assert_eq!(decoded.reference_request_body.capacity(), BODY_BYTES);
    Ok(())
}

#[test]
fn f053_legacy_open_accepts_exact_head_and_body_byte_bounds() -> TestResult {
    let (_, mut open) = open_fixture(false)?;
    open.reference_request_head = vec![b'h'; HEAD_BYTES - 4];
    open.reference_request_head.extend_from_slice(b"\r\n\r\n");
    open.reference_request_body = vec![b'b'; BODY_BYTES];
    let commitment = crate::audit::BrokerAuditReferencePrecommitment::generate(
        &open.reference_request_head,
        &open.reference_request_body,
    )?;
    open.reference_commitment_salt = commitment.commitment_salt().to_owned();
    open.reference_commitment_sha256 = commitment.commitment_sha256().to_owned();
    let bytes = wire(&open)?;
    let decoded = decode_open_wire(&bytes)?;
    assert_eq!(decoded.reference_request_head, open.reference_request_head);
    assert_eq!(decoded.reference_request_body, open.reference_request_body);
    decoded.validate()?;
    Ok(())
}

#[test]
fn f053_legacy_open_refuses_one_byte_over_head_or_body_before_secret_copy() -> TestResult {
    let mut accepted_fields = Vec::new();
    for head_over in [true, false] {
        let (_, mut open) = open_fixture(false)?;
        if head_over {
            open.reference_request_head = vec![b'h'; HEAD_BYTES - 3];
            open.reference_request_head.extend_from_slice(b"\r\n\r\n");
        } else {
            open.reference_request_body = vec![b'b'; BODY_BYTES + 1];
        }
        let bytes = wire(&open)?;
        if !matches!(decode_open_wire(&bytes), Err(BrokerError::InvalidRequest(message))
            if message == "privileged audit reference request is malformed or oversized")
        {
            accepted_fields.push(if head_over { "head" } else { "body" });
        }
    }
    assert!(
        accepted_fields.is_empty(),
        "original privileged decoder accepted over-bound reference fields: {accepted_fields:?}"
    );
    Ok(())
}

#[test]
fn f053_legacy_open_late_decode_error_drops_both_private_arrays() -> TestResult {
    let (_, mut open) = open_fixture(true)?;
    open.request.request.body.clear();
    open.request.request.headers.clear();
    let mut bytes = wire(&open)?;
    bytes.pop();
    bytes.extend_from_slice(b",\"unknownAfterPrivateFields\":true}");
    reset_sensitive_drop_observer();
    let error = decode_open_wire(&bytes)
        .err()
        .ok_or("unknown audit field was accepted")?;
    assert_eq!(error.diagnostic_code(), "signed_json_invalid_shape");
    assert!(std::error::Error::source(&error).is_some());
    assert!(
        sensitive_drop_observation().0 >= 2,
        "original late typed failure dropped private Vec fields outside bounded custody"
    );
    Ok(())
}

#[test]
fn f053_legacy_open_partial_array_error_cleans_live_private_prefix() -> TestResult {
    let (_, mut open) = open_fixture(true)?;
    open.reference_request_body.clear();
    let mut bytes = wire(&open)?;
    let marker = b"\"referenceRequestHead\":[";
    let position = bytes
        .windows(marker.len())
        .position(|candidate| candidate == marker)
        .ok_or("reference head field missing from fixture")?;
    bytes.truncate(position + marker.len() + 20);
    reset_sensitive_drop_observer();
    let error = decode_open_wire(&bytes)
        .err()
        .ok_or("partial audit array was accepted")?;
    assert_eq!(error.diagnostic_code(), "signed_json_invalid_shape");
    assert!(std::error::Error::source(&error).is_some());
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    let mut native_eof = false;
    for _ in 0..16 {
        let Some(current) = source else {
            break;
        };
        if let Some(native) = current.downcast_ref::<serde_json::Error>() {
            native_eof = native.is_eof();
            break;
        }
        source = current.source();
    }
    assert!(
        native_eof,
        "partial head parse must retain its actual native serde EOF cause"
    );
    assert!(
        sensitive_drop_observation().0 >= 1,
        "original array parse failure released a private prefix without a bounded owner"
    );
    Ok(())
}

#[test]
fn f053_legacy_open_exact_canonical_fields_preserve_native_bytes_and_order() -> TestResult {
    let (_, open) = open_fixture(false)?;
    let expected = wire(&open)?;
    let encoded = encode_open_wire(&open)?;
    assert!(
        encoded.as_slice() == expected.as_slice(),
        "original wire view changed canonical fields"
    );
    let decoded = decode_open_wire(&encoded)?;
    assert_eq!(decoded.request, open.request);
    assert_eq!(decoded.schema, open.schema);
    assert_eq!(decoded.audit_id, open.audit_id);
    assert_eq!(
        decoded.reference_commitment_salt,
        open.reference_commitment_salt
    );
    assert_eq!(
        decoded.reference_commitment_sha256,
        open.reference_commitment_sha256
    );
    assert_eq!(decoded.reference_request_head, open.reference_request_head);
    assert_eq!(decoded.reference_request_body, open.reference_request_body);
    assert_eq!(decoded.reference_source, open.reference_source);
    assert_eq!(
        decoded.revocation_authority_domain,
        open.revocation_authority_domain
    );
    Ok(())
}

#[test]
fn f053_legacy_open_rejects_duplicate_unknown_and_alternate_json() -> TestResult {
    let (_, open) = open_fixture(false)?;
    let canonical = wire(&open)?;
    for tail in [
        b",\"auditId\":\"duplicate\"}".as_slice(),
        b",\"unknown\":true}".as_slice(),
    ] {
        let mut bytes = Zeroizing::new(canonical.to_vec());
        bytes.pop();
        bytes.extend_from_slice(tail);
        let error = decode_open_wire(&bytes)
            .err()
            .ok_or("duplicate/unknown audit fields accepted")?;
        assert_eq!(error.diagnostic_code(), "signed_json_invalid_shape");
        assert!(std::error::Error::source(&error).is_some());
    }
    let mut spaced = Zeroizing::new(vec![b' ']);
    spaced.extend_from_slice(&canonical);
    assert!(matches!(
        decode_open_wire(&spaced),
        Err(BrokerError::UntrustedInput(
            UntrustedJsonError::NonCanonical
        ))
    ));
    let mut escaped = Zeroizing::new(canonical.to_vec());
    let marker = b"\"referenceCommitmentSalt\":\"";
    let position = escaped
        .windows(marker.len())
        .position(|candidate| candidate == marker)
        .ok_or("salt field missing")?
        + marker.len();
    let first = *escaped.get(position).ok_or("salt fixture empty")?;
    escaped.splice(
        position..position + 1,
        format!("\\u{:04x}", first).into_bytes(),
    );
    assert!(matches!(
        decode_open_wire(&escaped),
        Err(BrokerError::UntrustedInput(
            UntrustedJsonError::NonCanonical
        ))
    ));
    Ok(())
}

#[test]
fn f053_legacy_open_sensitive_export_uses_direct_borrowed_arrays() -> TestResult {
    let (_, open) = open_fixture(true)?;
    reset_private_byte_serialization_observer();
    let encoded = encode_open_wire(&open)?;
    let outbound = private_byte_serialization_observation();
    reset_private_byte_serialization_observer();
    let decoded = decode_open_wire(&encoded)?;
    assert_eq!(decoded.reference_request_head, open.reference_request_head);
    let inbound = private_byte_serialization_observation();
    assert_eq!((outbound, inbound), (0, 0),
        "original Open encode and inbound equality forwarded secret bytes into generic serde numeric arrays");
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn f053_legacy_open_preserves_auth_phase_order_and_healthy_comparison() -> TestResult {
    use crate::privileged_audit::{
        read_privileged_audit_challenge_frame, read_privileged_audit_evidence_frame,
        write_privileged_audit_commit_frame, write_privileged_audit_open_frame,
        BrokerPrivilegedAuditCommitRequest, BrokerPrivilegedAuditEndpoint,
        BrokerPrivilegedAuditEndpointConfig, BrokerPrivilegedAuditServeOutcome,
        BROKER_PRIVILEGED_AUDIT_COMMIT_SCHEMA,
    };
    use chio_core_types::{Ed25519Backend, SigningBackend};
    use std::os::unix::net::UnixStream;
    let (fixture, open) = open_fixture(false)?;
    let before_calls = fixture.live_authority_calls.load(Ordering::SeqCst);
    assert!(decode_open_wire(b"{\"referenceRequestHead\":[80").is_err());
    assert_eq!(
        fixture.live_authority_calls.load(Ordering::SeqCst),
        before_calls
    );
    assert_eq!(fixture.resolver_calls.load(Ordering::SeqCst), 0);
    let commitment = crate::audit::BrokerAuditReferencePrecommitment::generate(
        &open.reference_request_head,
        &open.reference_request_body,
    )?;
    let mut open = open;
    open.reference_commitment_salt = commitment.commitment_salt().to_owned();
    open.reference_commitment_sha256 = commitment.commitment_sha256().to_owned();
    let directory = crate::private_tempdir()?;
    let path = directory.path().join("f053-custody").join("audit.sock");
    let signer: Arc<dyn SigningBackend> =
        Arc::new(Ed25519Backend::new(Keypair::from_seed(&[3; 32])));
    let trusted = signer.public_key();
    let endpoint = BrokerPrivilegedAuditEndpoint::bind(
        BrokerPrivilegedAuditEndpointConfig {
            socket_path: path.clone(),
            trusted_service_uid: rustix::process::geteuid().as_raw(),
            authorized_runner_uid: rustix::process::geteuid().as_raw(),
            authorized_runner_gid: rustix::process::getegid().as_raw(),
            read_timeout_ms: 2_000,
            write_timeout_ms: 2_000,
            authorization_lifetime_seconds: 60,
            deployment_id: "test-deployment".to_owned(),
            broker_instance_id: "test-broker-instance".to_owned(),
            tenant_scope: "tenant-a".to_owned(),
            runner_id: "test-enterprise-runner".to_owned(),
        },
        signer,
        Arc::new(SocketAuditHandler {
            service: Arc::clone(&fixture.service),
            admin: Arc::clone(&fixture.audit_admin),
            trusted_runner: fixture.audit_runner_key.clone(),
        }),
    )?;
    let server = thread::spawn(move || endpoint.try_serve_one());
    let mut stream = UnixStream::connect(&path)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(3)))?;
    write_privileged_audit_open_frame(&mut stream, &open)?;
    let challenge = read_privileged_audit_challenge_frame(&mut stream, &trusted, &commitment)?;
    let authorization = crate::audit::SignedBrokerAuditRunnerAuthorization::sign(
        challenge.body.runner_authorization_body.clone(),
        fixture.audit_runner.as_ref(),
    )?;
    let intent =
        crate::audit::broker_audit_governed_intent_for_runner_authorization(&authorization)?;
    let admin = governed_audit_authorization(&fixture, &intent);
    let commit = BrokerPrivilegedAuditCommitRequest {
        schema: BROKER_PRIVILEGED_AUDIT_COMMIT_SCHEMA.to_owned(),
        session_nonce: challenge.body.session_nonce.clone(),
        session_commitment_sha256: challenge.body.session_commitment_sha256.clone(),
        runner_authorization: authorization,
        governed_admin_authorization: admin.as_bytes().to_vec(),
    };
    write_privileged_audit_commit_frame(&mut stream, &commit, &challenge)?;
    let evidence = read_privileged_audit_evidence_frame(&mut stream, &trusted)?;
    assert_eq!(evidence.challenge.body, challenge.body);
    let outcome = server
        .join()
        .map_err(|_| "audit fixture thread panicked")??
        .ok_or("audit fixture did not serve a connection")?;
    assert_eq!(outcome, BrokerPrivilegedAuditServeOutcome::EvidenceWritten);
    assert!(fixture
        .observed_authorizations
        .lock()
        .map_err(|_| "fixture lock")?
        .is_empty());
    Ok(())
}
