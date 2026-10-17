use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use chio_core::{
    canonical_json_bytes, sha256_hex, Ed25519Backend, Keypair, PublicKey, Signature, SigningBackend,
};
use chio_secure_ipc::PeerIdentity as BrokerPeerIdentity;
#[cfg(target_os = "linux")]
use chio_security_types::ports::ErrorCode;
use chio_security_types::ports::{Digest32, PortErrorKind, RequestId};
use chio_test_support::prelude::*;

use super::client::ProductionActiveResponseAuthorityClient;
use super::transport::now_unix_seconds;
use super::*;

fn deployment_digest() -> Digest32 {
    Digest32::new([0x41; 32])
}

fn store_digest() -> Digest32 {
    Digest32::new([0x52; 32])
}

fn test_client(
    config: ProductionActiveResponseAuthorityFileConfig,
) -> ProductionActiveResponseAuthorityClient {
    let signer: Arc<dyn SigningBackend> =
        Arc::new(Ed25519Backend::new(Keypair::from_seed(&[42_u8; 32])));
    #[cfg(target_os = "linux")]
    let client = ProductionActiveResponseAuthorityClient::new_for_test_with_same_process_policy(
        config, signer, true,
    );
    #[cfg(not(target_os = "linux"))]
    let client = ProductionActiveResponseAuthorityClient::new(config, signer);
    client.test_expect("valid active-response authority client")
}

const INVALID_CONFIG_MESSAGE: &str =
    "active-response authority path, peer identity, deadline, or freshness bound is invalid";

fn different_process_id() -> u32 {
    let current = std::process::id();
    if current == u32::MAX {
        current.saturating_sub(1)
    } else {
        current + 1
    }
}

fn signed_response(
    request_id: &str,
    request_digest: &str,
    issued_at_unix_seconds: u64,
    declared_authority: PublicKey,
    signer: &Keypair,
    result: ActiveResponseAuthorityResult,
) -> SignedActiveResponseAuthorityResponse {
    let body = ActiveResponseAuthorityResponseBody {
        schema: ACTIVE_RESPONSE_AUTHORITY_SCHEMA.to_string(),
        deployment_digest: deployment_digest(),
        store_digest: store_digest(),
        request_id: RequestId::new(request_id).test_expect("bounded authority request id"),
        request_digest: request_digest.to_string(),
        issued_at_unix_seconds,
        authority: declared_authority,
        result,
    };
    let canonical = active_response_authority_response_signing_bytes(&body)
        .test_expect("canonical active-response authority response signing input");
    let signature = signer.sign(&canonical);
    SignedActiveResponseAuthorityResponse {
        body,
        algorithm: signature.algorithm(),
        signature,
    }
}

fn signed_health_response(
    request_id: &str,
    request_digest: &str,
    issued_at_unix_seconds: u64,
    declared_authority: PublicKey,
    signer: &Keypair,
) -> SignedActiveResponseAuthorityResponse {
    signed_response(
        request_id,
        request_digest,
        issued_at_unix_seconds,
        declared_authority,
        signer,
        ActiveResponseAuthorityResult::Ready {
            protocol: ACTIVE_RESPONSE_AUTHORITY_SCHEMA.to_string(),
            deployment_digest: deployment_digest(),
            store_digest: store_digest(),
        },
    )
}

#[test]
fn production_authority_configuration_rejects_unpinned_or_unbounded_inputs() {
    let key = Keypair::from_seed(&[41_u8; 32]).public_key();
    let valid = ProductionActiveResponseAuthorityFileConfig {
        socket_path: PathBuf::from("/run/chio/active-response-authority.sock"),
        expected_peer: BrokerPeerIdentity {
            process_id: 7,
            user_id: 8,
            group_id: 9,
        },
        trusted_authority: key,
        deployment_digest: deployment_digest(),
        store_digest: store_digest(),
        timeout_ms: 1_000,
        maximum_clock_skew_seconds: 5,
    };
    assert!(valid.validate().is_ok());

    let mut invalid = valid.clone();
    invalid.socket_path = PathBuf::from("relative.sock");
    assert_eq!(invalid.validate(), Err(INVALID_CONFIG_MESSAGE.to_string()));
    let mut invalid = valid.clone();
    invalid.socket_path = PathBuf::from("/run/chio/../authority.sock");
    assert_eq!(invalid.validate(), Err(INVALID_CONFIG_MESSAGE.to_string()));
    let mut invalid = valid.clone();
    invalid.expected_peer.process_id = 0;
    assert_eq!(invalid.validate(), Err(INVALID_CONFIG_MESSAGE.to_string()));
    let mut invalid = valid.clone();
    invalid.timeout_ms = 30_001;
    assert_eq!(invalid.validate(), Err(INVALID_CONFIG_MESSAGE.to_string()));
    let mut invalid = valid.clone();
    invalid.store_digest = Digest32::new([0; 32]);
    assert_eq!(invalid.validate(), Err(INVALID_CONFIG_MESSAGE.to_string()));
    let mut invalid = valid;
    invalid.maximum_clock_skew_seconds = 31;
    assert_eq!(invalid.validate(), Err(INVALID_CONFIG_MESSAGE.to_string()));
}

#[test]
fn response_verification_rejects_wrong_signer_replay_and_staleness() {
    let authority = Keypair::from_seed(&[43_u8; 32]);
    let wrong_authority = Keypair::from_seed(&[44_u8; 32]);
    let now = now_unix_seconds().test_expect("current Unix time");
    let client = test_client(ProductionActiveResponseAuthorityFileConfig {
        socket_path: PathBuf::from("/run/chio/active-response-authority.sock"),
        expected_peer: BrokerPeerIdentity {
            process_id: 7,
            user_id: 8,
            group_id: 9,
        },
        trusted_authority: authority.public_key(),
        deployment_digest: deployment_digest(),
        store_digest: store_digest(),
        timeout_ms: 1_000,
        maximum_clock_skew_seconds: 5,
    });

    let wrong_signature = signed_health_response(
        "request-1",
        &"a".repeat(64),
        now,
        authority.public_key(),
        &wrong_authority,
    );
    assert_eq!(
        client.verify_response(&wrong_signature, "request-1", &"a".repeat(64), now),
        Err(PortError::integrity_failure())
    );
    let replayed = signed_health_response(
        "request-1",
        &"b".repeat(64),
        now,
        authority.public_key(),
        &authority,
    );
    assert_eq!(
        client.verify_response(&replayed, "request-1", &"a".repeat(64), now),
        Err(PortError::integrity_failure())
    );
    let stale = signed_health_response(
        "request-1",
        &"a".repeat(64),
        now.saturating_sub(6),
        authority.public_key(),
        &authority,
    );
    assert_eq!(
        client.verify_response(&stale, "request-1", &"a".repeat(64), now),
        Err(PortError::integrity_failure())
    );
    let mut wrong_store = signed_health_response(
        "request-1",
        &"a".repeat(64),
        now,
        authority.public_key(),
        &authority,
    );
    wrong_store.body.store_digest = Digest32::new([99; 32]);
    let signing_bytes = active_response_authority_response_signing_bytes(&wrong_store.body)
        .test_expect("mismatched store response signing bytes");
    wrong_store.signature = authority.sign(&signing_bytes);
    assert_eq!(
        client.verify_response(&wrong_store, "request-1", &"a".repeat(64), now),
        Err(PortError::integrity_failure())
    );
}

struct SwitchingBackend {
    initial: Keypair,
    replacement: Keypair,
    rotated: AtomicBool,
}

impl SigningBackend for SwitchingBackend {
    fn public_key(&self) -> chio_core::error::Result<PublicKey> {
        Ok(if self.rotated.load(Ordering::SeqCst) {
            self.replacement.public_key()
        } else {
            self.initial.public_key()
        })
    }

    fn sign_bytes(&self, message: &[u8]) -> chio_core_types::Result<Signature> {
        Ok(if self.rotated.load(Ordering::SeqCst) {
            self.replacement.sign(message)
        } else {
            self.initial.sign(message)
        })
    }
}

#[test]
fn client_signer_identity_is_immutable_after_construction() {
    let authority = Keypair::from_seed(&[43_u8; 32]);
    let backend = Arc::new(SwitchingBackend {
        initial: Keypair::from_seed(&[42_u8; 32]),
        replacement: Keypair::from_seed(&[99_u8; 32]),
        rotated: AtomicBool::new(false),
    });
    let signer: Arc<dyn SigningBackend> = backend.clone();
    let client = ProductionActiveResponseAuthorityClient::new(
        ProductionActiveResponseAuthorityFileConfig {
            socket_path: PathBuf::from("/run/chio/active-response-authority.sock"),
            expected_peer: BrokerPeerIdentity {
                process_id: different_process_id(),
                user_id: 8,
                group_id: 9,
            },
            trusted_authority: authority.public_key(),
            deployment_digest: deployment_digest(),
            store_digest: store_digest(),
            timeout_ms: 1_000,
            maximum_clock_skew_seconds: 5,
        },
        signer,
    )
    .test_expect("client with initial signing identity");
    backend.rotated.store(true, Ordering::SeqCst);

    let error = client
        .sign_request(ActiveResponseAuthorityOperation::Health, 1_700_000_000)
        .test_expect_err("rotated client signer must fail closed");
    assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
}

#[test]
fn client_constructor_rejects_a_signer_that_is_also_the_response_authority() {
    let signer = Keypair::from_seed(&[42_u8; 32]);
    let signer_backend: Arc<dyn SigningBackend> = Arc::new(Ed25519Backend::new(signer.clone()));
    let Err(error) = ProductionActiveResponseAuthorityClient::new(
        ProductionActiveResponseAuthorityFileConfig {
            socket_path: PathBuf::from("/run/chio/active-response-authority.sock"),
            expected_peer: BrokerPeerIdentity {
                process_id: different_process_id(),
                user_id: 8,
                group_id: 9,
            },
            trusted_authority: signer.public_key(),
            deployment_digest: deployment_digest(),
            store_digest: store_digest(),
            timeout_ms: 1_000,
            maximum_clock_skew_seconds: 5,
        },
        signer_backend,
    ) else {
        panic!("client and authority signing roles must be distinct");
    };
    assert!(error.contains("distinct keys"));
}

#[test]
fn authority_payloads_reject_unknown_fields_and_unbounded_rejection_codes() {
    let unknown_ready_field = serde_json::json!({
        "result": "ready",
        "output": {
            "protocol": ACTIVE_RESPONSE_AUTHORITY_SCHEMA,
            "deploymentDigest": deployment_digest(),
            "storeDigest": store_digest(),
            "unexpected": true
        }
    });
    let Err(error) = serde_json::from_value::<ActiveResponseAuthorityResult>(unknown_ready_field)
    else {
        panic!("a ready result with an unknown field must be refused");
    };
    assert!(
        error.to_string().contains("unknown field `unexpected`"),
        "{error}"
    );

    let unbounded_rejection = serde_json::json!({
        "result": "rejected",
        "output": { "classification": "permanent", "code": "x".repeat(257) }
    });
    let Err(error) = serde_json::from_value::<ActiveResponseAuthorityResult>(unbounded_rejection)
    else {
        panic!("a rejection code beyond the bound must be refused");
    };
    assert!(
        error
            .to_string()
            .contains("identifier exceeds the byte limit"),
        "{error}"
    );

    let digestless_request = serde_json::json!({
        "schema": ACTIVE_RESPONSE_AUTHORITY_SCHEMA,
        "requestId": "digestless",
        "issuedAtUnixSeconds": 1_700_000_000_u64,
        "client": Keypair::from_seed(&[42; 32]).public_key(),
        "operation": { "operation": "health" }
    });
    let Err(error) =
        serde_json::from_value::<ActiveResponseAuthorityRequestBody>(digestless_request)
    else {
        panic!("a request body without deployment and store digests must be refused");
    };
    assert!(error
        .to_string()
        .contains("missing field `deploymentDigest`"));
}

#[test]
fn authority_results_are_bound_to_the_requested_operation() {
    let ready = ActiveResponseAuthorityResult::Ready {
        protocol: ACTIVE_RESPONSE_AUTHORITY_SCHEMA.to_string(),
        deployment_digest: deployment_digest(),
        store_digest: store_digest(),
    };
    assert_eq!(
        super::protocol::validate_operation_result(
            &ActiveResponseAuthorityOperation::Health,
            &ActiveResponseAuthorityResult::Ready {
                protocol: "wrong-protocol".to_string(),
                deployment_digest: deployment_digest(),
                store_digest: store_digest(),
            },
        ),
        Err(PortError::integrity_failure())
    );
    assert!(super::protocol::validate_operation_result(
        &ActiveResponseAuthorityOperation::Health,
        &ready,
    )
    .is_ok());
}

#[test]
fn request_and_response_wire_golden_vectors_are_exact() {
    let client = Keypair::from_seed(&[42_u8; 32]);
    let request_body = ActiveResponseAuthorityRequestBody {
        schema: ACTIVE_RESPONSE_AUTHORITY_SCHEMA.to_string(),
        deployment_digest: deployment_digest(),
        store_digest: store_digest(),
        request_id: RequestId::new("golden-request-v1").test_expect("golden request id"),
        issued_at_unix_seconds: 1_700_000_000,
        client: client.public_key(),
        operation: ActiveResponseAuthorityOperation::Health,
    };
    let request_input = active_response_authority_request_signing_bytes(&request_body)
        .test_expect("golden request signing input");
    assert_eq!(
        request_input,
        br#"{"body":{"client":"197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61","deploymentDigest":[65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65],"issuedAtUnixSeconds":1700000000,"operation":{"operation":"health"},"requestId":"golden-request-v1","schema":"chio.active-response-policy-authority.v1","storeDigest":[82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82]},"domain":"chio.active-response-policy-authority.request.v1\u0000"}"#
    );
    assert_eq!(
        sha256_hex(&request_input),
        "16bd6d08e999ae270a20e294db8b48a00f2ec9e94bb965eb1659d6e80134e6be"
    );
    let request_signature = client.sign(&request_input);
    assert_eq!(
        request_signature.to_hex(),
        "ba04ee2d0b42ba52e7bdd967668bf167058cbca1c588269d4d19bf0567be851c707c7aff212ace615b696f5e3ea5c36299362b9a53cc3fb0aac3d51a4daf2009"
    );
    let request = SignedActiveResponseAuthorityRequest {
        body: request_body,
        algorithm: request_signature.algorithm(),
        signature: request_signature,
    };
    let request_wire = canonical_json_bytes(&request).test_expect("golden request wire");
    assert_eq!(
        request_wire,
        br#"{"algorithm":"ed25519","body":{"client":"197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61","deploymentDigest":[65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65],"issuedAtUnixSeconds":1700000000,"operation":{"operation":"health"},"requestId":"golden-request-v1","schema":"chio.active-response-policy-authority.v1","storeDigest":[82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82]},"signature":"ba04ee2d0b42ba52e7bdd967668bf167058cbca1c588269d4d19bf0567be851c707c7aff212ace615b696f5e3ea5c36299362b9a53cc3fb0aac3d51a4daf2009"}"#
    );
    assert_eq!(
        sha256_hex(&request_wire),
        "1f01d82e7f8a828ae4e600af91cd6f5c622a2788b3110fc9c900464b7d3d29a3"
    );

    let authority = Keypair::from_seed(&[45_u8; 32]);
    let response_body = ActiveResponseAuthorityResponseBody {
        schema: ACTIVE_RESPONSE_AUTHORITY_SCHEMA.to_string(),
        deployment_digest: deployment_digest(),
        store_digest: store_digest(),
        request_id: RequestId::new("golden-request-v1").test_expect("golden response request id"),
        request_digest: sha256_hex(&request_wire),
        issued_at_unix_seconds: 1_700_000_001,
        authority: authority.public_key(),
        result: ActiveResponseAuthorityResult::Ready {
            protocol: ACTIVE_RESPONSE_AUTHORITY_SCHEMA.to_string(),
            deployment_digest: deployment_digest(),
            store_digest: store_digest(),
        },
    };
    let response_input = active_response_authority_response_signing_bytes(&response_body)
        .test_expect("golden response signing input");
    assert_eq!(
        response_input,
        br#"{"body":{"authority":"a87b8a99bd88a69686c994a80b629d8154871aa295540834c01d79f4f916502f","deploymentDigest":[65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65],"issuedAtUnixSeconds":1700000001,"requestDigest":"1f01d82e7f8a828ae4e600af91cd6f5c622a2788b3110fc9c900464b7d3d29a3","requestId":"golden-request-v1","result":{"output":{"deploymentDigest":[65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65],"protocol":"chio.active-response-policy-authority.v1","storeDigest":[82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82]},"result":"ready"},"schema":"chio.active-response-policy-authority.v1","storeDigest":[82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82]},"domain":"chio.active-response-policy-authority.response.v1\u0000"}"#
    );
    assert_eq!(
        sha256_hex(&response_input),
        "c73f7b01b48e8765b0e47203c471f822190cae86770c5cd491e2c10e3b65dbea"
    );
    let response_signature = authority.sign(&response_input);
    assert_eq!(
        response_signature.to_hex(),
        "bd8313dbed5f053678871fc41c8d455f88a830501be2e817b77d218e0784a9548f5a55748fd6e1dbf44bdfd031bc4f20e1ad187708e3e00bbd059758a8dd0301"
    );
    let response = SignedActiveResponseAuthorityResponse {
        body: response_body,
        algorithm: response_signature.algorithm(),
        signature: response_signature,
    };
    let response_wire = canonical_json_bytes(&response).test_expect("golden response wire bytes");
    assert_eq!(
        response_wire,
        br#"{"algorithm":"ed25519","body":{"authority":"a87b8a99bd88a69686c994a80b629d8154871aa295540834c01d79f4f916502f","deploymentDigest":[65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65],"issuedAtUnixSeconds":1700000001,"requestDigest":"1f01d82e7f8a828ae4e600af91cd6f5c622a2788b3110fc9c900464b7d3d29a3","requestId":"golden-request-v1","result":{"output":{"deploymentDigest":[65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65,65],"protocol":"chio.active-response-policy-authority.v1","storeDigest":[82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82]},"result":"ready"},"schema":"chio.active-response-policy-authority.v1","storeDigest":[82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82,82]},"signature":"bd8313dbed5f053678871fc41c8d455f88a830501be2e817b77d218e0784a9548f5a55748fd6e1dbf44bdfd031bc4f20e1ad187708e3e00bbd059758a8dd0301"}"#
    );
    assert_eq!(
        sha256_hex(&response_wire),
        "47b355e030609545faa0ee13a5460761ecd4138c3f9ba7f923a7bf4934d195f1"
    );
}

#[test]
fn submission_proof_digest_text_must_be_nonzero_canonical_lowercase_hex() {
    let valid = "0123456789abcdef".repeat(4);
    let mut expected = [0_u8; 32];
    for chunk in expected.chunks_exact_mut(8) {
        chunk.copy_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    }
    assert_eq!(
        nonzero_lower_hex_digest(&valid),
        Ok(Digest32::new(expected))
    );
    assert_eq!(
        nonzero_lower_hex_digest(&"ff".repeat(32)),
        Ok(Digest32::new([0xff; 32]))
    );
    for text in [
        "0".repeat(64),
        String::new(),
        valid[..62].to_string(),
        valid[..63].to_string(),
        format!("{valid}0"),
        format!("{valid}00"),
        valid.to_ascii_uppercase(),
        format!("A{}", &valid[1..]),
        format!("0x{}", &valid[2..]),
        format!("0x{valid}"),
        format!(" {}", &valid[1..]),
        format!("{valid}\n"),
        format!("g{}", &valid[1..]),
        format!("\u{e9}{}", &valid[2..]),
    ] {
        assert_eq!(
            nonzero_lower_hex_digest(&text),
            Err(PortError::integrity_failure()),
            "accepted {text:?}"
        );
    }
}

#[cfg(target_os = "linux")]
mod linux_uds {
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::thread;
    use std::time::{Duration, Instant};

    use chio_secure_ipc::{read_bounded_frame, write_bounded_frame};

    use crate::security::event_consumer::AttestedFindingResponsePolicyPlanner;

    use super::super::transport::connect_unix_stream_before;
    use super::*;

    fn peer_identity() -> BrokerPeerIdentity {
        BrokerPeerIdentity {
            process_id: std::process::id(),
            user_id: rustix::process::geteuid().as_raw(),
            group_id: rustix::process::getegid().as_raw(),
        }
    }

    fn bind_private_listener(directory: &tempfile::TempDir) -> (PathBuf, UnixListener) {
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .test_expect("set active-response authority directory permissions");
        let socket_path = directory.path().join("active-response-authority.sock");
        let listener = UnixListener::bind(&socket_path)
            .test_expect("bind active-response authority test socket");
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
            .test_expect("set active-response authority socket permissions");
        (socket_path, listener)
    }

    struct HealthOnlyHandler {
        rejection: Option<ActiveResponseAuthorityRejection>,
    }

    impl ActiveResponseAuthorityHandler for HealthOnlyHandler {
        fn health(&self) -> ActiveResponseAuthorityHandlerResult<()> {
            self.rejection
                .clone()
                .map_or(Ok(()), |rejection| Err(rejection.into()))
        }

        fn select_policy(
            &self,
            _evidence_id: &OpaqueReceiptRef,
            _finding: &chio_core::receipt::security::CorrelatedFindingReceiptBody,
            _binding: &AttestedFindingBatchBinding,
        ) -> ActiveResponseAuthorityHandlerResult<ActiveResponsePolicySelectionWire> {
            Err(ActiveResponseAuthorityRejection::permanent(
                ErrorCode::new("active_response.unsupported")
                    .test_expect("bounded unsupported code"),
            )
            .into())
        }

        fn load_artifacts(
            &self,
            _response_plan: &ResponsePlan,
            _admission_artifact_ref: &AdmissionArtifactRef,
        ) -> ActiveResponseAuthorityHandlerResult<ActiveResponseAdmissionArtifactsDraftWire>
        {
            Err(ActiveResponseAuthorityRejection::permanent(
                ErrorCode::new("active_response.unsupported")
                    .test_expect("bounded unsupported code"),
            )
            .into())
        }
    }

    struct FatalHealthHandler;

    impl ActiveResponseAuthorityHandler for FatalHealthHandler {
        fn health(&self) -> ActiveResponseAuthorityHandlerResult<()> {
            Err(ActiveResponseAuthorityHandlerError::Fatal(
                PortError::integrity_failure(),
            ))
        }

        fn select_policy(
            &self,
            _evidence_id: &OpaqueReceiptRef,
            _finding: &chio_core::receipt::security::CorrelatedFindingReceiptBody,
            _binding: &AttestedFindingBatchBinding,
        ) -> ActiveResponseAuthorityHandlerResult<ActiveResponsePolicySelectionWire> {
            Err(ActiveResponseAuthorityHandlerError::Fatal(
                PortError::integrity_failure(),
            ))
        }

        fn load_artifacts(
            &self,
            _response_plan: &ResponsePlan,
            _admission_artifact_ref: &AdmissionArtifactRef,
        ) -> ActiveResponseAuthorityHandlerResult<ActiveResponseAdmissionArtifactsDraftWire>
        {
            Err(ActiveResponseAuthorityHandlerError::Fatal(
                PortError::integrity_failure(),
            ))
        }
    }

    fn protocol_server(
        signer: Keypair,
        rejection: Option<ActiveResponseAuthorityRejection>,
    ) -> ActiveResponseAuthorityProtocolServer {
        let authority_signer: Arc<dyn SigningBackend> = Arc::new(Ed25519Backend::new(signer));
        ActiveResponseAuthorityProtocolServer::new_for_test_with_same_process_policy(
            ActiveResponseAuthorityProtocolServerConfig {
                expected_client_peer: peer_identity(),
                trusted_client: Keypair::from_seed(&[42_u8; 32]).public_key(),
                deployment_digest: deployment_digest(),
                store_digest: store_digest(),
                timeout_ms: 1_000,
                maximum_clock_skew_seconds: 5,
                maximum_replay_entries: 128,
            },
            authority_signer,
            Arc::new(HealthOnlyHandler { rejection }),
            true,
        )
        .test_expect("active-response protocol server")
    }

    fn serve_protocol_once(
        listener: UnixListener,
        signer: Keypair,
        rejection: Option<ActiveResponseAuthorityRejection>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let (stream, _) = listener
                .accept()
                .test_expect("accept active-response authority client");
            protocol_server(signer, rejection)
                .serve_one(stream)
                .test_expect("serve active-response protocol request");
        })
    }

    fn client_config(
        socket_path: PathBuf,
        authority: PublicKey,
    ) -> ProductionActiveResponseAuthorityFileConfig {
        ProductionActiveResponseAuthorityFileConfig {
            socket_path,
            expected_peer: peer_identity(),
            trusted_authority: authority,
            deployment_digest: deployment_digest(),
            store_digest: store_digest(),
            timeout_ms: 1_000,
            maximum_clock_skew_seconds: 5,
        }
    }

    #[test]
    fn public_constructors_reject_same_process_peers_and_shared_role_keys() {
        let authority = Keypair::from_seed(&[45_u8; 32]);
        let client_key = Keypair::from_seed(&[42_u8; 32]);
        let authority_signer: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(authority.clone()));
        let client_signer: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(client_key.clone()));
        let same_process_client_config = ProductionActiveResponseAuthorityFileConfig {
            socket_path: PathBuf::from("/run/chio/active-response-authority.sock"),
            expected_peer: peer_identity(),
            trusted_authority: authority.public_key(),
            deployment_digest: deployment_digest(),
            store_digest: store_digest(),
            timeout_ms: 1_000,
            maximum_clock_skew_seconds: 5,
        };
        let Err(client_error) =
            ProductionActiveResponseAuthorityClient::new(same_process_client_config, client_signer)
        else {
            panic!("same-process response authority must be rejected");
        };
        assert!(client_error.contains("separate processes"));

        let same_process_server_config = ActiveResponseAuthorityProtocolServerConfig {
            expected_client_peer: peer_identity(),
            trusted_client: client_key.public_key(),
            deployment_digest: deployment_digest(),
            store_digest: store_digest(),
            timeout_ms: 1_000,
            maximum_clock_skew_seconds: 5,
            maximum_replay_entries: 128,
        };
        let Err(server_error) = ActiveResponseAuthorityProtocolServer::new(
            same_process_server_config,
            authority_signer,
            Arc::new(HealthOnlyHandler { rejection: None }),
        ) else {
            panic!("same-process broker client must be rejected");
        };
        assert!(server_error.contains("separate processes"));

        let shared_key = Keypair::from_seed(&[46_u8; 32]);
        let shared_signer: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(shared_key.clone()));
        let Err(role_error) = ActiveResponseAuthorityProtocolServer::new(
            ActiveResponseAuthorityProtocolServerConfig {
                expected_client_peer: BrokerPeerIdentity {
                    process_id: different_process_id(),
                    user_id: peer_identity().user_id,
                    group_id: peer_identity().group_id,
                },
                trusted_client: shared_key.public_key(),
                deployment_digest: deployment_digest(),
                store_digest: store_digest(),
                timeout_ms: 1_000,
                maximum_clock_skew_seconds: 5,
                maximum_replay_entries: 128,
            },
            shared_signer,
            Arc::new(HealthOnlyHandler { rejection: None }),
        ) else {
            panic!("server and client signing roles must be distinct");
        };
        assert!(role_error.contains("distinct keys"));
    }

    #[test]
    fn runtime_boundaries_reject_same_process_topologies_without_test_override() {
        let directory =
            chio_test_support::private_tempdir().test_expect("same-process socket directory");
        let authority = Keypair::from_seed(&[45_u8; 32]);
        let (socket_path, _listener) = bind_private_listener(&directory);
        let client_signer: Arc<dyn SigningBackend> =
            Arc::new(Ed25519Backend::new(Keypair::from_seed(&[42_u8; 32])));
        let client =
            ProductionActiveResponseAuthorityClient::new_for_test_with_same_process_policy(
                client_config(socket_path, authority.public_key()),
                client_signer,
                false,
            )
            .test_expect("test client bypasses construction check only");
        let client_error = client
            .ensure_ready()
            .test_expect_err("connect must reject same-process authority");
        assert_eq!(client_error.kind(), PortErrorKind::IntegrityFailure);

        let authority_signer: Arc<dyn SigningBackend> = Arc::new(Ed25519Backend::new(authority));
        let server = ActiveResponseAuthorityProtocolServer::new_for_test_with_same_process_policy(
            ActiveResponseAuthorityProtocolServerConfig {
                expected_client_peer: peer_identity(),
                trusted_client: Keypair::from_seed(&[42_u8; 32]).public_key(),
                deployment_digest: deployment_digest(),
                store_digest: store_digest(),
                timeout_ms: 1_000,
                maximum_clock_skew_seconds: 5,
                maximum_replay_entries: 128,
            },
            authority_signer,
            Arc::new(HealthOnlyHandler { rejection: None }),
            false,
        )
        .test_expect("test server bypasses construction check only");
        let (_client_stream, server_stream) =
            UnixStream::pair().test_expect("same-process protocol stream pair");
        let server_error = server
            .serve_one(server_stream)
            .test_expect_err("serve must reject same-process broker client");
        assert_eq!(server_error.kind(), PortErrorKind::IntegrityFailure);
    }

    #[test]
    fn signed_uds_health_round_trip_authenticates_both_peers_without_owning_socket() {
        let directory =
            chio_test_support::private_tempdir().test_expect("authority socket directory");
        let authority = Keypair::from_seed(&[45_u8; 32]);
        let (socket_path, listener) = bind_private_listener(&directory);
        let server = serve_protocol_once(listener, authority.clone(), None);
        let client = test_client(client_config(socket_path.clone(), authority.public_key()));

        client
            .ensure_ready()
            .test_expect("signed authority health response");
        server.join().test_expect("authority server thread");
        assert!(socket_path.exists());
    }

    #[test]
    fn signed_uds_policy_rejection_is_a_permanent_conflict() {
        let directory =
            chio_test_support::private_tempdir().test_expect("authority socket directory");
        let authority = Keypair::from_seed(&[49_u8; 32]);
        let rejection_code =
            ErrorCode::new("active_response.policy_rejected").test_expect("bounded rejection code");
        let (socket_path, listener) = bind_private_listener(&directory);
        let server = serve_protocol_once(
            listener,
            authority.clone(),
            Some(ActiveResponseAuthorityRejection::permanent(
                rejection_code.clone(),
            )),
        );
        let client = test_client(client_config(socket_path, authority.public_key()));

        let error = client
            .call(ActiveResponseAuthorityOperation::Health)
            .test_expect_err("signed authority rejection must terminate the request");
        assert_eq!(error.kind(), ACTIVE_RESPONSE_AUTHORITY_REJECTION_KIND);
        assert_eq!(error.code(), &rejection_code);
        server.join().test_expect("authority server thread");
    }

    #[test]
    fn signed_uds_transient_rejection_is_retryable_unavailable() {
        let directory =
            chio_test_support::private_tempdir().test_expect("authority socket directory");
        let authority = Keypair::from_seed(&[53_u8; 32]);
        let rejection_code = ErrorCode::new("active_response.authority_busy")
            .test_expect("bounded transient rejection code");
        let (socket_path, listener) = bind_private_listener(&directory);
        let server = serve_protocol_once(
            listener,
            authority.clone(),
            Some(ActiveResponseAuthorityRejection::transient(
                rejection_code.clone(),
            )),
        );
        let client = test_client(client_config(socket_path, authority.public_key()));

        let error = client
            .call(ActiveResponseAuthorityOperation::Health)
            .test_expect_err("transient authority rejection must remain retryable");
        assert_eq!(
            error.kind(),
            ACTIVE_RESPONSE_AUTHORITY_TRANSIENT_REJECTION_KIND
        );
        assert_eq!(error.code(), &rejection_code);
        server.join().test_expect("authority server thread");
    }

    #[test]
    fn protocol_server_rejects_request_replay_across_connections() {
        let authority = Keypair::from_seed(&[52_u8; 32]);
        let server = protocol_server(authority.clone(), None);
        let client = test_client(client_config(
            PathBuf::from("/run/chio/unused.sock"),
            authority.public_key(),
        ));
        let request = client
            .sign_request(
                ActiveResponseAuthorityOperation::Health,
                now_unix_seconds().test_expect("current Unix time"),
            )
            .test_expect("signed replay test request");
        let bytes = canonical_json_bytes(&request).test_expect("canonical replay test request");

        let (mut client_stream, server_stream) =
            UnixStream::pair().test_expect("first protocol stream pair");
        write_bounded_frame(
            &mut client_stream,
            &bytes,
            super::MAX_ACTIVE_RESPONSE_AUTHORITY_WIRE_BYTES,
        )
        .test_expect("write first request");
        server
            .serve_one(server_stream)
            .test_expect("serve first request");
        read_bounded_frame(
            &mut client_stream,
            super::MAX_ACTIVE_RESPONSE_AUTHORITY_WIRE_BYTES,
        )
        .test_expect("read first response");

        let (mut replay_stream, server_stream) =
            UnixStream::pair().test_expect("replay protocol stream pair");
        write_bounded_frame(
            &mut replay_stream,
            &bytes,
            super::MAX_ACTIVE_RESPONSE_AUTHORITY_WIRE_BYTES,
        )
        .test_expect("write replay request");
        let outcome = server
            .serve_one(server_stream)
            .test_expect("request replay is a classified client fault");
        assert_eq!(
            outcome,
            ActiveResponseAuthorityServeOutcome::ClientFault {
                kind: PortErrorKind::Conflict,
                code: PortError::conflict().code().clone(),
            }
        );
    }

    #[test]
    fn protocol_server_rechecks_freshness_before_reserving_verified_request() {
        struct JumpAtReservation(std::sync::atomic::AtomicUsize);
        impl chio_security_types::clock::Clock for JumpAtReservation {
            fn read(
                &self,
            ) -> Result<
                chio_security_types::clock::ClockReading,
                chio_security_types::clock::ClockError,
            > {
                let call = self.0.fetch_add(1, Ordering::SeqCst);
                chio_security_types::clock::Clock::read(
                    &chio_security_types::clock::FixedClock::new(if call >= 5 {
                        1006
                    } else {
                        1000
                    }),
                )
            }
        }
        let authority = Keypair::from_seed(&[52_u8; 32]);
        let server = protocol_server(authority.clone(), None).with_clock(Arc::new(
            JumpAtReservation(std::sync::atomic::AtomicUsize::new(0)),
        ));
        let client = test_client(client_config(
            PathBuf::from("/run/chio/unused.sock"),
            authority.public_key(),
        ));
        let request = client
            .sign_request(ActiveResponseAuthorityOperation::Health, 1000)
            .test_expect("signed request before the forward step");
        let bytes = canonical_json_bytes(&request).test_expect("canonical request");
        let (mut peer, stream) = UnixStream::pair().test_expect("protocol stream");
        write_bounded_frame(
            &mut peer,
            &bytes,
            super::MAX_ACTIVE_RESPONSE_AUTHORITY_WIRE_BYTES,
        )
        .test_expect("complete inbound frame");
        assert_eq!(
            server
                .serve_one(stream)
                .test_expect("classified stale request"),
            ActiveResponseAuthorityServeOutcome::ClientFault {
                kind: PortErrorKind::IntegrityFailure,
                code: ErrorCode::new("urn:chio:error:transport:response-authority-freshness")
                    .test_expect("registered reason"),
            }
        );
    }

    #[test]
    fn protocol_server_surfaces_internal_handler_failure_to_supervision() {
        let authority = Keypair::from_seed(&[54_u8; 32]);
        let signer: Arc<dyn SigningBackend> = Arc::new(Ed25519Backend::new(authority.clone()));
        let server = ActiveResponseAuthorityProtocolServer::new_for_test_with_same_process_policy(
            ActiveResponseAuthorityProtocolServerConfig {
                expected_client_peer: peer_identity(),
                trusted_client: Keypair::from_seed(&[42_u8; 32]).public_key(),
                deployment_digest: deployment_digest(),
                store_digest: store_digest(),
                timeout_ms: 1_000,
                maximum_clock_skew_seconds: 5,
                maximum_replay_entries: 128,
            },
            signer,
            Arc::new(FatalHealthHandler),
            true,
        )
        .test_expect("fatal-handler protocol server");
        let client = test_client(client_config(
            PathBuf::from("/run/chio/unused.sock"),
            authority.public_key(),
        ));
        let request = client
            .sign_request(
                ActiveResponseAuthorityOperation::Health,
                now_unix_seconds().test_expect("current Unix time"),
            )
            .test_expect("signed health request");
        let request = canonical_json_bytes(&request).test_expect("canonical health request");
        let (mut client_stream, server_stream) =
            UnixStream::pair().test_expect("fatal-handler protocol stream pair");
        write_bounded_frame(
            &mut client_stream,
            &request,
            super::MAX_ACTIVE_RESPONSE_AUTHORITY_WIRE_BYTES,
        )
        .test_expect("write fatal-handler request");

        let error = server
            .serve_one(server_stream)
            .test_expect_err("internal handler failure must reach supervision");
        assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
    }

    #[test]
    fn signed_uds_trickle_cannot_extend_the_absolute_read_deadline() {
        let directory =
            chio_test_support::private_tempdir().test_expect("authority socket directory");
        let authority = Keypair::from_seed(&[50_u8; 32]);
        let (socket_path, listener) = bind_private_listener(&directory);
        let server_authority = authority.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener
                .accept()
                .test_expect("accept trickle test connection");
            let request_bytes =
                read_bounded_frame(&mut stream, super::MAX_ACTIVE_RESPONSE_AUTHORITY_WIRE_BYTES)
                    .test_expect("read authority request");
            let request: SignedActiveResponseAuthorityRequest =
                serde_json::from_slice(&request_bytes).test_expect("decode authority request");
            let response = signed_health_response(
                request.body.request_id.as_str(),
                &sha256_hex(&request_bytes),
                now_unix_seconds().test_expect("current Unix time"),
                server_authority.public_key(),
                &server_authority,
            );
            let response_bytes =
                canonical_json_bytes(&response).test_expect("canonical trickle response");
            let response_length =
                u32::try_from(response_bytes.len()).test_expect("bounded response length");
            let mut framed = response_length.to_be_bytes().to_vec();
            framed.extend_from_slice(&response_bytes);
            for chunk in framed.chunks(16) {
                if stream.write_all(chunk).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(15));
            }
        });
        let mut config = client_config(socket_path, authority.public_key());
        config.timeout_ms = 60;
        let client = test_client(config);
        let started = Instant::now();

        assert_eq!(client.ensure_ready(), Err(PortError::unavailable()));
        assert!(started.elapsed() < Duration::from_millis(500));
        server.join().test_expect("authority server thread");
    }

    #[test]
    fn saturated_unix_backlog_cannot_extend_the_connect_deadline() {
        use rustix::net::{
            bind, listen, socket_with, AddressFamily, SocketAddrUnix, SocketFlags, SocketType,
        };

        let directory =
            chio_test_support::private_tempdir().test_expect("backlog socket directory");
        let socket_path = directory.path().join("backlog.sock");
        let socket = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .test_expect("create backlog listener");
        let address = SocketAddrUnix::new(&socket_path).test_expect("backlog socket address");
        bind(&socket, &address).test_expect("bind backlog listener");
        listen(&socket, 1).test_expect("listen with bounded backlog");
        let _listener = UnixListener::from(socket);
        let mut queued = Vec::new();
        for _ in 0..32 {
            match connect_unix_stream_before(
                &socket_path,
                chio_security_types::clock::Clock::monotonic(
                    &chio_security_types::clock::SystemClock,
                )
                .unwrap_or_else(|e| panic!("clock: {e}"))
                .checked_add(Duration::from_millis(20))
                .unwrap_or_else(|e| panic!("deadline: {e}")),
                &chio_security_types::clock::SystemClock,
            ) {
                Ok(stream) => queued.push(stream),
                Err(_) => break,
            }
        }
        assert!(!queued.is_empty());
        assert!(queued.len() < 32);
        let started = Instant::now();
        assert_eq!(
            connect_unix_stream_before(
                &socket_path,
                chio_security_types::clock::Clock::monotonic(
                    &chio_security_types::clock::SystemClock
                )
                .unwrap_or_else(|e| panic!("clock: {e}"))
                .checked_add(Duration::from_millis(60))
                .unwrap_or_else(|e| panic!("deadline: {e}")),
                &chio_security_types::clock::SystemClock,
            )
            .err()
            .map(|error| error.kind()),
            Some(chio_security_types::ports::PortErrorKind::Unavailable)
        );
        assert!(started.elapsed() < Duration::from_millis(500));
    }
}
