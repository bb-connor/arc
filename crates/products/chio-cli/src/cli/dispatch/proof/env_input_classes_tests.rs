use super::*;
use chio_errors::_generated::error_codes::CLI_IO;

fn has_source<T: std::error::Error + 'static>(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut source = error.source();
    while let Some(cause) = source {
        if cause.downcast_ref::<T>().is_some() {
            return true;
        }
        source = cause.source();
    }
    false
}

#[test]
fn malformed_rpc_json_is_an_io_failure() {
    for bytes in [
        b"<html>private-marker</html>".as_slice(),
        b"{",
        br#"{"result":1,"result":2}"#,
    ] {
        let error = settlement_rpc_result(bytes).unwrap_err();
        assert!(has_source::<chio_core_types::canonical::UntrustedJsonError>(&error));
        assert!(!error.to_string().contains("private-marker"));
        assert_rejection(error, &CLI_IO, 1);
    }
}

#[test]
fn malformed_rpc_envelopes_are_io_failures() {
    for bytes in [
        b"[]".as_slice(),
        br#"{"jsonrpc":"1.0","id":1,"result":1}"#,
        br#"{"jsonrpc":"2.0","id":2,"result":1}"#,
        br#"{"jsonrpc":"2.0","id":1,"result":1,"error":null}"#,
        br#"{"jsonrpc":"2.0","id":1}"#,
        br#"{"jsonrpc":"2.0","id":1,"error":{"code":"bad","message":"private-marker"}}"#,
    ] {
        let error = settlement_rpc_result(bytes).unwrap_err();
        assert!(!error.to_string().contains("private-marker"));
        assert_rejection(error, &CLI_IO, 1);
    }
}

#[test]
fn malformed_rpc_result_shapes_are_io_failures() {
    for value in [
        serde_json::json!(null),
        serde_json::json!(7),
        serde_json::json!("12"),
        serde_json::json!("0xnope"),
        serde_json::json!("0x10000000000000000"),
    ] {
        let error = parse_json_rpc_hex_u64(&value, "eth_blockNumber result").unwrap_err();
        if value.as_str().is_some_and(|raw| raw.starts_with("0x")) {
            assert!(has_source::<std::num::ParseIntError>(&error));
        }
        assert_rejection(error, &CLI_IO, 1);
    }
    for value in [
        serde_json::json!(null),
        serde_json::json!({}),
        serde_json::json!({"hash": 7}),
    ] {
        assert_rejection(
            required_json_rpc_string(&value, "hash", "eth_getBlockByNumber result").unwrap_err(),
            &CLI_IO,
            1,
        );
    }
}

#[test]
fn valid_rpc_result_shapes_are_accepted() {
    assert_eq!(
        parse_json_rpc_hex_u64(&serde_json::json!("0x10"), "eth_blockNumber result").unwrap(),
        16
    );
    let block = serde_json::json!({"hash": "0xabc"});
    assert_eq!(
        required_json_rpc_string(&block, "hash", "eth_getBlockByNumber result").unwrap(),
        "0xabc"
    );
}

#[test]
fn rpc_result_requires_protocol_request_identity_and_unambiguous_envelope() {
    assert_eq!(
        settlement_rpc_result(br#"{"jsonrpc":"2.0","id":1,"result":"0x100"}"#).unwrap(),
        "0x100"
    );
    for bytes in [
        br#"{"jsonrpc":"1.0","id":1,"result":"0x100"}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":999,"result":"0x100"}"#,
        br#"{"jsonrpc":"2.0","id":1,"result":"0x100","error":null}"#,
        br#"{"jsonrpc":"2.0","id":1,"result":1,"result":2}"#,
        br#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"private-marker"}}"#,
    ] {
        let error = settlement_rpc_result(bytes).unwrap_err();
        assert!(!error.to_string().contains("private-marker"));
    }
}

fn assert_rejection(error: CliError, spec: &chio_errors::ErrorCodeSpec, exit_code: i32) {
    assert_eq!(error.report().code, spec.urn, "{error}");
    assert_eq!(
        super::super::proof_verify_exit_code(&error),
        exit_code,
        "{error}"
    );
}

#[test]
fn verifier_context_sites_carry_typed_codes() {
    use chio_errors::_generated::error_codes::{
        CLI_IO, TRANSACTION_ARTIFACT_SCHEMA_INVALID, TRANSACTION_VERIFIER_CONTEXT_INVALID,
    };
    assert_rejection(
        parse_public_keys("CHIO_TRANSACTION_TRUSTED_ROOT_KEYS", "digest mismatch").unwrap_err(),
        &TRANSACTION_VERIFIER_CONTEXT_INVALID,
        50,
    );
    assert_rejection(
        parse_string_list("CHIO_PUBLIC_SETTLEMENT_ALLOWED_CHAIN_IDS", " , ").unwrap_err(),
        &TRANSACTION_VERIFIER_CONTEXT_INVALID,
        50,
    );
    assert_rejection(
        settlement_rpc_result(br#"{"jsonrpc":"2.0","id":2,"result":"0x1"}"#).unwrap_err(),
        &CLI_IO,
        1,
    );
    assert_rejection(
        settlement_rpc_result(br#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"m"}}"#)
            .unwrap_err(),
        &CLI_IO,
        1,
    );
    assert_rejection(
        claim_set_bytes_advertise_verified_prefix(
            br#"{"claims":[{"claim_id":"claim.finding.x","status":1}]}"#,
            "claim.finding.",
        )
        .unwrap_err(),
        &TRANSACTION_ARTIFACT_SCHEMA_INVALID,
        30,
    );
}

#[cfg(feature = "finding-market")]
mod finding_inputs {
    use super::super::super::unit_tests::{TestEnvGuard, AGENT_WEB_ENV_LOCK};
    use super::super::finding::*;
    use super::*;
    use chio_errors::_generated::error_codes::TRANSACTION_VERIFIER_CONTEXT_INVALID;

    fn assert_context_rejection(error: CliError) {
        assert!(has_source::<CliError>(&error));
        assert_rejection(error, &TRANSACTION_VERIFIER_CONTEXT_INVALID, 50);
    }

    fn with_pinned_document<T>(name: &'static str, bytes: &[u8], read: impl FnOnce() -> T) -> T {
        let _lock = AGENT_WEB_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), bytes).unwrap();
        let _env = TestEnvGuard::set(&[(name, file.path().as_os_str())]);
        read()
    }

    fn authority_policy() -> chio_finding::FindingAuthorityKeyPolicy {
        chio_finding::FindingAuthorityKeyPolicy {
            authority_id: "verifier-input-test".to_owned(),
            key: chio_core_types::Keypair::from_seed(&[121_u8; 32]).public_key(),
            key_epoch: 1,
            valid_from: 1,
            valid_until: 1000,
            rotation_policy_ref: "rotation/test-v1".to_owned(),
            revocation_status_ref: "revocation/test-v1".to_owned(),
        }
    }

    #[test]
    fn malformed_pinned_verifier_profile_is_context_invalid() {
        let error = with_pinned_document(FINDING_VERIFIER_PROFILE_PATH_ENV, b"{", || {
            finding_verifier_profile_from_env().unwrap_err()
        });
        assert_context_rejection(error);
    }

    #[test]
    fn malformed_pinned_authority_status_is_context_invalid() {
        let policy = authority_policy();
        let error = with_pinned_document(FINDING_VERIFIER_AUTHORITY_STATUS_PATH_ENV, b"{", || {
            finding_authority_status_trust_from_env(
                FINDING_VERIFIER_AUTHORITY_STATUS_PATH_ENV,
                &policy.key,
                &policy,
                10,
                5,
            )
            .map(|_| ())
            .unwrap_err()
        });
        assert_context_rejection(error);
    }

    #[test]
    fn malformed_pinned_authority_policy_is_context_invalid() {
        let error = with_pinned_document(
            FINDING_VERIFIER_STATUS_AUTHORITY_POLICY_PATH_ENV,
            b"{",
            || {
                finding_authority_policy_from_env(
                    FINDING_VERIFIER_STATUS_AUTHORITY_POLICY_PATH_ENV,
                    "verifier authority",
                )
                .unwrap_err()
            },
        );
        assert_context_rejection(error);
    }

    #[test]
    fn malformed_pinned_status_authorization_is_context_invalid() {
        let policy = authority_policy();
        let error =
            with_pinned_document(FINDING_STATUS_OPERATOR_AUTHORIZATION_PATH_ENV, b"{", || {
                cognition_market_status_trust_from_env(&policy, &policy.key, 10, 5)
                    .map(|_| ())
                    .unwrap_err()
            });
        assert_context_rejection(error);
    }

    fn verifier_profile() -> chio_finding::SignedFindingChallengeVerifierProfile {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../fixtures/proof-room/finding/cognition-market-qualified-profile/deployment/verifier-profile.json");
        crate::input::json(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn noncanonical_pinned_verifier_profile_is_context_invalid() {
        let bytes = serde_json::to_vec_pretty(&verifier_profile()).unwrap();
        let error = with_pinned_document(FINDING_VERIFIER_PROFILE_PATH_ENV, &bytes, || {
            finding_verifier_profile_from_env().unwrap_err()
        });
        assert_context_rejection(error);
    }

    #[test]
    fn canonical_pinned_verifier_profile_is_accepted() {
        let profile = verifier_profile();
        let bytes = chio_core_types::canonical_json_bytes(&profile).unwrap();
        let parsed = with_pinned_document(FINDING_VERIFIER_PROFILE_PATH_ENV, &bytes, || {
            finding_verifier_profile_from_env().unwrap()
        });
        assert_eq!(
            chio_core_types::canonical_json_bytes(&parsed).unwrap(),
            bytes
        );
    }

    #[test]
    fn verifier_status_authority_site_carries_typed_code() {
        let signer = chio_core_types::Keypair::from_seed(&[115_u8; 32]).public_key();
        assert_rejection(
            require_independent_verifier_status_authority(&signer, &signer).unwrap_err(),
            &TRANSACTION_VERIFIER_CONTEXT_INVALID,
            50,
        );
    }
}
