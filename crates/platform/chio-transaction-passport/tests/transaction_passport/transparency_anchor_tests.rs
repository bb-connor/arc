//! Standalone minimal passports promote only verified transparency anchors.

use super::*;

#[test]
fn standalone_minimal_passport_promotes_verified_transparency_anchor() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|_| {});

    let report =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect("verified transparency anchor promotes");

    assert_eq!(report.transparency_state, "trust_anchored");
}

#[test]
fn standalone_minimal_passport_rejects_receipt_anchor_without_checkpoint_statement() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|artifact| {
            let object = artifact
                .as_object_mut()
                .test_expect("inclusion artifact is an object");
            object.remove("checkpoint_statement");
        });

    let error =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect_err("a receipt inclusion proof without its signed anchor must deny");

    assert!(
        matches!(&error, chio_transaction_passport::TransactionPassportError::Input(source) if source.code() == "urn:chio:error:attest:signed-json-invalid-shape")
    );
    assert!(std::error::Error::source(&error).is_some());
}

#[test]
fn standalone_minimal_passport_requires_the_complete_receipt_inclusion_envelope() {
    for field in ["proof_id", "log_id", "checkpoint", "verified_at"] {
        let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
            transparency_anchored_fixture(|artifact| {
                artifact
                    .as_object_mut()
                    .test_expect("inclusion artifact is an object")
                    .remove(field);
            });

        let error =
            verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
                .test_expect_err("an incomplete v2 envelope must deny");
        assert!(
            matches!(&error, chio_transaction_passport::TransactionPassportError::Input(source) if source.code() == "urn:chio:error:attest:signed-json-invalid-shape")
        );
        assert!(std::error::Error::source(&error).is_some());
    }
}

#[test]
fn standalone_minimal_passport_rejects_unknown_receipt_inclusion_envelope_fields() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|artifact| {
            artifact["smuggled"] = json!("field");
        });

    let error =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect_err("a field-smuggled v2 envelope must deny");
    assert!(matches!(
        &error,
        chio_transaction_passport::TransactionPassportError::Input(_)
    ));
    assert!(std::error::Error::source(&error).is_some());
    assert!(!error.to_string().contains("smuggled"));
}

#[test]
fn standalone_minimal_passport_keeps_selective_disclosure_proofs_at_preview() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|artifact| {
            artifact["schema"] = json!("chio.transparency.inclusion-proof.v1");
        });

    let error =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect_err(
                "selective-disclosure proof hashing must not qualify as an RFC 6962 anchor",
            );

    assert!(
        error
            .to_string()
            .contains("transparency state not accepted by verifier policy: transparency_preview"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_rejects_transparency_anchor_from_untrusted_signer() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|artifact| {
            let rogue = Keypair::from_seed(&[99u8; 32]);
            let mut body = artifact["checkpoint_statement"]["body"].clone();
            body["kernel_key"] = json!(rogue.public_key().to_hex());
            let signature = rogue
                .sign_wrapped(
                    "chio.checkpoint_statement.v1",
                    &chio_core_types::CanonicalBytes::from_serializable(&body)
                        .test_expect("canonical rogue statement body"),
                )
                .test_expect("rogue statement signs")
                .to_hex();
            artifact["checkpoint_statement"] = json!({
                "body": body,
                "signature": signature
            });
        });

    let error =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect_err("a checkpoint signed outside the pinned key set must not promote");

    assert!(
        error
            .to_string()
            .contains("transparency state not accepted by verifier policy: transparency_preview"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_rejects_transparency_anchor_with_tampered_root() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|artifact| {
            artifact["root_hash"] = json!(format!("0x{}", "0".repeat(64)));
        });

    let error =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect_err("a root the checkpoint does not commit must not promote");

    assert!(
        error
            .to_string()
            .contains("inclusion proof does not target the committed checkpoint tree"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_rejects_transparency_anchor_with_unbound_subject() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|artifact| {
            artifact["artifact_ref"] = json!("b".repeat(64));
        });

    let error =
        verify_standalone_anchored(&artifacts, &evidence_graph_bytes, &verifier_policy_bytes)
            .test_expect_err("an anchor not bound to a graph artifact must not promote");

    assert!(
        error
            .to_string()
            .contains("inclusion proof subject is not this transaction's receipt"),
        "{error}"
    );
}

#[test]
fn standalone_minimal_passport_rejects_checkpoint_keys_shared_with_passport_roots() {
    let (artifacts, evidence_graph_bytes, verifier_policy_bytes) =
        transparency_anchored_fixture(|_| {});

    let error = verify_standalone_anchored_with_checkpoint_keys(
        &artifacts,
        &evidence_graph_bytes,
        &verifier_policy_bytes,
        &governed_action_trusted_root_keys(),
    )
    .test_expect_err("a passport root key must not double as a checkpoint signer");

    assert!(
        error.to_string().contains(
            "trusted checkpoint signer keys must be disjoint from passport root signer keys"
        ),
        "{error}"
    );
}
