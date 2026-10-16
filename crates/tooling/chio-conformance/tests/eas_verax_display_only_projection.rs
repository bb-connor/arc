//! EAS and Verax attestations are display-only projections, never proofs.
//!
//! An external attestation that asserts a settlement fact (for example that a
//! Merkle root was anchored) is carried only inside a
//! `chio.agent-web-proof-envelope.v1` projection. The anchor recompute lane
//! (`verify_anchor_inclusion_proof`) takes the committed root only from the
//! kernel-signed checkpoint statement and never admits an attested value.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_web3::anchors::{
    verify_anchor_inclusion_proof, AnchorInclusionProof, CHIO_ANCHOR_INCLUSION_PROOF_SCHEMA,
};
use serde_json::{json, Value};

const AGENT_WEB_PROOF_ENVELOPE_SCHEMA: &str = "chio.agent-web-proof-envelope.v1";

const ANCHOR_INCLUSION_PROOF_FIXTURE: &str =
    include_str!("../../../../docs/standards/CHIO_ANCHOR_INCLUSION_PROOF_EXAMPLE.json");

const EAS_ATTESTED_ROOT: &str =
    "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

const VERAX_ATTESTED_ROOT: &str =
    "0xabababababababababababababababababababababababababababababababab";

fn fixture_value() -> Value {
    serde_json::from_str(ANCHOR_INCLUSION_PROOF_FIXTURE).expect("anchor inclusion fixture parses")
}

fn eas_attestation() -> Value {
    json!({
        "schema": "external.eas.attestation.v1",
        "id": "eas:0x9c8b7a6f5e4d3c2b1a09f8e7d6c5b4a3928170615243342516071839405a6b7c",
        "uid": "0x9c8b7a6f5e4d3c2b1a09f8e7d6c5b4a3928170615243342516071839405a6b7c",
        "schema_uid": "0x1122334455667788990011223344556677889900112233445566778899001122",
        "attester": "0x3333333333333333333333333333333333333333",
        "recipient": "0x2222222222222222222222222222222222222222",
        "time": 1_743_292_800u64,
        "revocable": true,
        "revoked": false,
        "attested_merkle_root": EAS_ATTESTED_ROOT,
        "checkpoint_seq": 1_042u64,
        "attester_signature": "0x4444444444444444444444444444444444444444444444444444444444444444"
    })
}

fn verax_attestation() -> Value {
    json!({
        "schema": "external.verax.attestation.v1",
        "id": "verax:0x5b4a3928170615243342516071839405a6b7c9c8b7a6f5e4d3c2b1a09f8e7d6c5",
        "attestation_id": "0x5b4a3928170615243342516071839405a6b7c9c8b7a6f5e4d3c2b1a09f8e7d6c5",
        "schema_id": "0x9988776655443322110099887766554433221100998877665544332211009988",
        "portal": "0x5555555555555555555555555555555555555555",
        "attester": "0x6666666666666666666666666666666666666666",
        "subject": "0x7777777777777777777777777777777777777777",
        "attested_on": 1_743_292_800u64,
        "revoked": false,
        "attested_merkle_root": VERAX_ATTESTED_ROOT,
        "checkpoint_seq": 2_058u64,
        "attestation_data": "0x8888888888888888888888888888888888888888888888888888888888888888"
    })
}

fn attestations() -> [(&'static str, Value); 2] {
    [("eas", eas_attestation()), ("verax", verax_attestation())]
}

fn proof_envelope_projection(source_protocol: &str, attestation: Value) -> Value {
    json!({
        "schema": AGENT_WEB_PROOF_ENVELOPE_SCHEMA,
        "source_protocol": source_protocol,
        "source_protocol_version": "v1",
        "external_subject": attestation["id"].clone(),
        "external_subject_schema": attestation["schema"].clone(),
        "external_subject_artifact": attestation,
        "chio_claim_refs": [
            "claim.agent_web.external_subject_digest_bound",
            "claim.agent_web.sidecar_not_native_authority",
        ],
        "unsupported_claims": [
            format!("claim.external.{source_protocol}_attestation_is_chio_authority")
        ],
    })
}

#[test]
fn attestation_and_its_projection_do_not_parse_as_an_inclusion_proof() {
    for (source_protocol, attestation) in attestations() {
        assert!(
            serde_json::from_value::<AnchorInclusionProof>(attestation.clone()).is_err(),
            "{source_protocol} attestation parsed as an anchor inclusion proof"
        );
        let projection = proof_envelope_projection(source_protocol, attestation);
        assert!(
            serde_json::from_value::<AnchorInclusionProof>(projection).is_err(),
            "{source_protocol} projection parsed as an anchor inclusion proof"
        );
    }
}

#[test]
fn projection_envelope_schema_is_not_the_inclusion_proof_schema() {
    assert_ne!(
        AGENT_WEB_PROOF_ENVELOPE_SCHEMA,
        CHIO_ANCHOR_INCLUSION_PROOF_SCHEMA
    );
}

#[test]
fn attested_root_spliced_into_a_genuine_proof_fails_closed() {
    for attested_root in [EAS_ATTESTED_ROOT, VERAX_ATTESTED_ROOT] {
        let mut inclusion_only = fixture_value();
        inclusion_only["receipt_inclusion"]["merkle_root"] = json!(attested_root);
        let proof: AnchorInclusionProof =
            serde_json::from_value(inclusion_only).expect("spliced proof still deserializes");
        let err = verify_anchor_inclusion_proof(&proof)
            .expect_err("an attested inclusion root must fail closed");
        assert!(
            err.to_string()
                .contains("receipt inclusion merkle_root must match checkpoint statement"),
            "expected inclusion/checkpoint root-binding rejection, got: {err}"
        );

        let mut committed_everywhere = fixture_value();
        committed_everywhere["receipt_inclusion"]["merkle_root"] = json!(attested_root);
        committed_everywhere["checkpoint_statement"]["merkle_root"] = json!(attested_root);
        committed_everywhere["chain_anchor"]["anchored_merkle_root"] = json!(attested_root);
        let proof: AnchorInclusionProof =
            serde_json::from_value(committed_everywhere).expect("spliced proof still deserializes");
        let err = verify_anchor_inclusion_proof(&proof)
            .expect_err("an attested root without a kernel-signed commitment must fail closed");
        assert!(
            err.to_string()
                .contains("checkpoint statement signature verification failed"),
            "expected kernel-signature rejection, got: {err}"
        );
    }
}

#[test]
fn genuine_recomputing_proof_verifies() {
    let proof: AnchorInclusionProof =
        serde_json::from_value(fixture_value()).expect("genuine proof deserializes");
    verify_anchor_inclusion_proof(&proof).expect("genuine recomputing proof must verify");
}

#[test]
fn production_register_has_no_eas_or_verax_source_protocol() {
    let ids = chio_agent_web_interop::registered_source_protocol_ids();
    assert!(!ids.is_empty());
    for id in ids {
        assert!(
            !id.split(['-', '_', '.'])
                .any(|segment| segment.eq_ignore_ascii_case("eas")
                    || segment.eq_ignore_ascii_case("verax")),
            "EAS/Verax must not be a registered source protocol, found `{id}`"
        );
    }
}
