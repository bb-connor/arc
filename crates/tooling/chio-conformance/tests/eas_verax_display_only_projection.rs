//! EAS/Verax carried ONLY as
//! `chio.agent-web-proof-envelope.v1` projections, recompute the sole proof lane.
//!
//! Threat: an integrator carries an external attestation-service record (an
//! Ethereum Attestation Service / SAS attestation, or a Verax / Linea
//! attestation-registry record) that *asserts* a settlement fact (for example
//! that a Merkle root was anchored), and tries to present that attestation as
//! if it were a Chio proof, or to "upgrade" a genuine recompute proof by
//! splicing the attested value into it. EAS and Verax are display/interop
//! surfaces, not proof surfaces: a verifier that trusts an attester signature
//! would admit settlement state that was never recomputed.
//!
//! Invariant (recompute is the sole proof lane, viewed from the projection
//! angle): EAS/Verax attestations are carried ONLY as Agent Web proof-envelope
//! projections (a VIEW for display/interop). They are NEVER admissible as a
//! recompute proof. The recompute lane (`chio-web3 verify_anchor_inclusion_proof`,
//! the verifier-side mirror of the on-chain `getRoot` / `verifyInclusionDetailed`
//! calls) stays the SOLE proof lane: it takes the committed root only from the
//! kernel-signed checkpoint statement, recomputes the receipt leaf from the
//! canonical receipt body, and re-walks the audit path. It never trusts an
//! attester-asserted value.
//!
//! Projection register + display-only guard. The register below mirrors the
//! 30-protocol projection manifest pattern in
//! `chio-agent-web-interop::protocols` (`SourceProtocolSpec`): each external
//! standard is bound to the `chio.agent-web-proof-envelope.v1` envelope schema
//! and carries a `claim.external.<x>_is_chio_authority` claim that MUST be held
//! as an UNSUPPORTED claim (the same display-only discipline enforced by that
//! crate's `validate_required_unsupported_claims`). EAS and Verax extend that
//! register as display-only projections (`proof_admissible = false`), and the
//! `display_only_guard` fails closed whenever such a projection is presented in
//! a proof position.
//!
//! This harness proves five fail-closed facts:
//!
//!   1. EAS and Verax are registered ONLY as display-only proof-envelope
//!      projections (never proof-admissible), each carrying a required
//!      unsupported authority claim.
//!   2. The display-only guard admits a projection for display/interop but
//!      denies it fail-closed in a proof position.
//!   3. A projected EAS/Verax attestation (and the projection envelope that
//!      carries it) does not even deserialize as a
//!      `chio.anchor-inclusion-proof.v1`: it cannot stand in for a recompute
//!      proof.
//!   4. Splicing an attested root into a genuine recompute proof fails closed
//!      at every layer (root-binding, then kernel-signature recompute): a
//!      projected attestation cannot UPGRADE a recompute proof.
//!   5. The recompute lane still admits a genuine recomputing proof, so
//!      recompute via getRoot / verifyInclusionDetailed remains the sole lane.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_web3::anchors::{
    verify_anchor_inclusion_proof, AnchorInclusionProof, CHIO_ANCHOR_INCLUSION_PROOF_SCHEMA,
};
use serde_json::{json, Value};

/// The envelope schema that carries every Agent Web projection. Mirrors the
/// schema gate in `chio-agent-web-interop` (`parse_artifact(.., node,
/// "chio.agent-web-proof-envelope.v1")`). An EAS/Verax attestation is carried
/// ONLY inside this envelope, as a display-only VIEW.
const AGENT_WEB_PROOF_ENVELOPE_SCHEMA: &str = "chio.agent-web-proof-envelope.v1";

/// A single display-only projection spec. Mirrors the `SourceProtocolSpec`
/// shape in `chio-agent-web-interop::protocols`: a source-protocol id, the
/// external-subject schema it digest-binds, the envelope schema that carries
/// it, and the `*_is_chio_authority` claim that must be held UNSUPPORTED.
struct ProofEnvelopeProjectionSpec {
    /// Agent Web source-protocol id (mirrors `SourceProtocolSpec.id`).
    source_protocol: &'static str,
    /// External-subject schema the projection digest-binds (the display VIEW).
    external_subject_schema: &'static str,
    /// The envelope schema that carries the projection.
    projection_envelope_schema: &'static str,
    /// The `claim.external.<x>_is_chio_authority` claim that MUST be carried as
    /// an unsupported claim (the display-only discipline; mirrors
    /// `validate_required_unsupported_claims`).
    required_unsupported_authority_claim: &'static str,
    /// Display-only projections are NEVER admissible as a recompute proof.
    proof_admissible: bool,
}

/// The EAS/Verax projection register. Both attestation services are carried
/// ONLY as display-only proof-envelope projections: `proof_admissible = false`.
const EAS_VERAX_PROJECTION_REGISTER: &[ProofEnvelopeProjectionSpec] = &[
    ProofEnvelopeProjectionSpec {
        source_protocol: "eas",
        external_subject_schema: "external.eas.attestation.v1",
        projection_envelope_schema: AGENT_WEB_PROOF_ENVELOPE_SCHEMA,
        required_unsupported_authority_claim: "claim.external.eas_attestation_is_chio_authority",
        proof_admissible: false,
    },
    ProofEnvelopeProjectionSpec {
        source_protocol: "verax",
        external_subject_schema: "external.verax.attestation.v1",
        projection_envelope_schema: AGENT_WEB_PROOF_ENVELOPE_SCHEMA,
        required_unsupported_authority_claim: "claim.external.verax_attestation_is_chio_authority",
        proof_admissible: false,
    },
];

/// Where a projection is being presented to a verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EvidencePosition {
    /// The projection is shown for display/interop only (a VIEW).
    DisplayInterop,
    /// The projection is presented where a recompute proof is required.
    ProofOfInclusion,
}

/// Fail-closed display-only guard. A registered projection may be presented for
/// display/interop, but a non-`proof_admissible` projection is DENIED in a
/// proof position. Recompute (getRoot / verifyInclusionDetailed via chio-web3)
/// stays the sole proof lane.
fn display_only_guard(
    spec: &ProofEnvelopeProjectionSpec,
    position: EvidencePosition,
) -> Result<(), String> {
    match position {
        EvidencePosition::DisplayInterop => Ok(()),
        EvidencePosition::ProofOfInclusion => {
            if spec.proof_admissible {
                Ok(())
            } else {
                Err(format!(
                    "{} projection is display-only and is not admissible as a recompute proof; \
                     recompute via getRoot/verifyInclusionDetailed is the sole proof lane",
                    spec.source_protocol
                ))
            }
        }
    }
}

fn spec(source_protocol: &str) -> &'static ProofEnvelopeProjectionSpec {
    EAS_VERAX_PROJECTION_REGISTER
        .iter()
        .find(|spec| spec.source_protocol == source_protocol)
        .expect("projection spec is registered")
}

/// A genuine inclusion proof whose committed root recomputes from the receipt
/// leaf and a kernel-signed checkpoint statement. This is the only shape the
/// recompute lane admits.
const ANCHOR_INCLUSION_PROOF_FIXTURE: &str =
    include_str!("../../../../docs/standards/CHIO_ANCHOR_INCLUSION_PROOF_EXAMPLE.json");

/// A 32-byte Merkle root the EAS attestation merely *asserts*.
const EAS_ATTESTED_ROOT: &str =
    "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

/// A 32-byte Merkle root the Verax attestation merely *asserts*.
const VERAX_ATTESTED_ROOT: &str =
    "0xabababababababababababababababababababababababababababababababab";

fn fixture_value() -> Value {
    serde_json::from_str(ANCHOR_INCLUSION_PROOF_FIXTURE).expect("anchor inclusion fixture parses")
}

/// Model of an external EAS/SAS attestation as a projected external subject: an
/// attester-signed statement asserting a Merkle root was anchored. It carries
/// no receipt, no inclusion proof, and no kernel-signed checkpoint statement.
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
        // The fact the attester signs over: a root it CLAIMS was anchored.
        "attested_merkle_root": EAS_ATTESTED_ROOT,
        "checkpoint_seq": 1_042u64,
        "attester_signature": "0x4444444444444444444444444444444444444444444444444444444444444444"
    })
}

/// Model of an external Verax (Linea attestation registry) record as a projected
/// external subject: a portal-attested statement asserting a Merkle root. Like
/// EAS it carries no recompute inputs.
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
        // The fact the portal attests over: a root it CLAIMS was anchored.
        "attested_merkle_root": VERAX_ATTESTED_ROOT,
        "checkpoint_seq": 2_058u64,
        "attestation_data": "0x8888888888888888888888888888888888888888888888888888888888888888"
    })
}

fn attestation_for(source_protocol: &str) -> Value {
    match source_protocol {
        "eas" => eas_attestation(),
        "verax" => verax_attestation(),
        other => panic!("no attestation model for {other}"),
    }
}

/// The `chio.agent-web-proof-envelope.v1` projection that CARRIES an attestation
/// as a display-only VIEW. Critically it carries NO recompute inputs (no
/// `receipt_inclusion`, no `checkpoint_statement`, no audit path), and its
/// `unsupported_claims` holds the `*_is_chio_authority` claim: the attestation
/// is never a Chio authority, only a projection.
fn proof_envelope_projection(spec: &ProofEnvelopeProjectionSpec) -> Value {
    let attestation = attestation_for(spec.source_protocol);
    let external_subject_id = attestation
        .get("id")
        .and_then(Value::as_str)
        .expect("attestation carries an id")
        .to_string();
    json!({
        "schema": spec.projection_envelope_schema,
        "source_protocol": spec.source_protocol,
        "source_protocol_version": "v1",
        "external_subject": external_subject_id,
        "external_subject_schema": spec.external_subject_schema,
        "external_subject_artifact": attestation,
        "chio_claim_refs": [
            "claim.agent_web.external_subject_digest_bound",
            "claim.agent_web.sidecar_not_native_authority",
        ],
        // The attester/portal authority claim is held UNSUPPORTED: a projected
        // attestation is never trusted as a Chio authority or proof.
        "unsupported_claims": [spec.required_unsupported_authority_claim],
        "limitations": [
            "EAS/Verax attestation is a display-only projection; not admissible as a recompute proof"
        ]
    })
}

// (1) REGISTER: EAS and Verax are carried ONLY as display-only proof-envelope
// projections, each with a required unsupported authority claim.
#[test]
fn eas_and_verax_are_registered_as_display_only_proof_envelope_projections() {
    for source_protocol in ["eas", "verax"] {
        let spec = spec(source_protocol);
        assert_eq!(
            spec.projection_envelope_schema, AGENT_WEB_PROOF_ENVELOPE_SCHEMA,
            "{source_protocol} must be carried inside the agent-web proof-envelope schema"
        );
        assert!(
            !spec.proof_admissible,
            "{source_protocol} must be display-only (never admissible as a recompute proof)"
        );
        // Mirror chio-agent-web-interop's `*_is_chio_authority` required
        // unsupported-claim convention.
        assert!(
            spec.required_unsupported_authority_claim
                .starts_with("claim.external.")
                && spec
                    .required_unsupported_authority_claim
                    .ends_with("_is_chio_authority"),
            "{source_protocol} authority claim must follow the external-authority convention"
        );

        // The carrying projection holds the authority claim as UNSUPPORTED.
        let projection = proof_envelope_projection(spec);
        assert_eq!(
            projection["schema"], AGENT_WEB_PROOF_ENVELOPE_SCHEMA,
            "{source_protocol} projection must declare the proof-envelope schema"
        );
        let unsupported = projection["unsupported_claims"]
            .as_array()
            .expect("projection carries unsupported_claims");
        assert!(
            unsupported
                .iter()
                .any(|claim| claim == spec.required_unsupported_authority_claim),
            "{source_protocol} projection must carry its authority claim as unsupported"
        );
    }

    // Display-only is total over the register: nothing is proof-admissible.
    assert!(
        EAS_VERAX_PROJECTION_REGISTER
            .iter()
            .all(|spec| !spec.proof_admissible),
        "every EAS/Verax projection must be display-only"
    );
}

// (2) DISPLAY-ONLY GUARD: admit for display/interop, deny fail-closed in a
// proof position.
#[test]
fn display_only_guard_admits_display_but_denies_a_proof_position_fail_closed() {
    for source_protocol in ["eas", "verax"] {
        let spec = spec(source_protocol);

        display_only_guard(spec, EvidencePosition::DisplayInterop)
            .expect("a display-only projection may be presented for display/interop");

        let denial = display_only_guard(spec, EvidencePosition::ProofOfInclusion)
            .expect_err("a display-only projection must be denied in a proof position");
        assert!(
            denial.contains("display-only")
                && denial.contains(
                    "recompute via getRoot/verifyInclusionDetailed is the sole proof lane"
                ),
            "expected fail-closed display-only denial, got: {denial}"
        );
    }
}

// (3) NOT A PROOF: neither a projected attestation nor the projection envelope
// that carries it deserializes as a recompute inclusion proof.
#[test]
fn projected_attestation_is_not_admissible_as_a_recompute_proof() {
    for source_protocol in ["eas", "verax"] {
        let attestation = attestation_for(source_protocol);
        let admitted_subject = serde_json::from_value::<AnchorInclusionProof>(attestation);
        assert!(
            admitted_subject.is_err(),
            "a {source_protocol} attestation must not deserialize as an anchoring inclusion proof"
        );

        let projection = proof_envelope_projection(spec(source_protocol));
        let admitted_envelope = serde_json::from_value::<AnchorInclusionProof>(projection);
        assert!(
            admitted_envelope.is_err(),
            "a {source_protocol} proof-envelope projection must not deserialize as a recompute proof"
        );
    }
}

// (3b) SCHEMA: the projection envelope schema is not the recompute-proof schema.
#[test]
fn projection_envelope_schema_is_not_the_recompute_proof_schema() {
    assert_ne!(
        AGENT_WEB_PROOF_ENVELOPE_SCHEMA, CHIO_ANCHOR_INCLUSION_PROOF_SCHEMA,
        "the display-only projection envelope must not share the recompute-proof schema"
    );
}

// (4) CANNOT UPGRADE: splicing an attested root into a genuine recompute proof
// fails closed at every layer.
#[test]
fn projected_attested_root_cannot_upgrade_a_recompute_proof_fail_closed() {
    for attested_root in [EAS_ATTESTED_ROOT, VERAX_ATTESTED_ROOT] {
        // Splice the attested root into the inclusion claim only: the lane
        // refuses because the inclusion root must equal the kernel-signed
        // checkpoint root.
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

        // Now rewrite the attested root into every committed root field, as a
        // "trust the attested value" readback would. Root-equality checks pass,
        // but the kernel-signed checkpoint no longer covers the attested root.
        let mut committed_everywhere = fixture_value();
        committed_everywhere["receipt_inclusion"]["merkle_root"] = json!(attested_root);
        committed_everywhere["checkpoint_statement"]["merkle_root"] = json!(attested_root);
        committed_everywhere["chain_anchor"]["anchored_merkle_root"] = json!(attested_root);
        let proof: AnchorInclusionProof =
            serde_json::from_value(committed_everywhere).expect("spliced proof still deserializes");
        let err = verify_anchor_inclusion_proof(&proof)
            .expect_err("an attested root with no kernel-signed commitment must fail closed");
        assert!(
            err.to_string()
                .contains("checkpoint statement signature verification failed"),
            "expected kernel-signature recompute rejection, got: {err}"
        );
    }
}

// (5) SOLE LANE: the recompute lane still admits a genuine recomputing proof.
#[test]
fn recompute_via_get_root_verify_inclusion_remains_the_sole_proof_lane() {
    let proof: AnchorInclusionProof =
        serde_json::from_value(fixture_value()).expect("genuine proof deserializes");
    verify_anchor_inclusion_proof(&proof).expect("genuine recomputing proof must verify");
}

/// Production drift guard: the register above is a test-local EXTENSION of the
/// production source-protocol manifest, so this asserts against the production
/// crate that EAS and Verax remain UNREGISTERED there. If a future change
/// registers either as a source protocol, this fails and forces a conscious
/// re-review of the display-only discipline (facts 1-5 above) against the real
/// registration, instead of this harness silently asserting a stale mirror.
#[test]
fn production_register_carries_no_eas_or_verax_projection() {
    let ids = chio_agent_web_interop::registered_source_protocol_ids();
    assert!(
        !ids.is_empty(),
        "the production source-protocol manifest must be readable"
    );
    for id in ids {
        let lowered = id.to_ascii_lowercase();
        assert!(
            !lowered.contains("eas") && !lowered.contains("verax"),
            "EAS/Verax must stay display-only projections with no production \
             source-protocol registration, found registered id `{id}`"
        );
    }
}
