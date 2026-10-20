#[test]
fn evidence_and_checkpoint_identifiers_are_pinned() {
    use chio_core_types::receipt::checkpoint::{
        CHECKPOINT_CONSISTENCY_PROOF_SCHEMA, CHECKPOINT_EQUIVOCATION_SCHEMA,
        CHECKPOINT_PUBLICATION_SCHEMA, CHECKPOINT_SCHEMA, CHECKPOINT_WITNESS_SCHEMA,
    };
    use chio_core_types::receipt::evidence::{
        EVIDENCE_DISCLOSURE_NOTICE_SCHEMA, EVIDENCE_EXPORT_COMMITMENT_SCHEMA,
        EVIDENCE_EXPORT_MANIFEST_SCHEMA, EVIDENCE_TRANSPARENCY_CLAIMS_SCHEMA,
        FEDERATED_EVIDENCE_SHARE_SCHEMA, FEDERATION_POLICY_SCHEMA,
    };
    use chio_core_types::root_authority::CHIO_VERIFIER_TRUST_SCHEMA;

    for (constant, literal) in [
        (CHECKPOINT_SCHEMA, "chio.checkpoint_statement.v1"),
        (
            CHECKPOINT_PUBLICATION_SCHEMA,
            "chio.checkpoint_publication.v1",
        ),
        (CHECKPOINT_WITNESS_SCHEMA, "chio.checkpoint_witness.v1"),
        (
            CHECKPOINT_CONSISTENCY_PROOF_SCHEMA,
            "chio.checkpoint_consistency_proof.v1",
        ),
        (
            CHECKPOINT_EQUIVOCATION_SCHEMA,
            "chio.checkpoint_equivocation.v1",
        ),
        (
            EVIDENCE_TRANSPARENCY_CLAIMS_SCHEMA,
            "chio.evidence_transparency_claims.v1",
        ),
        (
            EVIDENCE_EXPORT_MANIFEST_SCHEMA,
            "chio.evidence_export_manifest.v1",
        ),
        (
            EVIDENCE_EXPORT_COMMITMENT_SCHEMA,
            "chio.evidence_export_commitment.v1",
        ),
        (
            EVIDENCE_DISCLOSURE_NOTICE_SCHEMA,
            "chio.evidence_export_disclosure_notice.v1",
        ),
        (FEDERATION_POLICY_SCHEMA, "chio.federation-policy.v1"),
        (
            FEDERATED_EVIDENCE_SHARE_SCHEMA,
            "chio.federated-evidence-share.v1",
        ),
        (CHIO_VERIFIER_TRUST_SCHEMA, "chio.verifier-trust.v1"),
    ] {
        assert_eq!(constant, literal);
    }
}
