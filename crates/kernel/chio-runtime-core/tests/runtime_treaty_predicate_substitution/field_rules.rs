use super::*;

const fn rule(path: &'static str, comparison: Comparison, substituted: Outcome) -> FieldRule {
    FieldRule {
        path,
        comparison,
        substituted: Some(substituted),
        without_lineage: None,
        probe: None,
    }
}

/// A leaf no strict statement of this call carries, either because the profile
/// refuses it or because the wire type marks it optional and this call omits
/// it. Neither can be reached by substitution.
const fn absent(path: &'static str, comparison: Comparison) -> FieldRule {
    FieldRule {
        path,
        comparison,
        substituted: None,
        without_lineage: None,
        probe: None,
    }
}

const fn with_probe(
    path: &'static str,
    comparison: Comparison,
    substituted: Outcome,
    probe: (MutationSpec, Outcome),
) -> FieldRule {
    FieldRule {
        path,
        comparison,
        substituted: Some(substituted),
        without_lineage: None,
        probe: Some(probe),
    }
}

const fn conditional(
    path: &'static str,
    comparison: Comparison,
    substituted: Outcome,
    without_lineage: Outcome,
) -> FieldRule {
    FieldRule {
        path,
        comparison,
        substituted: Some(substituted),
        without_lineage: Some(without_lineage),
        probe: None,
    }
}

/// Every leaf of a strict bilateral statement, with what the receiver compares
/// it against and what substituting it does.
pub(super) const FIELD_RULES: &[FieldRule] = &[
    // --- in-toto Statement envelope -------------------------------------
    rule(
        "_type",
        Comparison::Shape("the in-toto Statement v1 type constant"),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
    ),
    rule(
        "predicateType",
        Comparison::Shape("the strict bilateral-cosign-invocation predicate type constant"),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
    ),
    rule(
        "subject/0/name",
        Comparison::SelfConsistent("the receipt subject name derived from predicate.invocation_id"),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
    ),
    rule(
        "subject/0/digest/sha256",
        Comparison::Uncompared {
            shape: ANY_VALUE_OF_ITS_JSON_TYPE,
            reason: "the strict admission path binds the receipts through \
                     treaty_binding_ref.local_receipt_sha256 and remote_receipt_sha256, which \
                     are compared against the lineage bundle and the invocation record; the \
                     subject digest itself is compared against nothing the receiver holds",
        },
        Outcome::Admitted,
    ),
    // --- predicate, identity and shape ----------------------------------
    absent(
        "predicate/schema",
        Comparison::AbsentRequired(
            "strict predicates carry no schema discriminator; predicateType is the \
             verifier-facing one, and a statement carrying this field is refused",
        ),
    ),
    rule(
        "predicate/invocation_id",
        Comparison::SelfConsistent("the subject name, which must be its receipt-subject form"),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
    ),
    rule(
        "predicate/tool_server_a/kernel_id",
        Comparison::ReceiverState(
            "the origin kernel id of the request, after the statement's own signer list agrees \
             with it",
        ),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
    ),
    rule(
        "predicate/tool_server_a/passport_key_fingerprint",
        Comparison::ReceiverState("the key id of the pinned public key of the first signer"),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
    ),
    rule(
        "predicate/tool_server_a/alg",
        Comparison::Shape("the ed25519 algorithm constant"),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
    ),
    rule(
        "predicate/tool_server_b/kernel_id",
        Comparison::ReceiverState(
            "the receiving kernel's own id, after the statement's own signer list agrees with it",
        ),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
    ),
    rule(
        "predicate/tool_server_b/passport_key_fingerprint",
        Comparison::ReceiverState("the key id of the pinned public key of the second signer"),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
    ),
    rule(
        "predicate/tool_server_b/alg",
        Comparison::Shape("the ed25519 algorithm constant"),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
    ),
    rule(
        "predicate/tool_name",
        Comparison::ReceiverState("the tool name of the request being admitted"),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
    ),
    with_probe(
        "predicate/co_sign",
        Comparison::ReceiverState("the co-signing mode of the resolved action class"),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
        (
            MutationSpec::Literal("\"bilateral_if_cross_org\""),
            Outcome::Denied(UNVERIFIED_EVIDENCE),
        ),
    ),
    rule(
        "predicate/consistency_model",
        Comparison::ReceiverState("the consistency model of the resolved action class"),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
    ),
    with_probe(
        "predicate/cross_org_visibility",
        Comparison::Shape(
            "the four declared visibility labels; inside that domain the receiver does not \
             compare the value at all, as the second declared value shows, because it takes its \
             disclosure decisions from its own agreement",
        ),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
        (MutationSpec::Literal("\"federated\""), Outcome::Admitted),
    ),
    rule(
        "predicate/timestamp_unix_ms",
        Comparison::Uncompared {
            shape: ANY_VALUE_OF_ITS_JSON_TYPE,
            reason: "the presentation window is enforced by the continuation, the lease, and \
                     the agreement intervals, all of which the receiver holds; the statement's \
                     own timestamp is not read by admission",
        },
        Outcome::Admitted,
    ),
    rule(
        "predicate/tool_args_hash/alg",
        Comparison::Shape("the sha256 algorithm constant"),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
    ),
    rule(
        "predicate/tool_args_hash/value",
        Comparison::ReceiverState(
            "the canonical argument hash of the request, cross-checked first against \
             treaty_binding_ref.request_sha256",
        ),
        Outcome::Denied(BINDING_MISMATCH),
    ),
    absent(
        "predicate/receipt_canonical_json",
        Comparison::AbsentRequired(
            "the embedded receipt copy belongs to the compatibility signature-slice profile and \
             is refused in strict predicates",
        ),
    ),
    // --- predicate, capability lease ------------------------------------
    rule(
        "predicate/capability_lease_ref/lease_id",
        Comparison::SelfConsistent(
            "treaty_binding_ref.lease_refs, which is what the receiver \
             compares against its own admission bundle",
        ),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
    ),
    with_probe(
        "predicate/capability_lease_ref/issuer",
        Comparison::ReceiverState("the issuer of the lease the receiver resolved"),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
        (
            MutationSpec::Literal("\"kernel.vendor-b\""),
            Outcome::Denied(UNVERIFIED_EVIDENCE),
        ),
    ),
    with_probe(
        "predicate/capability_lease_ref/expires_at_unix_ms",
        Comparison::ReceiverDomain(
            "the instants inside the presentation window the receiver resolved for the lease \
             issuer: a lease may end early, so the second declared value, one millisecond \
             inside the window, is admitted, while the generated value, one millisecond past \
             the window's end, is not",
        ),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
        (MutationSpec::Literal("1800003599999"), Outcome::Admitted),
    ),
    absent(
        "predicate/capability_lease_ref/scope_digest/alg",
        Comparison::AbsentOptional(
            "the lease scope digest is optional and this call omits it; the strict profile does \
             not refuse it, so the addition corpus is what reaches it",
        ),
    ),
    absent(
        "predicate/capability_lease_ref/scope_digest/value",
        Comparison::AbsentOptional(
            "the lease scope digest is optional and this call omits it; the strict profile does \
             not refuse it, so the addition corpus is what reaches it",
        ),
    ),
    // --- predicate, policy evaluation summary ---------------------------
    with_probe(
        "predicate/policy_evaluation_summary/server_a_verdict/verdict",
        Comparison::SelfConsistent(
            "the peer verdict and the joint disposition, and required to be allow for admission",
        ),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
        (
            MutationSpec::Literal("\"deny\""),
            Outcome::Denied(UNVERIFIED_EVIDENCE),
        ),
    ),
    with_probe(
        "predicate/policy_evaluation_summary/server_a_verdict/policy_id",
        Comparison::Uncompared {
            shape: "a non-empty string",
            reason: "the receiver does not resolve either party's policy identity; the verdict \
                     it acts on is its own, and this field is audit content",
        },
        Outcome::Admitted,
        (
            MutationSpec::Literal("\"\""),
            Outcome::Denied(UNVERIFIED_EVIDENCE),
        ),
    ),
    with_probe(
        "predicate/policy_evaluation_summary/server_a_verdict/policy_version",
        Comparison::Uncompared {
            shape: "a non-empty string",
            reason: "audit content, as for the policy id",
        },
        Outcome::Admitted,
        (
            MutationSpec::Literal("\"\""),
            Outcome::Denied(UNVERIFIED_EVIDENCE),
        ),
    ),
    absent(
        "predicate/policy_evaluation_summary/server_a_verdict/rationale_code",
        Comparison::AbsentOptional(
            "the rationale code is optional and this call omits it; the strict profile does not \
             refuse it, so the addition corpus is what reaches it",
        ),
    ),
    with_probe(
        "predicate/policy_evaluation_summary/server_b_verdict/verdict",
        Comparison::SelfConsistent("the peer verdict and the joint disposition"),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
        (
            MutationSpec::Literal("\"deny\""),
            Outcome::Denied(UNVERIFIED_EVIDENCE),
        ),
    ),
    with_probe(
        "predicate/policy_evaluation_summary/server_b_verdict/policy_id",
        Comparison::Uncompared {
            shape: "a non-empty string",
            reason: "audit content, as for the first signer's policy id",
        },
        Outcome::Admitted,
        (
            MutationSpec::Literal("\"\""),
            Outcome::Denied(UNVERIFIED_EVIDENCE),
        ),
    ),
    with_probe(
        "predicate/policy_evaluation_summary/server_b_verdict/policy_version",
        Comparison::Uncompared {
            shape: "a non-empty string",
            reason: "audit content, as for the first signer's policy version",
        },
        Outcome::Admitted,
        (
            MutationSpec::Literal("\"\""),
            Outcome::Denied(UNVERIFIED_EVIDENCE),
        ),
    ),
    absent(
        "predicate/policy_evaluation_summary/server_b_verdict/rationale_code",
        Comparison::AbsentOptional(
            "the rationale code is optional and this call omits it; the strict profile does not \
             refuse it, so the addition corpus is what reaches it",
        ),
    ),
    with_probe(
        "predicate/policy_evaluation_summary/joint_disposition",
        Comparison::SelfConsistent("the two verdicts it summarizes"),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
        (
            MutationSpec::Literal("\"deny\""),
            Outcome::Denied(UNVERIFIED_EVIDENCE),
        ),
    ),
    // --- predicate, governance receipt reference ------------------------
    rule(
        "predicate/governance_receipt_ref/receipt_id",
        Comparison::SelfConsistent(
            "treaty_binding_ref.governance_refs, which is what the \
             receiver compares against its own admission bundle",
        ),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
    ),
    rule(
        "predicate/governance_receipt_ref/kernel_id",
        Comparison::ReceiverState("the issuer of the governance receipt the receiver activated"),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
    ),
    rule(
        "predicate/governance_receipt_ref/digest/alg",
        Comparison::ReceiverState(
            "the hash algorithm of the governance receipt the receiver activated",
        ),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
    ),
    rule(
        "predicate/governance_receipt_ref/digest/value",
        Comparison::ReceiverState("the digest of the governance receipt the receiver activated"),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
    ),
    rule(
        "predicate/consistency_anchor",
        Comparison::Uncompared {
            shape: ANY_VALUE_OF_ITS_JSON_TYPE,
            reason: "the anchor is carried for the peer's own reconciliation and is not resolved \
                     during admission",
        },
        Outcome::Admitted,
    ),
    // --- predicate, treaty binding reference ----------------------------
    rule(
        "predicate/treaty_binding_ref/treaty_id",
        Comparison::ReceiverState("the identifier of the agreement the receiver resolved"),
        Outcome::Denied(BINDING_MISMATCH),
    ),
    rule(
        "predicate/treaty_binding_ref/treaty_scope_sha256",
        Comparison::ReceiverState("the digest the receiver recomputes over its own agreement"),
        Outcome::Denied(BINDING_MISMATCH),
    ),
    rule(
        "predicate/treaty_binding_ref/ladder_intersection_sha256",
        Comparison::ReceiverState("the digest of the intersection the receiver resolved"),
        Outcome::Denied(BINDING_MISMATCH),
    ),
    with_probe(
        "predicate/treaty_binding_ref/admission_report_sha256",
        Comparison::Uncompared {
            shape: "sixty-four lowercase hex characters",
            reason: "checked for that shape and then overwritten with the digest of the \
                     receiver's own report before that report is signed, so no peer-supplied \
                     value reaches a locally signed receipt",
        },
        Outcome::Admitted,
        (
            MutationSpec::Literal(
                "\"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\"",
            ),
            Outcome::Denied(UNVERIFIED_EVIDENCE),
        ),
    ),
    rule(
        "predicate/treaty_binding_ref/continuation_sha256",
        Comparison::ReceiverState("the digest of the continuation the receiver resolved"),
        Outcome::Denied(BINDING_MISMATCH),
    ),
    conditional(
        "predicate/treaty_binding_ref/lineage_bundle_sha256",
        Comparison::ReceiverState(
            "the digest of the lineage bundle the receiver resolved, when the action class made \
             it resolve one",
        ),
        Outcome::Denied(BINDING_MISMATCH),
        Outcome::Admitted,
    ),
    rule(
        "predicate/treaty_binding_ref/action_class_id",
        Comparison::ReceiverState("the action class the receiver resolved for this request"),
        Outcome::Denied(BINDING_MISMATCH),
    ),
    rule(
        "predicate/treaty_binding_ref/consistency_model",
        Comparison::ReceiverState("the consistency model of the resolved action class"),
        Outcome::Denied(BINDING_MISMATCH),
    ),
    rule(
        "predicate/treaty_binding_ref/request_sha256",
        Comparison::ReceiverState("the canonical argument hash in the receiver's admission bundle"),
        Outcome::Denied(BINDING_MISMATCH),
    ),
    rule(
        "predicate/treaty_binding_ref/outcome_sha256",
        Comparison::ReceiverState(
            "the outcome digest of the invocation record the receiver resolved",
        ),
        Outcome::Denied(BINDING_MISMATCH),
    ),
    rule(
        "predicate/treaty_binding_ref/local_receipt_sha256",
        Comparison::ReceiverState(
            "the root receipt digest of the resolved lineage bundle, and the local receipt digest \
             of the resolved invocation record",
        ),
        Outcome::Denied(BINDING_MISMATCH),
    ),
    rule(
        "predicate/treaty_binding_ref/remote_receipt_sha256",
        Comparison::ReceiverState(
            "the leaf receipt digest of the resolved lineage bundle, and the remote receipt \
             digest of the resolved invocation record",
        ),
        Outcome::Denied(BINDING_MISMATCH),
    ),
    rule(
        "predicate/treaty_binding_ref/lease_refs/0",
        Comparison::ReceiverState("the lease id in the receiver's own admission bundle"),
        Outcome::Denied(BINDING_MISMATCH),
    ),
    rule(
        "predicate/treaty_binding_ref/governance_refs/0",
        Comparison::ReceiverState(
            "the governance receipt id in the receiver's own admission bundle",
        ),
        Outcome::Denied(BINDING_MISMATCH),
    ),
    rule(
        "predicate/treaty_binding_ref/signer_kernel_ids/0",
        Comparison::ReceiverState("the participant set of the resolved agreement"),
        Outcome::Denied(BINDING_MISMATCH),
    ),
    rule(
        "predicate/treaty_binding_ref/signer_kernel_ids/1",
        Comparison::ReceiverState("the participant set of the resolved agreement"),
        Outcome::Denied(BINDING_MISMATCH),
    ),
];

/// The sixteen leaves of the binding reference, as paths. The pair corpus runs
/// over every unordered pair of this set, so the ordered signer list counts as
/// two leaves rather than one.
pub(super) const BINDING_FIELDS: &[&str] = &[
    "predicate/treaty_binding_ref/treaty_id",
    "predicate/treaty_binding_ref/treaty_scope_sha256",
    "predicate/treaty_binding_ref/ladder_intersection_sha256",
    "predicate/treaty_binding_ref/admission_report_sha256",
    "predicate/treaty_binding_ref/continuation_sha256",
    "predicate/treaty_binding_ref/lineage_bundle_sha256",
    "predicate/treaty_binding_ref/action_class_id",
    "predicate/treaty_binding_ref/consistency_model",
    "predicate/treaty_binding_ref/request_sha256",
    "predicate/treaty_binding_ref/outcome_sha256",
    "predicate/treaty_binding_ref/local_receipt_sha256",
    "predicate/treaty_binding_ref/remote_receipt_sha256",
    "predicate/treaty_binding_ref/lease_refs/0",
    "predicate/treaty_binding_ref/governance_refs/0",
    "predicate/treaty_binding_ref/signer_kernel_ids/0",
    "predicate/treaty_binding_ref/signer_kernel_ids/1",
];
