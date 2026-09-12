//! Exhaustive substitution corpus over every leaf a strict
//! `chio.bilateral-cosign-invocation.v1` statement can carry.
//!
//! The corpus is generated from the wire types rather than hand-listed. A
//! maximally populated [`DsseStatement`] is built with exhaustive struct
//! literals, serialized, and walked to its scalar leaves; that leaf set is the
//! set of fields the crossing object can present. Every leaf must appear in
//! [`FIELD_RULES`] with a classification saying what the receiver compares it
//! against, or why it compares nothing, and what a substitution therefore
//! does. Adding a field to the predicate breaks the struct literal, and
//! populating a field the rules do not name fails the totality test, so the
//! comparison set cannot drift without someone classifying the new field.
//!
//! Each exercised leaf is then substituted for real: the value is replaced
//! with a well-formed value of the same JSON type, the statement is re-signed
//! by both participant keys so the envelope stays cryptographically valid over
//! the substituted bytes, and the result is driven through the pre-dispatch
//! admission hook. The observed outcome must equal the declared one. Denials
//! additionally assert that no verified federation material reached dispatch
//! and that the continuation the statement named is still unconsumed.
//!
//! Beyond the single-field cases the corpus runs every pair inside the
//! fifteen-field binding reference, the pairs whose two members duplicate one
//! another across the predicate (where a consistent two-field substitution
//! could pass an internal agreement check that a one-field substitution
//! trips), and the simultaneous substitution of every field the receiver does
//! not compare.

mod support;

use base64::Engine as _;
use chio_core_types::capability::{
    governance::GovernedTransactionIntent,
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair, Signature};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::BoundaryClass, kinds::ReceiptKind, kinds::RedactionMode, kinds::ToolOrigin,
    kinds::TrustLevel, metadata::ActorRef,
};
use chio_federation::bilateral_dsse::{
    pae, sign_chio_bilateral_dsse_envelope, BilateralPredicate, BilateralPredicateExtensions,
    CapabilityLeaseRef, DsseEnvelope, DsseSignature, DsseStatement, GovernanceReceiptRef,
    HashRecord, KernelIdentity, Keyid, PolicyEvaluationSummary, PolicyVerdict, StatementSubject,
    SubjectDigest, TreatyBindingRef, PAYLOAD_TYPE_IN_TOTO,
};
use chio_kernel::{RuntimeAdmissionContext, RuntimeAdmissionHook, ToolCallRequest};
use chio_runtime_core::{
    bilateral_dsse_consistency_model, bilateral_invocation_binding_sha256,
    compute_ladder_intersection, governance_ladder_manifest_sha256, ladder_intersection_sha256,
    runtime_admission_bundle_sha256, runtime_peer_weights_sha256, tool_args_sha256,
    treaty_scope_sha256, BilateralInvocation, ChioRuntimeAdmissionHook, CrossKernelContinuation,
    LadderIntersection, ReceiptLineageBundle, ReceiptLineageStatement, RuntimeAdmissionBundle,
    RuntimeAdmissionProfile, RuntimePeerWeight, RuntimePeerWeights, RuntimePheromoneAdvisory,
    RuntimePheromonePolicy, RuntimePheromonePolicyRule, RuntimeRequestBinding,
    RuntimeTrustedVerifierKey, RuntimeVerifierTrustBundleV4, SqliteRuntimeOrchestrationStore,
    TreatyScope, CHIO_BILATERAL_INVOCATION_SCHEMA, CHIO_CROSS_KERNEL_CONTINUATION_SCHEMA,
    CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA, CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA,
    CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA, CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA,
    CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA, CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA,
    CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA,
};
use serde_json::Value;
use std::io;
use support::treaty::{treaty_action_class, treaty_manifest, treaty_scope};

const BINDING_MISMATCH: &str = "chio_treaty_dsse_binding_mismatch";
const UNVERIFIED_EVIDENCE: &str = "chio_treaty_unverified_required_evidence";
const CONTINUATION_REPLAY: &str = "chio_treaty_continuation_replay";

type TestResult = Result<(), Box<dyn std::error::Error>>;
type BoxError = Box<dyn std::error::Error>;

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// What the receiver does with one leaf of the crossing statement.
#[derive(Clone, Copy)]
enum Comparison {
    /// Compared for equality against the named receiver-held value.
    ReceiverState(&'static str),
    /// Compared against the named receiver-held value as an inequality rather
    /// than for equality, so only values outside the admissible interval are
    /// refused.
    ReceiverBound(&'static str),
    /// Constrained to a fixed value or a fixed domain the receiver holds as
    /// code. A constant is not receiver state: it separates profiles, it does
    /// not bind this call.
    Shape(&'static str),
    /// Checked only for agreement with another field of the same statement.
    /// A consistent substitution of both copies passes this check, so the
    /// pair corpus below is what covers it.
    SelfConsistent(&'static str),
    /// Not compared against anything. The note says why the receiver can
    /// admit a call whose value here was chosen by the sender.
    Uncompared(&'static str),
    /// Required absent from a strict statement, so there is no value to
    /// substitute.
    AbsentByProfile(&'static str),
}

impl Comparison {
    /// The receiver-side value, domain, or reason, as the classification
    /// states it.
    fn against(self) -> &'static str {
        match self {
            Self::ReceiverState(value)
            | Self::ReceiverBound(value)
            | Self::Shape(value)
            | Self::SelfConsistent(value)
            | Self::Uncompared(value)
            | Self::AbsentByProfile(value) => value,
        }
    }

    fn kind(self) -> &'static str {
        match self {
            Self::ReceiverState(_) => "compared against receiver state",
            Self::ReceiverBound(_) => "bounded by receiver state",
            Self::Shape(_) => "constrained to a fixed domain",
            Self::SelfConsistent(_) => "compared with another field of the statement",
            Self::Uncompared(_) => "not compared",
            Self::AbsentByProfile(_) => "absent from a strict statement",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Outcome {
    Admitted,
    Denied(&'static str),
}

struct FieldRule {
    /// Slash-separated path from the statement root. Array elements are
    /// addressed by index.
    path: &'static str,
    comparison: Comparison,
    /// Outcome of substituting the generated value at this path under an
    /// action class that resolves both the receipt lineage bundle and the
    /// bilateral invocation record. `None` means the leaf is not carried by a
    /// strict statement and is therefore not exercised.
    substituted: Option<Outcome>,
    /// Outcome under an action class that resolves no lineage bundle, stated
    /// only where it differs from `substituted`.
    without_lineage: Option<Outcome>,
    /// A second declared value, for leaves where the generated value cannot
    /// separate a domain constraint from a comparison against receiver state.
    probe: Option<(MutationSpec, Outcome)>,
}

const fn rule(path: &'static str, comparison: Comparison, substituted: Outcome) -> FieldRule {
    FieldRule {
        path,
        comparison,
        substituted: Some(substituted),
        without_lineage: None,
        probe: None,
    }
}

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
const FIELD_RULES: &[FieldRule] = &[
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
        Comparison::Uncompared(
            "the strict admission path binds the receipts through \
             treaty_binding_ref.local_receipt_sha256 and remote_receipt_sha256, which are \
             compared against the lineage bundle and the invocation record; the subject digest \
             itself is compared against nothing the receiver holds",
        ),
        Outcome::Admitted,
    ),
    // --- predicate, identity and shape ----------------------------------
    absent(
        "predicate/schema",
        Comparison::AbsentByProfile(
            "strict predicates carry no schema discriminator; predicateType is the \
             verifier-facing one",
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
        Comparison::Uncompared(
            "the presentation window is enforced by the continuation, the lease, and the \
             agreement intervals, all of which the receiver holds; the statement's own timestamp \
             is not read by admission",
        ),
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
        Comparison::AbsentByProfile(
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
    rule(
        "predicate/capability_lease_ref/issuer",
        Comparison::ReceiverState("the two participant kernel ids of the resolved agreement"),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
    ),
    with_probe(
        "predicate/capability_lease_ref/expires_at_unix_ms",
        Comparison::ReceiverBound("the receiver's clock, as a strict lower bound"),
        Outcome::Admitted,
        (
            MutationSpec::Literal("1"),
            Outcome::Denied(UNVERIFIED_EVIDENCE),
        ),
    ),
    absent(
        "predicate/capability_lease_ref/scope_digest/alg",
        Comparison::AbsentByProfile("the optional lease scope digest is not present in this call"),
    ),
    absent(
        "predicate/capability_lease_ref/scope_digest/value",
        Comparison::AbsentByProfile("the optional lease scope digest is not present in this call"),
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
    rule(
        "predicate/policy_evaluation_summary/server_a_verdict/policy_id",
        Comparison::Uncompared(
            "the receiver does not resolve either party's policy identity; the verdict it acts on \
             is its own, and this field is audit content",
        ),
        Outcome::Admitted,
    ),
    rule(
        "predicate/policy_evaluation_summary/server_a_verdict/policy_version",
        Comparison::Uncompared("audit content, as for the policy id"),
        Outcome::Admitted,
    ),
    absent(
        "predicate/policy_evaluation_summary/server_a_verdict/rationale_code",
        Comparison::AbsentByProfile("the optional rationale code is not present in this call"),
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
    rule(
        "predicate/policy_evaluation_summary/server_b_verdict/policy_id",
        Comparison::Uncompared("audit content, as for the first signer's policy id"),
        Outcome::Admitted,
    ),
    rule(
        "predicate/policy_evaluation_summary/server_b_verdict/policy_version",
        Comparison::Uncompared("audit content, as for the first signer's policy version"),
        Outcome::Admitted,
    ),
    absent(
        "predicate/policy_evaluation_summary/server_b_verdict/rationale_code",
        Comparison::AbsentByProfile("the optional rationale code is not present in this call"),
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
        Comparison::Uncompared(
            "the governance receipt the receiver acts on is the one its own admission bundle \
             names; the issuing kernel recorded here is audit content",
        ),
        Outcome::Admitted,
    ),
    rule(
        "predicate/governance_receipt_ref/digest/alg",
        Comparison::Uncompared("audit content, as for the governance kernel id"),
        Outcome::Admitted,
    ),
    rule(
        "predicate/governance_receipt_ref/digest/value",
        Comparison::Uncompared(
            "the receiver resolves the governance receipt by id from its own store and never \
             compares this digest against the record it resolved",
        ),
        Outcome::Admitted,
    ),
    rule(
        "predicate/consistency_anchor",
        Comparison::Uncompared(
            "the anchor is carried for the peer's own reconciliation and is not resolved during \
             admission",
        ),
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
    rule(
        "predicate/treaty_binding_ref/admission_report_sha256",
        Comparison::Uncompared(
            "required to be 64 lowercase hex and then overwritten with the digest of the \
             receiver's own report before that report is signed, so no peer-supplied value \
             reaches a locally signed receipt",
        ),
        Outcome::Admitted,
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

/// The fifteen fields of the binding reference, as paths. The pair corpus runs
/// over this set.
const BINDING_FIELDS: &[&str] = &[
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
];

/// Cases whose leaves duplicate one another across the statement. A
/// single-field substitution trips the internal agreement check between the
/// two copies; rewriting both consistently passes it, and what is left is the
/// comparison against receiver state. These are the cases where one check
/// could mask another.
struct MaskingCase {
    id: &'static str,
    mutations: &'static [(&'static str, MutationSpec)],
    expected: Outcome,
    note: &'static str,
}

const MASKING_CASES: &[MaskingCase] = &[
    MaskingCase {
        id: "invocation identity and subject name",
        mutations: &[
            ("predicate/invocation_id", MutationSpec::Generated),
            (
                "subject/0/name",
                MutationSpec::Prefixed {
                    from: "predicate/invocation_id",
                    prefix: "chio-receipt:",
                },
            ),
        ],
        expected: Outcome::Admitted,
        note: "the invocation id is the identifier of the receipt the statement is about and the \
               subject name is its receipt-subject form; the two agree after the rewrite, and \
               neither is compared against the invocation record the receiver resolved",
    },
    MaskingCase {
        id: "both copies of the consistency model",
        mutations: &[
            ("predicate/consistency_model", MutationSpec::Generated),
            (
                "predicate/treaty_binding_ref/consistency_model",
                MutationSpec::Generated,
            ),
        ],
        expected: Outcome::Denied(BINDING_MISMATCH),
        note: "the inner copy is still compared against the resolved action class",
    },
    MaskingCase {
        id: "both copies of the request digest",
        mutations: &[
            ("predicate/tool_args_hash/value", MutationSpec::Generated),
            (
                "predicate/treaty_binding_ref/request_sha256",
                MutationSpec::Generated,
            ),
        ],
        expected: Outcome::Denied(BINDING_MISMATCH),
        note: "the two request digests agree after the rewrite, so the internal cross-check \
               passes and the comparison against the receiver's admission bundle is what denies",
    },
    MaskingCase {
        id: "both copies of the lease id",
        mutations: &[
            (
                "predicate/capability_lease_ref/lease_id",
                MutationSpec::Generated,
            ),
            (
                "predicate/treaty_binding_ref/lease_refs/0",
                MutationSpec::Generated,
            ),
        ],
        expected: Outcome::Denied(BINDING_MISMATCH),
        note: "the lease id agrees with the binding reference after the rewrite, and the \
               receiver's own admission bundle is what denies",
    },
    MaskingCase {
        id: "both copies of the governance receipt id",
        mutations: &[
            (
                "predicate/governance_receipt_ref/receipt_id",
                MutationSpec::Generated,
            ),
            (
                "predicate/treaty_binding_ref/governance_refs/0",
                MutationSpec::Generated,
            ),
        ],
        expected: Outcome::Denied(BINDING_MISMATCH),
        note: "as for the lease id, with the governance receipt id",
    },
    MaskingCase {
        id: "the origin kernel in both the signer list and the identity block",
        mutations: &[
            ("predicate/tool_server_a/kernel_id", MutationSpec::Generated),
            (
                "predicate/treaty_binding_ref/signer_kernel_ids/0",
                MutationSpec::Generated,
            ),
        ],
        expected: Outcome::Denied(BINDING_MISMATCH),
        note: "the signer list agrees with the named kernels after the rewrite, and the \
               participant set of the resolved agreement is what denies",
    },
    MaskingCase {
        id: "the receiving kernel in both the signer list and the identity block",
        mutations: &[
            ("predicate/tool_server_b/kernel_id", MutationSpec::Generated),
            (
                "predicate/treaty_binding_ref/signer_kernel_ids/1",
                MutationSpec::Generated,
            ),
        ],
        expected: Outcome::Denied(BINDING_MISMATCH),
        note: "as for the origin kernel",
    },
    MaskingCase {
        id: "two leaves the receiver does not compare",
        mutations: &[
            ("subject/0/digest/sha256", MutationSpec::Generated),
            (
                "predicate/treaty_binding_ref/admission_report_sha256",
                MutationSpec::Generated,
            ),
        ],
        expected: Outcome::Admitted,
        note: "moving two uncompared leaves at once is admitted, which is the residual an \
               adversary holding both signing keys can choose",
    },
];

// ---------------------------------------------------------------------------
// Totality of the classification
// ---------------------------------------------------------------------------

/// Every leaf the wire types can carry is classified, and every classification
/// names a leaf the wire types can carry. The maximal statement is built with
/// exhaustive struct literals, so a field added to the predicate stops this
/// file compiling until it is constructed, and stops this test passing until
/// it is classified.
#[test]
fn every_statement_leaf_is_classified() -> TestResult {
    let maximal = serde_json::to_value(maximal_statement())?;
    let mut leaves = leaf_paths(&maximal);
    leaves.sort();
    let mut classified: Vec<String> = FIELD_RULES
        .iter()
        .map(|rule| rule.path.to_string())
        .collect();
    classified.sort();
    assert_eq!(
        leaves, classified,
        "the classification must cover exactly the leaves a bilateral statement can carry"
    );
    let mut seen = std::collections::BTreeSet::new();
    for rule in FIELD_RULES {
        assert!(
            seen.insert(rule.path),
            "duplicate classification for {}",
            rule.path
        );
        assert!(
            !rule.comparison.against().is_empty(),
            "{} must say what it is compared against, or why it is not",
            rule.path
        );
        match (rule.comparison, rule.substituted) {
            (Comparison::AbsentByProfile(_), Some(_)) => {
                panic!("{} is classified absent but declares an outcome", rule.path)
            }
            (Comparison::AbsentByProfile(_), None) => {}
            (_, None) => panic!("{} declares no substitution outcome", rule.path),
            (Comparison::Uncompared(_), Some(outcome)) => assert_eq!(
                outcome,
                Outcome::Admitted,
                "{} is classified uncompared, so its substitution must be admitted",
                rule.path
            ),
            (Comparison::ReceiverBound(_), Some(_)) => assert!(
                rule.probe.is_some(),
                "{} is bounded rather than compared for equality, so it needs a declared value \
                 outside the bound",
                rule.path
            ),
            (_, Some(outcome)) => assert!(
                matches!(outcome, Outcome::Denied(_)),
                "{} is classified as compared, so its substitution must be denied",
                rule.path
            ),
        }
        println!(
            "{}\t{}\t{}\t{:?}",
            rule.path,
            rule.comparison.kind(),
            rule.comparison.against(),
            rule.substituted
        );
    }
    Ok(())
}

/// The leaves a strict statement actually carries are exactly the classified
/// leaves that the corpus exercises. A field the profile requires to be absent
/// has no case; a field this call populates must have one.
#[test]
fn the_exercised_leaves_are_the_leaves_a_strict_statement_carries() -> TestResult {
    let fixture = treaty_fixture(Evidence::LineageAndRecord)?;
    let (statement, _) = fixture.envelope.decode_statement()?;
    let mut present = leaf_paths(&serde_json::to_value(&statement)?);
    present.sort();
    let mut exercised: Vec<String> = FIELD_RULES
        .iter()
        .filter(|rule| rule.substituted.is_some())
        .map(|rule| rule.path.to_string())
        .collect();
    exercised.sort();
    assert_eq!(
        present, exercised,
        "every leaf of the statement under test must be exercised, and only those"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Single-field corpus
// ---------------------------------------------------------------------------

/// Substitute each leaf in turn and check the observed outcome against the
/// declared one, on the action class that resolves both the lineage bundle and
/// the invocation record.
#[test]
fn single_field_substitutions_match_their_classification() -> TestResult {
    for rule in FIELD_RULES {
        let Some(expected) = rule.substituted else {
            continue;
        };
        let run = admit_with(
            Evidence::LineageAndRecord,
            &[(rule.path, MutationSpec::Generated)],
        )?;
        assert_outcome(&run, expected, rule.path, "generated substitution");
        if let Some((spec, probe_expected)) = rule.probe {
            let probe = admit_with(Evidence::LineageAndRecord, &[(rule.path, spec)])?;
            assert_outcome(&probe, probe_expected, rule.path, &spec.describe());
        }
    }
    Ok(())
}

/// The same corpus against an action class that resolves no lineage bundle.
/// The four conditional comparisons in the binding reference are the ones that
/// can differ, and the declared difference is checked here rather than argued.
#[test]
fn single_field_substitutions_match_their_classification_without_lineage() -> TestResult {
    for rule in FIELD_RULES {
        let Some(default) = rule.substituted else {
            continue;
        };
        let expected = rule.without_lineage.unwrap_or(default);
        let run = admit_with(
            Evidence::RecordOnly,
            &[(rule.path, MutationSpec::Generated)],
        )?;
        assert_outcome(
            &run,
            expected,
            rule.path,
            "generated substitution, no lineage bundle",
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Multi-field corpus
// ---------------------------------------------------------------------------

/// All 105 pairs inside the fifteen-field binding reference. Exactly one of
/// the fifteen is not compared, so every pair contains at least one compared
/// field and every pair must be denied without dispatch. A pair that admitted
/// would be one comparison masking another.
#[test]
fn every_pair_inside_the_binding_reference_is_rejected() -> TestResult {
    let mut pairs = 0usize;
    for (index, left) in BINDING_FIELDS.iter().enumerate() {
        for right in BINDING_FIELDS.iter().skip(index + 1) {
            let run = admit_with(
                Evidence::LineageAndRecord,
                &[
                    (left, MutationSpec::Generated),
                    (right, MutationSpec::Generated),
                ],
            )?;
            assert!(
                !run.substituted.allowed,
                "substituting {left} and {right} together must not be admitted"
            );
            assert!(
                !run.substituted.verified_treaty_material,
                "a denied admission must hand no verified treaty material to dispatch"
            );
            assert!(
                run.baseline_after.allowed,
                "substituting {left} and {right} together must not consume the continuation: {:?}",
                run.baseline_after.failure_code
            );
            pairs += 1;
        }
    }
    assert_eq!(
        pairs,
        BINDING_FIELDS.len() * (BINDING_FIELDS.len() - 1) / 2,
        "the pair corpus must cover every unordered pair of binding fields"
    );
    Ok(())
}

/// Cases whose leaves duplicate one another across the statement, rewritten
/// consistently so the statement's internal agreement checks pass. What is
/// left is the comparison against receiver state, and these cases record
/// whether it is there.
#[test]
fn duplicated_leaves_do_not_mask_the_receiver_comparison() -> TestResult {
    for case in MASKING_CASES {
        let run = admit_with(Evidence::LineageAndRecord, case.mutations)?;
        assert_outcome(&run, case.expected, case.id, case.note);
    }
    Ok(())
}

/// Every leaf whose single substitution is admitted, substituted at once. This
/// is the exact residual of the comparison set: a statement in which all of
/// these were chosen by whoever holds the two signing keys is admitted and
/// dispatches. It is stated as a test rather than as prose because it is what
/// the completeness argument leaves on the table.
#[test]
fn the_uncompared_leaves_substituted_together_are_still_admitted() -> TestResult {
    let mutations: Vec<(&str, MutationSpec)> = FIELD_RULES
        .iter()
        .filter(|rule| rule.substituted == Some(Outcome::Admitted))
        .map(|rule| (rule.path, MutationSpec::Generated))
        .collect();
    assert!(
        mutations.len() >= 8,
        "the uncompared set should not silently shrink to nothing: {}",
        mutations.len()
    );
    let run = admit_with(Evidence::LineageAndRecord, &mutations)?;
    assert!(
        run.substituted.allowed,
        "substituting every uncompared leaf at once must still admit: {:?}",
        run.substituted.failure_code
    );
    assert!(run.substituted.verified_treaty_material);
    assert_eq!(
        run.baseline_after.failure_code.as_deref(),
        Some(CONTINUATION_REPLAY),
        "an admitted substitution must have consumed the continuation it named"
    );
    Ok(())
}

/// The unsubstituted statement admits and consumes its continuation, which is
/// the counterfactual every denial above rests on.
#[test]
fn the_unsubstituted_statement_is_admitted_and_consumes_its_continuation() -> TestResult {
    let run = admit_with(Evidence::LineageAndRecord, &[])?;
    assert!(
        run.substituted.allowed,
        "the unsubstituted statement must admit: {:?}",
        run.substituted.failure_code
    );
    assert!(run.substituted.verified_treaty_material);
    assert_eq!(
        run.baseline_after.failure_code.as_deref(),
        Some(CONTINUATION_REPLAY)
    );

    let without_lineage = admit_with(Evidence::RecordOnly, &[])?;
    assert!(
        without_lineage.substituted.allowed,
        "the unsubstituted statement must admit without a lineage bundle too: {:?}",
        without_lineage.substituted.failure_code
    );
    Ok(())
}

fn assert_outcome(run: &SubstitutionRun, expected: Outcome, path: &str, label: &str) {
    match expected {
        Outcome::Admitted => {
            assert!(
                run.substituted.allowed,
                "{path} ({label}) was declared uncompared but was denied: {:?}",
                run.substituted.failure_code
            );
            assert!(
                run.substituted.verified_treaty_material,
                "{path} ({label}) was admitted without verified treaty material"
            );
            assert_eq!(
                run.baseline_after.failure_code.as_deref(),
                Some(CONTINUATION_REPLAY),
                "{path} ({label}) was admitted, so it must have consumed the continuation"
            );
        }
        Outcome::Denied(code) => {
            assert!(
                !run.substituted.allowed,
                "{path} ({label}) was declared compared but was admitted"
            );
            assert_eq!(
                run.substituted.failure_code.as_deref(),
                Some(code),
                "{path} ({label}) denied with an unexpected code"
            );
            assert!(
                !run.substituted.verified_treaty_material,
                "{path} ({label}) was denied but handed verified treaty material to dispatch"
            );
            assert!(
                run.baseline_after.allowed,
                "{path} ({label}) was denied, so it must not have consumed the continuation: {:?}",
                run.baseline_after.failure_code
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Leaf enumeration and substitution
// ---------------------------------------------------------------------------

/// Every scalar leaf of a JSON value, as slash-separated paths with array
/// elements addressed by index.
fn leaf_paths(value: &Value) -> Vec<String> {
    let mut out = Vec::new();
    collect_leaf_paths(value, &mut String::new(), &mut out);
    out
}

fn collect_leaf_paths(value: &Value, prefix: &mut String, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let restore = prefix.len();
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(key);
                collect_leaf_paths(child, prefix, out);
                prefix.truncate(restore);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let restore = prefix.len();
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(&index.to_string());
                collect_leaf_paths(child, prefix, out);
                prefix.truncate(restore);
            }
        }
        _ => out.push(prefix.clone()),
    }
}

/// How one leaf is replaced.
#[derive(Clone, Copy)]
enum MutationSpec {
    /// A well-formed value of the same JSON type, derived from the value it
    /// replaces: a different digest for a 64-character lowercase hex string, a
    /// suffixed string otherwise, the successor of a number, the negation of a
    /// boolean.
    Generated,
    /// A value declared by the classification, as a JSON literal, for leaves
    /// where the generated value cannot separate a domain constraint from a
    /// comparison against receiver state.
    Literal(&'static str),
    /// The prefix followed by whatever value another leaf now holds, for the
    /// leaves that are required to be a decorated copy of another. It is
    /// applied after the leaf it reads, so the pair stays consistent.
    Prefixed {
        from: &'static str,
        prefix: &'static str,
    },
}

impl MutationSpec {
    fn describe(self) -> String {
        match self {
            Self::Generated => "generated substitution".to_string(),
            Self::Literal(text) => format!("declared value {text}"),
            Self::Prefixed { from, prefix } => {
                format!("{prefix} followed by the substituted {from}")
            }
        }
    }
}

fn generated_substitution(value: &Value) -> Result<Value, BoxError> {
    Ok(match value {
        Value::String(text) if is_sha256_hex(text) => {
            Value::String(sha256_hex(format!("substituted:{text}").as_bytes()))
        }
        Value::String(text) => Value::String(format!("{text}-substituted")),
        Value::Number(number) => {
            let Some(integer) = number.as_u64() else {
                return Err(Box::new(io::Error::other(
                    "only unsigned integers appear as numeric leaves of a bilateral statement",
                )));
            };
            Value::Number(integer.saturating_add(1).into())
        }
        Value::Bool(flag) => Value::Bool(!flag),
        other => {
            return Err(Box::new(io::Error::other(format!(
                "no substitution is defined for the leaf value {other}"
            ))))
        }
    })
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn value_at<'a>(root: &'a Value, path: &str) -> Result<&'a Value, BoxError> {
    let mut cursor = root;
    for segment in path.split('/') {
        cursor = match cursor {
            Value::Object(map) => map
                .get(segment)
                .ok_or_else(|| io::Error::other(format!("no leaf at {path}")))?,
            Value::Array(items) => {
                let index: usize = segment.parse()?;
                items
                    .get(index)
                    .ok_or_else(|| io::Error::other(format!("no leaf at {path}")))?
            }
            _ => return Err(Box::new(io::Error::other(format!("no leaf at {path}")))),
        };
    }
    Ok(cursor)
}

fn set_value_at(root: &mut Value, path: &str, replacement: Value) -> Result<(), BoxError> {
    let mut cursor = root;
    let segments: Vec<&str> = path.split('/').collect();
    let Some((last, leading)) = segments.split_last() else {
        return Err(Box::new(io::Error::other("empty substitution path")));
    };
    for segment in leading {
        cursor = match cursor {
            Value::Object(map) => map
                .get_mut(*segment)
                .ok_or_else(|| io::Error::other(format!("no leaf at {path}")))?,
            Value::Array(items) => {
                let index: usize = segment.parse()?;
                items
                    .get_mut(index)
                    .ok_or_else(|| io::Error::other(format!("no leaf at {path}")))?
            }
            _ => return Err(Box::new(io::Error::other(format!("no leaf at {path}")))),
        };
    }
    match cursor {
        Value::Object(map) => {
            let slot = map
                .get_mut(*last)
                .ok_or_else(|| io::Error::other(format!("no leaf at {path}")))?;
            *slot = replacement;
        }
        Value::Array(items) => {
            let index: usize = last.parse()?;
            let slot = items
                .get_mut(index)
                .ok_or_else(|| io::Error::other(format!("no leaf at {path}")))?;
            *slot = replacement;
        }
        _ => return Err(Box::new(io::Error::other(format!("no leaf at {path}")))),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

struct DecisionSummary {
    allowed: bool,
    failure_code: Option<String>,
    verified_treaty_material: bool,
}

struct SubstitutionRun {
    substituted: DecisionSummary,
    baseline_after: DecisionSummary,
}

/// Which artifacts the action class makes the admission resolve.
#[derive(Clone, Copy)]
enum Evidence {
    /// The class names the receipt lineage bundle and the invocation record,
    /// so every conditional comparison runs.
    LineageAndRecord,
    /// The class names only the co-signed statement. No lineage bundle is
    /// resolved. The invocation record is still forced into the required
    /// evidence by the class's co-signing mode.
    RecordOnly,
}

/// Apply the substitutions to the statement, re-sign it with both participant
/// keys over its own pre-authentication bytes, and drive the pre-dispatch
/// hook. The unsubstituted bundle is then driven against the same store, so a
/// caller can see whether the substituted admission consumed the single-use
/// continuation.
fn admit_with(
    evidence: Evidence,
    mutations: &[(&str, MutationSpec)],
) -> Result<SubstitutionRun, BoxError> {
    let fixture = treaty_fixture(evidence)?;
    let substituted_envelope = resign_with_substitutions(&fixture, mutations)?;
    assert_envelope_signatures_valid(&fixture, &substituted_envelope)?;

    let directory = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(
        directory.path().join("predicate-substitution.sqlite3"),
    )?;
    let arguments = tool_arguments();
    let mut admission_bundle = bundle();
    admission_bundle.binding.tool_args_sha256 = tool_args_sha256(&arguments)?;
    let bundle_sha256 = runtime_admission_bundle_sha256(&admission_bundle)?;
    store.insert_bundle(admission_bundle)?;
    insert_treaty_artifacts(&store, &fixture)?;

    let substituted_sha256 = sha256_hex(&canonical_json_bytes(&substituted_envelope)?);
    store.insert_treaty_runtime_artifact(
        "bilateral_dsse_envelope",
        SUBSTITUTED_DSSE_ID,
        &substituted_envelope,
    )?;

    let hook = allowing_hook(store)?;
    let substituted_request = treaty_request(
        arguments.clone(),
        bundle_sha256.clone(),
        treaty_context(&fixture, SUBSTITUTED_DSSE_ID, &substituted_sha256),
    )?;
    let substituted = summarize(hook.evaluate(&admission_context(&substituted_request))?);

    let baseline_request = treaty_request(
        arguments,
        bundle_sha256,
        treaty_context(&fixture, BASELINE_DSSE_ID, &fixture.envelope_sha256),
    )?;
    let baseline_after = summarize(hook.evaluate(&admission_context(&baseline_request))?);

    Ok(SubstitutionRun {
        substituted,
        baseline_after,
    })
}

fn summarize(decision: chio_kernel::RuntimeAdmissionDecision) -> DecisionSummary {
    let metadata = decision.metadata.clone().unwrap_or(Value::Null);
    DecisionSummary {
        allowed: decision.allowed,
        failure_code: metadata["chio_runtime"]["failure_code"]
            .as_str()
            .map(std::string::ToString::to_string),
        verified_treaty_material: decision.has_verified_treaty_material(),
    }
}

fn admission_context(request: &ToolCallRequest) -> RuntimeAdmissionContext<'_> {
    RuntimeAdmissionContext {
        request,
        extra_metadata: None,
        now_unix_secs: 1_800_000_001,
        now_unix_ms: 1_800_000_001_000,
        matched_grant_index: Some(0),
        local_kernel_id: "kernel.vendor-b".to_string(),
    }
}

/// Apply the substitutions and sign the resulting statement with both
/// participant keys. The producer API refuses many of these statements at
/// construction time, so the statement is encoded and signed directly, which
/// is what an adversary holding both keys would do.
fn resign_with_substitutions(
    fixture: &TreatyFixture,
    mutations: &[(&str, MutationSpec)],
) -> Result<DsseEnvelope, BoxError> {
    let (statement, _) = fixture.envelope.decode_statement()?;
    let mut document = serde_json::to_value(&statement)?;
    for (path, spec) in mutations {
        let replacement = match spec {
            MutationSpec::Generated => generated_substitution(value_at(&document, path)?)?,
            MutationSpec::Literal(text) => serde_json::from_str(text)?,
            MutationSpec::Prefixed { from, prefix } => {
                let source = value_at(&document, from)?.as_str().ok_or_else(|| {
                    io::Error::other(format!("{from} is not a string, so {path} cannot copy it"))
                })?;
                Value::String(format!("{prefix}{source}"))
            }
        };
        set_value_at(&mut document, path, replacement)?;
    }
    let substituted: DsseStatement = serde_json::from_value(document)?;
    let statement_bytes = substituted.canonical_bytes()?;
    let pae_bytes = pae(PAYLOAD_TYPE_IN_TOTO, &statement_bytes);
    Ok(DsseEnvelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_string(),
        payload: base64::engine::general_purpose::STANDARD.encode(&statement_bytes),
        signatures: vec![
            dsse_signature(&fixture.signer_a, &pae_bytes),
            dsse_signature(&fixture.signer_b, &pae_bytes),
        ],
    })
}

fn dsse_signature(keypair: &Keypair, pae_bytes: &[u8]) -> DsseSignature {
    DsseSignature {
        keyid: Keyid::from_public_key(&keypair.public_key()).0,
        sig: base64::engine::general_purpose::STANDARD.encode(keypair.sign(pae_bytes).to_bytes()),
    }
}

/// Both participant keys signed the substituted pre-authentication bytes, so
/// every denial is a comparison rather than a broken signature.
fn assert_envelope_signatures_valid(
    fixture: &TreatyFixture,
    envelope: &DsseEnvelope,
) -> TestResult {
    let pae_bytes = envelope.pae_bytes()?;
    for (keypair, signature) in [
        (&fixture.signer_a, &envelope.signatures[0]),
        (&fixture.signer_b, &envelope.signatures[1]),
    ] {
        let decoded = base64::engine::general_purpose::STANDARD.decode(signature.sig.as_bytes())?;
        let bytes: [u8; 64] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| io::Error::other("re-signed envelope signature is not 64 bytes"))?;
        assert!(
            keypair
                .public_key()
                .verify(&pae_bytes, &Signature::from_bytes(&bytes)),
            "re-signed envelope must verify under the participant key that signed it"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Maximal statement
// ---------------------------------------------------------------------------

/// A statement populated in every field the wire types admit, including the
/// optional fields a strict predicate refuses. Nothing signs or verifies this
/// value: it exists so that the leaf set of the classification is derived from
/// the types. The exhaustive struct literals are the enforcement point. A
/// field added to any of these types stops this file compiling.
fn maximal_statement() -> DsseStatement {
    DsseStatement {
        statement_type: "https://in-toto.io/Statement/v1".to_string(),
        subject: vec![StatementSubject {
            name: "chio-receipt:maximal".to_string(),
            digest: SubjectDigest {
                sha256: "0".repeat(64),
            },
        }],
        predicate_type: "chio.bilateral-cosign-invocation.v1".to_string(),
        predicate: BilateralPredicate {
            schema: Some("chio.bilateral-signature-slice.v1".to_string()),
            invocation_id: "maximal".to_string(),
            tool_server_a: KernelIdentity {
                kernel_id: "kernel.a".to_string(),
                passport_key_fingerprint: Keyid("1".repeat(64)),
                alg: "ed25519".to_string(),
            },
            tool_server_b: KernelIdentity {
                kernel_id: "kernel.b".to_string(),
                passport_key_fingerprint: Keyid("2".repeat(64)),
                alg: "ed25519".to_string(),
            },
            tool_name: "close_account".to_string(),
            co_sign: "bilateral_required".to_string(),
            consistency_model: "totally-ordered".to_string(),
            cross_org_visibility: "treaty_only".to_string(),
            timestamp_unix_ms: 1,
            tool_args_hash: Some(HashRecord {
                alg: "sha256".to_string(),
                value: "3".repeat(64),
            }),
            receipt_canonical_json: Some("{}".to_string()),
            capability_lease_ref: Some(CapabilityLeaseRef {
                lease_id: "lease".to_string(),
                issuer: "kernel.a".to_string(),
                expires_at_unix_ms: 2,
                scope_digest: Some(HashRecord {
                    alg: "sha256".to_string(),
                    value: "4".repeat(64),
                }),
            }),
            policy_evaluation_summary: Some(PolicyEvaluationSummary {
                server_a_verdict: PolicyVerdict {
                    verdict: "allow".to_string(),
                    policy_id: "policy-a".to_string(),
                    policy_version: "v1".to_string(),
                    rationale_code: Some("ok".to_string()),
                },
                server_b_verdict: PolicyVerdict {
                    verdict: "allow".to_string(),
                    policy_id: "policy-b".to_string(),
                    policy_version: "v1".to_string(),
                    rationale_code: Some("ok".to_string()),
                },
                joint_disposition: Some("allow".to_string()),
            }),
            governance_receipt_ref: Some(GovernanceReceiptRef {
                receipt_id: "gov".to_string(),
                kernel_id: "kernel.b".to_string(),
                digest: HashRecord {
                    alg: "sha256".to_string(),
                    value: "5".repeat(64),
                },
            }),
            consistency_anchor: Some("anchor".to_string()),
            treaty_binding_ref: Some(TreatyBindingRef {
                treaty_id: "treaty".to_string(),
                treaty_scope_sha256: "6".repeat(64),
                ladder_intersection_sha256: "7".repeat(64),
                admission_report_sha256: "8".repeat(64),
                continuation_sha256: "9".repeat(64),
                lineage_bundle_sha256: "a".repeat(64),
                action_class_id: "workflow.destructive.vendor_call".to_string(),
                consistency_model: "totally-ordered".to_string(),
                request_sha256: "b".repeat(64),
                outcome_sha256: "c".repeat(64),
                local_receipt_sha256: "d".repeat(64),
                remote_receipt_sha256: "e".repeat(64),
                lease_refs: vec!["lease".to_string()],
                governance_refs: vec!["gov".to_string()],
                signer_kernel_ids: vec!["kernel.a".to_string(), "kernel.b".to_string()],
            }),
        },
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

const BASELINE_DSSE_ID: &str = "bilateral-dsse-predicate-substitution";
const SUBSTITUTED_DSSE_ID: &str = "bilateral-dsse-predicate-substituted";

struct TreatyFixture {
    evidence: Evidence,
    signer_a: Keypair,
    signer_b: Keypair,
    treaty_scope: TreatyScope,
    treaty_scope_sha256: String,
    ladder_intersection: LadderIntersection,
    ladder_intersection_sha256: String,
    continuation: CrossKernelContinuation,
    continuation_sha256: String,
    lineage_bundle: ReceiptLineageBundle,
    lineage_bundle_sha256: String,
    bilateral_invocation: BilateralInvocation,
    bilateral_invocation_sha256: String,
    envelope: DsseEnvelope,
    envelope_sha256: String,
}

fn tool_arguments() -> Value {
    serde_json::json!({"record": "vendor-ledger-7", "value": "closed"})
}

fn treaty_fixture(evidence: Evidence) -> Result<TreatyFixture, BoxError> {
    let evidence_required = match evidence {
        Evidence::LineageAndRecord => {
            vec!["bilateral_dsse", "bilateral_invocation", "receipt_lineage"]
        }
        Evidence::RecordOnly => vec!["bilateral_dsse"],
    };
    let buyer = treaty_manifest(
        "kernel.buyer",
        treaty_action_class(
            "receipt_backed",
            true,
            "totally_ordered",
            evidence_required.clone(),
        ),
    );
    let vendor = treaty_manifest(
        "kernel.vendor-b",
        treaty_action_class("receipt_backed", true, "totally_ordered", evidence_required),
    );
    let signer_a = Keypair::generate();
    let signer_b = Keypair::generate();
    let mut treaty_scope = treaty_scope();
    treaty_scope.participant_public_keys = vec![signer_a.public_key(), signer_b.public_key()];
    treaty_scope.ladder_manifest_sha256s = vec![
        governance_ladder_manifest_sha256(&buyer)?,
        governance_ladder_manifest_sha256(&vendor)?,
    ];
    let treaty_scope_sha256 = treaty_scope_sha256(&treaty_scope)?;
    let ladder_intersection =
        compute_ladder_intersection(&treaty_scope, &[buyer, vendor], 1_800_000_001_000)?;
    let ladder_intersection_sha256 = ladder_intersection_sha256(&ladder_intersection)?;

    let continuation = CrossKernelContinuation {
        schema: CHIO_CROSS_KERNEL_CONTINUATION_SCHEMA.to_string(),
        continuation_id: "continue-predicate-substitution-1".to_string(),
        source_kernel_id: "kernel.buyer".to_string(),
        target_kernel_id: "kernel.vendor-b".to_string(),
        parent_receipt_sha256: "1".repeat(64),
        parent_session_anchor_sha256: "2".repeat(64),
        capability_id: "cap-live-1".to_string(),
        action_class_id: "workflow.destructive.vendor_call".to_string(),
        audience_tool: "vendor-ledger.close_account".to_string(),
        nonce: "nonce-predicate-substitution-1".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
    };
    let continuation_sha256 = sha256_hex(&canonical_json_bytes(&continuation)?);

    let mut bilateral_invocation = BilateralInvocation {
        schema: CHIO_BILATERAL_INVOCATION_SCHEMA.to_string(),
        invocation_id: "invoke-predicate-substitution-1".to_string(),
        treaty_id: treaty_scope.treaty_id.clone(),
        ladder_intersection_sha256: ladder_intersection_sha256.clone(),
        continuation_sha256: continuation_sha256.clone(),
        lineage_statement_sha256: String::new(),
        action_class_id: continuation.action_class_id.clone(),
        consistency_model: "totally_ordered".to_string(),
        capability_id: continuation.capability_id.clone(),
        request_sha256: tool_args_sha256(&tool_arguments())?,
        outcome_sha256: "5".repeat(64),
        local_receipt_sha256: continuation.parent_receipt_sha256.clone(),
        remote_receipt_sha256: String::new(),
        signer_kernel_ids: vec!["kernel.buyer".to_string(), "kernel.vendor-b".to_string()],
    };

    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: bilateral_invocation.invocation_id.clone(),
            timestamp: 1_800_000_001,
            capability_id: bilateral_invocation.capability_id.clone(),
            tool_server: "vendor-ledger".to_string(),
            tool_name: "close_account".to_string(),
            action: ToolCallAction::from_parameters(tool_arguments())?,
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: vec![ActorRef {
                actor_id: "agent:chio-runtime/admission".to_string(),
                actor_kind: Some("agent".to_string()),
            }],
            content_hash: bilateral_invocation.outcome_sha256.clone(),
            policy_hash: "policy-live".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: signer_b.public_key(),
            bbs_projection_version: None,
        },
        &signer_b,
    )?;
    bilateral_invocation.remote_receipt_sha256 = sha256_hex(&canonical_json_bytes(&receipt)?);
    let bilateral_invocation_sha256 = bilateral_invocation_binding_sha256(&bilateral_invocation)?;

    let lineage_statement = ReceiptLineageStatement {
        schema: CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
        statement_id: "lineage-predicate-substitution-1".to_string(),
        parent_receipt_sha256: bilateral_invocation.local_receipt_sha256.clone(),
        child_receipt_sha256: bilateral_invocation.remote_receipt_sha256.clone(),
        continuation_sha256: continuation_sha256.clone(),
        bilateral_invocation_sha256: bilateral_invocation_sha256.clone(),
        evidence_class: "verified".to_string(),
        source_kernel_id: continuation.source_kernel_id.clone(),
        target_kernel_id: continuation.target_kernel_id.clone(),
    };
    bilateral_invocation.lineage_statement_sha256 =
        sha256_hex(&canonical_json_bytes(&lineage_statement)?);
    let lineage_bundle = ReceiptLineageBundle {
        schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
        bundle_id: "lineage-bundle-predicate-substitution-1".to_string(),
        root_receipt_sha256: lineage_statement.parent_receipt_sha256.clone(),
        leaf_receipt_sha256: lineage_statement.child_receipt_sha256.clone(),
        statements: vec![lineage_statement],
    };
    let lineage_bundle_sha256 = sha256_hex(&canonical_json_bytes(&lineage_bundle)?);

    let dsse_consistency_model =
        bilateral_dsse_consistency_model(&bilateral_invocation.consistency_model)?.to_string();
    let envelope = sign_chio_bilateral_dsse_envelope(
        &receipt,
        &signer_a,
        &signer_b,
        &bilateral_invocation.signer_kernel_ids[0],
        &bilateral_invocation.signer_kernel_ids[1],
        "close_account",
        1_800_000_001_000,
        BilateralPredicateExtensions {
            capability_lease_ref: Some(CapabilityLeaseRef {
                lease_id: "lease-live-1".to_string(),
                issuer: bilateral_invocation.signer_kernel_ids[0].clone(),
                expires_at_unix_ms: 1_800_003_600_000,
                scope_digest: None,
            }),
            policy_evaluation_summary: Some(allow_policy_evaluation_summary()),
            governance_receipt_ref: Some(GovernanceReceiptRef {
                receipt_id: "gov-live-1".to_string(),
                kernel_id: bilateral_invocation.signer_kernel_ids[1].clone(),
                digest: HashRecord {
                    alg: "sha256".to_string(),
                    value: "d".repeat(64),
                },
            }),
            consistency_anchor: Some("anchor-live".to_string()),
            consistency_model: Some(dsse_consistency_model.clone()),
            cross_org_visibility: Some("treaty_only".to_string()),
            treaty_binding_ref: Some(TreatyBindingRef {
                treaty_id: bilateral_invocation.treaty_id.clone(),
                treaty_scope_sha256: treaty_scope_sha256.clone(),
                ladder_intersection_sha256: ladder_intersection_sha256.clone(),
                admission_report_sha256: "6".repeat(64),
                continuation_sha256: continuation_sha256.clone(),
                lineage_bundle_sha256: lineage_bundle_sha256.clone(),
                action_class_id: bilateral_invocation.action_class_id.clone(),
                consistency_model: dsse_consistency_model,
                request_sha256: bilateral_invocation.request_sha256.clone(),
                outcome_sha256: bilateral_invocation.outcome_sha256.clone(),
                local_receipt_sha256: bilateral_invocation.local_receipt_sha256.clone(),
                remote_receipt_sha256: bilateral_invocation.remote_receipt_sha256.clone(),
                lease_refs: vec!["lease-live-1".to_string()],
                governance_refs: vec!["gov-live-1".to_string()],
                signer_kernel_ids: bilateral_invocation.signer_kernel_ids.clone(),
            }),
        },
    )?;
    let envelope_sha256 = sha256_hex(&canonical_json_bytes(&envelope)?);

    Ok(TreatyFixture {
        evidence,
        signer_a,
        signer_b,
        treaty_scope,
        treaty_scope_sha256,
        ladder_intersection,
        ladder_intersection_sha256,
        continuation,
        continuation_sha256,
        lineage_bundle,
        lineage_bundle_sha256,
        bilateral_invocation,
        bilateral_invocation_sha256,
        envelope,
        envelope_sha256,
    })
}

fn allow_policy_evaluation_summary() -> PolicyEvaluationSummary {
    PolicyEvaluationSummary {
        server_a_verdict: PolicyVerdict {
            verdict: "allow".to_string(),
            policy_id: "policy-buyer".to_string(),
            policy_version: "v1".to_string(),
            rationale_code: None,
        },
        server_b_verdict: PolicyVerdict {
            verdict: "allow".to_string(),
            policy_id: "policy-vendor".to_string(),
            policy_version: "v1".to_string(),
            rationale_code: None,
        },
        joint_disposition: Some("allow".to_string()),
    }
}

fn insert_treaty_artifacts(
    store: &SqliteRuntimeOrchestrationStore,
    fixture: &TreatyFixture,
) -> TestResult {
    store.insert_treaty_runtime_artifact(
        "treaty_scope",
        &fixture.treaty_scope.treaty_id,
        &fixture.treaty_scope,
    )?;
    store.insert_treaty_runtime_artifact(
        "ladder_intersection",
        &fixture.ladder_intersection.intersection_id,
        &fixture.ladder_intersection,
    )?;
    store.insert_treaty_runtime_artifact(
        "cross_kernel_continuation",
        &fixture.continuation.continuation_id,
        &fixture.continuation,
    )?;
    store.insert_treaty_runtime_artifact(
        "receipt_lineage_bundle",
        &fixture.lineage_bundle.bundle_id,
        &fixture.lineage_bundle,
    )?;
    store.insert_treaty_runtime_artifact(
        "bilateral_invocation",
        &fixture.bilateral_invocation.invocation_id,
        &fixture.bilateral_invocation,
    )?;
    store.insert_treaty_runtime_artifact(
        "bilateral_dsse_envelope",
        BASELINE_DSSE_ID,
        &fixture.envelope,
    )?;
    Ok(())
}

fn treaty_context(fixture: &TreatyFixture, dsse_id: &str, dsse_sha256: &str) -> Value {
    let mut context = serde_json::json!({
        "treatyScopeId": fixture.treaty_scope.treaty_id,
        "treatyScopeSha256": fixture.treaty_scope_sha256,
        "ladderIntersectionId": fixture.ladder_intersection.intersection_id,
        "ladderIntersectionSha256": fixture.ladder_intersection_sha256,
        "actionClassId": "workflow.destructive.vendor_call",
        "crossKernelContinuation": {
            "id": fixture.continuation.continuation_id,
            "sha256": fixture.continuation_sha256
        },
        "bilateralInvocation": {
            "id": fixture.bilateral_invocation.invocation_id,
            "sha256": fixture.bilateral_invocation_sha256
        },
        "bilateralDsse": {
            "id": dsse_id,
            "sha256": dsse_sha256
        }
    });
    if matches!(fixture.evidence, Evidence::LineageAndRecord) {
        context["receiptLineageBundle"] = serde_json::json!({
            "id": fixture.lineage_bundle.bundle_id,
            "sha256": fixture.lineage_bundle_sha256
        });
    }
    context
}

// ---------------------------------------------------------------------------
// Receiver-owned configuration
// ---------------------------------------------------------------------------

fn profile() -> RuntimeAdmissionProfile {
    RuntimeAdmissionProfile {
        schema: CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.to_string(),
        profile_id: "profile-live-spine".to_string(),
        local_kernel_id: "kernel.vendor-b".to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
    }
}

fn binding() -> RuntimeRequestBinding {
    RuntimeRequestBinding {
        request_id: "req-live-destructive".to_string(),
        capability_id: "cap-live-1".to_string(),
        server_id: "vendor-ledger".to_string(),
        tool_name: "close_account".to_string(),
        tool_args_sha256: "a".repeat(64),
        origin_kernel_id: Some("kernel.buyer".to_string()),
        host_kernel_id: "kernel.vendor-b".to_string(),
    }
}

fn bundle() -> RuntimeAdmissionBundle {
    RuntimeAdmissionBundle {
        schema: CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA.to_string(),
        admission_id: "adm-live-1".to_string(),
        binding: binding(),
        workflow_id: "wf-live-1".to_string(),
        workflow_grant_id: "grant-live-1".to_string(),
        step_index: 1,
        destructive: true,
        lease_id: Some("lease-live-1".to_string()),
        governance_receipt_id: Some("gov-live-1".to_string()),
        trust_bundle_sha256: "b".repeat(64),
        verification_context_sha256: "c".repeat(64),
    }
}

fn capability(capability_id: &str) -> Result<CapabilityToken, BoxError> {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    Ok(CapabilityToken::sign(
        CapabilityTokenBody {
            id: capability_id.to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "vendor-ledger".to_string(),
                    tool_name: "close_account".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            issued_at: 1_800_000_000,
            expires_at: 1_800_003_600,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )?)
}

fn treaty_request(
    arguments: Value,
    bundle_sha256: String,
    treaty_context: Value,
) -> Result<ToolCallRequest, BoxError> {
    let capability = capability("cap-live-1")?;
    let mut request = ToolCallRequest {
        request_id: "req-live-destructive".to_string(),
        capability: capability.clone(),
        tool_name: "close_account".to_string(),
        server_id: "vendor-ledger".to_string(),
        agent_id: capability.subject.to_hex(),
        arguments,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: Some("kernel.buyer".to_string()),
    };
    request.governed_intent = Some(GovernedTransactionIntent {
        id: "intent-live-1".to_string(),
        server_id: "vendor-ledger".to_string(),
        tool_name: "close_account".to_string(),
        purpose: "close governed vendor account".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(serde_json::json!({
            "chioAdmission": {
                "admissionId": "adm-live-1",
                "bundleSha256": bundle_sha256
            },
            "chioTreaty": treaty_context
        })),
        body: Default::default(),
    });
    Ok(request)
}

fn allowing_hook(
    store: SqliteRuntimeOrchestrationStore,
) -> Result<ChioRuntimeAdmissionHook<SqliteRuntimeOrchestrationStore>, BoxError> {
    let verifier = Keypair::generate();
    let signed_trust = SignedExportEnvelope::sign(trust_body(), &verifier)?;
    let weights = peer_weights();
    let signed_policy =
        SignedExportEnvelope::sign(policy(runtime_peer_weights_sha256(&weights)?), &verifier)?;
    let signed_weights = SignedExportEnvelope::sign(weights, &verifier)?;
    let signed_query_report = SignedExportEnvelope::sign(query_report_body(), &verifier)?;
    Ok(ChioRuntimeAdmissionHook::new(profile(), store)
        .with_runtime_trust_input(signed_trust, trusted_keys(&verifier))
        .with_pheromone_query_report(signed_query_report)
        .with_runtime_pheromone_policy(signed_policy, signed_weights))
}

fn trusted_keys(verifier: &Keypair) -> Vec<RuntimeTrustedVerifierKey> {
    vec![RuntimeTrustedVerifierKey {
        verifier_id: "did:chio:buyer-verifier".to_string(),
        key_id: "verifier-key-1".to_string(),
        public_key: verifier.public_key(),
        valid_from_unix_ms: 1_800_000_000_000,
        valid_until_unix_ms: 1_800_003_600_000,
        status: "active".to_string(),
    }]
}

fn trust_body() -> RuntimeVerifierTrustBundleV4 {
    RuntimeVerifierTrustBundleV4 {
        schema: CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA.to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        key_id: "verifier-key-1".to_string(),
        version: 1,
        previous_hash_sha256: None,
        trust_bundle_sha256: "b".repeat(64),
        verification_context_sha256: "c".repeat(64),
        revocation_checkpoint_sha256: "d".repeat(64),
        revocation_authority_roots: vec!["did:chio:revocation-authority".to_string()],
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
    }
}

fn advisory() -> RuntimePheromoneAdvisory {
    RuntimePheromoneAdvisory {
        source_report_sha256: "1".repeat(64),
        accepted: true,
        subject_class: "workflow.destructive_step".to_string(),
        subject_class_namespace: "chio.runtime".to_string(),
        total_strength: 0.10,
        distinct_origin_pairs: 1,
        reputation_epoch: 7,
        evaluated_at_unix_ms: 1_800_000_001_000,
        observe_only: true,
    }
}

fn query_report_body() -> Value {
    let advisory = advisory();
    serde_json::json!({
        "schema": "chio.pheromone.query-report.v1",
        "accepted": advisory.accepted,
        "concentration": {
            "subjectClass": advisory.subject_class,
            "subjectClassNamespace": advisory.subject_class_namespace,
            "totalStrength": advisory.total_strength,
            "distinctOriginPairs": advisory.distinct_origin_pairs,
            "reputationEpoch": advisory.reputation_epoch,
            "evaluatedAtUnixMs": advisory.evaluated_at_unix_ms
        }
    })
}

fn policy(peer_weights_sha256: String) -> RuntimePheromonePolicy {
    RuntimePheromonePolicy {
        schema: CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA.to_string(),
        policy_id: "policy-runtime-risk".to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        key_id: "verifier-key-1".to_string(),
        policy_version: 1,
        mode: "enforce".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        allowed_reputation_epochs: vec![7],
        max_query_report_age_ms: 60_000,
        min_distinct_origin_pairs: 1,
        runtime_trust_bundle_sha256: "b".repeat(64),
        peer_weights_sha256,
        rules: vec![RuntimePheromonePolicyRule {
            rule_id: "deny-high-runtime-risk".to_string(),
            subject_class: "workflow.destructive_step".to_string(),
            subject_class_namespace: "chio.runtime".to_string(),
            action_class_id: "*".to_string(),
            direction: "deny_if_at_or_above".to_string(),
            threshold_total_strength: 0.75,
            effect: "deny".to_string(),
        }],
    }
}

fn peer_weights() -> RuntimePeerWeights {
    RuntimePeerWeights {
        schema: CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA.to_string(),
        verifier_id: "did:chio:buyer-verifier".to_string(),
        key_id: "verifier-key-1".to_string(),
        reputation_epoch: 7,
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
        weights: vec![RuntimePeerWeight {
            peer_kernel_id: "kernel.vendor-b".to_string(),
            weight: 1.0,
        }],
    }
}
