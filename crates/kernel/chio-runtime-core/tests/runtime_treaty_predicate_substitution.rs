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
//! the substituted bytes, and the result is driven through a kernel whose only
//! registered tool server counts the invocations it receives. The observed
//! outcome must equal the declared one. Denials additionally assert that the
//! dispatch counter reads zero, that no verified federation material reached
//! dispatch, and that the continuation the statement named is still
//! unconsumed; admissions assert the counter reads exactly one, which is what
//! makes zero on a denial a measurement rather than an absence.
//!
//! Two leaves are bounded rather than compared for equality: the lease expiry
//! against the presentation window the receiver resolved for the lease issuer,
//! and the lease issuer against the agreement's participant set. Both carry a
//! second declared value on the other side of the bound, so the corpus records
//! the domain rather than pretending it is an equality.
//!
//! A leaf the receiver compares against nothing is not therefore a leaf whose
//! value is free. Each such leaf declares the shape the wire form still
//! requires of it, and the leaves whose shape is narrower than their JSON type
//! carry a second declared value outside that shape, which is denied.
//!
//! The wire type marks six leaves optional; the strict profile refuses two of
//! them outright and permits the other four, which this call does not carry.
//! Those four cannot be reached by substitution, so the corpus adds each one
//! to the doubly signed statement and records what the receiver does.
//!
//! Beyond the single-field cases the corpus runs every pair inside the
//! sixteen-field binding reference, the pairs whose two members duplicate one
//! another across the predicate (where a consistent two-field substitution
//! could pass an internal agreement check that a one-field substitution
//! trips), and the simultaneous substitution of every field the receiver does
//! not compare.
//!
//! The same enumeration and the same classification are mechanized in
//! `formal/lean4/Chio/Chio/Treaty/AdmissionBinding.lean`. That file is read
//! here and the two are asserted equal leaf for leaf, so neither can drift
//! into disagreeing with the other.

mod support;

#[path = "support/dispatch_counter.rs"]
mod dispatch_counter;

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
use chio_kernel::{RuntimeAdmissionHook, ToolCallRequest};
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

/// The shape of a leaf the receiver compares against nothing, when the wire
/// form requires no more of it than its JSON type. A leaf declaring this needs
/// no probe, because there is no value of the right type outside its shape.
const ANY_VALUE_OF_ITS_JSON_TYPE: &str = "any value of its JSON type";

/// What the receiver does with one leaf of the crossing statement.
#[derive(Clone, Copy)]
enum Comparison {
    /// Compared for equality against the named receiver-held value.
    ReceiverState(&'static str),
    /// Required to lie in the named receiver-held domain, which is not a
    /// singleton: an admitted statement pins the leaf to the domain and not to
    /// a value. The lease expiry and the lease issuer are of this kind.
    ReceiverDomain(&'static str),
    /// Constrained to a fixed value or a fixed domain the receiver holds as
    /// code. A constant is not receiver state: it separates profiles, it does
    /// not bind this call.
    Shape(&'static str),
    /// Checked only for agreement with another field of the same statement.
    /// A consistent substitution of both copies passes this check, so the
    /// pair corpus below is what covers it.
    SelfConsistent(&'static str),
    /// Compared against nothing the receiver holds. `shape` is what the wire
    /// form still requires of the value, which is the domain whoever holds the
    /// two signing keys chooses inside; `reason` says why admission reads
    /// nothing else from it.
    Uncompared {
        shape: &'static str,
        reason: &'static str,
    },
    /// Refused outright by the strict profile, so no strict statement carries
    /// it and there is no value to substitute.
    AbsentRequired(&'static str),
    /// Marked optional by the wire type and not carried by this call. The
    /// profile permits it, so another strict statement may carry it; the
    /// addition corpus is what reaches it.
    AbsentOptional(&'static str),
}

impl Comparison {
    /// The receiver-side value, domain, or reason, as the classification
    /// states it.
    fn against(self) -> &'static str {
        match self {
            Self::ReceiverState(value)
            | Self::ReceiverDomain(value)
            | Self::Shape(value)
            | Self::SelfConsistent(value)
            | Self::AbsentRequired(value)
            | Self::AbsentOptional(value) => value,
            Self::Uncompared { reason, .. } => reason,
        }
    }

    fn kind(self) -> &'static str {
        match self {
            Self::ReceiverState(_) => "compared against receiver state",
            Self::ReceiverDomain(_) => "required to lie in a receiver-held domain",
            Self::Shape(_) => "constrained to a fixed domain",
            Self::SelfConsistent(_) => "compared with another field of the statement",
            Self::Uncompared { .. } => "not compared",
            Self::AbsentRequired(_) => "refused by the strict profile",
            Self::AbsentOptional(_) => "optional, and not carried by this call",
        }
    }

    /// The constructor the Lean model classifies the same leaf with. The
    /// cross-check test compares the two classifications through this name.
    fn lean_constructor(self) -> &'static str {
        match self {
            Self::ReceiverState(_) => "receiverState",
            Self::ReceiverDomain(_) => "receiverDomain",
            Self::Shape(_) => "shape",
            Self::SelfConsistent(_) => "selfConsistent",
            Self::Uncompared { .. } => "uncompared",
            Self::AbsentRequired(_) => "absentRequired",
            Self::AbsentOptional(_) => "absentOptional",
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
        Comparison::ReceiverDomain(
            "the two participant kernel ids of the resolved agreement, as a membership test \
             rather than an equality: either participant is admitted",
        ),
        Outcome::Denied(UNVERIFIED_EVIDENCE),
        (
            MutationSpec::Literal("\"kernel.vendor-b\""),
            Outcome::Admitted,
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
        Comparison::Uncompared {
            shape: ANY_VALUE_OF_ITS_JSON_TYPE,
            reason: "the governance receipt the receiver acts on is the one its own admission \
                     bundle names; the issuing kernel recorded here is audit content",
        },
        Outcome::Admitted,
    ),
    rule(
        "predicate/governance_receipt_ref/digest/alg",
        Comparison::Uncompared {
            shape: ANY_VALUE_OF_ITS_JSON_TYPE,
            reason: "audit content, as for the governance kernel id",
        },
        Outcome::Admitted,
    ),
    rule(
        "predicate/governance_receipt_ref/digest/value",
        Comparison::Uncompared {
            shape: ANY_VALUE_OF_ITS_JSON_TYPE,
            reason: "the receiver resolves the governance receipt by id from its own store and \
                     never compares this digest against the record it resolved",
        },
        Outcome::Admitted,
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
    "predicate/treaty_binding_ref/signer_kernel_ids/1",
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

/// A leaf the wire type marks optional and this call does not carry. The
/// strict profile refuses two optional leaves outright, and these are the ones
/// it permits: substitution cannot reach them, because the statement under
/// test has no value there to replace, so the corpus adds them to the doubly
/// signed statement instead and records what the receiver does.
struct AdditionCase {
    id: &'static str,
    /// The object to insert into, the key to insert, and the JSON value, in
    /// order.
    insertions: &'static [(&'static str, &'static str, &'static str)],
    /// The classified leaves the insertion adds. The corpus checks that the
    /// statement gains exactly these.
    leaves: &'static [&'static str],
    expected: Outcome,
    note: &'static str,
}

const LEASE_SCOPE_DIGEST: &str =
    "{\"alg\":\"sha256\",\"value\":\"8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92\"}";

const ADDITION_CASES: &[AdditionCase] = &[
    AdditionCase {
        id: "a capability lease scope digest",
        insertions: &[(
            "predicate/capability_lease_ref",
            "scope_digest",
            LEASE_SCOPE_DIGEST,
        )],
        leaves: &[
            "predicate/capability_lease_ref/scope_digest/alg",
            "predicate/capability_lease_ref/scope_digest/value",
        ],
        expected: Outcome::Admitted,
        note: "the field's own contract says a registry record's scope digest must match it, \
               but the pre-dispatch hook resolves no lease registry record, so nothing reads \
               the value",
    },
    AdditionCase {
        id: "an origin policy rationale code",
        insertions: &[(
            "predicate/policy_evaluation_summary/server_a_verdict",
            "rationale_code",
            "\"policy.added-by-the-sender\"",
        )],
        leaves: &["predicate/policy_evaluation_summary/server_a_verdict/rationale_code"],
        expected: Outcome::Admitted,
        note: "the rationale code is verifier-opaque and admission reads nothing from it",
    },
    AdditionCase {
        id: "a receiving-side policy rationale code",
        insertions: &[(
            "predicate/policy_evaluation_summary/server_b_verdict",
            "rationale_code",
            "\"policy.added-by-the-sender\"",
        )],
        leaves: &["predicate/policy_evaluation_summary/server_b_verdict/rationale_code"],
        expected: Outcome::Admitted,
        note: "as for the origin rationale code, on the verdict attributed to the receiver \
               itself",
    },
    AdditionCase {
        id: "every optional leaf this call omits, at once",
        insertions: &[
            (
                "predicate/capability_lease_ref",
                "scope_digest",
                LEASE_SCOPE_DIGEST,
            ),
            (
                "predicate/policy_evaluation_summary/server_a_verdict",
                "rationale_code",
                "\"policy.added-by-the-sender\"",
            ),
            (
                "predicate/policy_evaluation_summary/server_b_verdict",
                "rationale_code",
                "\"policy.added-by-the-sender\"",
            ),
        ],
        leaves: &[
            "predicate/capability_lease_ref/scope_digest/alg",
            "predicate/capability_lease_ref/scope_digest/value",
            "predicate/policy_evaluation_summary/server_a_verdict/rationale_code",
            "predicate/policy_evaluation_summary/server_b_verdict/rationale_code",
        ],
        expected: Outcome::Admitted,
        note: "the addition residual, alongside the substitution residual: leaves the receiver \
               never validates can be added to a doubly signed statement as well as rewritten \
               inside it",
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
            (Comparison::AbsentRequired(_) | Comparison::AbsentOptional(_), Some(_)) => {
                panic!(
                    "{} is classified absent from this statement but declares a substitution \
                     outcome",
                    rule.path
                )
            }
            (Comparison::AbsentRequired(_) | Comparison::AbsentOptional(_), None) => {}
            (_, None) => panic!("{} declares no substitution outcome", rule.path),
            (Comparison::Uncompared { shape, .. }, Some(outcome)) => {
                assert_eq!(
                    outcome,
                    Outcome::Admitted,
                    "{} is classified uncompared, so its substitution must be admitted",
                    rule.path
                );
                if shape != ANY_VALUE_OF_ITS_JSON_TYPE {
                    let Some((_, probe_outcome)) = rule.probe else {
                        panic!(
                            "{} declares the shape {shape:?}, which is narrower than its JSON \
                             type, so it needs a declared value outside that shape",
                            rule.path
                        )
                    };
                    assert!(
                        matches!(probe_outcome, Outcome::Denied(_)),
                        "{} declares a shape, so a value outside it must be denied",
                        rule.path
                    );
                }
            }
            (Comparison::ReceiverDomain(_), Some(_)) => assert!(
                rule.probe.is_some(),
                "{} is required to lie in a domain rather than to equal a value, so it needs a \
                 second declared value inside or outside that domain",
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

/// The leaves a strict statement of this call actually carries are exactly the
/// classified leaves the substitution corpus exercises. A leaf the profile
/// refuses and a leaf the wire type marks optional and this call omits have no
/// substitution case; a leaf this call populates must have one.
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

/// All 120 pairs inside the sixteen-leaf binding reference. Exactly one of the
/// sixteen is not compared, so every pair contains at least one compared leaf
/// and every pair must be denied without dispatch. A pair that admitted would
/// be one comparison masking another.
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

/// The leaves the wire type marks optional and this call omits, added to the
/// doubly signed statement one at a time and then all at once. Substitution
/// cannot reach them, so without this group the completeness claim would have
/// a hole exactly where it claims totality: the corpus would record nothing
/// about four of the fifty-five leaves. Each case also checks that the
/// insertion adds exactly the leaves the classification says it adds.
#[test]
fn optional_leaves_this_call_omits_can_be_added_to_the_signed_statement() -> TestResult {
    let fixture = treaty_fixture(Evidence::LineageAndRecord)?;
    let baseline = rewritten_document(&fixture, &[], &[])?;
    let baseline_leaves: std::collections::BTreeSet<String> =
        leaf_paths(&baseline).into_iter().collect();

    let classified_optional: std::collections::BTreeSet<&str> = FIELD_RULES
        .iter()
        .filter(|rule| matches!(rule.comparison, Comparison::AbsentOptional(_)))
        .map(|rule| rule.path)
        .collect();
    let covered: std::collections::BTreeSet<&str> = ADDITION_CASES
        .iter()
        .flat_map(|case| case.leaves.iter().copied())
        .collect();
    assert_eq!(
        covered, classified_optional,
        "every leaf classified optional and absent must be added by some case, and no case may \
         name a leaf that is not"
    );

    for case in ADDITION_CASES {
        let document = rewritten_document(&fixture, &[], case.insertions)?;
        let added: std::collections::BTreeSet<String> = leaf_paths(&document)
            .into_iter()
            .filter(|leaf| !baseline_leaves.contains(leaf))
            .collect();
        let declared: std::collections::BTreeSet<String> =
            case.leaves.iter().map(|leaf| (*leaf).to_string()).collect();
        assert_eq!(
            added, declared,
            "{} must add exactly the leaves it names",
            case.id
        );
        let run = admit_with_insertions(Evidence::LineageAndRecord, &[], case.insertions)?;
        assert_outcome(&run, case.expected, case.id, case.note);
    }
    Ok(())
}

/// The mechanized enumeration and the executed one are the same enumeration,
/// checked rather than asserted. The Lean model carries the leaf paths and the
/// classification as an inductive type and a total match; this reads that file
/// and requires both to agree with [`FIELD_RULES`] leaf for leaf, so a leaf
/// added on one side or reclassified on one side fails here instead of leaving
/// the two silently disagreeing.
#[test]
fn the_lean_model_and_the_executed_classification_are_the_same_enumeration() -> TestResult {
    let source = std::fs::read_to_string(lean_model_path())?;
    let paths = lean_match_arms(&source, "def path : Field -> String := fun f =>\n")?;
    let kinds = lean_match_arms(&source, "def classify : Field -> Comparison := fun f =>\n")?;

    let path_constructors: Vec<&String> = paths.iter().map(|(name, _)| name).collect();
    let kind_constructors: Vec<&String> = kinds.iter().map(|(name, _)| name).collect();
    assert_eq!(
        path_constructors, kind_constructors,
        "the Lean model must name each leaf the wire path and the classification in the same order"
    );

    let mut lean_classification: Vec<(String, String)> = paths
        .iter()
        .zip(kinds.iter())
        .map(|((_, path), (_, kind))| (path.clone(), kind.clone()))
        .collect();
    lean_classification.sort();
    let mut executed_classification: Vec<(String, String)> = FIELD_RULES
        .iter()
        .map(|rule| {
            (
                rule.path.to_string(),
                rule.comparison.lean_constructor().to_string(),
            )
        })
        .collect();
    executed_classification.sort();
    assert_eq!(
        lean_classification, executed_classification,
        "the Lean classification and the executed classification must agree leaf for leaf"
    );
    Ok(())
}

fn lean_model_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("formal/lean4/Chio/Chio/Treaty/AdmissionBinding.lean")
}

/// The arms of one Lean match on the leaf enumeration, as pairs of constructor
/// name and payload head. For the path function the payload head is the wire
/// path; for the classification it is the comparison constructor.
fn lean_match_arms(source: &str, header: &str) -> Result<Vec<(String, String)>, BoxError> {
    let body = source
        .split_once(header)
        .ok_or_else(|| io::Error::other(format!("the Lean model has no {header:?}")))?
        .1;
    let body = match body.split_once("\n/--") {
        Some((section, _)) => section,
        None => body,
    };
    let mut arms: Vec<(String, String)> = Vec::new();
    let mut pending: Option<String> = None;
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("| .") {
            if let Some(name) = pending.take() {
                return Err(Box::new(io::Error::other(format!(
                    "the Lean arm for {name} has no payload"
                ))));
            }
            match rest.split_once(" => ") {
                Some((name, payload)) => arms.push((name.to_string(), lean_payload_head(payload)?)),
                None => {
                    let name = rest.strip_suffix(" =>").ok_or_else(|| {
                        io::Error::other(format!("unparsed Lean match arm: {trimmed}"))
                    })?;
                    pending = Some(name.to_string());
                }
            }
            continue;
        }
        if let Some(name) = pending.take() {
            arms.push((name, lean_payload_head(trimmed)?));
        }
    }
    if let Some(name) = pending {
        return Err(Box::new(io::Error::other(format!(
            "the Lean arm for {name} has no payload"
        ))));
    }
    Ok(arms)
}

/// The head of a Lean match arm's payload: a quoted string yields its
/// contents, and a constructor application yields the constructor name.
fn lean_payload_head(payload: &str) -> Result<String, BoxError> {
    let payload = payload.trim();
    if let Some(rest) = payload.strip_prefix('"') {
        let text = rest.strip_suffix('"').ok_or_else(|| {
            io::Error::other(format!("unterminated Lean string payload: {payload}"))
        })?;
        return Ok(text.to_string());
    }
    let constructor = payload
        .strip_prefix('.')
        .and_then(|rest| rest.split_whitespace().next())
        .ok_or_else(|| io::Error::other(format!("unparsed Lean payload: {payload}")))?;
    Ok(constructor.to_string())
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
        run.substituted.dispatches, 1,
        "the unsubstituted statement must dispatch to the tool exactly once"
    );
    assert_eq!(
        run.baseline_after.failure_code.as_deref(),
        Some(CONTINUATION_REPLAY)
    );
    assert_eq!(
        run.baseline_after.dispatches, 0,
        "the replayed continuation must leave the dispatch counter at zero"
    );

    let without_lineage = admit_with(Evidence::RecordOnly, &[])?;
    assert!(
        without_lineage.substituted.allowed,
        "the unsubstituted statement must admit without a lineage bundle too: {:?}",
        without_lineage.substituted.failure_code
    );
    assert_eq!(
        without_lineage.substituted.dispatches, 1,
        "the unsubstituted statement must dispatch without a lineage bundle too"
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
                run.substituted.dispatches, 1,
                "{path} ({label}) was admitted, so it must have dispatched to the tool exactly once"
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
            assert_eq!(
                run.substituted.dispatches, 0,
                "{path} ({label}) was denied, so the tool server dispatch counter must read zero"
            );
            assert!(
                run.baseline_after.allowed,
                "{path} ({label}) was denied, so it must not have consumed the continuation: {:?} {:?}",
                run.baseline_after.failure_code, run.baseline_after.reason
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

/// Insert a key the statement does not carry into the object at `path`. The
/// key must be absent, so an insertion can only add leaves.
fn insert_value_at(root: &mut Value, path: &str, key: &str, value: Value) -> Result<(), BoxError> {
    let mut cursor = root;
    for segment in path.split('/') {
        cursor = match cursor {
            Value::Object(map) => map
                .get_mut(segment)
                .ok_or_else(|| io::Error::other(format!("no object at {path}")))?,
            Value::Array(items) => {
                let index: usize = segment.parse()?;
                items
                    .get_mut(index)
                    .ok_or_else(|| io::Error::other(format!("no object at {path}")))?
            }
            _ => return Err(Box::new(io::Error::other(format!("no object at {path}")))),
        };
    }
    let Value::Object(map) = cursor else {
        return Err(Box::new(io::Error::other(format!(
            "{path} is not an object, so {key} cannot be inserted"
        ))));
    };
    if map.contains_key(key) {
        return Err(Box::new(io::Error::other(format!(
            "{path}/{key} is already present, so inserting it would be a substitution"
        ))));
    }
    map.insert(key.to_string(), value);
    Ok(())
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

struct DecisionSummary {
    allowed: bool,
    failure_code: Option<String>,
    verified_treaty_material: bool,
    /// How many times the kernel dispatched to the registered tool server
    /// while evaluating this request.
    dispatches: u64,
    /// The kernel's denial reason, which a gate outside runtime admission can
    /// set without setting a runtime failure code.
    reason: Option<String>,
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
    admit_with_insertions(evidence, mutations, &[])
}

/// As [`admit_with`], and additionally inserts leaves the statement does not
/// carry before it is re-signed.
fn admit_with_insertions(
    evidence: Evidence,
    mutations: &[(&str, MutationSpec)],
    insertions: &[(&str, &str, &str)],
) -> Result<SubstitutionRun, BoxError> {
    let fixture = treaty_fixture(evidence)?;
    let document = rewritten_document(&fixture, mutations, insertions)?;
    let substituted_envelope = sign_document(&fixture, document)?;
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

    let hook = std::sync::Arc::new(dispatch_counter::TreatyMaterialRecorder::new(Box::new(
        allowing_hook(store)?,
    )));
    let substituted_request = treaty_request(
        arguments.clone(),
        bundle_sha256.clone(),
        treaty_context(&fixture, SUBSTITUTED_DSSE_ID, &substituted_sha256),
    )?;
    let substituted = summarize(&hook, &substituted_request)?;

    let baseline_request = treaty_request(
        arguments,
        bundle_sha256,
        treaty_context(&fixture, BASELINE_DSSE_ID, &fixture.envelope_sha256),
    )?;
    let baseline_after = summarize(&hook, &baseline_request)?;

    Ok(SubstitutionRun {
        substituted,
        baseline_after,
    })
}

/// Drive one request through a kernel whose only tool server counts its own
/// invocations, so the decision and the dispatch it did or did not cause are
/// read from the same run.
fn summarize(
    hook: &std::sync::Arc<dispatch_counter::TreatyMaterialRecorder>,
    request: &ToolCallRequest,
) -> Result<DecisionSummary, BoxError> {
    let outcome = dispatch_counter::dispatch_through_kernel(
        std::sync::Arc::clone(hook) as std::sync::Arc<dyn RuntimeAdmissionHook>,
        request,
        &dispatch_target(),
    )?;
    Ok(DecisionSummary {
        allowed: outcome.allowed,
        failure_code: outcome.failure_code,
        verified_treaty_material: hook.verified_treaty_material(),
        dispatches: outcome.dispatches,
        reason: outcome.reason,
    })
}

fn dispatch_target() -> dispatch_counter::KernelDispatchTarget<'static> {
    dispatch_counter::KernelDispatchTarget {
        local_kernel_id: "kernel.vendor-b",
        origin_kernel_id: Some("kernel.buyer"),
        server_id: "vendor-ledger",
        tool_name: "close_account",
        now_unix_ms: 1_800_000_001_000,
    }
}

/// Apply the substitutions and the insertions to the statement document. The
/// document is rewritten as JSON rather than through the producer API, which
/// refuses many of these statements at construction time, because what an
/// adversary holding both keys can do is encode and sign whatever it likes.
fn rewritten_document(
    fixture: &TreatyFixture,
    mutations: &[(&str, MutationSpec)],
    insertions: &[(&str, &str, &str)],
) -> Result<Value, BoxError> {
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
    for (object, key, json) in insertions {
        insert_value_at(&mut document, object, key, serde_json::from_str(json)?)?;
    }
    Ok(document)
}

/// Sign a statement document with both participant keys over its own
/// pre-authentication bytes.
fn sign_document(fixture: &TreatyFixture, document: Value) -> Result<DsseEnvelope, BoxError> {
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
    let signer_a = dispatch_counter::origin_kernel_keypair();
    let signer_b = dispatch_counter::receiver_kernel_keypair();
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
    let issuer = dispatch_counter::receiver_kernel_keypair();
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
        .with_runtime_pheromone_policy(signed_policy, signed_weights)
        .with_fixed_now_unix_ms(1_800_000_001_000))
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
