//! Differential corpus over the two deciders of a cross-organization call.
//!
//! Two implementations answer the same question in two disjoint code families.
//! The specification's numbered conforming verifier
//! (`chio_federation::bilateral_verifier::verify_chio_bilateral_invocation`)
//! answers offline from a pin set, a receipt store, a lease registry, a
//! governance receipt store and a revocation oracle. The kernel's pre-dispatch
//! admission hook (`chio_runtime_core::ChioRuntimeAdmissionHook`) answers
//! inline during admission from the receiver's own runtime store, and it is the
//! one that decides a live call.
//!
//! Every case below builds one cross-organization call, projects it into both
//! deciders, and records what each one answered. Three outcomes are legitimate
//! and each case declares which one it expects:
//!
//!   * `Agree` - both accept, or both reject. Drift in either decider breaks
//!     the case.
//!   * `VerifierOnly` - the offline verifier rejects and the hook admits,
//!     because the check belongs to state the hook never resolves. Each such
//!     case carries the reason, and the set of them is asserted whole, so a new
//!     one cannot appear silently.
//!   * `HookOnly` - the hook rejects and the offline verifier admits, because
//!     the check is over receiver-owned runtime state that no envelope carries
//!     and no offline verifier holds.
//!
//! The asymmetries are the point. The offline verifier resolves the subject
//! receipt, the lease and the governance record; the hook resolves none of the
//! three. The hook enforces the single-use continuation, the agreement scope,
//! the ladder intersection and the request's own smuggling refusals; the
//! offline verifier sees none of the four. A reader who needs one sentence: the
//! two deciders agree on everything the envelope alone determines and diverge
//! exactly where one of them holds state the other does not.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;

use base64::Engine as _;
use chio_core_types::capability::{
    governance::GovernedTransactionIntent,
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision as ReceiptDecision,
    decision::ToolCallAction,
    kinds::BoundaryClass, kinds::ReceiptKind, kinds::RedactionMode, kinds::ToolOrigin,
    kinds::TrustLevel, metadata::ActorRef,
};
use chio_federation::bilateral_dsse::{
    pae, sign_chio_bilateral_dsse_envelope, BilateralPredicateExtensions,
    CapabilityLeaseRef, DsseEnvelope, DsseSignature, DsseStatement, GovernanceReceiptRef,
    HashRecord, Keyid, PolicyEvaluationSummary, PolicyVerdict, TreatyBindingRef,
    PAYLOAD_TYPE_IN_TOTO,
};
use chio_federation::bilateral_verifier::{
    verify_chio_bilateral_invocation, ActionClassKind, ChioBilateralVerifierConfig,
    DenyListRevocationOracle, InMemoryGovernanceReceiptStore, InMemoryLeaseRegistry,
    InMemoryReceiptStore, PeerPinSet, PinnedEpoch, PinnedPeer, ResolvedGovernanceReceipt,
    ResolvedLease, UnknownActionClassPolicy, VerifierConfig,
};
use chio_federation::trust_establishment::LadderManifestRef;
use chio_kernel::{RuntimeAdmissionContext, RuntimeAdmissionHook, ToolCallRequest};
use chio_runtime_core::{
    bilateral_dsse_consistency_model, bilateral_invocation_binding_sha256,
    compute_ladder_intersection, governance_ladder_manifest_sha256, ladder_intersection_sha256,
    runtime_admission_bundle_sha256, runtime_peer_weights_sha256, tool_args_sha256,
    treaty_scope_sha256, BilateralInvocation, ChioRuntimeAdmissionHook, CrossKernelContinuation,
    GovernanceLadderActionClass, GovernanceLadderManifest, InMemoryRuntimeAdmissionStore,
    LadderIntersection, ReceiptLineageBundle, ReceiptLineageStatement, RuntimeAdmissionBundle,
    RuntimeAdmissionProfile, RuntimeAdmissionStore, RuntimePeerWeight, RuntimePeerWeights,
    RuntimePheromonePolicy, RuntimePheromonePolicyRule, RuntimeRequestBinding,
    RuntimeTrustedVerifierKey, RuntimeVerifierTrustBundleV4, TreatyScope,
    CHIO_BILATERAL_INVOCATION_SCHEMA, CHIO_CROSS_KERNEL_CONTINUATION_SCHEMA,
    CHIO_GOVERNANCE_LADDER_MANIFEST_SCHEMA,
    CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA, CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA,
    CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA, CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA,
    CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA, CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA,
    CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA, CHIO_TREATY_SCOPE_SCHEMA,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type BoxError = Box<dyn std::error::Error>;
/// Mutation of the receiver's runtime state, which can fail against the store.
type HookStateMutation = fn(&mut HookState) -> Result<(), BoxError>;

const ORIGIN_KERNEL: &str = "kernel.buyer";
const RECEIVER_KERNEL: &str = "kernel.vendor-b";
const TOOL_SERVER: &str = "vendor-ledger";
const TOOL_NAME: &str = "close_account";
const ACTION_CLASS: &str = "workflow.destructive.vendor_call";
const CAPABILITY_ID: &str = "cap-conformance-1";
const LEASE_ID: &str = "lease-conformance-1";
const GOVERNANCE_ID: &str = "gov-conformance-1";
const ADMISSION_ID: &str = "adm-conformance-1";
const REQUEST_ID: &str = "req-conformance-1";
const CONTINUATION_ID: &str = "continue-conformance-1";
const INVOCATION_ID: &str = "invoke-conformance-1";
const DSSE_ID: &str = "bilateral-dsse-conformance-1";
const VERIFIER_ID: &str = "did:chio:receiver-verifier";
const VERIFIER_KEY_ID: &str = "verifier-key-1";

const ISSUED_AT_MS: u64 = 1_800_000_000_000;
const NOW_MS: u64 = 1_800_000_001_000;
const EXPIRES_AT_MS: u64 = 1_800_003_600_000;
const EPOCH_HEIGHT: u64 = 7;
const TRUST_BUNDLE_SHA256: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const VERIFICATION_CONTEXT_SHA256: &str =
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const REVOCATION_CHECKPOINT_SHA256: &str =
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const OUTCOME_SHA256: &str = "5555555555555555555555555555555555555555555555555555555555555555";

// ---------------------------------------------------------------------------
// What a decider answered
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    Admit,
    Reject(String),
}

impl Answer {
    fn is_admit(&self) -> bool {
        matches!(self, Answer::Admit)
    }

    fn code(&self) -> &str {
        match self {
            Answer::Admit => "",
            Answer::Reject(code) => code.as_str(),
        }
    }
}

/// How the two deciders are expected to relate on one input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Relation {
    /// Both admit.
    AgreeAdmit,
    /// Both reject. The codes come from two disjoint code families, so each
    /// case names both.
    AgreeReject,
    /// The offline verifier rejects; the hook admits because the check is over
    /// state the hook never resolves.
    VerifierOnly,
    /// The hook rejects; the offline verifier admits because the check is over
    /// receiver-owned runtime state the envelope does not carry.
    HookOnly,
}

struct Case {
    name: &'static str,
    /// Applied to the decoded statement before it is re-signed, so the envelope
    /// stays cryptographically valid over the mutated bytes.
    mutate_statement: Option<fn(&mut DsseStatement)>,
    /// Applied to the envelope after signing, for the malformed-envelope cases.
    mutate_envelope: Option<fn(&mut DsseEnvelope)>,
    /// Applied to the receiver-owned state the offline verifier reads.
    mutate_verifier_state: Option<fn(&mut VerifierState)>,
    /// Applied to the receiver-owned runtime state the kernel hook reads.
    mutate_hook_state: Option<HookStateMutation>,
    relation: Relation,
    /// Expected dotted code from the conforming verifier, empty when it admits.
    verifier_code: &'static str,
    /// Expected runtime failure code from the pre-dispatch hook, empty when it
    /// admits.
    hook_code: &'static str,
    /// Why the two are allowed to differ. Empty for the agreement cases.
    divergence: &'static str,
}

// ---------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------

fn corpus() -> Vec<Case> {
    vec![
        Case {
            name: "accept",
            mutate_statement: None,
            mutate_envelope: None,
            mutate_verifier_state: None,
            mutate_hook_state: None,
            relation: Relation::AgreeAdmit,
            verifier_code: "",
            hook_code: "",
            divergence: "",
        },
        // -- both reject: the envelope alone decides ----------------------
        Case {
            name: "wrong payload type",
            mutate_statement: None,
            mutate_envelope: Some(|envelope| {
                envelope.payload_type = "application/json".to_string();
            }),
            mutate_verifier_state: None,
            mutate_hook_state: None,
            relation: Relation::AgreeReject,
            verifier_code: "dsse.malformed",
            hook_code: "chio_treaty_unverified_required_evidence",
            divergence: "",
        },
        Case {
            name: "payload mutated after signing",
            mutate_statement: None,
            mutate_envelope: Some(|envelope| {
                let mut decoded = base64::engine::general_purpose::STANDARD
                    .decode(envelope.payload.as_bytes())
                    .unwrap_or_default();
                if let Some(position) = decoded.iter().position(|byte| *byte == b'0') {
                    decoded[position] = b'1';
                }
                envelope.payload = base64::engine::general_purpose::STANDARD.encode(&decoded);
            }),
            mutate_verifier_state: None,
            mutate_hook_state: None,
            relation: Relation::AgreeReject,
            verifier_code: "signature.server_a_invalid",
            hook_code: "chio_treaty_unverified_required_evidence",
            divergence: "",
        },
        Case {
            name: "one signature removed",
            mutate_statement: None,
            mutate_envelope: Some(|envelope| {
                envelope.signatures.truncate(1);
            }),
            mutate_verifier_state: None,
            mutate_hook_state: None,
            relation: Relation::AgreeReject,
            verifier_code: "dsse.malformed",
            hook_code: "chio_treaty_unverified_required_evidence",
            divergence: "",
        },
        Case {
            name: "duplicate signature keyid",
            mutate_statement: None,
            mutate_envelope: Some(|envelope| {
                if envelope.signatures.len() == 2 {
                    envelope.signatures[1].keyid = envelope.signatures[0].keyid.clone();
                }
            }),
            mutate_verifier_state: None,
            mutate_hook_state: None,
            relation: Relation::AgreeReject,
            verifier_code: "dsse.malformed",
            hook_code: "chio_treaty_unverified_required_evidence",
            divergence: "",
        },
        Case {
            name: "predicate type is the compatibility profile",
            mutate_statement: Some(|statement| {
                statement.predicate_type = "chio.bilateral-signature-slice.v1".to_string();
            }),
            mutate_envelope: None,
            mutate_verifier_state: None,
            mutate_hook_state: None,
            relation: Relation::AgreeReject,
            verifier_code: "predicate.type_unrecognised",
            hook_code: "chio_treaty_unverified_required_evidence",
            divergence: "",
        },
        Case {
            name: "origin kernel renamed to an unpinned identity",
            mutate_statement: Some(|statement| {
                statement.predicate.tool_server_a.kernel_id = "kernel.impostor".to_string();
                if let Some(treaty) = statement.predicate.treaty_binding_ref.as_mut() {
                    treaty.signer_kernel_ids[0] = "kernel.impostor".to_string();
                }
            }),
            mutate_envelope: None,
            mutate_verifier_state: None,
            mutate_hook_state: None,
            relation: Relation::AgreeReject,
            verifier_code: "peer.unpinned_or_keyid_mismatch",
            hook_code: "chio_treaty_dsse_binding_mismatch",
            divergence: "",
        },
        Case {
            name: "declared passport fingerprint disagrees with the pin",
            mutate_statement: Some(|statement| {
                statement.predicate.tool_server_a.passport_key_fingerprint =
                    Keyid(sha256_hex(b"conformance:not-the-pinned-key"));
            }),
            mutate_envelope: None,
            mutate_verifier_state: None,
            mutate_hook_state: None,
            relation: Relation::AgreeReject,
            verifier_code: "peer.unpinned_or_keyid_mismatch",
            hook_code: "chio_treaty_unverified_required_evidence",
            divergence: "",
        },
        Case {
            name: "the two verdicts disagree",
            mutate_statement: Some(|statement| {
                if let Some(summary) = statement.predicate.policy_evaluation_summary.as_mut() {
                    summary.server_b_verdict.verdict = "deny".to_string();
                    summary.joint_disposition = None;
                }
            }),
            mutate_envelope: None,
            mutate_verifier_state: None,
            mutate_hook_state: None,
            relation: Relation::AgreeReject,
            verifier_code: "policy.verdict_disagreement",
            hook_code: "chio_treaty_unverified_required_evidence",
            divergence: "",
        },
        Case {
            name: "request hash substituted in the binding reference",
            mutate_statement: Some(|statement| {
                if let Some(treaty) = statement.predicate.treaty_binding_ref.as_mut() {
                    treaty.request_sha256 = sha256_hex(b"conformance:other-arguments");
                }
            }),
            mutate_envelope: None,
            mutate_verifier_state: None,
            mutate_hook_state: None,
            relation: Relation::AgreeReject,
            verifier_code: "predicate.schema_invalid",
            hook_code: "chio_treaty_dsse_binding_mismatch",
            divergence: "",
        },
        Case {
            name: "signer order transposed in the binding reference",
            mutate_statement: Some(|statement| {
                if let Some(treaty) = statement.predicate.treaty_binding_ref.as_mut() {
                    treaty.signer_kernel_ids.swap(0, 1);
                }
            }),
            mutate_envelope: None,
            mutate_verifier_state: None,
            mutate_hook_state: None,
            relation: Relation::AgreeReject,
            verifier_code: "predicate.schema_invalid",
            hook_code: "chio_treaty_unverified_required_evidence",
            divergence: "",
        },
        Case {
            name: "lease reference substituted in the binding reference",
            mutate_statement: Some(|statement| {
                if let Some(treaty) = statement.predicate.treaty_binding_ref.as_mut() {
                    treaty.lease_refs = vec!["lease-conformance-other".to_string()];
                }
            }),
            mutate_envelope: None,
            mutate_verifier_state: None,
            mutate_hook_state: None,
            relation: Relation::AgreeReject,
            verifier_code: "predicate.schema_invalid",
            hook_code: "chio_treaty_dsse_binding_mismatch",
            divergence: "",
        },
        Case {
            name: "consistency model downgraded below the class",
            mutate_statement: Some(|statement| {
                statement.predicate.consistency_model = "crdt-commutative".to_string();
                if let Some(treaty) = statement.predicate.treaty_binding_ref.as_mut() {
                    treaty.consistency_model = "crdt-commutative".to_string();
                }
            }),
            mutate_envelope: None,
            mutate_verifier_state: None,
            mutate_hook_state: None,
            relation: Relation::HookOnly,
            verifier_code: "",
            hook_code: "chio_treaty_dsse_binding_mismatch",
            divergence: "the offline verifier has no ladder intersection, so it cannot know \
                         which consistency model the action class requires; it accepts any \
                         model the predicate and its binding reference agree on. The hook \
                         compares both against the intersection it computed itself.",
        },
        // -- the field neither decider compares ---------------------------
        Case {
            name: "admission report digest substituted",
            mutate_statement: Some(|statement| {
                if let Some(treaty) = statement.predicate.treaty_binding_ref.as_mut() {
                    treaty.admission_report_sha256 = sha256_hex(b"conformance:other-report");
                }
            }),
            mutate_envelope: None,
            mutate_verifier_state: None,
            mutate_hook_state: None,
            relation: Relation::AgreeAdmit,
            verifier_code: "",
            hook_code: "",
            divergence: "",
        },
        // -- the offline verifier checks what the hook does not ------------
        Case {
            name: "subject digest does not match the receipt body",
            mutate_statement: Some(|statement| {
                statement.subject[0].digest.sha256 = sha256_hex(b"conformance:other-receipt-body");
            }),
            mutate_envelope: None,
            mutate_verifier_state: None,
            mutate_hook_state: None,
            relation: Relation::VerifierOnly,
            verifier_code: "subject.digest_mismatch",
            hook_code: "",
            divergence: "the pre-dispatch hook never resolves the subject receipt and never \
                         reads the statement's subject, so the subject binding of the \
                         conforming verifier's steps 17 to 19 has no counterpart on the \
                         dispatch path.",
        },
        Case {
            name: "subject receipt absent from the receiver's receipt store",
            mutate_statement: None,
            mutate_envelope: None,
            mutate_verifier_state: Some(|state| {
                state.receipt_store = InMemoryReceiptStore::new();
            }),
            mutate_hook_state: None,
            relation: Relation::VerifierOnly,
            verifier_code: "subject.digest_mismatch",
            hook_code: "",
            divergence: "the hook has no receipt store on this path, so a statement whose \
                         subject names a receipt the receiver does not hold still admits.",
        },
        Case {
            name: "capability lease absent from the receiver's registry",
            mutate_statement: None,
            mutate_envelope: None,
            mutate_verifier_state: Some(|state| {
                state.lease_registry = InMemoryLeaseRegistry::new();
            }),
            mutate_hook_state: None,
            relation: Relation::VerifierOnly,
            verifier_code: "capability.lease_expired_or_unknown",
            hook_code: "",
            divergence: "the hook compares the binding's lease references against the lease \
                         identifier its own admission bundle names; it does not resolve the \
                         lease record itself, so expiry and issuer are not checked here.",
        },
        Case {
            name: "governance record absent from the receiver's store",
            mutate_statement: None,
            mutate_envelope: None,
            mutate_verifier_state: Some(|state| {
                state.governance_store = InMemoryGovernanceReceiptStore::new();
            }),
            mutate_hook_state: None,
            relation: Relation::VerifierOnly,
            verifier_code: "governance.receipt_required_missing",
            hook_code: "",
            divergence: "the hook compares governance references against its own admission \
                         bundle and does not resolve the governance record or re-derive its \
                         digest.",
        },
        Case {
            name: "peer passport revoked at the pinned epoch",
            mutate_statement: None,
            mutate_envelope: None,
            mutate_verifier_state: Some(|state| {
                state.revoke_origin = true;
            }),
            mutate_hook_state: None,
            relation: Relation::VerifierOnly,
            verifier_code: "peer.revoked_at_epoch",
            hook_code: "",
            divergence: "revocation reaches the kernel through its revocation view rather \
                         than through this hook; the hook resolves no revocation oracle.",
        },
        Case {
            name: "pinned peer has no ladder manifest reference",
            mutate_statement: None,
            mutate_envelope: None,
            mutate_verifier_state: Some(|state| {
                state.drop_origin_ladder_ref = true;
            }),
            mutate_hook_state: None,
            relation: Relation::VerifierOnly,
            verifier_code: "ladder.manifest_missing",
            hook_code: "",
            divergence: "the hook activates both manifests itself and stores their \
                         intersection, so it checks the intersection rather than a per-peer \
                         manifest reference.",
        },
        Case {
            name: "unanimous deny",
            mutate_statement: Some(|statement| {
                if let Some(summary) = statement.predicate.policy_evaluation_summary.as_mut() {
                    summary.server_a_verdict.verdict = "deny".to_string();
                    summary.server_b_verdict.verdict = "deny".to_string();
                    summary.joint_disposition = Some("deny".to_string());
                }
            }),
            mutate_envelope: None,
            mutate_verifier_state: None,
            mutate_hook_state: None,
            relation: Relation::HookOnly,
            verifier_code: "",
            hook_code: "chio_treaty_policy_denied",
            divergence: "a unanimous deny is a valid statement and the conforming verifier \
                         returns it verified for audit and dispute review. Admission is the \
                         stricter caller: the hook requires allow.",
        },
        // -- the hook checks what the offline verifier cannot --------------
        Case {
            name: "continuation already spent",
            mutate_statement: None,
            mutate_envelope: None,
            mutate_verifier_state: None,
            mutate_hook_state: Some(|state| {
                state
                    .store
                    .consume_treaty_continuation(CONTINUATION_ID, "adm-conformance-earlier")?;
                Ok(())
            }),
            relation: Relation::HookOnly,
            verifier_code: "",
            hook_code: "chio_treaty_continuation_replay",
            divergence: "single use is a property of one table in the receiver's store. \
                         Nothing in the envelope records whether the continuation was spent, \
                         so an offline verifier cannot decide it.",
        },
        Case {
            name: "continuation outside its validity window",
            mutate_statement: None,
            mutate_envelope: None,
            mutate_verifier_state: None,
            mutate_hook_state: Some(|state| {
                state.continuation_expires_at_unix_ms = ISSUED_AT_MS + 1;
                Ok(())
            }),
            relation: Relation::HookOnly,
            verifier_code: "",
            hook_code: "chio_treaty_continuation_stale",
            divergence: "the continuation is a receiver-owned record the statement names \
                         only by digest; the offline verifier never resolves it.",
        },
        Case {
            name: "request smuggles a trust root",
            mutate_statement: None,
            mutate_envelope: None,
            mutate_verifier_state: None,
            mutate_hook_state: Some(|state| {
                state.smuggle_trust_root = true;
                Ok(())
            }),
            relation: Relation::HookOnly,
            verifier_code: "",
            hook_code: "request_smuggled_trust_root",
            divergence: "the refusal is over the request's own agreement context, which no \
                         offline verifier of an envelope ever sees.",
        },
        Case {
            name: "agreement scope digest presented does not match the store",
            mutate_statement: None,
            mutate_envelope: None,
            mutate_verifier_state: None,
            mutate_hook_state: Some(|state| {
                state.presented_treaty_scope_sha256 =
                    Some(sha256_hex(b"conformance:other-treaty-scope"));
                Ok(())
            }),
            relation: Relation::HookOnly,
            verifier_code: "",
            hook_code: "chio_treaty_scope_hash_mismatch",
            divergence: "the agreement is resolved by identifier out of the receiver's own \
                         store and compared against the digest the request presented. No \
                         agreement record reaches the offline verifier.",
        },
        Case {
            name: "action class presented disagrees with the stored continuation",
            mutate_statement: None,
            mutate_envelope: None,
            mutate_verifier_state: None,
            mutate_hook_state: Some(|state| {
                state.presented_action_class_id = Some("workflow.destructive.other".to_string());
                Ok(())
            }),
            relation: Relation::HookOnly,
            verifier_code: "",
            hook_code: "chio_treaty_continuation_mismatch",
            divergence: "the class the request names is checked against the continuation and \
                         the intersection the receiver stored, and the continuation is \
                         compared first. The envelope carries the class identifier and \
                         nothing that would let an offline verifier decide whether the \
                         receiver admits that class.",
        },
    ]
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

#[test]
fn the_two_deciders_relate_as_the_corpus_declares() -> TestResult {
    for case in corpus() {
        let observed = run_case(&case)?;
        let relation = observed.relation();
        assert_eq!(
            relation, case.relation,
            "case {:?}: expected {:?}, observed {:?} (verifier {:?}, hook {:?})",
            case.name, case.relation, relation, observed.verifier, observed.hook
        );
        assert_eq!(
            observed.verifier.code(),
            case.verifier_code,
            "case {:?}: conforming verifier code",
            case.name
        );
        assert_eq!(
            observed.hook.code(),
            case.hook_code,
            "case {:?}: pre-dispatch hook code",
            case.name
        );
    }
    Ok(())
}

#[test]
fn every_divergence_carries_its_reason() {
    for case in corpus() {
        match case.relation {
            Relation::AgreeAdmit | Relation::AgreeReject => assert!(
                case.divergence.is_empty(),
                "case {:?} agrees and must not carry a divergence note",
                case.name
            ),
            Relation::VerifierOnly | Relation::HookOnly => assert!(
                !case.divergence.is_empty(),
                "case {:?} diverges and must say why",
                case.name
            ),
        }
    }
}

/// The divergence set is asserted whole. A check that moves between the two
/// deciders, in either direction, changes this list and fails here.
#[test]
fn the_divergence_set_is_exactly_this() {
    let mut verifier_only: Vec<&str> = Vec::new();
    let mut hook_only: Vec<&str> = Vec::new();
    for case in corpus() {
        match case.relation {
            Relation::VerifierOnly => verifier_only.push(case.name),
            Relation::HookOnly => hook_only.push(case.name),
            _ => {}
        }
    }
    assert_eq!(
        verifier_only,
        vec![
            "subject digest does not match the receipt body",
            "subject receipt absent from the receiver's receipt store",
            "capability lease absent from the receiver's registry",
            "governance record absent from the receiver's store",
            "peer passport revoked at the pinned epoch",
            "pinned peer has no ladder manifest reference",
        ]
    );
    assert_eq!(
        hook_only,
        vec![
            "consistency model downgraded below the class",
            "unanimous deny",
            "continuation already spent",
            "continuation outside its validity window",
            "request smuggles a trust root",
            "agreement scope digest presented does not match the store",
            "action class presented disagrees with the stored continuation",
        ]
    );
}

/// The single most consequential divergence, stated on its own so a reader of
/// the failure output sees it by name: the receiver-side receipt resolution the
/// conforming verifier performs does not run on the dispatch path.
#[test]
fn the_hook_does_not_resolve_the_subject_receipt() -> TestResult {
    let case = corpus()
        .into_iter()
        .find(|case| case.name == "subject digest does not match the receipt body")
        .ok_or("the subject-digest case is missing from the corpus")?;
    let observed = run_case(&case)?;
    assert_eq!(
        observed.verifier,
        Answer::Reject("subject.digest_mismatch".to_string()),
        "the conforming verifier re-derives the subject digest from the receipt it resolved"
    );
    assert!(
        observed.hook.is_admit(),
        "the pre-dispatch hook reads no subject and resolves no receipt, so it admits"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Running one case through both deciders
// ---------------------------------------------------------------------------

struct Observed {
    verifier: Answer,
    hook: Answer,
}

impl Observed {
    fn relation(&self) -> Relation {
        match (self.verifier.is_admit(), self.hook.is_admit()) {
            (true, true) => Relation::AgreeAdmit,
            (false, false) => Relation::AgreeReject,
            (false, true) => Relation::VerifierOnly,
            (true, false) => Relation::HookOnly,
        }
    }
}

fn run_case(case: &Case) -> Result<Observed, BoxError> {
    let fixture = Fixture::build()?;
    let envelope = mutated_envelope(&fixture, case)?;

    let mut verifier_state = VerifierState::from_fixture(&fixture)?;
    if let Some(mutate) = case.mutate_verifier_state {
        mutate(&mut verifier_state);
    }

    let mut hook_state = HookState::from_fixture(&fixture);
    if let Some(mutate) = case.mutate_hook_state {
        mutate(&mut hook_state)?;
    }

    Ok(Observed {
        verifier: verifier_state.decide(&envelope),
        hook: hook_state.decide(&fixture, &envelope)?,
    })
}

/// Build the baseline envelope through the producer API, then decode, mutate
/// and re-sign with both participant keys, so every rejection below is a
/// comparison rather than a broken signature. Mutations that must leave the
/// signatures broken run afterwards, on the envelope.
fn mutated_envelope(fixture: &Fixture, case: &Case) -> Result<DsseEnvelope, BoxError> {
    let mut envelope = fixture.envelope.clone();
    if let Some(mutate) = case.mutate_statement {
        let (mut statement, _) = envelope.decode_statement()?;
        mutate(&mut statement);
        let statement_bytes = statement.canonical_bytes()?;
        let pae_bytes = pae(PAYLOAD_TYPE_IN_TOTO, &statement_bytes);
        envelope = DsseEnvelope {
            payload_type: PAYLOAD_TYPE_IN_TOTO.to_string(),
            payload: base64::engine::general_purpose::STANDARD.encode(&statement_bytes),
            signatures: vec![
                dsse_signature(&fixture.origin_key, &pae_bytes),
                dsse_signature(&fixture.receiver_key, &pae_bytes),
            ],
        };
    }
    if let Some(mutate) = case.mutate_envelope {
        mutate(&mut envelope);
    }
    Ok(envelope)
}

fn dsse_signature(keypair: &Keypair, pae_bytes: &[u8]) -> DsseSignature {
    DsseSignature {
        keyid: Keyid::from_public_key(&keypair.public_key()).0,
        sig: base64::engine::general_purpose::STANDARD.encode(keypair.sign(pae_bytes).to_bytes()),
    }
}

// ---------------------------------------------------------------------------
// Decider one: the specification's numbered conforming verifier
// ---------------------------------------------------------------------------

struct VerifierState {
    origin_public_key: chio_core_types::crypto::PublicKey,
    receiver_public_key: chio_core_types::crypto::PublicKey,
    receipt_store: InMemoryReceiptStore,
    lease_registry: InMemoryLeaseRegistry,
    governance_store: InMemoryGovernanceReceiptStore,
    revoke_origin: bool,
    drop_origin_ladder_ref: bool,
}

impl VerifierState {
    fn from_fixture(fixture: &Fixture) -> Result<Self, BoxError> {
        let mut receipt_store = InMemoryReceiptStore::new();
        receipt_store.insert(fixture.receipt.clone());
        let mut lease_registry = InMemoryLeaseRegistry::new();
        lease_registry.insert(ResolvedLease {
            lease_id: LEASE_ID.to_string(),
            issuer: ORIGIN_KERNEL.to_string(),
            expires_at_unix_ms: EXPIRES_AT_MS,
            scope_digest_hex: None,
        });
        let mut governance_store = InMemoryGovernanceReceiptStore::new();
        governance_store.insert(ResolvedGovernanceReceipt {
            receipt_id: GOVERNANCE_ID.to_string(),
            kernel_id: RECEIVER_KERNEL.to_string(),
            canonical_json: governance_canonical_json(),
        });
        Ok(Self {
            origin_public_key: fixture.origin_key.public_key(),
            receiver_public_key: fixture.receiver_key.public_key(),
            receipt_store,
            lease_registry,
            governance_store,
            revoke_origin: false,
            drop_origin_ladder_ref: false,
        })
    }

    fn decide(&self, envelope: &DsseEnvelope) -> Answer {
        let mut pin_set = PeerPinSet::new();
        pin_set.insert(PinnedPeer {
            kernel_id: ORIGIN_KERNEL.to_string(),
            public_key: self.origin_public_key.clone(),
            ladder_manifest_ref: if self.drop_origin_ladder_ref {
                None
            } else {
                Some(ladder_manifest_ref("manifest-origin"))
            },
        });
        pin_set.insert(PinnedPeer {
            kernel_id: RECEIVER_KERNEL.to_string(),
            public_key: self.receiver_public_key.clone(),
            ladder_manifest_ref: Some(ladder_manifest_ref("manifest-receiver")),
        });

        let mut oracle = DenyListRevocationOracle::new();
        if self.revoke_origin {
            oracle.revoke(&Keyid::from_public_key(&self.origin_public_key));
        }

        let mut action_classes = BTreeMap::new();
        action_classes.insert(TOOL_NAME.to_string(), ActionClassKind::ReceiptBacked);

        let base = VerifierConfig {
            peer_pin_set: &pin_set,
            receipt_store: &self.receipt_store,
            lease_registry: &self.lease_registry,
            governance_receipt_store: &self.governance_store,
            revocation_oracle: &oracle,
            pinned_epoch: PinnedEpoch {
                now_unix_ms: NOW_MS,
                epoch_height: EPOCH_HEIGHT,
            },
            action_classes,
            unknown_action_class_policy: UnknownActionClassPolicy::Reject,
        };
        let config = ChioBilateralVerifierConfig { base: &base };
        match verify_chio_bilateral_invocation(envelope, &config) {
            Ok(_) => Answer::Admit,
            Err(error) => Answer::Reject(error.code().to_string()),
        }
    }
}

fn ladder_manifest_ref(manifest_id: &str) -> LadderManifestRef {
    LadderManifestRef {
        manifest_id: manifest_id.to_string(),
        sha256: sha256_hex(manifest_id.as_bytes()),
        issued_at_unix_ms: ISSUED_AT_MS,
        expires_at_unix_ms: EXPIRES_AT_MS,
    }
}

fn governance_canonical_json() -> String {
    format!("{{\"receiptId\":\"{GOVERNANCE_ID}\"}}")
}

// ---------------------------------------------------------------------------
// Decider two: the kernel's pre-dispatch admission hook
// ---------------------------------------------------------------------------

struct HookState {
    store: InMemoryRuntimeAdmissionStore,
    continuation_expires_at_unix_ms: u64,
    smuggle_trust_root: bool,
    presented_treaty_scope_sha256: Option<String>,
    presented_action_class_id: Option<String>,
}

impl HookState {
    fn from_fixture(fixture: &Fixture) -> Self {
        Self {
            store: InMemoryRuntimeAdmissionStore::new(),
            continuation_expires_at_unix_ms: fixture.continuation.expires_at_unix_ms,
            smuggle_trust_root: false,
            presented_treaty_scope_sha256: None,
            presented_action_class_id: None,
        }
    }

    fn decide(&self, fixture: &Fixture, envelope: &DsseEnvelope) -> Result<Answer, BoxError> {
        let mut continuation = fixture.continuation.clone();
        continuation.expires_at_unix_ms = self.continuation_expires_at_unix_ms;
        let continuation_sha256 = sha256_hex(&canonical_json_bytes(&continuation)?);
        let continuation_is_baseline = continuation_sha256 == fixture.continuation_sha256;

        self.store.insert_bundle(fixture.bundle.clone())?;
        self.store.insert_treaty_runtime_artifact(
            "treaty_scope",
            &fixture.treaty_scope.treaty_id,
            &fixture.treaty_scope,
        )?;
        self.store.insert_treaty_runtime_artifact(
            "ladder_intersection",
            &fixture.ladder_intersection.intersection_id,
            &fixture.ladder_intersection,
        )?;
        self.store.insert_treaty_runtime_artifact(
            "cross_kernel_continuation",
            CONTINUATION_ID,
            &continuation,
        )?;
        self.store.insert_treaty_runtime_artifact(
            "receipt_lineage_bundle",
            &fixture.lineage_bundle.bundle_id,
            &fixture.lineage_bundle,
        )?;
        self.store.insert_treaty_runtime_artifact(
            "bilateral_invocation",
            INVOCATION_ID,
            &fixture.invocation,
        )?;
        self.store
            .insert_treaty_runtime_artifact("bilateral_dsse_envelope", DSSE_ID, envelope)?;

        let envelope_sha256 = sha256_hex(&canonical_json_bytes(envelope)?);
        let mut context = serde_json::json!({
            "treatyScopeId": fixture.treaty_scope.treaty_id,
            "treatyScopeSha256": self
                .presented_treaty_scope_sha256
                .clone()
                .unwrap_or_else(|| fixture.treaty_scope_sha256.clone()),
            "ladderIntersectionId": fixture.ladder_intersection.intersection_id,
            "ladderIntersectionSha256": fixture.ladder_intersection_sha256,
            "actionClassId": self
                .presented_action_class_id
                .clone()
                .unwrap_or_else(|| ACTION_CLASS.to_string()),
            "crossKernelContinuation": {
                "id": CONTINUATION_ID,
                "sha256": continuation_sha256,
            },
            "receiptLineageBundle": {
                "id": fixture.lineage_bundle.bundle_id,
                "sha256": fixture.lineage_bundle_sha256,
            },
            "bilateralInvocation": {
                "id": INVOCATION_ID,
                "sha256": fixture.invocation_sha256,
            },
            "bilateralDsse": { "id": DSSE_ID, "sha256": envelope_sha256 },
        });
        if self.smuggle_trust_root {
            context["trustRoot"] = serde_json::json!("did:chio:attacker-root");
        }
        // A continuation the case moved out of its window no longer hashes to
        // the digest the co-signed binding names, so the hook would answer the
        // binding mismatch first. The window check is what this case is for, so
        // the binding reference is realigned to the continuation the receiver
        // actually stored.
        let envelope = if continuation_is_baseline {
            envelope.clone()
        } else {
            realign_binding_continuation(fixture, envelope, &continuation_sha256)?
        };
        if !continuation_is_baseline {
            let realigned_sha256 = sha256_hex(&canonical_json_bytes(&envelope)?);
            self.store.insert_treaty_runtime_artifact(
                "bilateral_dsse_envelope",
                "bilateral-dsse-conformance-realigned",
                &envelope,
            )?;
            context["bilateralDsse"] = serde_json::json!({
                "id": "bilateral-dsse-conformance-realigned",
                "sha256": realigned_sha256,
            });
            let mut invocation = fixture.invocation.clone();
            invocation.continuation_sha256 = continuation_sha256.clone();
            let invocation_sha256 = bilateral_invocation_binding_sha256(&invocation)?;
            self.store.insert_treaty_runtime_artifact(
                "bilateral_invocation",
                "invoke-conformance-realigned",
                &invocation,
            )?;
            context["bilateralInvocation"] = serde_json::json!({
                "id": "invoke-conformance-realigned",
                "sha256": invocation_sha256,
            });
            let mut lineage_bundle = fixture.lineage_bundle.clone();
            for statement in &mut lineage_bundle.statements {
                statement.continuation_sha256 = continuation_sha256.clone();
                statement.bilateral_invocation_sha256 = invocation_sha256.clone();
            }
            let lineage_bundle_sha256 = sha256_hex(&canonical_json_bytes(&lineage_bundle)?);
            self.store.insert_treaty_runtime_artifact(
                "receipt_lineage_bundle",
                "lineage-bundle-conformance-realigned",
                &lineage_bundle,
            )?;
            context["receiptLineageBundle"] = serde_json::json!({
                "id": "lineage-bundle-conformance-realigned",
                "sha256": lineage_bundle_sha256,
            });
        }

        let request = treaty_request(&fixture.bundle_sha256, context)?;
        let hook = allowing_hook(self.store.clone())?;
        let decision = hook.evaluate(&RuntimeAdmissionContext {
            request: &request,
            extra_metadata: None,
            now_unix_secs: NOW_MS / 1_000,
            now_unix_ms: NOW_MS,
            matched_grant_index: Some(0),
            local_kernel_id: RECEIVER_KERNEL.to_string(),
        })?;
        if decision.allowed {
            return Ok(Answer::Admit);
        }
        let metadata = decision.metadata.unwrap_or(serde_json::Value::Null);
        let code = metadata["chio_runtime"]["failure_code"]
            .as_str()
            .unwrap_or("unknown_failure_code")
            .to_string();
        Ok(Answer::Reject(code))
    }
}

/// Re-sign the statement with the binding reference pointing at a different
/// continuation digest, keeping every other field and both signatures valid.
fn realign_binding_continuation(
    fixture: &Fixture,
    envelope: &DsseEnvelope,
    continuation_sha256: &str,
) -> Result<DsseEnvelope, BoxError> {
    let (mut statement, _) = envelope.decode_statement()?;
    if let Some(treaty) = statement.predicate.treaty_binding_ref.as_mut() {
        treaty.continuation_sha256 = continuation_sha256.to_string();
    }
    let statement_bytes = statement.canonical_bytes()?;
    let pae_bytes = pae(PAYLOAD_TYPE_IN_TOTO, &statement_bytes);
    Ok(DsseEnvelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_string(),
        payload: base64::engine::general_purpose::STANDARD.encode(&statement_bytes),
        signatures: vec![
            dsse_signature(&fixture.origin_key, &pae_bytes),
            dsse_signature(&fixture.receiver_key, &pae_bytes),
        ],
    })
}

// ---------------------------------------------------------------------------
// The shared world
// ---------------------------------------------------------------------------

struct Fixture {
    origin_key: Keypair,
    receiver_key: Keypair,
    treaty_scope: TreatyScope,
    treaty_scope_sha256: String,
    ladder_intersection: LadderIntersection,
    ladder_intersection_sha256: String,
    continuation: CrossKernelContinuation,
    continuation_sha256: String,
    lineage_bundle: ReceiptLineageBundle,
    lineage_bundle_sha256: String,
    invocation: BilateralInvocation,
    invocation_sha256: String,
    receipt: ChioReceipt,
    envelope: DsseEnvelope,
    bundle: RuntimeAdmissionBundle,
    bundle_sha256: String,
}

impl Fixture {
    fn build() -> Result<Self, BoxError> {
        let origin_key = Keypair::generate();
        let receiver_key = Keypair::generate();

        let origin_manifest = ladder_manifest(ORIGIN_KERNEL);
        let receiver_manifest = ladder_manifest(RECEIVER_KERNEL);
        let treaty_scope = TreatyScope {
            schema: CHIO_TREATY_SCOPE_SCHEMA.to_string(),
            treaty_id: "treaty:conformance:1".to_string(),
            participant_kernel_ids: vec![ORIGIN_KERNEL.to_string(), RECEIVER_KERNEL.to_string()],
            participant_public_keys: vec![origin_key.public_key(), receiver_key.public_key()],
            ladder_manifest_sha256s: vec![
                governance_ladder_manifest_sha256(&origin_manifest)?,
                governance_ladder_manifest_sha256(&receiver_manifest)?,
            ],
            allowed_action_classes: vec![ACTION_CLASS.to_string()],
            issued_at_unix_ms: ISSUED_AT_MS,
            expires_at_unix_ms: EXPIRES_AT_MS,
            revocation_epoch_sha256: REVOCATION_CHECKPOINT_SHA256.to_string(),
            trust_bundle_sha256: TRUST_BUNDLE_SHA256.to_string(),
        };
        let treaty_scope_sha256 = treaty_scope_sha256(&treaty_scope)?;
        let ladder_intersection = compute_ladder_intersection(
            &treaty_scope,
            &[origin_manifest, receiver_manifest],
            NOW_MS,
        )?;
        let ladder_intersection_sha256 = ladder_intersection_sha256(&ladder_intersection)?;

        let arguments = tool_arguments();
        let request_sha256 = tool_args_sha256(&arguments)?;

        let continuation = CrossKernelContinuation {
            schema: CHIO_CROSS_KERNEL_CONTINUATION_SCHEMA.to_string(),
            continuation_id: CONTINUATION_ID.to_string(),
            source_kernel_id: ORIGIN_KERNEL.to_string(),
            target_kernel_id: RECEIVER_KERNEL.to_string(),
            parent_receipt_sha256: sha256_hex(b"conformance:parent-receipt"),
            parent_session_anchor_sha256: sha256_hex(b"conformance:session-anchor"),
            capability_id: CAPABILITY_ID.to_string(),
            action_class_id: ACTION_CLASS.to_string(),
            audience_tool: format!("{TOOL_SERVER}.{TOOL_NAME}"),
            nonce: "nonce-conformance-1".to_string(),
            issued_at_unix_ms: ISSUED_AT_MS,
            expires_at_unix_ms: EXPIRES_AT_MS,
        };
        let continuation_sha256 = sha256_hex(&canonical_json_bytes(&continuation)?);

        let receipt = receiver_receipt(&receiver_key, &arguments)?;
        let remote_receipt_sha256 = sha256_hex(&canonical_json_bytes(&receipt)?);

        let mut invocation = BilateralInvocation {
            schema: CHIO_BILATERAL_INVOCATION_SCHEMA.to_string(),
            invocation_id: INVOCATION_ID.to_string(),
            treaty_id: treaty_scope.treaty_id.clone(),
            ladder_intersection_sha256: ladder_intersection_sha256.clone(),
            continuation_sha256: continuation_sha256.clone(),
            lineage_statement_sha256: String::new(),
            action_class_id: ACTION_CLASS.to_string(),
            consistency_model: "totally_ordered".to_string(),
            capability_id: CAPABILITY_ID.to_string(),
            request_sha256: request_sha256.clone(),
            outcome_sha256: OUTCOME_SHA256.to_string(),
            local_receipt_sha256: continuation.parent_receipt_sha256.clone(),
            remote_receipt_sha256: remote_receipt_sha256.clone(),
            signer_kernel_ids: vec![ORIGIN_KERNEL.to_string(), RECEIVER_KERNEL.to_string()],
        };
        let invocation_sha256 = bilateral_invocation_binding_sha256(&invocation)?;

        let lineage_statement = ReceiptLineageStatement {
            schema: CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
            statement_id: "lineage-conformance-1".to_string(),
            parent_receipt_sha256: invocation.local_receipt_sha256.clone(),
            child_receipt_sha256: remote_receipt_sha256.clone(),
            continuation_sha256: continuation_sha256.clone(),
            bilateral_invocation_sha256: invocation_sha256.clone(),
            evidence_class: "verified".to_string(),
            source_kernel_id: ORIGIN_KERNEL.to_string(),
            target_kernel_id: RECEIVER_KERNEL.to_string(),
        };
        invocation.lineage_statement_sha256 =
            sha256_hex(&canonical_json_bytes(&lineage_statement)?);
        let lineage_bundle = ReceiptLineageBundle {
            schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
            bundle_id: "lineage-bundle-conformance-1".to_string(),
            root_receipt_sha256: lineage_statement.parent_receipt_sha256.clone(),
            leaf_receipt_sha256: lineage_statement.child_receipt_sha256.clone(),
            statements: vec![lineage_statement],
        };
        let lineage_bundle_sha256 = sha256_hex(&canonical_json_bytes(&lineage_bundle)?);

        let consistency_model = bilateral_dsse_consistency_model("totally_ordered")?.to_string();
        let envelope = sign_chio_bilateral_dsse_envelope(
            &receipt,
            &origin_key,
            &receiver_key,
            ORIGIN_KERNEL,
            RECEIVER_KERNEL,
            TOOL_NAME,
            NOW_MS,
            BilateralPredicateExtensions {
                capability_lease_ref: Some(CapabilityLeaseRef {
                    lease_id: LEASE_ID.to_string(),
                    issuer: ORIGIN_KERNEL.to_string(),
                    expires_at_unix_ms: EXPIRES_AT_MS,
                    scope_digest: None,
                }),
                policy_evaluation_summary: Some(allow_summary()),
                governance_receipt_ref: Some(GovernanceReceiptRef {
                    receipt_id: GOVERNANCE_ID.to_string(),
                    kernel_id: RECEIVER_KERNEL.to_string(),
                    digest: HashRecord {
                        alg: "sha256".to_string(),
                        value: sha256_hex(governance_canonical_json().as_bytes()),
                    },
                }),
                consistency_anchor: Some("anchor:conformance".to_string()),
                consistency_model: Some(consistency_model.clone()),
                cross_org_visibility: Some("treaty_only".to_string()),
                treaty_binding_ref: Some(TreatyBindingRef {
                    treaty_id: treaty_scope.treaty_id.clone(),
                    treaty_scope_sha256: treaty_scope_sha256.clone(),
                    ladder_intersection_sha256: ladder_intersection_sha256.clone(),
                    admission_report_sha256: sha256_hex(b"conformance:admission-report"),
                    continuation_sha256: continuation_sha256.clone(),
                    lineage_bundle_sha256: lineage_bundle_sha256.clone(),
                    action_class_id: ACTION_CLASS.to_string(),
                    consistency_model,
                    request_sha256: request_sha256.clone(),
                    outcome_sha256: OUTCOME_SHA256.to_string(),
                    local_receipt_sha256: invocation.local_receipt_sha256.clone(),
                    remote_receipt_sha256,
                    lease_refs: vec![LEASE_ID.to_string()],
                    governance_refs: vec![GOVERNANCE_ID.to_string()],
                    signer_kernel_ids: vec![
                        ORIGIN_KERNEL.to_string(),
                        RECEIVER_KERNEL.to_string(),
                    ],
                }),
            },
        )?;

        let bundle = RuntimeAdmissionBundle {
            schema: CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA.to_string(),
            admission_id: ADMISSION_ID.to_string(),
            binding: RuntimeRequestBinding {
                request_id: REQUEST_ID.to_string(),
                capability_id: CAPABILITY_ID.to_string(),
                server_id: TOOL_SERVER.to_string(),
                tool_name: TOOL_NAME.to_string(),
                tool_args_sha256: request_sha256,
                origin_kernel_id: Some(ORIGIN_KERNEL.to_string()),
                host_kernel_id: RECEIVER_KERNEL.to_string(),
            },
            workflow_id: "wf-conformance-1".to_string(),
            workflow_grant_id: "grant-conformance-1".to_string(),
            step_index: 1,
            destructive: true,
            lease_id: Some(LEASE_ID.to_string()),
            governance_receipt_id: Some(GOVERNANCE_ID.to_string()),
            trust_bundle_sha256: TRUST_BUNDLE_SHA256.to_string(),
            verification_context_sha256: VERIFICATION_CONTEXT_SHA256.to_string(),
        };
        let bundle_sha256 = runtime_admission_bundle_sha256(&bundle)?;

        Ok(Self {
            origin_key,
            receiver_key,
            treaty_scope,
            treaty_scope_sha256,
            ladder_intersection,
            ladder_intersection_sha256,
            continuation,
            continuation_sha256,
            lineage_bundle,
            lineage_bundle_sha256,
            invocation,
            invocation_sha256,
            receipt,
            envelope,
            bundle,
            bundle_sha256,
        })
    }
}

fn tool_arguments() -> serde_json::Value {
    serde_json::json!({"record": "vendor-ledger-7", "value": "closed"})
}

fn allow_summary() -> PolicyEvaluationSummary {
    PolicyEvaluationSummary {
        server_a_verdict: PolicyVerdict {
            verdict: "allow".to_string(),
            policy_id: "policy-origin".to_string(),
            policy_version: "v1".to_string(),
            rationale_code: None,
        },
        server_b_verdict: PolicyVerdict {
            verdict: "allow".to_string(),
            policy_id: "policy-receiver".to_string(),
            policy_version: "v1".to_string(),
            rationale_code: None,
        },
        joint_disposition: Some("allow".to_string()),
    }
}

/// The subject receipt. It is signed by the receiving kernel, which is what
/// step 17 of the conforming verifier requires: the subject of an inbound
/// statement is a receipt the receiver itself issued.
fn receiver_receipt(
    receiver_key: &Keypair,
    arguments: &serde_json::Value,
) -> Result<ChioReceipt, BoxError> {
    Ok(ChioReceipt::sign(
        ChioReceiptBody {
            id: INVOCATION_ID.to_string(),
            timestamp: NOW_MS / 1_000,
            capability_id: CAPABILITY_ID.to_string(),
            tool_server: TOOL_SERVER.to_string(),
            tool_name: TOOL_NAME.to_string(),
            action: ToolCallAction::from_parameters(arguments.clone())?,
            decision: Some(ReceiptDecision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: vec![ActorRef {
                actor_id: format!("agent:{ORIGIN_KERNEL}/conformance"),
                actor_kind: Some("agent".to_string()),
            }],
            content_hash: OUTCOME_SHA256.to_string(),
            policy_hash: sha256_hex(b"conformance:policy"),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: receiver_key.public_key(),
            bbs_projection_version: None,
        },
        receiver_key,
    )?)
}

fn ladder_manifest(kernel_id: &str) -> GovernanceLadderManifest {
    GovernanceLadderManifest {
        schema: CHIO_GOVERNANCE_LADDER_MANIFEST_SCHEMA.to_string(),
        manifest_id: format!("manifest:{kernel_id}"),
        kernel_id: kernel_id.to_string(),
        issuer: kernel_id.to_string(),
        key_id: format!("key:{kernel_id}"),
        issued_at_unix_ms: ISSUED_AT_MS,
        expires_at_unix_ms: EXPIRES_AT_MS,
        destructive_floor: "receipt_backed".to_string(),
        default_unknown_mode: "deny".to_string(),
        action_classes: vec![GovernanceLadderActionClass {
            action_class_id: ACTION_CLASS.to_string(),
            mode: "receipt_backed".to_string(),
            destructive: true,
            consistency_model: "totally_ordered".to_string(),
            co_sign: "bilateral_required".to_string(),
            co_sign_quorum: None,
            evidence_required: vec![
                "bilateral_dsse".to_string(),
                "bilateral_invocation".to_string(),
                "receipt_lineage".to_string(),
            ],
            aliases: Vec::new(),
        }],
    }
}

// ---------------------------------------------------------------------------
// The receiver's own admission configuration
// ---------------------------------------------------------------------------

fn treaty_request(
    bundle_sha256: &str,
    treaty_context: serde_json::Value,
) -> Result<ToolCallRequest, BoxError> {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: CAPABILITY_ID.to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: TOOL_SERVER.to_string(),
                    tool_name: TOOL_NAME.to_string(),
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
            issued_at: ISSUED_AT_MS / 1_000,
            expires_at: EXPIRES_AT_MS / 1_000,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )?;
    let agent_id = capability.subject.to_hex();
    Ok(ToolCallRequest {
        request_id: REQUEST_ID.to_string(),
        capability,
        tool_name: TOOL_NAME.to_string(),
        server_id: TOOL_SERVER.to_string(),
        agent_id,
        arguments: tool_arguments(),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(GovernedTransactionIntent {
            id: "intent-conformance-1".to_string(),
            server_id: TOOL_SERVER.to_string(),
            tool_name: TOOL_NAME.to_string(),
            purpose: "close a governed vendor account across the boundary".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(serde_json::json!({
                "chioAdmission": {
                    "admissionId": ADMISSION_ID,
                    "bundleSha256": bundle_sha256,
                },
                "chioTreaty": treaty_context,
            })),
            body: Default::default(),
        }),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: Some(ORIGIN_KERNEL.to_string()),
    })
}

fn allowing_hook(
    store: InMemoryRuntimeAdmissionStore,
) -> Result<ChioRuntimeAdmissionHook<InMemoryRuntimeAdmissionStore>, BoxError> {
    let verifier = Keypair::generate();
    let signed_trust = SignedExportEnvelope::sign(trust_bundle(), &verifier)?;
    let weights = peer_weights();
    let signed_policy = SignedExportEnvelope::sign(
        pheromone_policy(runtime_peer_weights_sha256(&weights)?),
        &verifier,
    )?;
    let signed_weights = SignedExportEnvelope::sign(weights, &verifier)?;
    let signed_query_report = SignedExportEnvelope::sign(query_report(), &verifier)?;
    Ok(ChioRuntimeAdmissionHook::new(profile(), store)
        .with_runtime_trust_input(signed_trust, trusted_verifier_keys(&verifier))
        .with_pheromone_query_report(signed_query_report)
        .with_runtime_pheromone_policy(signed_policy, signed_weights))
}

fn profile() -> RuntimeAdmissionProfile {
    RuntimeAdmissionProfile {
        schema: CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.to_string(),
        profile_id: "profile-conformance".to_string(),
        local_kernel_id: RECEIVER_KERNEL.to_string(),
        verifier_id: VERIFIER_ID.to_string(),
        issued_at_unix_ms: ISSUED_AT_MS,
        expires_at_unix_ms: EXPIRES_AT_MS,
    }
}

fn trusted_verifier_keys(verifier: &Keypair) -> Vec<RuntimeTrustedVerifierKey> {
    vec![RuntimeTrustedVerifierKey {
        verifier_id: VERIFIER_ID.to_string(),
        key_id: VERIFIER_KEY_ID.to_string(),
        public_key: verifier.public_key(),
        valid_from_unix_ms: ISSUED_AT_MS,
        valid_until_unix_ms: EXPIRES_AT_MS,
        status: "active".to_string(),
    }]
}

fn trust_bundle() -> RuntimeVerifierTrustBundleV4 {
    RuntimeVerifierTrustBundleV4 {
        schema: CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA.to_string(),
        verifier_id: VERIFIER_ID.to_string(),
        key_id: VERIFIER_KEY_ID.to_string(),
        version: 1,
        previous_hash_sha256: None,
        trust_bundle_sha256: TRUST_BUNDLE_SHA256.to_string(),
        verification_context_sha256: VERIFICATION_CONTEXT_SHA256.to_string(),
        revocation_checkpoint_sha256: REVOCATION_CHECKPOINT_SHA256.to_string(),
        revocation_authority_roots: vec!["did:chio:revocation-authority".to_string()],
        issued_at_unix_ms: ISSUED_AT_MS,
        expires_at_unix_ms: EXPIRES_AT_MS,
    }
}

fn query_report() -> serde_json::Value {
    serde_json::json!({
        "schema": "chio.pheromone.query-report.v1",
        "accepted": true,
        "concentration": {
            "subjectClass": "workflow.destructive_step",
            "subjectClassNamespace": "chio.runtime",
            "totalStrength": 0.10,
            "distinctOriginPairs": 1,
            "reputationEpoch": EPOCH_HEIGHT,
            "evaluatedAtUnixMs": NOW_MS
        }
    })
}

fn pheromone_policy(peer_weights_sha256: String) -> RuntimePheromonePolicy {
    RuntimePheromonePolicy {
        schema: CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA.to_string(),
        policy_id: "policy-conformance-risk".to_string(),
        verifier_id: VERIFIER_ID.to_string(),
        key_id: VERIFIER_KEY_ID.to_string(),
        policy_version: 1,
        mode: "enforce".to_string(),
        issued_at_unix_ms: ISSUED_AT_MS,
        expires_at_unix_ms: EXPIRES_AT_MS,
        allowed_reputation_epochs: vec![EPOCH_HEIGHT],
        max_query_report_age_ms: 60_000,
        min_distinct_origin_pairs: 1,
        runtime_trust_bundle_sha256: TRUST_BUNDLE_SHA256.to_string(),
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
        verifier_id: VERIFIER_ID.to_string(),
        key_id: VERIFIER_KEY_ID.to_string(),
        reputation_epoch: EPOCH_HEIGHT,
        issued_at_unix_ms: ISSUED_AT_MS,
        expires_at_unix_ms: EXPIRES_AT_MS,
        weights: vec![RuntimePeerWeight {
            peer_kernel_id: RECEIVER_KERNEL.to_string(),
            weight: 1.0,
        }],
    }
}
