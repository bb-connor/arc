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
//! offline verifier sees none of the four. The two also read the participants'
//! public keys out of two different receiver-owned stores: the verifier from
//! its pin set, the hook from the activated agreement, which is its own
//! divergence and has its own case here.
//!
//! Coverage is exact and asserted mechanically rather than claimed. The corpus
//! exercises all sixteen rejection codes `VerifierError::code` can return and
//! nineteen of the twenty-four `chio_treaty_` codes the runtime registry
//! defines; `the_corpus_covers_every_verifier_rejection_class` and
//! `the_agreement_scoped_hook_codes_the_corpus_covers` name both sets and the
//! five codes no case reaches. This is a corpus, not a proof: it establishes
//! how the two deciders relate on these inputs and nothing about inputs it does
//! not contain, so a check added to either decider must be added here too.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};

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
    decision::ToolCallAction, kinds::BoundaryClass, kinds::ReceiptKind, kinds::RedactionMode,
    kinds::ToolOrigin, kinds::TrustLevel, metadata::ActorRef,
};
use chio_federation::bilateral::RejectionCode;
use chio_federation::bilateral_dsse::{
    pae, sign_chio_bilateral_dsse_envelope, BilateralPredicateExtensions, CapabilityLeaseRef,
    DsseEnvelope, DsseSignature, DsseStatement, GovernanceReceiptRef, HashRecord, Keyid,
    PolicyEvaluationSummary, PolicyVerdict, TreatyBindingRef, PAYLOAD_TYPE_IN_TOTO,
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
    CHIO_GOVERNANCE_LADDER_MANIFEST_SCHEMA, CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA,
    CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA, CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA,
    CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA, CHIO_RUNTIME_FAILURE_CODES,
    CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA, CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA,
    CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA, CHIO_TREATY_SCOPE_SCHEMA,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type BoxError = Box<dyn std::error::Error>;
/// Mutation of the decoded statement, applied before it is re-signed.
type StatementMutation = fn(&mut DsseStatement, &Fixture);
/// Mutation of the receiver's runtime state, which can fail against the store.
type HookStateMutation = fn(&mut HookState) -> Result<(), BoxError>;

const ORIGIN_KERNEL: &str = "kernel.buyer";
const RECEIVER_KERNEL: &str = "kernel.vendor-b";
const TOOL_SERVER: &str = "vendor-ledger";
const TOOL_NAME: &str = "close_account";
const ACTION_CLASS: &str = "workflow.destructive.vendor_call";
const OTHER_ACTION_CLASS: &str = "workflow.destructive.other";
const CAPABILITY_ID: &str = "cap-conformance-1";
const OTHER_CAPABILITY_ID: &str = "cap-conformance-other";
const LEASE_ID: &str = "lease-conformance-1";
const GOVERNANCE_ID: &str = "gov-conformance-1";
const ADMISSION_ID: &str = "adm-conformance-1";
const REQUEST_ID: &str = "req-conformance-1";
const CONTINUATION_ID: &str = "continue-conformance-1";
const INVOCATION_ID: &str = "invoke-conformance-1";
const LINEAGE_BUNDLE_ID: &str = "lineage-bundle-conformance-1";
const DSSE_ID: &str = "bilateral-dsse-conformance-1";
const VERIFIER_ID: &str = "did:chio:receiver-verifier";
const VERIFIER_KEY_ID: &str = "verifier-key-1";
/// Identifier no case ever stores, for the artifact-does-not-resolve cases.
const ABSENT_ID: &str = "conformance-absent";

const ORIGIN_SEED: [u8; 32] = [0x11; 32];
const RECEIVER_SEED: [u8; 32] = [0x22; 32];
/// The origin's key after a rotation the receiver carried into the activated
/// agreement but not into its pin set.
const ROTATED_ORIGIN_SEED: [u8; 32] = [0x33; 32];

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
    mutate_statement: Option<StatementMutation>,
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

impl Case {
    /// A case both deciders admit. The relation and codes are narrowed by one
    /// of the four terminal builders below.
    fn new(name: &'static str) -> Self {
        Self {
            name,
            mutate_statement: None,
            mutate_envelope: None,
            mutate_verifier_state: None,
            mutate_hook_state: None,
            relation: Relation::AgreeAdmit,
            verifier_code: "",
            hook_code: "",
            divergence: "",
        }
    }

    fn statement(mut self, mutate: StatementMutation) -> Self {
        self.mutate_statement = Some(mutate);
        self
    }

    fn envelope(mut self, mutate: fn(&mut DsseEnvelope)) -> Self {
        self.mutate_envelope = Some(mutate);
        self
    }

    fn verifier_state(mut self, mutate: fn(&mut VerifierState)) -> Self {
        self.mutate_verifier_state = Some(mutate);
        self
    }

    fn hook_state(mut self, mutate: HookStateMutation) -> Self {
        self.mutate_hook_state = Some(mutate);
        self
    }

    fn agree_reject(mut self, verifier_code: &'static str, hook_code: &'static str) -> Self {
        self.relation = Relation::AgreeReject;
        self.verifier_code = verifier_code;
        self.hook_code = hook_code;
        self
    }

    fn verifier_only(mut self, verifier_code: &'static str, divergence: &'static str) -> Self {
        self.relation = Relation::VerifierOnly;
        self.verifier_code = verifier_code;
        self.divergence = divergence;
        self
    }

    fn hook_only(mut self, hook_code: &'static str, divergence: &'static str) -> Self {
        self.relation = Relation::HookOnly;
        self.hook_code = hook_code;
        self.divergence = divergence;
        self
    }
}

// ---------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------

fn corpus() -> Vec<Case> {
    vec![
        Case::new("accept"),
        // -- both reject: the envelope alone decides ----------------------
        Case::new("wrong payload type")
            .envelope(|envelope| {
                envelope.payload_type = "application/json".to_string();
            })
            .agree_reject("dsse.malformed", "chio_treaty_unverified_required_evidence"),
        Case::new("payload is not parseable JSON")
            .envelope(|envelope| {
                envelope.payload = base64::engine::general_purpose::STANDARD.encode(b"{\"_type\":");
            })
            .agree_reject(
                "statement.malformed",
                "chio_treaty_unverified_required_evidence",
            ),
        Case::new("statement type is not in-toto Statement v1")
            .statement(|statement, _fixture| {
                statement.statement_type = "https://in-toto.io/Statement/v0.1".to_string();
            })
            .agree_reject(
                "statement.schema_invalid",
                "chio_treaty_unverified_required_evidence",
            ),
        Case::new("payload mutated after signing")
            .envelope(|envelope| {
                let mut decoded = base64::engine::general_purpose::STANDARD
                    .decode(envelope.payload.as_bytes())
                    .unwrap_or_default();
                if let Some(position) = decoded.iter().position(|byte| *byte == b'0') {
                    decoded[position] = b'1';
                }
                envelope.payload = base64::engine::general_purpose::STANDARD.encode(&decoded);
            })
            .agree_reject(
                "signature.server_a_invalid",
                "chio_treaty_unverified_required_evidence",
            ),
        // The two signature-isolation cases. Each leaves one signature valid
        // over unmodified bytes and forges the other, which is what separates
        // what each participant's key contributes from what the envelope as a
        // whole contributes.
        Case::new("only the origin's signature is forged")
            .envelope(|envelope| {
                if let Some(signature) = envelope.signatures.first_mut() {
                    signature.sig = forged_signature(&signature.sig);
                }
            })
            .agree_reject(
                "signature.server_a_invalid",
                "chio_treaty_unverified_required_evidence",
            ),
        Case::new("only the receiver's signature is forged")
            .envelope(|envelope| {
                if let Some(signature) = envelope.signatures.get_mut(1) {
                    signature.sig = forged_signature(&signature.sig);
                }
            })
            .agree_reject(
                "signature.server_b_invalid",
                "chio_treaty_unverified_required_evidence",
            ),
        Case::new("one signature removed")
            .envelope(|envelope| {
                envelope.signatures.truncate(1);
            })
            .agree_reject("dsse.malformed", "chio_treaty_unverified_required_evidence"),
        Case::new("duplicate signature keyid")
            .envelope(|envelope| {
                if envelope.signatures.len() == 2 {
                    envelope.signatures[1].keyid = envelope.signatures[0].keyid.clone();
                }
            })
            .agree_reject("dsse.malformed", "chio_treaty_unverified_required_evidence"),
        Case::new("predicate type is the compatibility profile")
            .statement(|statement, _fixture| {
                statement.predicate_type = "chio.bilateral-signature-slice.v1".to_string();
            })
            .agree_reject(
                "predicate.type_unrecognised",
                "chio_treaty_unverified_required_evidence",
            ),
        Case::new("origin kernel renamed to an unpinned identity")
            .statement(|statement, _fixture| {
                statement.predicate.tool_server_a.kernel_id = "kernel.impostor".to_string();
                if let Some(treaty) = statement.predicate.treaty_binding_ref.as_mut() {
                    treaty.signer_kernel_ids[0] = "kernel.impostor".to_string();
                }
            })
            .agree_reject(
                "peer.unpinned_or_keyid_mismatch",
                "chio_treaty_dsse_binding_mismatch",
            ),
        Case::new("declared passport fingerprint disagrees with the pin")
            .statement(|statement, _fixture| {
                statement.predicate.tool_server_a.passport_key_fingerprint =
                    Keyid(sha256_hex(b"conformance:not-the-pinned-key"));
            })
            .agree_reject(
                "peer.unpinned_or_keyid_mismatch",
                "chio_treaty_unverified_required_evidence",
            ),
        Case::new("the two verdicts disagree")
            .statement(|statement, _fixture| {
                if let Some(summary) = statement.predicate.policy_evaluation_summary.as_mut() {
                    summary.server_b_verdict.verdict = "deny".to_string();
                    summary.joint_disposition = None;
                }
            })
            .agree_reject(
                "policy.verdict_disagreement",
                "chio_treaty_unverified_required_evidence",
            ),
        Case::new("request hash substituted in the binding reference")
            .statement(|statement, _fixture| {
                if let Some(treaty) = statement.predicate.treaty_binding_ref.as_mut() {
                    treaty.request_sha256 = sha256_hex(b"conformance:other-arguments");
                }
            })
            .agree_reject(
                "predicate.schema_invalid",
                "chio_treaty_dsse_binding_mismatch",
            ),
        Case::new("signer order transposed in the binding reference")
            .statement(|statement, _fixture| {
                if let Some(treaty) = statement.predicate.treaty_binding_ref.as_mut() {
                    treaty.signer_kernel_ids.swap(0, 1);
                }
            })
            .agree_reject(
                "predicate.schema_invalid",
                "chio_treaty_unverified_required_evidence",
            ),
        Case::new("lease reference substituted in the binding reference")
            .statement(|statement, _fixture| {
                if let Some(treaty) = statement.predicate.treaty_binding_ref.as_mut() {
                    treaty.lease_refs = vec!["lease-conformance-other".to_string()];
                }
            })
            .agree_reject(
                "predicate.schema_invalid",
                "chio_treaty_dsse_binding_mismatch",
            ),
        // -- the field neither decider compares ---------------------------
        Case::new("admission report digest substituted").statement(|statement, _fixture| {
            if let Some(treaty) = statement.predicate.treaty_binding_ref.as_mut() {
                treaty.admission_report_sha256 = sha256_hex(b"conformance:other-report");
            }
        }),
        // -- the offline verifier checks what the hook does not ------------
        Case::new("subject digest does not match the receipt body")
            .statement(|statement, _fixture| {
                statement.subject[0].digest.sha256 = sha256_hex(b"conformance:other-receipt-body");
            })
            .verifier_only(
                "subject.digest_mismatch",
                "the pre-dispatch hook never resolves the subject receipt and never reads the \
                 statement's subject, so the subject binding of the conforming verifier's steps \
                 17 to 19 has no counterpart on the dispatch path.",
            ),
        Case::new("subject receipt absent from the receiver's receipt store")
            .verifier_state(|state| {
                state.receipt_store = InMemoryReceiptStore::new();
            })
            .verifier_only(
                "subject.digest_mismatch",
                "the hook has no receipt store on this path, so a statement whose subject names \
                 a receipt the receiver does not hold still admits.",
            ),
        Case::new("capability lease absent from the receiver's registry")
            .verifier_state(|state| {
                state.lease_registry = InMemoryLeaseRegistry::new();
            })
            .verifier_only(
                "capability.lease_expired_or_unknown",
                "the hook compares the binding's lease references against the lease identifier \
                 its own admission bundle names; it does not resolve the lease record itself, so \
                 expiry and issuer are not checked here.",
            ),
        Case::new("governance record absent from the receiver's store")
            .verifier_state(|state| {
                state.governance_store = InMemoryGovernanceReceiptStore::new();
            })
            .verifier_only(
                "governance.receipt_required_missing",
                "the hook compares governance references against its own admission bundle and \
                 does not resolve the governance record or re-derive its digest.",
            ),
        Case::new("tool name absent from the verifier's action-class table")
            .verifier_state(|state| {
                state.action_class_table_is_empty = true;
            })
            .verifier_only(
                "governance.unknown_action_class",
                "the verifier's unknown-class policy is reject and its table is verifier-owned. \
                 The hook reads the class out of the ladder intersection it computed itself, so \
                 a table the verifier has not been given does not reach it.",
            ),
        Case::new("peer passport revoked at the pinned epoch")
            .verifier_state(|state| {
                state.revoke_origin = true;
            })
            .verifier_only(
                "peer.revoked_at_epoch",
                "revocation reaches the kernel through its revocation view rather than through \
                 this hook; the hook resolves no revocation oracle.",
            ),
        Case::new("pinned peer has no ladder manifest reference")
            .verifier_state(|state| {
                state.drop_origin_ladder_ref = true;
            })
            .verifier_only(
                "ladder.manifest_missing",
                "the hook activates both manifests itself and stores their intersection, so it \
                 checks the intersection rather than a per-peer manifest reference.",
            ),
        Case::new("pinned peer's ladder manifest reference is stale")
            .verifier_state(|state| {
                state.stale_origin_ladder_ref = true;
            })
            .verifier_only(
                "ladder.manifest_stale",
                "manifest freshness is measured against the verifier's pinned epoch, which the \
                 hook does not hold; the hook bounds the same material through the validity \
                 window of the intersection it stored.",
            ),
        // The divergence axis in the participants' keys themselves: the
        // verifier reads them from its pin set, the hook from the activated
        // agreement. One input, two receiver-owned sources, two answers.
        Case::new("origin passport key rotated in the agreement but not in the pin set")
            .statement(|statement, fixture| {
                statement.predicate.tool_server_a.passport_key_fingerprint =
                    Keyid::from_public_key(&fixture.rotated_origin_key.public_key());
                if let Some(treaty) = statement.predicate.treaty_binding_ref.as_mut() {
                    treaty.treaty_scope_sha256 = fixture.rotated_treaty_scope_sha256.clone();
                }
            })
            .hook_state(|state| {
                state.agreement = Agreement::RotatedOriginKey;
                Ok(())
            })
            .verifier_only(
                "peer.unpinned_or_keyid_mismatch",
                "the two deciders resolve the participants' public keys from two different \
                 receiver-owned stores: the conforming verifier from its pin set, the hook from \
                 the activated agreement. A rotation carried into one and not the other is \
                 admitted by whichever decider holds the newer key. A deployment MUST keep the \
                 two in agreement or run both deciders.",
            ),
        // -- the hook checks what the offline verifier cannot --------------
        Case::new("consistency model downgraded below the class")
            .statement(|statement, _fixture| {
                statement.predicate.consistency_model = "crdt-commutative".to_string();
                if let Some(treaty) = statement.predicate.treaty_binding_ref.as_mut() {
                    treaty.consistency_model = "crdt-commutative".to_string();
                }
            })
            .hook_only(
                "chio_treaty_dsse_binding_mismatch",
                "the offline verifier has no ladder intersection, so it cannot know which \
                 consistency model the action class requires; it accepts any model the predicate \
                 and its binding reference agree on. The hook compares both against the \
                 intersection it computed itself.",
            ),
        Case::new("unanimous deny")
            .statement(|statement, _fixture| {
                if let Some(summary) = statement.predicate.policy_evaluation_summary.as_mut() {
                    summary.server_a_verdict.verdict = "deny".to_string();
                    summary.server_b_verdict.verdict = "deny".to_string();
                    summary.joint_disposition = Some("deny".to_string());
                }
            })
            .hook_only(
                "chio_treaty_policy_denied",
                "a unanimous deny is a valid statement and the conforming verifier returns it \
                 verified for audit and dispute review. Admission is the stricter caller: the \
                 hook requires allow.",
            ),
        Case::new("agreement absent from the receiver's store")
            .hook_state(|state| {
                state.presented.treaty_scope_id = Some(ABSENT_ID.to_string());
                Ok(())
            })
            .hook_only(
                "chio_treaty_missing_scope",
                "the agreement is resolved by identifier out of the receiver's own store; no \
                 agreement record reaches the offline verifier at all.",
            ),
        Case::new("agreement scope digest presented does not match the store")
            .hook_state(|state| {
                state.presented.treaty_scope_sha256 =
                    Some(sha256_hex(b"conformance:other-treaty-scope"));
                Ok(())
            })
            .hook_only(
                "chio_treaty_scope_hash_mismatch",
                "the agreement is resolved by identifier out of the receiver's own store and \
                 compared against the digest the request presented. No agreement record reaches \
                 the offline verifier.",
            ),
        Case::new("action class outside the agreement's allowed classes")
            .statement(|statement, fixture| {
                if let Some(treaty) = statement.predicate.treaty_binding_ref.as_mut() {
                    treaty.treaty_scope_sha256 = fixture.restricted_treaty_scope_sha256.clone();
                }
            })
            .hook_state(|state| {
                state.agreement = Agreement::RestrictedActionClasses;
                Ok(())
            })
            .hook_only(
                "chio_treaty_action_class_not_allowed",
                "which classes the two organizations put in scope is a field of the agreement \
                 the receiver activated. The envelope names a class; nothing in it says whether \
                 this receiver's agreement admits that class.",
            ),
        Case::new("ladder intersection absent from the receiver's store")
            .hook_state(|state| {
                state.presented.ladder_intersection_id = Some(ABSENT_ID.to_string());
                Ok(())
            })
            .hook_only(
                "chio_treaty_missing_intersection",
                "the intersection is computed and stored by the receiver and is never \
                 transferred, so an offline verifier of an envelope has nothing to resolve.",
            ),
        Case::new("presented ladder intersection digest does not match the store")
            .hook_state(|state| {
                state.presented.ladder_intersection_sha256 =
                    Some(sha256_hex(b"conformance:other-intersection"));
                Ok(())
            })
            .hook_only(
                "chio_treaty_intersection_mismatch",
                "the intersection the request names is compared against the one the receiver \
                 stored; the offline verifier holds no intersection to compare.",
            ),
        Case::new("continuation absent from the receiver's store")
            .hook_state(|state| {
                state.presented.continuation_id = Some(ABSENT_ID.to_string());
                Ok(())
            })
            .hook_only(
                "chio_treaty_missing_continuation",
                "the continuation is authenticated by residency in the receiver's own store; \
                 the statement names it only by digest.",
            ),
        Case::new("presented continuation digest does not match the store")
            .hook_state(|state| {
                state.presented.continuation_sha256 =
                    Some(sha256_hex(b"conformance:other-continuation"));
                Ok(())
            })
            .hook_only(
                "chio_treaty_continuation_hash_mismatch",
                "the digest the request presents is compared against the stored continuation; \
                 the offline verifier resolves no continuation.",
            ),
        Case::new("continuation already spent")
            .hook_state(|state| {
                state
                    .store
                    .consume_treaty_continuation(CONTINUATION_ID, "adm-conformance-earlier")?;
                Ok(())
            })
            .hook_only(
                "chio_treaty_continuation_replay",
                "single use is a property of one table in the receiver's store. Nothing in the \
                 envelope records whether the continuation was spent, so an offline verifier \
                 cannot decide it.",
            ),
        Case::new("continuation outside its validity window")
            .hook_state(|state| {
                state.continuation_expires_at_unix_ms = ISSUED_AT_MS + 1;
                Ok(())
            })
            .hook_only(
                "chio_treaty_continuation_stale",
                "the continuation is a receiver-owned record the statement names only by digest; \
                 the offline verifier never resolves it.",
            ),
        Case::new("action class presented disagrees with the stored continuation")
            .hook_state(|state| {
                state.presented.action_class_id = Some(OTHER_ACTION_CLASS.to_string());
                Ok(())
            })
            .hook_only(
                "chio_treaty_continuation_mismatch",
                "the class the request names is checked against the continuation and the \
                 intersection the receiver stored, and the continuation is compared first. The \
                 envelope carries the class identifier and nothing that would let an offline \
                 verifier decide whether the receiver admits that class.",
            ),
        Case::new("presented lineage bundle digest does not match the store")
            .hook_state(|state| {
                state.presented.lineage_bundle_sha256 =
                    Some(sha256_hex(b"conformance:other-lineage-bundle"));
                Ok(())
            })
            .hook_only(
                "chio_treaty_lineage_hash_mismatch",
                "the lineage bundle is resolved out of the receiver's store by identifier and \
                 its stored digest is compared against the presented one; no bundle crosses.",
            ),
        Case::new("lineage bundle does not bind the stored continuation")
            .hook_state(|state| {
                state.unbind_lineage_from_continuation = true;
                Ok(())
            })
            .hook_only(
                "chio_treaty_lineage_mismatch",
                "the walk for a lineage statement that binds this continuation is over records \
                 the receiver wrote; the conforming verifier never sees the bundle.",
            ),
        Case::new("invocation record absent from the receiver's store")
            .hook_state(|state| {
                state.presented.invocation_id = Some(ABSENT_ID.to_string());
                Ok(())
            })
            .hook_only(
                "chio_treaty_missing_bilateral_evidence",
                "a class whose co-signing mode requires two signatures forces the invocation \
                 record into its required-evidence set, and the record lives only in the \
                 receiver's store.",
            ),
        Case::new("presented invocation record digest does not match the store")
            .hook_state(|state| {
                state.presented.invocation_sha256 =
                    Some(sha256_hex(b"conformance:other-invocation"));
                Ok(())
            })
            .hook_only(
                "chio_treaty_bilateral_hash_mismatch",
                "the invocation record is resolved by identifier and its stored digest compared \
                 against the presented one; the record is never carried on the wire.",
            ),
        Case::new("invocation record does not bind the requested dispatch")
            .hook_state(|state| {
                state.unbind_invocation_from_dispatch = true;
                Ok(())
            })
            .hook_only(
                "chio_treaty_bilateral_mismatch",
                "the record is compared against the receiver's own admission bundle, which the \
                 conforming verifier does not hold.",
            ),
        Case::new("envelope reference omitted for a class that requires it")
            .hook_state(|state| {
                state.presented.omit_envelope = true;
                Ok(())
            })
            .hook_only(
                "chio_treaty_missing_required_evidence",
                "which evidence classes a call must carry comes from the action class in the \
                 intersection the receiver stored. An offline verifier handed an envelope is \
                 never in a position to observe that one was not presented.",
            ),
        Case::new("request smuggles a trust root")
            .hook_state(|state| {
                state.smuggle_trust_root = true;
                Ok(())
            })
            .hook_only(
                "request_smuggled_trust_root",
                "the refusal is over the request's own agreement context, which no offline \
                 verifier of an envelope ever sees.",
            ),
    ]
}

/// A 64-byte signature that decodes cleanly and verifies under no key, so the
/// rejection under test is the signature check and not a shape check.
fn forged_signature(encoded: &str) -> String {
    let mut bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .unwrap_or_else(|_| vec![0u8; 64]);
    if let Some(first) = bytes.first_mut() {
        *first ^= 0xff;
    }
    base64::engine::general_purpose::STANDARD.encode(&bytes)
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
            "tool name absent from the verifier's action-class table",
            "peer passport revoked at the pinned epoch",
            "pinned peer has no ladder manifest reference",
            "pinned peer's ladder manifest reference is stale",
            "origin passport key rotated in the agreement but not in the pin set",
        ]
    );
    assert_eq!(
        hook_only,
        vec![
            "consistency model downgraded below the class",
            "unanimous deny",
            "agreement absent from the receiver's store",
            "agreement scope digest presented does not match the store",
            "action class outside the agreement's allowed classes",
            "ladder intersection absent from the receiver's store",
            "presented ladder intersection digest does not match the store",
            "continuation absent from the receiver's store",
            "presented continuation digest does not match the store",
            "continuation already spent",
            "continuation outside its validity window",
            "action class presented disagrees with the stored continuation",
            "presented lineage bundle digest does not match the store",
            "lineage bundle does not bind the stored continuation",
            "invocation record absent from the receiver's store",
            "presented invocation record digest does not match the store",
            "invocation record does not bind the requested dispatch",
            "envelope reference omitted for a class that requires it",
            "request smuggles a trust root",
        ]
    );
}

/// The sixteen codes `VerifierError::code` can return. Each is asserted to be a
/// live member of the shared rejection-code enumeration, so a rename in the
/// implementation cannot leave this list quietly stale.
const CONFORMING_VERIFIER_CODES: [&str; 16] = [
    "capability.lease_expired_or_unknown",
    "dsse.malformed",
    "governance.receipt_required_missing",
    "governance.unknown_action_class",
    "ladder.manifest_missing",
    "ladder.manifest_stale",
    "peer.revoked_at_epoch",
    "peer.unpinned_or_keyid_mismatch",
    "policy.verdict_disagreement",
    "predicate.schema_invalid",
    "predicate.type_unrecognised",
    "signature.server_a_invalid",
    "signature.server_b_invalid",
    "statement.malformed",
    "statement.schema_invalid",
    "subject.digest_mismatch",
];

/// Every rejection class the conforming verifier can reach has a case.
#[test]
fn the_corpus_covers_every_verifier_rejection_class() {
    let defined: BTreeSet<&str> = RejectionCode::ALL
        .iter()
        .map(|code| code.as_str())
        .collect();
    for code in CONFORMING_VERIFIER_CODES {
        assert!(
            defined.contains(code),
            "{code:?} is no longer a rejection code the implementation defines"
        );
    }
    let covered: BTreeSet<&str> = corpus()
        .iter()
        .map(|case| case.verifier_code)
        .filter(|code| !code.is_empty())
        .collect();
    let expected: BTreeSet<&str> = CONFORMING_VERIFIER_CODES.into_iter().collect();
    assert_eq!(
        covered, expected,
        "the corpus no longer covers exactly the conforming verifier's rejection classes"
    );
}

/// The runtime codes scoped to agreement admission that the corpus reaches, and
/// the ones it does not. Both halves are asserted, so coverage is a measured
/// number rather than a claim.
#[test]
fn the_agreement_scoped_hook_codes_the_corpus_covers() {
    let family: BTreeSet<&str> = CHIO_RUNTIME_FAILURE_CODES
        .iter()
        .copied()
        .filter(|code| code.starts_with("chio_treaty_"))
        .collect();
    assert_eq!(family.len(), 24, "the agreement-scoped code family changed");

    let covered: BTreeSet<&str> = corpus()
        .iter()
        .map(|case| case.hook_code)
        .filter(|code| code.starts_with("chio_treaty_"))
        .collect();
    assert_eq!(
        covered,
        BTreeSet::from([
            "chio_treaty_action_class_not_allowed",
            "chio_treaty_bilateral_hash_mismatch",
            "chio_treaty_bilateral_mismatch",
            "chio_treaty_continuation_hash_mismatch",
            "chio_treaty_continuation_mismatch",
            "chio_treaty_continuation_replay",
            "chio_treaty_continuation_stale",
            "chio_treaty_dsse_binding_mismatch",
            "chio_treaty_intersection_mismatch",
            "chio_treaty_lineage_hash_mismatch",
            "chio_treaty_lineage_mismatch",
            "chio_treaty_missing_bilateral_evidence",
            "chio_treaty_missing_continuation",
            "chio_treaty_missing_intersection",
            "chio_treaty_missing_required_evidence",
            "chio_treaty_missing_scope",
            "chio_treaty_policy_denied",
            "chio_treaty_scope_hash_mismatch",
            "chio_treaty_unverified_required_evidence",
        ]),
        "the agreement-scoped codes the corpus covers changed"
    );

    let uncovered: BTreeSet<&str> = family.difference(&covered).copied().collect();
    assert_eq!(
        uncovered,
        BTreeSet::from([
            // Overwritten by the receiver before signing, so no input reaches it.
            "chio_treaty_admission_report_hash_mismatch",
            // Reached only through a continuation whose origin the receiver
            // did not mint, which this single-agreement fixture cannot build.
            "chio_treaty_continuation_origin_mismatch",
            // Reached only when the caller omits the intersection binding the
            // request schema requires, which fails earlier here.
            "chio_treaty_missing_intersection_binding",
            // Reached only from an agreement missing a participant key, which
            // the agreement validator rejects first.
            "chio_treaty_missing_participant",
            // Reached only outside the agreement's validity window, which this
            // fixed-epoch fixture does not move.
            "chio_treaty_stale",
        ]),
        "the agreement-scoped codes the corpus does not reach changed"
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

/// What the peer's signature is, measured rather than argued: the receiver
/// authors the pre-authentication bytes, and the signature over them is
/// determined by custody of the peer's key alone. A second holder of that key
/// material reproduces the peer's signature byte for byte, and the envelope it
/// builds admits on both sides. The signature therefore attributes the bytes to
/// a key; it does not constrain any field the receiver compares, because every
/// such field is compared against a record the receiver itself wrote.
#[test]
fn the_peer_signature_is_determined_by_custody_of_the_peer_key() -> TestResult {
    let fixture = Fixture::build()?;
    let (_, payload_bytes) = fixture.envelope.decode_statement()?;
    let pae_bytes = pae(PAYLOAD_TYPE_IN_TOTO, &payload_bytes);

    let second_holder = Keypair::from_seed(&ORIGIN_SEED);
    let reproduced = dsse_signature(&second_holder, &pae_bytes);
    let minted = fixture
        .envelope
        .signatures
        .first()
        .ok_or("the baseline envelope carries no origin signature")?;
    assert_eq!(
        reproduced.keyid, minted.keyid,
        "a second holder of the peer's key material presents the same keyid"
    );
    assert_eq!(
        reproduced.sig, minted.sig,
        "a second holder of the peer's key material reproduces the peer's signature"
    );

    let rebuilt = DsseEnvelope {
        payload_type: fixture.envelope.payload_type.clone(),
        payload: fixture.envelope.payload.clone(),
        signatures: vec![
            reproduced,
            dsse_signature(&fixture.receiver_key, &pae_bytes),
        ],
    };
    let verifier_state = VerifierState::from_fixture(&fixture)?;
    assert!(
        verifier_state.decide(&rebuilt).is_admit(),
        "the conforming verifier cannot distinguish which holder of the key signed"
    );
    let hook_state = HookState::from_fixture(&fixture);
    assert!(
        hook_state.decide(&fixture, &rebuilt)?.is_admit(),
        "the pre-dispatch hook cannot distinguish which holder of the key signed"
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
/// comparison rather than a broken signature. The origin key is chosen by the
/// fingerprint the mutated statement declares, so a case that rotates the
/// origin's passport key is signed by the key it names. Mutations that must
/// leave the signatures broken run afterwards, on the envelope.
fn mutated_envelope(fixture: &Fixture, case: &Case) -> Result<DsseEnvelope, BoxError> {
    let mut envelope = fixture.envelope.clone();
    if let Some(mutate) = case.mutate_statement {
        let (mut statement, _) = envelope.decode_statement()?;
        mutate(&mut statement, fixture);
        let origin_key = fixture.origin_key_for(&statement);
        let statement_bytes = statement.canonical_bytes()?;
        let pae_bytes = pae(PAYLOAD_TYPE_IN_TOTO, &statement_bytes);
        envelope = DsseEnvelope {
            payload_type: PAYLOAD_TYPE_IN_TOTO.to_string(),
            payload: base64::engine::general_purpose::STANDARD.encode(&statement_bytes),
            signatures: vec![
                dsse_signature(origin_key, &pae_bytes),
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
    stale_origin_ladder_ref: bool,
    action_class_table_is_empty: bool,
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
            stale_origin_ladder_ref: false,
            action_class_table_is_empty: false,
        })
    }

    fn decide(&self, envelope: &DsseEnvelope) -> Answer {
        let mut pin_set = PeerPinSet::new();
        pin_set.insert(PinnedPeer {
            kernel_id: ORIGIN_KERNEL.to_string(),
            public_key: self.origin_public_key.clone(),
            ladder_manifest_ref: if self.drop_origin_ladder_ref {
                None
            } else if self.stale_origin_ladder_ref {
                Some(stale_ladder_manifest_ref("manifest-origin"))
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
        if !self.action_class_table_is_empty {
            action_classes.insert(TOOL_NAME.to_string(), ActionClassKind::ReceiptBacked);
        }

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

/// Freshness is `issued <= now < expires`, so a reference that expires at the
/// pinned instant is stale at it.
fn stale_ladder_manifest_ref(manifest_id: &str) -> LadderManifestRef {
    LadderManifestRef {
        expires_at_unix_ms: NOW_MS,
        ..ladder_manifest_ref(manifest_id)
    }
}

fn governance_canonical_json() -> String {
    format!("{{\"receiptId\":\"{GOVERNANCE_ID}\"}}")
}

// ---------------------------------------------------------------------------
// Decider two: the kernel's pre-dispatch admission hook
// ---------------------------------------------------------------------------

/// Which activated agreement the receiver holds. The hook reads the
/// participants' public keys and the classes in scope out of this record, where
/// the conforming verifier reads the keys out of its pin set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Agreement {
    Baseline,
    RotatedOriginKey,
    RestrictedActionClasses,
}

/// What the request presents. Every field defaults to the artifact the receiver
/// stored; an override makes the request name something else, which is how the
/// resolve-and-compare rejections are reached.
#[derive(Debug, Clone, Default)]
struct Presented {
    treaty_scope_id: Option<String>,
    treaty_scope_sha256: Option<String>,
    ladder_intersection_id: Option<String>,
    ladder_intersection_sha256: Option<String>,
    action_class_id: Option<String>,
    continuation_id: Option<String>,
    continuation_sha256: Option<String>,
    lineage_bundle_id: Option<String>,
    lineage_bundle_sha256: Option<String>,
    invocation_id: Option<String>,
    invocation_sha256: Option<String>,
    omit_envelope: bool,
}

struct HookState {
    store: InMemoryRuntimeAdmissionStore,
    agreement: Agreement,
    continuation_expires_at_unix_ms: u64,
    smuggle_trust_root: bool,
    unbind_lineage_from_continuation: bool,
    unbind_invocation_from_dispatch: bool,
    presented: Presented,
}

impl HookState {
    fn from_fixture(fixture: &Fixture) -> Self {
        Self {
            store: InMemoryRuntimeAdmissionStore::new(),
            agreement: Agreement::Baseline,
            continuation_expires_at_unix_ms: fixture.continuation.expires_at_unix_ms,
            smuggle_trust_root: false,
            unbind_lineage_from_continuation: false,
            unbind_invocation_from_dispatch: false,
            presented: Presented::default(),
        }
    }

    fn agreement_record(&self, fixture: &Fixture) -> (TreatyScope, String) {
        match self.agreement {
            Agreement::Baseline => (
                fixture.treaty_scope.clone(),
                fixture.treaty_scope_sha256.clone(),
            ),
            Agreement::RotatedOriginKey => (
                fixture.rotated_treaty_scope.clone(),
                fixture.rotated_treaty_scope_sha256.clone(),
            ),
            Agreement::RestrictedActionClasses => (
                fixture.restricted_treaty_scope.clone(),
                fixture.restricted_treaty_scope_sha256.clone(),
            ),
        }
    }

    fn decide(&self, fixture: &Fixture, envelope: &DsseEnvelope) -> Result<Answer, BoxError> {
        let (treaty_scope, treaty_scope_sha256) = self.agreement_record(fixture);

        let mut continuation = fixture.continuation.clone();
        continuation.expires_at_unix_ms = self.continuation_expires_at_unix_ms;
        let continuation_sha256 = sha256_hex(&canonical_json_bytes(&continuation)?);
        let continuation_is_baseline = continuation_sha256 == fixture.continuation_sha256;

        // A continuation the case moved out of its window no longer hashes to
        // the digest the co-signed binding names, so the hook would answer the
        // binding mismatch first. The window check is what such a case is for,
        // so the binding reference is realigned to the continuation the
        // receiver actually stored.
        let envelope = if continuation_is_baseline {
            envelope.clone()
        } else {
            realign_binding_continuation(fixture, envelope, &continuation_sha256)?
        };
        let envelope_sha256 = sha256_hex(&canonical_json_bytes(&envelope)?);

        let mut invocation = fixture.invocation.clone();
        if !continuation_is_baseline {
            invocation.continuation_sha256 = continuation_sha256.clone();
        }
        if self.unbind_invocation_from_dispatch {
            invocation.capability_id = OTHER_CAPABILITY_ID.to_string();
        }
        let invocation_sha256 = bilateral_invocation_binding_sha256(&invocation)?;

        let mut lineage_bundle = fixture.lineage_bundle.clone();
        for statement in &mut lineage_bundle.statements {
            if !continuation_is_baseline {
                statement.continuation_sha256 = continuation_sha256.clone();
                statement.bilateral_invocation_sha256 = invocation_sha256.clone();
            }
            if self.unbind_lineage_from_continuation {
                statement.continuation_sha256 = sha256_hex(b"conformance:other-continuation");
            }
        }
        let lineage_bundle_sha256 = sha256_hex(&canonical_json_bytes(&lineage_bundle)?);

        self.store.insert_bundle(fixture.bundle.clone())?;
        self.store.insert_treaty_runtime_artifact(
            "treaty_scope",
            &treaty_scope.treaty_id,
            &treaty_scope,
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
            LINEAGE_BUNDLE_ID,
            &lineage_bundle,
        )?;
        self.store.insert_treaty_runtime_artifact(
            "bilateral_invocation",
            INVOCATION_ID,
            &invocation,
        )?;
        self.store
            .insert_treaty_runtime_artifact("bilateral_dsse_envelope", DSSE_ID, &envelope)?;

        let presented = &self.presented;
        let mut context = serde_json::json!({
            "treatyScopeId": presented
                .treaty_scope_id
                .clone()
                .unwrap_or_else(|| treaty_scope.treaty_id.clone()),
            "treatyScopeSha256": presented
                .treaty_scope_sha256
                .clone()
                .unwrap_or(treaty_scope_sha256),
            "ladderIntersectionId": presented
                .ladder_intersection_id
                .clone()
                .unwrap_or_else(|| fixture.ladder_intersection.intersection_id.clone()),
            "ladderIntersectionSha256": presented
                .ladder_intersection_sha256
                .clone()
                .unwrap_or_else(|| fixture.ladder_intersection_sha256.clone()),
            "actionClassId": presented
                .action_class_id
                .clone()
                .unwrap_or_else(|| ACTION_CLASS.to_string()),
            "crossKernelContinuation": {
                "id": presented
                    .continuation_id
                    .clone()
                    .unwrap_or_else(|| CONTINUATION_ID.to_string()),
                "sha256": presented
                    .continuation_sha256
                    .clone()
                    .unwrap_or(continuation_sha256),
            },
            "receiptLineageBundle": {
                "id": presented
                    .lineage_bundle_id
                    .clone()
                    .unwrap_or_else(|| LINEAGE_BUNDLE_ID.to_string()),
                "sha256": presented
                    .lineage_bundle_sha256
                    .clone()
                    .unwrap_or(lineage_bundle_sha256),
            },
            "bilateralInvocation": {
                "id": presented
                    .invocation_id
                    .clone()
                    .unwrap_or_else(|| INVOCATION_ID.to_string()),
                "sha256": presented
                    .invocation_sha256
                    .clone()
                    .unwrap_or(invocation_sha256),
            },
        });
        if !presented.omit_envelope {
            context["bilateralDsse"] =
                serde_json::json!({ "id": DSSE_ID, "sha256": envelope_sha256 });
        }
        if self.smuggle_trust_root {
            context["trustRoot"] = serde_json::json!("did:chio:attacker-root");
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
    let origin_key = fixture.origin_key_for(&statement);
    let statement_bytes = statement.canonical_bytes()?;
    let pae_bytes = pae(PAYLOAD_TYPE_IN_TOTO, &statement_bytes);
    Ok(DsseEnvelope {
        payload_type: PAYLOAD_TYPE_IN_TOTO.to_string(),
        payload: base64::engine::general_purpose::STANDARD.encode(&statement_bytes),
        signatures: vec![
            dsse_signature(origin_key, &pae_bytes),
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
    rotated_origin_key: Keypair,
    treaty_scope: TreatyScope,
    treaty_scope_sha256: String,
    rotated_treaty_scope: TreatyScope,
    rotated_treaty_scope_sha256: String,
    restricted_treaty_scope: TreatyScope,
    restricted_treaty_scope_sha256: String,
    ladder_intersection: LadderIntersection,
    ladder_intersection_sha256: String,
    continuation: CrossKernelContinuation,
    continuation_sha256: String,
    lineage_bundle: ReceiptLineageBundle,
    invocation: BilateralInvocation,
    receipt: ChioReceipt,
    envelope: DsseEnvelope,
    bundle: RuntimeAdmissionBundle,
    bundle_sha256: String,
}

impl Fixture {
    fn build() -> Result<Self, BoxError> {
        let origin_key = Keypair::from_seed(&ORIGIN_SEED);
        let receiver_key = Keypair::from_seed(&RECEIVER_SEED);
        let rotated_origin_key = Keypair::from_seed(&ROTATED_ORIGIN_SEED);

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

        // The same agreement after the origin rotated its passport key, which
        // the receiver activated without re-pinning.
        let rotated_treaty_scope = TreatyScope {
            participant_public_keys: vec![
                rotated_origin_key.public_key(),
                receiver_key.public_key(),
            ],
            ..treaty_scope.clone()
        };
        let rotated_treaty_scope_sha256 = treaty_scope_sha256(&rotated_treaty_scope)?;

        // The same agreement with this call's action class out of scope.
        let restricted_treaty_scope = TreatyScope {
            allowed_action_classes: vec![OTHER_ACTION_CLASS.to_string()],
            ..treaty_scope.clone()
        };
        let restricted_treaty_scope_sha256 = treaty_scope_sha256(&restricted_treaty_scope)?;

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
            bundle_id: LINEAGE_BUNDLE_ID.to_string(),
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
                    lineage_bundle_sha256,
                    action_class_id: ACTION_CLASS.to_string(),
                    consistency_model,
                    request_sha256: request_sha256.clone(),
                    outcome_sha256: OUTCOME_SHA256.to_string(),
                    local_receipt_sha256: invocation.local_receipt_sha256.clone(),
                    remote_receipt_sha256,
                    lease_refs: vec![LEASE_ID.to_string()],
                    governance_refs: vec![GOVERNANCE_ID.to_string()],
                    signer_kernel_ids: vec![ORIGIN_KERNEL.to_string(), RECEIVER_KERNEL.to_string()],
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
            rotated_origin_key,
            treaty_scope,
            treaty_scope_sha256,
            rotated_treaty_scope,
            rotated_treaty_scope_sha256,
            restricted_treaty_scope,
            restricted_treaty_scope_sha256,
            ladder_intersection,
            ladder_intersection_sha256,
            continuation,
            continuation_sha256,
            lineage_bundle,
            invocation,
            receipt,
            envelope,
            bundle,
            bundle_sha256,
        })
    }

    /// The origin key the statement declares. A case that rotates the origin's
    /// passport key names the rotated fingerprint, and the envelope must be
    /// signed by the key it names for the check under test to be the one the
    /// case is about.
    fn origin_key_for(&self, statement: &DsseStatement) -> &Keypair {
        let rotated = Keyid::from_public_key(&self.rotated_origin_key.public_key());
        if statement.predicate.tool_server_a.passport_key_fingerprint.0 == rotated.0 {
            &self.rotated_origin_key
        } else {
            &self.origin_key
        }
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
