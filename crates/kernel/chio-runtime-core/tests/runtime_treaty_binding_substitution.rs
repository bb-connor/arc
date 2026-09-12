//! Substitution corpus over the fifteen fields of the treaty binding reference
//! that a bilateral DSSE statement carries into cross-organization admission.
//!
//! Every case builds one complete, admissible treaty evidence bundle, replaces
//! exactly one binding field with a well-formed but different value, re-signs
//! the statement with both participant keys so the envelope stays
//! cryptographically valid over the substituted bytes, and drives the result
//! through the pre-dispatch admission hook. A rejection case asserts the exact
//! failure code, that no verified federation material reached dispatch, and
//! that the continuation the statement named is still unconsumed afterwards,
//! which is what shows the substituted call never dispatched a tool.
//!
//! Ten fields are compared on every cross-organization admission. Four are
//! compared only when the admission resolves the artifact they bind, and those
//! conditions are driven twice: once against an action class that resolves the
//! lineage bundle and the invocation record, and once against a class that
//! resolves only the record. One field is never compared, and its case asserts
//! admission instead of a code.

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
    pae, sign_chio_bilateral_dsse_envelope, BilateralPredicateExtensions, CapabilityLeaseRef,
    DsseEnvelope, DsseSignature, GovernanceReceiptRef, HashRecord, Keyid, PolicyEvaluationSummary,
    PolicyVerdict, TreatyBindingRef, PAYLOAD_TYPE_IN_TOTO,
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
use std::io;
use support::treaty::{treaty_action_class, treaty_manifest, treaty_scope};

const BINDING_MISMATCH: &str = "chio_treaty_dsse_binding_mismatch";
const UNVERIFIED_EVIDENCE: &str = "chio_treaty_unverified_required_evidence";
const CONTINUATION_REPLAY: &str = "chio_treaty_continuation_replay";

type TestResult = Result<(), Box<dyn std::error::Error>>;

// ---------------------------------------------------------------------------
// The fifteen fields, one case each.
// ---------------------------------------------------------------------------

#[test]
fn substituting_treaty_id_is_rejected_before_dispatch() -> TestResult {
    let run = substitute_and_admit(|binding| {
        binding.treaty_id = "treaty-buyer-vendor-substituted".to_string();
    })?;
    assert_rejected_without_dispatch(&run, BINDING_MISMATCH);
    Ok(())
}

#[test]
fn substituting_treaty_scope_digest_is_rejected_before_dispatch() -> TestResult {
    let run = substitute_and_admit(|binding| {
        binding.treaty_scope_sha256 = substituted_digest(&binding.treaty_scope_sha256);
    })?;
    assert_rejected_without_dispatch(&run, BINDING_MISMATCH);
    Ok(())
}

#[test]
fn substituting_ladder_intersection_digest_is_rejected_before_dispatch() -> TestResult {
    let run = substitute_and_admit(|binding| {
        binding.ladder_intersection_sha256 =
            substituted_digest(&binding.ladder_intersection_sha256);
    })?;
    assert_rejected_without_dispatch(&run, BINDING_MISMATCH);
    Ok(())
}

/// `admission_report_sha256` is the one binding field the receiver never
/// compares. It is required to be 64 hex characters and is then overwritten
/// with the digest of the report the receiver computed for itself, so a
/// substituted value changes nothing the receiver decides. The substituted
/// statement is admitted, and it reaches dispatch: the continuation it named
/// is consumed, so presenting the unsubstituted statement afterwards is
/// refused as a replay.
#[test]
fn substituting_admission_report_digest_is_admitted() -> TestResult {
    let run = substitute_and_admit(|binding| {
        binding.admission_report_sha256 = substituted_digest(&binding.admission_report_sha256);
    })?;

    assert!(
        run.substituted.allowed,
        "admission_report_sha256 is not compared, so the substitution must still admit: {:?}",
        run.substituted.failure_code
    );
    assert!(
        run.substituted.verified_treaty_material,
        "an admitted cross-organization dispatch must carry verified treaty material"
    );
    assert_eq!(
        run.baseline_after.failure_code.as_deref(),
        Some(CONTINUATION_REPLAY),
        "an admitted substitution must have consumed the continuation it named"
    );
    Ok(())
}

#[test]
fn substituting_continuation_digest_is_rejected_before_dispatch() -> TestResult {
    let run = substitute_and_admit(|binding| {
        binding.continuation_sha256 = substituted_digest(&binding.continuation_sha256);
    })?;
    assert_rejected_without_dispatch(&run, BINDING_MISMATCH);
    Ok(())
}

/// Compared only when the admission resolves a receipt lineage bundle, which
/// the action class forces by naming `receipt_lineage` in its required
/// evidence. This fixture's class does.
#[test]
fn substituting_lineage_bundle_digest_is_rejected_before_dispatch() -> TestResult {
    let run = substitute_and_admit(|binding| {
        binding.lineage_bundle_sha256 = substituted_digest(&binding.lineage_bundle_sha256);
    })?;
    assert_rejected_without_dispatch(&run, BINDING_MISMATCH);
    Ok(())
}

#[test]
fn substituting_action_class_id_is_rejected_before_dispatch() -> TestResult {
    let run = substitute_and_admit(|binding| {
        binding.action_class_id = "workflow.destructive.vendor_refund".to_string();
    })?;
    assert_rejected_without_dispatch(&run, BINDING_MISMATCH);
    Ok(())
}

#[test]
fn substituting_consistency_model_is_rejected_before_dispatch() -> TestResult {
    let run = substitute_and_admit(|binding| {
        binding.consistency_model = "crdt-commutative".to_string();
    })?;
    assert_rejected_without_dispatch(&run, BINDING_MISMATCH);
    Ok(())
}

#[test]
fn substituting_request_digest_is_rejected_before_dispatch() -> TestResult {
    let run = substitute_and_admit(|binding| {
        binding.request_sha256 = substituted_digest(&binding.request_sha256);
    })?;
    assert_rejected_without_dispatch(&run, BINDING_MISMATCH);
    Ok(())
}

/// Compared only when the admission resolves the bilateral invocation record,
/// which the action class forces by naming `bilateral_invocation` in its
/// required evidence. This fixture's class does.
#[test]
fn substituting_outcome_digest_is_rejected_before_dispatch() -> TestResult {
    let run = substitute_and_admit(|binding| {
        binding.outcome_sha256 = substituted_digest(&binding.outcome_sha256);
    })?;
    assert_rejected_without_dispatch(&run, BINDING_MISMATCH);
    Ok(())
}

/// Compared when the admission resolves either the lineage bundle or the
/// invocation record. This fixture resolves both, and the lineage comparison
/// is the one that runs first.
#[test]
fn substituting_local_receipt_digest_is_rejected_before_dispatch() -> TestResult {
    let run = substitute_and_admit(|binding| {
        binding.local_receipt_sha256 = substituted_digest(&binding.local_receipt_sha256);
    })?;
    assert_rejected_without_dispatch(&run, BINDING_MISMATCH);
    Ok(())
}

/// Compared when the admission resolves either the lineage bundle or the
/// invocation record, as for the root receipt digest above.
#[test]
fn substituting_remote_receipt_digest_is_rejected_before_dispatch() -> TestResult {
    let run = substitute_and_admit(|binding| {
        binding.remote_receipt_sha256 = substituted_digest(&binding.remote_receipt_sha256);
    })?;
    assert_rejected_without_dispatch(&run, BINDING_MISMATCH);
    Ok(())
}

#[test]
fn substituting_lease_refs_is_rejected_before_dispatch() -> TestResult {
    let run = substitute_and_admit(|binding| {
        binding.lease_refs = vec!["lease-live-substituted".to_string()];
    })?;
    assert_rejected_without_dispatch(&run, BINDING_MISMATCH);
    Ok(())
}

#[test]
fn substituting_governance_refs_is_rejected_before_dispatch() -> TestResult {
    let run = substitute_and_admit(|binding| {
        binding.governance_refs = vec!["gov-live-substituted".to_string()];
    })?;
    assert_rejected_without_dispatch(&run, BINDING_MISMATCH);
    Ok(())
}

#[test]
fn substituting_signer_kernel_ids_is_rejected_before_dispatch() -> TestResult {
    let run = substitute_and_admit(|binding| {
        binding.signer_kernel_ids = vec!["kernel.buyer".to_string(), "kernel.vendor-c".to_string()];
    })?;
    assert_rejected_without_dispatch(&run, BINDING_MISMATCH);
    Ok(())
}

/// Reordering the two signers leaves the set equal to the agreement's
/// participants, so the set comparison passes and the pinned keys are then
/// resolved in the substituted order. The envelope no longer verifies as a
/// strict bilateral statement under that pairing, so the denial is the
/// unverified-evidence code rather than the binding-mismatch code that a
/// changed signer set produces.
#[test]
fn reordering_signer_kernel_ids_is_rejected_before_dispatch() -> TestResult {
    let run = substitute_and_admit(|binding| {
        binding.signer_kernel_ids.reverse();
    })?;
    assert_rejected_without_dispatch(&run, UNVERIFIED_EVIDENCE);
    Ok(())
}

// ---------------------------------------------------------------------------
// The conditions in the "compared when" column, shown against an action class
// that resolves no lineage bundle.
// ---------------------------------------------------------------------------

/// With no lineage bundle resolved, the comparison that binds one does not
/// run, and the same substitution that is rejected above is admitted.
#[test]
fn lineage_bundle_digest_is_not_compared_without_a_resolved_bundle() -> TestResult {
    let run = substitute_and_admit_with(Evidence::RecordOnly, |binding| {
        binding.lineage_bundle_sha256 = substituted_digest(&binding.lineage_bundle_sha256);
    })?;
    assert!(
        run.substituted.allowed,
        "lineage_bundle_sha256 is compared only against a resolved lineage bundle: {:?}",
        run.substituted.failure_code
    );
    assert!(run.substituted.verified_treaty_material);
    Ok(())
}

/// The invocation record is not named by this class, but its co-signing mode
/// requires two signatures, which forces the record into the required evidence
/// the admission resolves. The outcome digest is therefore still compared.
#[test]
fn outcome_digest_is_compared_through_the_forced_invocation_record() -> TestResult {
    let run = substitute_and_admit_with(Evidence::RecordOnly, |binding| {
        binding.outcome_sha256 = substituted_digest(&binding.outcome_sha256);
    })?;
    assert_rejected_without_dispatch(&run, BINDING_MISMATCH);
    Ok(())
}

/// The receipt digests bind both the lineage bundle and the invocation
/// record. With no bundle resolved, the record carries the comparison.
#[test]
fn receipt_digests_are_compared_through_the_forced_invocation_record() -> TestResult {
    let local = substitute_and_admit_with(Evidence::RecordOnly, |binding| {
        binding.local_receipt_sha256 = substituted_digest(&binding.local_receipt_sha256);
    })?;
    assert_rejected_without_dispatch(&local, BINDING_MISMATCH);

    let remote = substitute_and_admit_with(Evidence::RecordOnly, |binding| {
        binding.remote_receipt_sha256 = substituted_digest(&binding.remote_receipt_sha256);
    })?;
    assert_rejected_without_dispatch(&remote, BINDING_MISMATCH);
    Ok(())
}

/// The unsubstituted bundle admits, so every rejection above is attributable
/// to the one field that changed and not to the fixture. It also fixes the
/// counterfactual the rejection cases rest on: an admission that reaches
/// dispatch consumes its continuation, so a second presentation is refused as
/// a replay. A rejection case that leaves the continuation available is
/// therefore one that never dispatched.
#[test]
fn unsubstituted_binding_is_admitted_and_consumes_its_continuation() -> TestResult {
    let run = substitute_and_admit(|_| {})?;
    assert!(
        run.substituted.allowed,
        "the unsubstituted bundle must admit: {:?}",
        run.substituted.failure_code
    );
    assert!(run.substituted.verified_treaty_material);
    assert!(!run.baseline_after.allowed);
    assert_eq!(
        run.baseline_after.failure_code.as_deref(),
        Some(CONTINUATION_REPLAY)
    );
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

fn assert_rejected_without_dispatch(run: &SubstitutionRun, expected_code: &str) {
    assert!(
        !run.substituted.allowed,
        "the substituted statement must not be admitted"
    );
    assert_eq!(
        run.substituted.failure_code.as_deref(),
        Some(expected_code),
        "unexpected failure code for the substituted statement"
    );
    assert!(
        !run.substituted.verified_treaty_material,
        "a denied admission must hand no verified treaty material to dispatch"
    );
    assert!(
        run.baseline_after.allowed,
        "the continuation must still be unconsumed, which it is not if the substituted \
         admission reached dispatch: {:?}",
        run.baseline_after.failure_code
    );
}

/// Which artifacts the action class makes the admission resolve. The paper's
/// refund example is [`Evidence::LineageAndRecord`].
#[derive(Clone, Copy)]
enum Evidence {
    /// The class names the receipt lineage bundle and the invocation record,
    /// so the admission resolves both and every conditional comparison runs.
    LineageAndRecord,
    /// The class names only the co-signed statement. No lineage bundle is
    /// resolved, so the comparisons that bind one do not run. The invocation
    /// record is still resolved, because a class whose co-signing mode
    /// requires two signatures has the record forced into its required
    /// evidence.
    RecordOnly,
}

fn substitute_and_admit(
    substitute: impl FnOnce(&mut TreatyBindingRef),
) -> Result<SubstitutionRun, Box<dyn std::error::Error>> {
    substitute_and_admit_with(Evidence::LineageAndRecord, substitute)
}

/// Build the bundle, substitute one binding field, re-sign, and drive the
/// pre-dispatch hook. The unsubstituted bundle is then driven against the same
/// store, so a caller can see whether the substituted admission consumed the
/// single-use continuation.
fn substitute_and_admit_with(
    evidence: Evidence,
    substitute: impl FnOnce(&mut TreatyBindingRef),
) -> Result<SubstitutionRun, Box<dyn std::error::Error>> {
    let fixture = treaty_fixture(evidence)?;
    let substituted_envelope = resign_with_substituted_binding(&fixture, substitute)?;
    assert_envelope_signatures_valid(&fixture, &substituted_envelope)?;

    let directory = tempfile::tempdir()?;
    let store = SqliteRuntimeOrchestrationStore::open(
        directory.path().join("binding-substitution.sqlite3"),
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
    let metadata = decision.metadata.clone().unwrap_or(serde_json::Value::Null);
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

/// A well-formed 64-character lowercase hex digest that differs from the one
/// it replaces.
fn substituted_digest(value: &str) -> String {
    sha256_hex(format!("substituted:{value}").as_bytes())
}

// ---------------------------------------------------------------------------
// Re-signing
// ---------------------------------------------------------------------------

/// Replace one binding field and sign the resulting statement with both
/// participant keys over its own pre-authentication bytes. The producer API
/// refuses several of these substitutions at construction time, so the
/// statement is encoded and signed directly, which is what an adversary
/// holding both keys would do.
fn resign_with_substituted_binding(
    fixture: &TreatyFixture,
    substitute: impl FnOnce(&mut TreatyBindingRef),
) -> Result<DsseEnvelope, Box<dyn std::error::Error>> {
    let (mut statement, _) = fixture.envelope.decode_statement()?;
    let binding = statement
        .predicate
        .treaty_binding_ref
        .as_mut()
        .ok_or_else(|| io::Error::other("fixture envelope carries no treaty binding reference"))?;
    substitute(binding);
    let statement_bytes = statement.canonical_bytes()?;
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
/// every denial below is a binding comparison rather than a broken signature.
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
// Fixture
// ---------------------------------------------------------------------------

const BASELINE_DSSE_ID: &str = "bilateral-dsse-binding-substitution";
const SUBSTITUTED_DSSE_ID: &str = "bilateral-dsse-binding-substituted";

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

fn tool_arguments() -> serde_json::Value {
    serde_json::json!({"record": "vendor-ledger-7", "value": "closed"})
}

fn treaty_fixture(evidence: Evidence) -> Result<TreatyFixture, Box<dyn std::error::Error>> {
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
        continuation_id: "continue-binding-substitution-1".to_string(),
        source_kernel_id: "kernel.buyer".to_string(),
        target_kernel_id: "kernel.vendor-b".to_string(),
        parent_receipt_sha256: "1".repeat(64),
        parent_session_anchor_sha256: "2".repeat(64),
        capability_id: "cap-live-1".to_string(),
        action_class_id: "workflow.destructive.vendor_call".to_string(),
        audience_tool: "vendor-ledger.close_account".to_string(),
        nonce: "nonce-binding-substitution-1".to_string(),
        issued_at_unix_ms: 1_800_000_000_000,
        expires_at_unix_ms: 1_800_003_600_000,
    };
    let continuation_sha256 = sha256_hex(&canonical_json_bytes(&continuation)?);

    let mut bilateral_invocation = BilateralInvocation {
        schema: CHIO_BILATERAL_INVOCATION_SCHEMA.to_string(),
        invocation_id: "invoke-binding-substitution-1".to_string(),
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
        statement_id: "lineage-binding-substitution-1".to_string(),
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
        bundle_id: "lineage-bundle-binding-substitution-1".to_string(),
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

fn treaty_context(fixture: &TreatyFixture, dsse_id: &str, dsse_sha256: &str) -> serde_json::Value {
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

fn capability(capability_id: &str) -> Result<CapabilityToken, Box<dyn std::error::Error>> {
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
    arguments: serde_json::Value,
    bundle_sha256: String,
    treaty_context: serde_json::Value,
) -> Result<ToolCallRequest, Box<dyn std::error::Error>> {
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
) -> Result<ChioRuntimeAdmissionHook<SqliteRuntimeOrchestrationStore>, Box<dyn std::error::Error>> {
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

fn query_report_body() -> serde_json::Value {
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
