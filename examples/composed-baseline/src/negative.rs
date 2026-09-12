//! The twenty-case negative corpus, driven against the composed alternative.
//!
//! Each entry names the Chio case it answers, states what the equivalent attack
//! is when the composed parts can express one, and records what the composed
//! receiver did. Where the composition carries no field the attack could touch,
//! the entry says so and says why: an attack with no surface is a result about
//! the surface, not a pass.

use crate::harness::{Observed, Runner, StateVariant};
use crate::request::{ComposedEnvelope, PolicyDecision};
use crate::scenario::{self, Keys, SealInputs};
use chio_core_types::crypto::canonical_json_bytes;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// How closely the composed parts can express the Chio case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Analogue {
    /// The same attack, against the field the composition carries for it.
    Direct,
    /// A weaker attack: the composition carries something adjacent, and the
    /// note says what the attack loses in translation.
    Partial,
    /// The composition carries no field the attack could touch.
    None,
}

#[derive(Debug, Clone, Serialize)]
pub struct NegativeResult {
    pub threat_id: &'static str,
    pub chio_case_id: &'static str,
    pub chio_expected_code: &'static str,
    pub baseline_case_id: &'static str,
    pub analogue: Analogue,
    pub attack: &'static str,
    pub note: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub composed: Option<ObservedJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardened: Option<ObservedJson>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObservedJson {
    pub admitted: bool,
    pub dispatched: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denial_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denial_step: Option<u32>,
}

impl From<Observed> for ObservedJson {
    fn from(observed: Observed) -> Self {
        Self {
            admitted: observed.admitted,
            dispatched: observed.dispatched,
            denial_code: observed.code,
            denial_step: observed.step,
        }
    }
}

type Drive = fn(&Runner<'_>, StateVariant, &str) -> Result<Observed, String>;

struct Spec {
    threat_id: &'static str,
    chio_case_id: &'static str,
    chio_expected_code: &'static str,
    baseline_case_id: &'static str,
    analogue: Analogue,
    attack: &'static str,
    note: &'static str,
    variant: StateVariant,
    drive: Option<Drive>,
}

fn context_with(key: &str, value: Value) -> BTreeMap<String, Value> {
    let mut context = BTreeMap::new();
    context.insert(key.to_string(), value);
    context
}

fn sealed(
    keys: &Keys,
    request_id: &str,
    args: Value,
    decision: PolicyDecision,
    context: BTreeMap<String, Value>,
) -> Result<ComposedEnvelope, String> {
    scenario::seal(SealInputs {
        request_id,
        caller: scenario::BUYER,
        tool_name: scenario::ACTION,
        tool_args: args,
        context,
        decision,
        raw_authorization: None,
        policy_signer: &keys.buyer_policy,
        channel_signer: Some(&keys.buyer_channel),
    })
}

// --- drives -----------------------------------------------------------------

fn drive_wrong_agreement(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let args = scenario::refund_args();
    let mut decision = scenario::base_decision(id, &args)?;
    decision.agreement_id = scenario::AGREEMENT_PILOT.to_string();
    let envelope = sealed(runner.keys, id, args, decision, BTreeMap::new())?;
    runner.drive_one(variant, &envelope, scenario::NOW_MS)
}

fn drive_unknown_agreement(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let args = scenario::refund_args();
    let mut decision = scenario::base_decision(id, &args)?;
    decision.agreement_id = "treaty-buyer-vendor-substituted".to_string();
    let envelope = sealed(runner.keys, id, args, decision, BTreeMap::new())?;
    runner.drive_one(variant, &envelope, scenario::NOW_MS)
}

fn drive_superseded_agreement(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let args = scenario::refund_args();
    let mut decision = scenario::base_decision(id, &args)?;
    decision.agreement_id = scenario::AGREEMENT_RETIRED.to_string();
    let envelope = sealed(runner.keys, id, args, decision, BTreeMap::new())?;
    runner.drive_one(variant, &envelope, scenario::NOW_MS)
}

fn drive_expired_authorization(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let args = scenario::refund_args();
    let mut decision = scenario::base_decision(id, &args)?;
    decision.expires_at_unix_ms = scenario::NOW_MS - 1;
    let envelope = sealed(runner.keys, id, args, decision, BTreeMap::new())?;
    runner.drive_one(variant, &envelope, scenario::NOW_MS)
}

fn drive_long_window_authorization(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let args = scenario::refund_args();
    let mut decision = scenario::base_decision(id, &args)?;
    decision.expires_at_unix_ms = scenario::NOW_MS + 315_360_000_000;
    let envelope = sealed(runner.keys, id, args, decision, BTreeMap::new())?;
    runner.drive_one(variant, &envelope, scenario::NOW_MS)
}

fn drive_args_digest_mismatch(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let signed_args = scenario::refund_args();
    let decision = scenario::base_decision(id, &signed_args)?;
    let mut sent_args = signed_args;
    sent_args["amount_minor"] = json!(9900u64);
    let envelope = sealed(runner.keys, id, sent_args, decision, BTreeMap::new())?;
    runner.drive_one(variant, &envelope, scenario::NOW_MS)
}

fn drive_unbound_resource(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let args = scenario::refund_args();
    let mut decision = scenario::base_decision(id, &args)?;
    decision.resource = "order-0000-unrelated".to_string();
    let envelope = sealed(runner.keys, id, args, decision, BTreeMap::new())?;
    runner.drive_one(variant, &envelope, scenario::NOW_MS)
}

fn drive_missing_peer_signature(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let args = scenario::refund_args();
    let decision = scenario::base_decision(id, &args)?;
    let envelope = scenario::seal(SealInputs {
        request_id: id,
        caller: scenario::BUYER,
        tool_name: scenario::ACTION,
        tool_args: args,
        context: BTreeMap::new(),
        decision,
        raw_authorization: None,
        policy_signer: &runner.keys.buyer_policy,
        channel_signer: None,
    })?;
    runner.drive_one(variant, &envelope, scenario::NOW_MS)
}

fn drive_collapsed_keys(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    // One party holds both keys: the same key signs the channel and the policy
    // decision, and the receiver pinned it for both roles.
    let args = scenario::refund_args();
    let decision = scenario::base_decision(id, &args)?;
    let envelope = scenario::seal(SealInputs {
        request_id: id,
        caller: scenario::BUYER,
        tool_name: scenario::ACTION,
        tool_args: args,
        context: BTreeMap::new(),
        decision,
        raw_authorization: None,
        policy_signer: &runner.keys.buyer_channel,
        channel_signer: Some(&runner.keys.buyer_channel),
    })?;
    runner.drive_one(variant, &envelope, scenario::NOW_MS)
}

fn drive_type_confusion(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    // A different document the same policy key signed for another purpose.
    let other = json!({
        "schema": "vendor.session-token.v1",
        "subject": scenario::BUYER,
        "issued_at_unix_ms": scenario::NOW_MS,
    });
    let bytes = canonical_json_bytes(&other).map_err(|error| error.to_string())?;
    let raw = String::from_utf8(bytes).map_err(|error| error.to_string())?;
    let args = scenario::refund_args();
    let decision = scenario::base_decision(id, &args)?;
    let envelope = scenario::seal(SealInputs {
        request_id: id,
        caller: scenario::BUYER,
        tool_name: scenario::ACTION,
        tool_args: args,
        context: BTreeMap::new(),
        decision,
        raw_authorization: Some(raw),
        policy_signer: &runner.keys.buyer_policy,
        channel_signer: Some(&runner.keys.buyer_channel),
    })?;
    runner.drive_one(variant, &envelope, scenario::NOW_MS)
}

fn drive_wrong_schema_tag(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let args = scenario::refund_args();
    let mut decision = scenario::base_decision(id, &args)?;
    decision.schema = "composed-baseline.policy-decision.v2".to_string();
    let envelope = sealed(runner.keys, id, args, decision, BTreeMap::new())?;
    runner.drive_one(variant, &envelope, scenario::NOW_MS)
}

fn drive_duplicate_key(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    // The transmitted bytes carry `action` twice: the honest value first, the
    // attacker's value last. The signature covers exactly these bytes.
    let args = scenario::refund_args();
    let decision = scenario::base_decision(id, &args)?;
    let canonical = canonical_json_bytes(&decision).map_err(|error| error.to_string())?;
    let canonical = String::from_utf8(canonical).map_err(|error| error.to_string())?;
    let needle = format!("\"action\":\"{}\"", scenario::ACTION);
    let raw = canonical.replacen(
        needle.as_str(),
        format!("{needle},\"action\":\"refund.issue.unbounded\"").as_str(),
        1,
    );
    let envelope = scenario::seal(SealInputs {
        request_id: id,
        caller: scenario::BUYER,
        tool_name: scenario::ACTION,
        tool_args: args,
        context: BTreeMap::new(),
        decision,
        raw_authorization: Some(raw),
        policy_signer: &runner.keys.buyer_policy,
        channel_signer: Some(&runner.keys.buyer_channel),
    })?;
    runner.drive_one(variant, &envelope, scenario::NOW_MS)
}

fn drive_reordered_encoding(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    // Semantically identical bytes in a non-canonical encoding. Admitting this
    // is not an attack; the case is here to show which profile notices.
    let args = scenario::refund_args();
    let decision = scenario::base_decision(id, &args)?;
    let raw = serde_json::to_string_pretty(&decision).map_err(|error| error.to_string())?;
    let envelope = scenario::seal(SealInputs {
        request_id: id,
        caller: scenario::BUYER,
        tool_name: scenario::ACTION,
        tool_args: args,
        context: BTreeMap::new(),
        decision,
        raw_authorization: Some(raw),
        policy_signer: &runner.keys.buyer_policy,
        channel_signer: Some(&runner.keys.buyer_channel),
    })?;
    runner.drive_one(variant, &envelope, scenario::NOW_MS)
}

fn drive_approval_unknown(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let mut args = scenario::refund_args();
    args["approval_id"] = json!("approval-refund-9999");
    let decision = scenario::base_decision(id, &args)?;
    let envelope = sealed(runner.keys, id, args, decision, BTreeMap::new())?;
    runner.drive_one(variant, &envelope, scenario::NOW_MS)
}

fn drive_approval_smuggled(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let mut args = scenario::refund_args();
    args["approval_id"] = json!("approval-refund-9999");
    let decision = scenario::base_decision(id, &args)?;
    let context = context_with(
        "approval",
        json!({
            "approval_id": "approval-refund-9999",
            "agreement_id": scenario::AGREEMENT,
            "action": scenario::ACTION,
            "max_amount_minor": 10_000u64,
        }),
    );
    let envelope = sealed(runner.keys, id, args, decision, context)?;
    runner.drive_one(variant, &envelope, scenario::NOW_MS)
}

fn drive_claimed_assurance(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let args = scenario::refund_args();
    let decision = scenario::base_decision(id, &args)?;
    let context = context_with("assurance_level", json!("attested"));
    let envelope = sealed(runner.keys, id, args, decision, context)?;
    runner.drive_one(variant, &envelope, scenario::NOW_MS)
}

fn drive_request_id_replay(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let envelope = scenario::admissible(runner.keys, id)?;
    let state = runner.state(variant);
    let store = runner.fresh_store()?;
    let first = runner
        .admit(&state, &store, &envelope, scenario::NOW_MS)
        .map_err(|error| error.to_string())?;
    if !first.admitted {
        return Err(format!(
            "the first presentation must be admitted for the replay to mean anything: {:?}",
            first.denial_code
        ));
    }
    let second = runner
        .admit(&state, &store, &envelope, scenario::NOW_MS)
        .map_err(|error| error.to_string())?;
    Ok(Observed::from(&second))
}

fn drive_authorization_replay(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    // The same signed decision, presented again under a request identifier the
    // caller chose freshly. The replay table has never seen the new identifier.
    let args = scenario::refund_args();
    let decision = scenario::base_decision(id, &args)?;
    let first = sealed(
        runner.keys,
        id,
        args.clone(),
        decision.clone(),
        BTreeMap::new(),
    )?;
    let second_id = format!("{id}-again");
    let second = sealed(
        runner.keys,
        second_id.as_str(),
        args,
        decision,
        BTreeMap::new(),
    )?;
    let state = runner.state(variant);
    let store = runner.fresh_store()?;
    let first_outcome = runner
        .admit(&state, &store, &first, scenario::NOW_MS)
        .map_err(|error| error.to_string())?;
    if !first_outcome.admitted {
        return Err(format!(
            "the first presentation must be admitted for the replay to mean anything: {:?}",
            first_outcome.denial_code
        ));
    }
    let second_outcome = runner
        .admit(&state, &store, &second, scenario::NOW_MS)
        .map_err(|error| error.to_string())?;
    Ok(Observed::from(&second_outcome))
}

fn drive_signer_verdict_deny(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let args = scenario::refund_args();
    let mut decision = scenario::base_decision(id, &args)?;
    decision.verdict = "deny".to_string();
    let envelope = sealed(runner.keys, id, args, decision, BTreeMap::new())?;
    runner.drive_one(variant, &envelope, scenario::NOW_MS)
}

fn drive_cross_receiver(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let envelope = scenario::admissible(runner.keys, id)?;
    runner.drive_one(variant, &envelope, scenario::NOW_MS)
}

fn drive_admissible(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let envelope = scenario::admissible(runner.keys, id)?;
    runner.drive_one(variant, &envelope, scenario::NOW_MS)
}

// --- the corpus -------------------------------------------------------------

#[allow(clippy::too_many_lines)]
fn specs() -> Vec<Spec> {
    vec![
        Spec {
            threat_id: "PS-TH-01",
            chio_case_id: "wrong-treaty",
            chio_expected_code: "chio_treaty_scope_hash_mismatch",
            baseline_case_id: "unknown-agreement",
            analogue: Analogue::Direct,
            attack: "the signed decision names an agreement identifier the receiver does not hold",
            note: "The composed receiver resolves the identifier in its own table, so an identifier it never provisioned denies. This is the one place the composition already practices receiver-side resolution.",
            variant: StateVariant::Default,
            drive: Some(drive_unknown_agreement),
        },
        Spec {
            threat_id: "PS-TH-01",
            chio_case_id: "wrong-treaty",
            chio_expected_code: "chio_treaty_scope_hash_mismatch",
            baseline_case_id: "wrong-live-agreement",
            analogue: Analogue::Direct,
            attack: "the signed decision names a different agreement the receiver does hold with the same counterparty, with a higher ceiling",
            note: "Nothing in the composition ties this call to the agreement under which it was authorized: the identifier is a field of the decision and any identifier that resolves and covers the caller and the action passes. The hardened profile denies only incidentally, because the approval record it resolves names the other agreement.",
            variant: StateVariant::Default,
            drive: Some(drive_wrong_agreement),
        },
        Spec {
            threat_id: "PS-TH-02",
            chio_case_id: "stale-treaty",
            chio_expected_code: "chio_treaty_stale",
            baseline_case_id: "superseded-agreement",
            analogue: Analogue::Partial,
            attack: "the signed decision names an agreement version the receiver has retired",
            note: "The composed request carries no agreement version, so neither profile can tell which version the signer decided under; the hardened profile denies only because the receiver's record for that identifier is itself marked retired. A decision issued under version 1 and presented against a live version 2 record is indistinguishable from one issued under version 2.",
            variant: StateVariant::Default,
            drive: Some(drive_superseded_agreement),
        },
        Spec {
            threat_id: "PS-TH-03",
            chio_case_id: "forged-intersection",
            chio_expected_code: "chio_treaty_intersection_mismatch",
            baseline_case_id: "no-jointly-computed-bound",
            analogue: Analogue::None,
            attack: "none: the composition has no object standing for the bound two organizations jointly accept",
            note: "The Chio case forges a digest of an intersection both kernels computed. The composed parts have a rule set on each side and no object representing their meet, so there is no digest to forge and no comparison to defeat. The nearest reachable attack is the claimed-attribute case under PS-TH-16.",
            variant: StateVariant::Default,
            drive: None,
        },
        Spec {
            threat_id: "PS-TH-04",
            chio_case_id: "missing-lineage",
            chio_expected_code: "chio_treaty_missing_required_evidence",
            baseline_case_id: "reference-to-unheld-record",
            analogue: Analogue::Partial,
            attack: "the call names an approval record the receiver does not hold",
            note: "The composed receiver can be given a rule requiring a locally-resolved approval, and then an unresolvable reference denies; this is the same drive the governance case runs, because the composition has one mechanism where Chio has two. What has no analogue is the part that matters: the approval is a static record provisioned out of band and reusable without limit, not evidence that this call rests on a specific prior call the receiver itself recorded.",
            variant: StateVariant::Default,
            drive: Some(drive_approval_unknown),
        },
        Spec {
            threat_id: "PS-TH-05",
            chio_case_id: "receipt-mismatch",
            chio_expected_code: "predicate.schema_invalid",
            baseline_case_id: "unbound-resource-field",
            analogue: Analogue::Partial,
            attack: "the signed decision names a resource unrelated to the arguments of the call",
            note: "The composition carries no digest of a receipt the receiver holds, so the Chio attack has no target. The reachable analogue is the decision's own resource field, which the composed receiver carries into its audit record and never compares against anything. It is the composition's counterpart of a carried-but-uncompared field.",
            variant: StateVariant::Default,
            drive: Some(drive_unbound_resource),
        },
        Spec {
            threat_id: "PS-TH-06",
            chio_case_id: "request-hash-mismatch",
            chio_expected_code: "predicate.schema_invalid",
            baseline_case_id: "args-digest-mismatch",
            analogue: Analogue::Direct,
            attack: "the arguments sent differ from the arguments the decision covers",
            note: "The receiver recomputes the digest over the canonical encoding of the arguments it received and compares it with the digest the decision carries. This is a recomputation from the request, not a resolution against receiver state, and it holds in both profiles.",
            variant: StateVariant::Default,
            drive: Some(drive_args_digest_mismatch),
        },
        Spec {
            threat_id: "PS-TH-07",
            chio_case_id: "outcome-hash-mismatch",
            chio_expected_code: "predicate.schema_invalid",
            baseline_case_id: "no-outcome-object",
            analogue: Analogue::None,
            attack: "none: the composition has no outcome digest, because it has no receipt of the prior call to bind one to",
            note: "A signed policy decision describes an intended action. It has no field for what a prior call returned, so there is nothing for a substituted outcome digest to contradict.",
            variant: StateVariant::Default,
            drive: None,
        },
        Spec {
            threat_id: "PS-TH-08",
            chio_case_id: "missing-signature",
            chio_expected_code: "dsse.malformed",
            baseline_case_id: "missing-peer-signature",
            analogue: Analogue::Direct,
            attack: "the request arrives without the peer signature",
            note: "Channel authentication is the composition's strongest part and it holds: an unsigned request never reaches the replay table.",
            variant: StateVariant::Default,
            drive: Some(drive_missing_peer_signature),
        },
        Spec {
            threat_id: "PS-TH-09",
            chio_case_id: "duplicate-signature-keyid",
            chio_expected_code: "dsse.malformed",
            baseline_case_id: "no-signature-set",
            analogue: Analogue::None,
            attack: "none: the composition carries one signature per role, so there is no set of signatures inside one envelope to populate with a duplicate key identifier",
            note: "The attack exists in Chio because the envelope carries a signature array that a verifier iterates. The composed request carries a channel signature and a detached decision signature, each verified against one pinned key, so a duplicate has nowhere to sit.",
            variant: StateVariant::Default,
            drive: None,
        },
        Spec {
            threat_id: "PS-TH-10",
            chio_case_id: "repeated-signer-key",
            chio_expected_code: "signer.independence_required",
            baseline_case_id: "one-party-holds-both-keys",
            analogue: Analogue::Direct,
            attack: "the counterparty's channel key and its policy-engine key are the same key, pinned for both roles",
            note: "Nothing in the composed wiring compares the two pinned keys, so one party signing both halves passes. The check is distinctness, not independence, in either system: two different keys held by one operator pass both.",
            variant: StateVariant::CollapsedKeys,
            drive: Some(drive_collapsed_keys),
        },
        Spec {
            threat_id: "PS-TH-11",
            chio_case_id: "wrong-predicate-type",
            chio_expected_code: "predicate.type_unrecognised",
            baseline_case_id: "type-confusion",
            analogue: Analogue::Direct,
            attack: "a different document the same policy key signed for another purpose is presented as the decision",
            note: "Domain separation by a schema tag and a strict parse that refuses unknown fields. This holds in both profiles and costs nothing.",
            variant: StateVariant::Default,
            drive: Some(drive_type_confusion),
        },
        Spec {
            threat_id: "PS-TH-12",
            chio_case_id: "noncanonical-payload",
            chio_expected_code: "statement.malformed",
            baseline_case_id: "duplicate-key-in-signed-bytes",
            analogue: Analogue::Direct,
            attack: "the transmitted decision bytes carry the action key twice, honest value first and the attacker's last, with the signature over exactly those bytes",
            note: "A strict parse rejects the duplicate before any profile-specific check, so the composition holds here without needing a canonicalization comparison.",
            variant: StateVariant::Default,
            drive: Some(drive_duplicate_key),
        },
        Spec {
            threat_id: "PS-TH-12",
            chio_case_id: "noncanonical-payload",
            chio_expected_code: "statement.malformed",
            baseline_case_id: "reordered-encoding",
            analogue: Analogue::Direct,
            attack: "the decision is transmitted in a semantically identical but non-canonical encoding",
            note: "Admitting this is not a defect: the parsed content is the same and the signature covers the bytes received. The case is recorded because it is the one place the two profiles differ for a reason that is not a security difference.",
            variant: StateVariant::Default,
            drive: Some(drive_reordered_encoding),
        },
        Spec {
            threat_id: "PS-TH-13",
            chio_case_id: "stale-lease",
            chio_expected_code: "capability.lease_expired_or_unknown",
            baseline_case_id: "expired-authorization",
            analogue: Analogue::Partial,
            attack: "the signed decision's validity window has closed",
            note: "The expiry holds. What does not translate is that the window is a timestamp the signer chose rather than a reference the receiver resolves: see the long-window case, where the same signer mints a decade.",
            variant: StateVariant::Default,
            drive: Some(drive_expired_authorization),
        },
        Spec {
            threat_id: "PS-TH-13",
            chio_case_id: "stale-lease",
            chio_expected_code: "capability.lease_expired_or_unknown",
            baseline_case_id: "signer-minted-decade-window",
            analogue: Analogue::Direct,
            attack: "the signed decision declares a ten-year validity window",
            note: "The receiver has no lease record to resolve, so the only bound on the window is the one the signer wrote. A Chio lease reference resolves in the receiver's own registry and carries the receiver's expiry, which a signer cannot extend.",
            variant: StateVariant::Default,
            drive: Some(drive_long_window_authorization),
        },
        Spec {
            threat_id: "PS-TH-14",
            chio_case_id: "missing-governance-receipt",
            chio_expected_code: "governance.receipt_required_missing",
            baseline_case_id: "approval-reference-unresolvable",
            analogue: Analogue::Direct,
            attack: "the call names an approval identifier the receiver does not hold, and presents nothing else",
            note: "The rule requiring an approval is operator-authored: the composition supplies the place to write it, not the requirement. With it written, an unresolvable reference denies in both profiles.",
            variant: StateVariant::Default,
            drive: Some(drive_approval_unknown),
        },
        Spec {
            threat_id: "PS-TH-15",
            chio_case_id: "replayed-continuation",
            chio_expected_code: "chio_treaty_continuation_replay",
            baseline_case_id: "request-id-replay",
            analogue: Analogue::Direct,
            attack: "the identical request is presented twice",
            note: "The replay table holds: a single-row insert on a primary key admits the first presentation and denies the second.",
            variant: StateVariant::Default,
            drive: Some(drive_request_id_replay),
        },
        Spec {
            threat_id: "PS-TH-15",
            chio_case_id: "replayed-continuation",
            chio_expected_code: "chio_treaty_continuation_replay",
            baseline_case_id: "authorization-replay-under-fresh-identifier",
            analogue: Analogue::Direct,
            attack: "the same signed decision is presented again under a request identifier the caller picked freshly",
            note: "The replay table is keyed by a value the caller chooses, so it makes an identifier single-use and leaves the authorization multi-use. A Chio continuation is minted by the receiver and named by the statement, so the second presentation resolves a row that is already consumed.",
            variant: StateVariant::Default,
            drive: Some(drive_authorization_replay),
        },
        Spec {
            threat_id: "PS-TH-16",
            chio_case_id: "request-smuggled-trust-root",
            chio_expected_code: "request_smuggled_trust_root",
            baseline_case_id: "request-supplied-assurance-attribute",
            analogue: Analogue::Direct,
            attack: "the request's policy context carries the assurance level the receiver's own record assigns, and the rule that gates the action reads it",
            note: "This is the composition's receiver-locality failure and it is not a bug in any part: passing the incoming request as the policy context is how every policy decision point is called. The hardened profile refuses any context attribute whose name the receiver owns, which is a denylist of exactly the kind the Chio receiver uses.",
            variant: StateVariant::DowngradedAssurance,
            drive: Some(drive_claimed_assurance),
        },
        Spec {
            threat_id: "PS-TH-17",
            chio_case_id: "dynamic-trust-smuggling",
            chio_expected_code: "request_smuggled_dynamic_trust",
            baseline_case_id: "request-supplied-approval-object",
            analogue: Analogue::Direct,
            attack: "the request presents the approval record inline instead of naming one the receiver holds",
            note: "Presenting a claim rather than naming one is the ordinary way a claim travels, so the composed wiring accepts it. The hardened wiring refuses the request-supplied attribute at the context step, before it reaches the rule that would have resolved the identifier, so the denial code is the same one the assurance case produces.",
            variant: StateVariant::Default,
            drive: Some(drive_approval_smuggled),
        },
        Spec {
            threat_id: "PS-TH-18",
            chio_case_id: "schema-mismatch",
            chio_expected_code: "dsse.malformed",
            baseline_case_id: "wrong-schema-tag",
            analogue: Analogue::Direct,
            attack: "the decision carries a schema tag the receiver does not recognise",
            note: "Holds in both profiles.",
            variant: StateVariant::Default,
            drive: Some(drive_wrong_schema_tag),
        },
        Spec {
            threat_id: "PS-TH-19",
            chio_case_id: "policy-disagreement",
            chio_expected_code: "policy.verdict_disagreement",
            baseline_case_id: "signer-denied-receiver-would-allow",
            analogue: Analogue::Partial,
            attack: "the signed decision's verdict is deny and the call is sent anyway",
            note: "The composed receiver refuses a decision that does not say allow, which covers the disagreement the Chio case tests. It is weaker in one respect: there is one signed verdict rather than two, so a receiver cannot tell a counterparty that never evaluated from one that evaluated and allowed.",
            variant: StateVariant::Default,
            drive: Some(drive_signer_verdict_deny),
        },
        Spec {
            threat_id: "PS-TH-20",
            chio_case_id: "signed-unanimous-deny",
            chio_expected_code: "chio_treaty_policy_denied",
            baseline_case_id: "signed-deny-presented",
            analogue: Analogue::Direct,
            attack: "a validly signed deny is presented as authorization",
            note: "The same drive as PS-TH-19: with one signed verdict the two Chio cases collapse into one baseline case, and it holds.",
            variant: StateVariant::Default,
            drive: Some(drive_signer_verdict_deny),
        },
        Spec {
            threat_id: "PS-EXTRA-01",
            chio_case_id: "audience-binding",
            chio_expected_code: "n/a",
            baseline_case_id: "cross-receiver-presentation",
            analogue: Analogue::Direct,
            attack: "the admissible call is presented unchanged to a second receiver that pinned the same counterparty keys and provisioned the same agreement identifier",
            note: "Not in the twenty-case corpus; it is the drive for the fourth property. A tool call has no audience field, so the composed wiring admits. The hardened wiring carries an audience in the decision and checks it.",
            variant: StateVariant::SecondReceiver,
            drive: Some(drive_cross_receiver),
        },
        Spec {
            threat_id: "PS-EXTRA-02",
            chio_case_id: "null-case",
            chio_expected_code: "n/a",
            baseline_case_id: "unmodified-admissible-call",
            analogue: Analogue::Direct,
            attack: "nothing is modified",
            note: "The null case. Without it the corpus could be denying everything for an unrelated reason.",
            variant: StateVariant::Default,
            drive: Some(drive_admissible),
        },
    ]
}

pub fn run(composed: &Runner<'_>, hardened: &Runner<'_>) -> Result<Vec<NegativeResult>, String> {
    let mut results = Vec::new();
    for (index, spec) in specs().into_iter().enumerate() {
        let id = format!("{}-{index}", spec.baseline_case_id);
        let (composed_observed, hardened_observed) = match spec.drive {
            Some(drive) => (
                Some(ObservedJson::from(drive(composed, spec.variant, &id)?)),
                Some(ObservedJson::from(drive(
                    hardened,
                    spec.variant,
                    format!("{id}-h").as_str(),
                )?)),
            ),
            None => (None, None),
        };
        results.push(NegativeResult {
            threat_id: spec.threat_id,
            chio_case_id: spec.chio_case_id,
            chio_expected_code: spec.chio_expected_code,
            baseline_case_id: spec.baseline_case_id,
            analogue: spec.analogue,
            attack: spec.attack,
            note: spec.note,
            composed: composed_observed,
            hardened: hardened_observed,
        });
    }
    Ok(results)
}
