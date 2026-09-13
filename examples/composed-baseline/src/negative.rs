//! The twenty Chio threat cases, answered one by one against the composed
//! alternative.
//!
//! Each entry names the Chio case it answers, states what the equivalent attack
//! is when the composed formats can express one, and records what the composed
//! receiver did. Where no format in the set carries a field the attack could
//! touch, the entry says so and says why: an attack with no surface is a result
//! about the surface, not a pass.
//!
//! Two driven entries are not attacks and are marked as such: the null case,
//! which must be admitted for any denial here to be attributable, and a case
//! driven only to record where the two wirings differ for a reason that is not
//! a security difference.

use crate::harness::{Observed, Runner, StateVariant};
use crate::request::ISSUED_TOKEN_TYPE_ACCESS_TOKEN;
use crate::scenario::{self, CallBuilder, Credential};
use chio_core_types::crypto::canonical_json_bytes;
use serde::Serialize;
use serde_json::json;

/// What a driven case is for. Only an `Attack` is a call the receiver ought to
/// refuse, so only an `Attack` belongs in a count of attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseRole {
    /// A call the receiver ought to refuse.
    Attack,
    /// The unmodified admissible call, driven so that every denial in the
    /// corpus is attributable to what the case changed.
    Null,
    /// A call that is admissible, driven to record a behavioural difference
    /// between the two wirings that is not a security difference.
    Informational,
}

/// How closely the composed formats can express the Chio case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Analogue {
    /// The same attack, against the field the composition carries for it.
    Direct,
    /// A weaker attack: the composition carries something adjacent, and the
    /// note says what the attack loses in translation.
    Partial,
    /// No format in the set carries a field the attack could touch.
    None,
}

#[derive(Debug, Clone, Serialize)]
pub struct NegativeResult {
    pub threat_id: &'static str,
    pub chio_case_id: &'static str,
    pub chio_expected_code: &'static str,
    pub baseline_case_id: &'static str,
    pub role: CaseRole,
    pub analogue: Analogue,
    pub attack: &'static str,
    pub note: &'static str,
    /// The experiment this case ran: the drive and the receiver state it ran
    /// against. Two cases sharing it ran one experiment, which is how the
    /// places where two Chio cases collapse onto one baseline drive are counted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drive_id: Option<String>,
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
    role: CaseRole,
    analogue: Analogue,
    attack: &'static str,
    note: &'static str,
    variant: StateVariant,
    /// Name of the drive this case runs. Two cases naming the same drive and
    /// the same state variant run the same experiment.
    drive_name: &'static str,
    drive: Option<Drive>,
}

// --- drives -----------------------------------------------------------------

fn drive_admissible(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let envelope = scenario::admissible(runner.keys, id)?;
    runner.drive_one(variant, &envelope, scenario::NOW_MS)
}

fn drive_unknown_agreement(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let mut call = CallBuilder::new(runner.keys, id);
    call.claims.scope = scenario::refund_scope("treaty-buyer-vendor-substituted", 1);
    runner.drive_one(variant, &call.build()?, scenario::NOW_MS)
}

fn drive_wrong_agreement(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    // The pilot agreement, at the version the receiver holds for it: an
    // adversary asserting a version asserts one that resolves.
    let mut call = CallBuilder::new(runner.keys, id);
    call.claims.scope = scenario::refund_scope(scenario::AGREEMENT_PILOT, 1);
    runner.drive_one(variant, &call.build()?, scenario::NOW_MS)
}

fn drive_superseded_agreement(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let mut call = CallBuilder::new(runner.keys, id);
    call.claims.scope = scenario::refund_scope(scenario::AGREEMENT_RETIRED, 1);
    runner.drive_one(variant, &call.build()?, scenario::NOW_MS)
}

fn drive_asserted_version_matches(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    // The caller asks its own authorization server for a token asserting the
    // version the receiver now holds, and sends the call it prepared under the
    // previous one. The asserted value is a string the caller chose.
    let mut call = CallBuilder::new(runner.keys, id);
    call.claims.scope =
        scenario::refund_scope(scenario::AGREEMENT, scenario::AGREEMENT_VERSION + 1);
    runner.drive_one(variant, &call.build()?, scenario::NOW_MS)
}

fn drive_arguments_differ(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    // The exchange was performed for a refund of 2500. The call sends 9900.
    // Nothing in the credential covers the arguments, so there is nothing to
    // contradict.
    let mut call = CallBuilder::new(runner.keys, id);
    call.arguments["amount_minor"] = json!(9900u64);
    runner.drive_one(variant, &call.build()?, scenario::NOW_MS)
}

fn drive_unbound_resource(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let mut call = CallBuilder::new(runner.keys, id);
    call.arguments["order_id"] = json!("order-0000-unrelated");
    runner.drive_one(variant, &call.build()?, scenario::NOW_MS)
}

fn drive_missing_channel_proof(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let mut call = CallBuilder::new(runner.keys, id);
    call.channel_signer = None;
    runner.drive_one(variant, &call.build()?, scenario::NOW_MS)
}

fn drive_collapsed_keys(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    // One party holds both: the key in the agent's SVID is also the key its
    // authorization server signs with, and the trust bundle carries it twice.
    let mut call = CallBuilder::new(runner.keys, id);
    call.credential = Credential::Issue(&runner.keys.buyer_svid);
    runner.drive_one(variant, &call.build()?, scenario::NOW_MS)
}

fn drive_token_type_confusion(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    // A different document the same issuer signed for another purpose: an
    // identity token, presented where the exchanged credential belongs.
    let other = json!({
        "iss": scenario::BUYER_ISSUER,
        "sub": scenario::BUYER_SUBJECT,
        "aud": [scenario::VENDOR_URI],
        "exp": scenario::NOW_S + 40,
        "iat": scenario::NOW_S - 1,
        "nonce": "n-0S6_WzA2Mj",
    });
    let mut call = CallBuilder::new(runner.keys, id);
    call.raw_claims = Some(canonical_json_bytes(&other).map_err(|error| error.to_string())?);
    runner.drive_one(variant, &call.build()?, scenario::NOW_MS)
}

fn drive_unrecognised_token_type(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let call = CallBuilder::new(runner.keys, id);
    let mut envelope = call.build()?;
    if let Some(credential) = envelope.credential.as_mut() {
        credential.issued_token_type = ISSUED_TOKEN_TYPE_ACCESS_TOKEN.to_string();
    }
    runner.drive_one(variant, &envelope, scenario::NOW_MS)
}

fn drive_duplicate_claim(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    // The transmitted claim bytes carry `scope` twice: the honest value first,
    // the attacker's value last. The signature covers exactly these bytes.
    let claims = scenario::base_claims(id);
    let canonical = canonical_json_bytes(&claims).map_err(|error| error.to_string())?;
    let canonical = String::from_utf8(canonical).map_err(|error| error.to_string())?;
    let needle = format!("\"scope\":\"{}\"", claims.scope);
    let widened = scenario::refund_scope(scenario::AGREEMENT_PILOT, 1);
    let raw = canonical.replacen(
        needle.as_str(),
        format!("{needle},\"scope\":\"{widened}\"").as_str(),
        1,
    );
    let mut call = CallBuilder::new(runner.keys, id);
    call.raw_claims = Some(raw.into_bytes());
    runner.drive_one(variant, &call.build()?, scenario::NOW_MS)
}

fn drive_reordered_encoding(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    // Semantically identical bytes in a non-canonical encoding. Admitting this
    // is not an attack; the case is here to show which wiring notices.
    let claims = scenario::base_claims(id);
    let raw = serde_json::to_string_pretty(&claims).map_err(|error| error.to_string())?;
    let mut call = CallBuilder::new(runner.keys, id);
    call.raw_claims = Some(raw.into_bytes());
    runner.drive_one(variant, &call.build()?, scenario::NOW_MS)
}

fn drive_expired_token(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let mut call = CallBuilder::new(runner.keys, id);
    call.claims.exp = scenario::NOW_S - 1;
    runner.drive_one(variant, &call.build()?, scenario::NOW_MS)
}

fn drive_long_window(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let mut call = CallBuilder::new(runner.keys, id);
    call.claims.exp = call.claims.iat + 315_360_000;
    runner.drive_one(variant, &call.build()?, scenario::NOW_MS)
}

fn drive_approval_unknown(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let mut call = CallBuilder::new(runner.keys, id);
    call.arguments["approval_id"] = json!("approval-refund-9999");
    runner.drive_one(variant, &call.build()?, scenario::NOW_MS)
}

fn drive_approval_smuggled(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let mut call = CallBuilder::new(runner.keys, id);
    call.arguments["approval_id"] = json!("approval-refund-9999");
    call.message_metadata.insert(
        "approval".to_string(),
        json!({
            "approval_id": "approval-refund-9999",
            "agreement_id": scenario::AGREEMENT,
            "action": scenario::ACTION,
            "max_amount_minor": 10_000u64,
        }),
    );
    runner.drive_one(variant, &call.build()?, scenario::NOW_MS)
}

fn drive_claimed_assurance(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let mut call = CallBuilder::new(runner.keys, id);
    call.message_metadata
        .insert("assurance_level".to_string(), json!("attested"));
    runner.drive_one(variant, &call.build()?, scenario::NOW_MS)
}

fn drive_unresolvable_task_reference(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let mut call = CallBuilder::new(runner.keys, id);
    call.reference_task_ids = vec!["task-refund-9999".to_string()];
    runner.drive_one(variant, &call.build()?, scenario::NOW_MS)
}

fn drive_message_id_replay(
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

fn drive_token_replay(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    // The same credential, presented again under a message identifier the
    // caller created freshly. The replay table has never seen the new one.
    let first = scenario::admissible(runner.keys, id)?;
    let credential = first
        .credential
        .clone()
        .ok_or_else(|| "the admissible call carries a credential".to_string())?;
    let mut second = CallBuilder::new(runner.keys, format!("{id}-again").as_str());
    second.credential = Credential::Reuse(credential);
    let second = second.build()?;

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

fn drive_task_handle_reuse(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    // Two calls naming the same task the receiver minted, each with its own
    // message identifier and its own credential. A task accepts many messages,
    // so the handle the receiver chose bounds nothing.
    let first = scenario::admissible(runner.keys, id)?;
    let second = scenario::admissible(runner.keys, format!("{id}-again").as_str())?;
    let state = runner.state(variant);
    let store = runner.fresh_store()?;
    let first_outcome = runner
        .admit(&state, &store, &first, scenario::NOW_MS)
        .map_err(|error| error.to_string())?;
    if !first_outcome.admitted {
        return Err(format!(
            "the first call must be admitted for the second to mean anything: {:?}",
            first_outcome.denial_code
        ));
    }
    let second_outcome = runner
        .admit(&state, &store, &second, scenario::NOW_MS)
        .map_err(|error| error.to_string())?;
    Ok(Observed::from(&second_outcome))
}

fn drive_no_credential(
    runner: &Runner<'_>,
    variant: StateVariant,
    id: &str,
) -> Result<Observed, String> {
    let mut call = CallBuilder::new(runner.keys, id);
    call.credential = Credential::None;
    runner.drive_one(variant, &call.build()?, scenario::NOW_MS)
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
            role: CaseRole::Attack,
            analogue: Analogue::Direct,
            attack: "the credential's scope names an agreement the receiver does not hold",
            note: "The composed receiver resolves the identifier in its own table, so an identifier it never provisioned denies. This is the one place the composition already practices receiver-side resolution, and it works because a scope value is opaque to everyone but the two organizations that agreed it.",
            variant: StateVariant::Default,
            drive_name: "drive_unknown_agreement",
            drive: Some(drive_unknown_agreement),
        },
        Spec {
            threat_id: "PS-TH-01",
            chio_case_id: "wrong-treaty",
            chio_expected_code: "chio_treaty_scope_hash_mismatch",
            baseline_case_id: "wrong-live-agreement",
            role: CaseRole::Attack,
            analogue: Analogue::Direct,
            attack: "the credential's scope names a different agreement the receiver does hold with the same counterparty, with a higher ceiling, at the version the receiver holds for it",
            note: "Nothing ties this call to the agreement it was prepared under: the identifier is a scope value the caller asked its own authorization server for, and any value that resolves and covers the subject and the action passes. The hardened wiring denies only incidentally, because the approval record it resolves names the other agreement.",
            variant: StateVariant::Default,
            drive_name: "drive_wrong_agreement",
            drive: Some(drive_wrong_agreement),
        },
        Spec {
            threat_id: "PS-TH-02",
            chio_case_id: "stale-treaty",
            chio_expected_code: "chio_treaty_stale",
            baseline_case_id: "superseded-agreement",
            role: CaseRole::Attack,
            analogue: Analogue::Partial,
            attack: "the credential's scope names an agreement the receiver has marked retired",
            note: "A weaker analogue than it looks: retirement is a flag on the receiver's own record, so the hardened wiring closes it with one condition on the lookup. It says nothing about which version of a live record the caller decided under, which is the next two cases.",
            variant: StateVariant::Default,
            drive_name: "drive_superseded_agreement",
            drive: Some(drive_superseded_agreement),
        },
        Spec {
            threat_id: "PS-TH-02",
            chio_case_id: "stale-treaty",
            chio_expected_code: "chio_treaty_stale",
            baseline_case_id: "agreement-version-advanced-in-flight",
            role: CaseRole::Attack,
            analogue: Analogue::Direct,
            attack: "a call whose credential asserts the version it was prepared under is presented against a receiver whose own record has moved to a later version",
            note: "The hardened wiring closes this one, and it is worth being exact about how: the only place a version can travel is a scope value, and the check compares what the caller's authorization server asserted with what the receiver holds. Against a caller that reports its stale read honestly, the comparison works. The next case is the same attack from a caller that does not.",
            variant: StateVariant::AgreementVersionAdvanced,
            drive_name: "drive_admissible",
            drive: Some(drive_admissible),
        },
        Spec {
            threat_id: "PS-TH-02",
            chio_case_id: "stale-treaty",
            chio_expected_code: "chio_treaty_stale",
            baseline_case_id: "asserted-version-matches-receiver-record",
            role: CaseRole::Attack,
            analogue: Analogue::Direct,
            attack: "the caller obtains a credential asserting the version the receiver currently holds and sends the call it prepared under the previous one",
            note: "The structural failure, in its sharpest form. Every value that reaches this receiver was minted by the caller or by the caller's own authorization server, so a check against receiver-held state is a comparison with an assertion, and the assertion is the adversary's to choose. No wiring of these formats closes it: to bind the version the receiver would need a value it minted itself inside the signed credential, and the token exchange request has no parameter to carry one.",
            variant: StateVariant::AgreementVersionAdvanced,
            drive_name: "drive_asserted_version_matches",
            drive: Some(drive_asserted_version_matches),
        },
        Spec {
            threat_id: "PS-TH-03",
            chio_case_id: "forged-intersection",
            chio_expected_code: "chio_treaty_intersection_mismatch",
            baseline_case_id: "no-jointly-computed-bound",
            role: CaseRole::Attack,
            analogue: Analogue::None,
            attack: "none: no format in the set has an object standing for a bound two organizations jointly accept",
            note: "The Chio case forges a digest of an intersection both kernels computed. Here each side has a policy of its own and there is no object representing their meet, so there is no digest to forge and no comparison to defeat. The nearest reachable attack is the claimed-attribute case under PS-TH-16.",
            variant: StateVariant::Default,
            drive_name: "none",
            drive: None,
        },
        Spec {
            threat_id: "PS-TH-04",
            chio_case_id: "missing-lineage",
            chio_expected_code: "chio_treaty_missing_required_evidence",
            baseline_case_id: "unresolvable-task-reference",
            role: CaseRole::Attack,
            analogue: Analogue::Partial,
            attack: "the message references a task the receiver has no record of",
            note: "A2A does carry a reference list: a message may name the task it belongs to and the tasks it references for additional context, and those identifiers were minted by this receiver. The hardened wiring resolves them and refuses one it never issued. What has no carrier is the part that matters: the reference is an identifier and not a digest, so a reference moved from one task the receiver holds to another is not a substitution anything notices, and nothing records that this call is the one the referenced task called for.",
            variant: StateVariant::Default,
            drive_name: "drive_unresolvable_task_reference",
            drive: Some(drive_unresolvable_task_reference),
        },
        Spec {
            threat_id: "PS-TH-05",
            chio_case_id: "receipt-mismatch",
            chio_expected_code: "predicate.schema_invalid",
            baseline_case_id: "call-unbound-to-its-resource",
            role: CaseRole::Attack,
            analogue: Analogue::Partial,
            attack: "the call names an order unrelated to the one the credential was obtained for",
            note: "The composition carries no digest of a receipt the receiver holds, so the Chio attack has no target. What is reachable is the granularity of the credential: scope names an action class, and a token obtained for one order authorizes any order within that class. Both wirings admit, and no operator check closes it, because nothing in the credential names an instance. The standards-track answer is rich authorization requests, which would put structured detail in the token and would still be detail the caller's own authorization server minted.",
            variant: StateVariant::Default,
            drive_name: "drive_unbound_resource",
            drive: Some(drive_unbound_resource),
        },
        Spec {
            threat_id: "PS-TH-06",
            chio_case_id: "request-hash-mismatch",
            chio_expected_code: "predicate.schema_invalid",
            baseline_case_id: "arguments-differ-from-authorized-call",
            role: CaseRole::Attack,
            analogue: Analogue::Direct,
            attack: "the arguments sent differ from the arguments the exchange was performed for",
            note: "No claim in the credential covers the body of the call, and no field of the message or the tool call carries a digest of it. The exchange happens at the caller's authorization server, which never sees the arguments and whose request has no parameter for them, so there is nothing for an operator to compare. Both wirings admit an amount the exchange never saw, bounded only by the receiver's own ceiling.",
            variant: StateVariant::Default,
            drive_name: "drive_arguments_differ",
            drive: Some(drive_arguments_differ),
        },
        Spec {
            threat_id: "PS-TH-07",
            chio_case_id: "outcome-hash-mismatch",
            chio_expected_code: "predicate.schema_invalid",
            baseline_case_id: "no-outcome-object",
            role: CaseRole::Attack,
            analogue: Analogue::None,
            attack: "none: nothing in the set carries an outcome digest, because nothing carries a receipt of the prior call to bind one to",
            note: "A delegated credential describes authority to act. It has no field for what a prior call returned, so there is nothing for a substituted outcome digest to contradict.",
            variant: StateVariant::Default,
            drive_name: "none",
            drive: None,
        },
        Spec {
            threat_id: "PS-TH-08",
            chio_case_id: "missing-signature",
            chio_expected_code: "dsse.malformed",
            baseline_case_id: "missing-channel-authentication",
            role: CaseRole::Attack,
            analogue: Analogue::Direct,
            attack: "the call arrives without proof of the private key of the SVID it claims",
            note: "Workload authentication is the composition's strongest part and it holds: a call that cannot prove possession never reaches the replay table.",
            variant: StateVariant::Default,
            drive_name: "drive_missing_channel_proof",
            drive: Some(drive_missing_channel_proof),
        },
        Spec {
            threat_id: "PS-TH-09",
            chio_case_id: "duplicate-signature-keyid",
            chio_expected_code: "dsse.malformed",
            baseline_case_id: "no-signature-set",
            role: CaseRole::Attack,
            analogue: Analogue::None,
            attack: "none: the composition carries one signature per role, so there is no set of signatures inside one envelope to populate with a duplicate key identifier",
            note: "The attack exists in Chio because the envelope carries a signature array a verifier iterates. Here a call carries one channel authentication and one issuer signature over the credential, each verified against one key the bundle names, so a duplicate has nowhere to sit.",
            variant: StateVariant::Default,
            drive_name: "none",
            drive: None,
        },
        Spec {
            threat_id: "PS-TH-10",
            chio_case_id: "repeated-signer-key",
            chio_expected_code: "signer.independence_required",
            baseline_case_id: "one-key-for-svid-and-issuer",
            role: CaseRole::Attack,
            analogue: Analogue::Direct,
            attack: "the counterparty's SVID key and its authorization server's signing key are the same key, and the trust bundle carries it for both",
            note: "Nothing in the composed wiring compares the two keys, so one party signing both halves passes. The check is distinctness, not independence, in either system: two different keys held by one operator pass both.",
            variant: StateVariant::CollapsedKeys,
            drive_name: "drive_collapsed_keys",
            drive: Some(drive_collapsed_keys),
        },
        Spec {
            threat_id: "PS-TH-11",
            chio_case_id: "wrong-predicate-type",
            chio_expected_code: "predicate.type_unrecognised",
            baseline_case_id: "token-type-confusion",
            role: CaseRole::Attack,
            analogue: Analogue::Direct,
            attack: "an identity token the same issuer signed for another purpose is presented as the exchanged credential",
            note: "A strict parse of the claim set refuses it before any profile-specific check. Typed tokens and a strict parse hold in both wirings and cost nothing.",
            variant: StateVariant::Default,
            drive_name: "drive_token_type_confusion",
            drive: Some(drive_token_type_confusion),
        },
        Spec {
            threat_id: "PS-TH-12",
            chio_case_id: "noncanonical-payload",
            chio_expected_code: "statement.malformed",
            baseline_case_id: "duplicate-claim-in-signed-token",
            role: CaseRole::Attack,
            analogue: Analogue::Direct,
            attack: "the transmitted claim bytes carry the scope claim twice, honest value first and a wider value last, with the signature over exactly those bytes",
            note: "A strict parse rejects the duplicate before any profile-specific check, so the composition holds here without needing a canonicalization comparison.",
            variant: StateVariant::Default,
            drive_name: "drive_duplicate_claim",
            drive: Some(drive_duplicate_claim),
        },
        Spec {
            threat_id: "PS-TH-12",
            chio_case_id: "noncanonical-payload",
            chio_expected_code: "statement.malformed",
            baseline_case_id: "reordered-token-encoding",
            role: CaseRole::Informational,
            analogue: Analogue::Direct,
            attack: "the claim set is transmitted in a semantically identical but non-canonical encoding",
            note: "Admitting this is not a defect: the parsed content is the same and the signature covers the bytes received. The case carries the informational role and is excluded from the attack counts for that reason. It is recorded because it is the one place the two wirings differ for a reason that is not a security difference.",
            variant: StateVariant::Default,
            drive_name: "drive_reordered_encoding",
            drive: Some(drive_reordered_encoding),
        },
        Spec {
            threat_id: "PS-TH-13",
            chio_case_id: "stale-lease",
            chio_expected_code: "capability.lease_expired_or_unknown",
            baseline_case_id: "expired-token",
            role: CaseRole::Attack,
            analogue: Analogue::Partial,
            attack: "the credential's validity window has closed",
            note: "The expiry holds, and it is required rather than optional: a JWT-SVID without an expiry is rejected outright. What does not translate is that the window is a pair of timestamps the issuer chose rather than a reference the receiver resolves: see the next case, where the same issuer mints a decade.",
            variant: StateVariant::Default,
            drive_name: "drive_expired_token",
            drive: Some(drive_expired_token),
        },
        Spec {
            threat_id: "PS-TH-13",
            chio_case_id: "stale-lease",
            chio_expected_code: "capability.lease_expired_or_unknown",
            baseline_case_id: "issuer-minted-decade-window",
            role: CaseRole::Attack,
            analogue: Analogue::Direct,
            attack: "the credential declares a ten-year validity window",
            note: "The composed wiring admits: the only bound on the window is the one the issuer wrote. The hardened wiring refuses it against a maximum validity the receiver holds as a constant, which is what a maximum token age is in any verifier that enforces one. The residual difference is not that Chio bounds the window and the composition cannot, but what the bound is made of: a Chio lease reference resolves in the receiver's own registry, so the receiver can revoke and re-scope it per counterparty between calls, where the constant is the same for every credential the receiver ever sees.",
            variant: StateVariant::Default,
            drive_name: "drive_long_window",
            drive: Some(drive_long_window),
        },
        Spec {
            threat_id: "PS-TH-14",
            chio_case_id: "missing-governance-receipt",
            chio_expected_code: "governance.receipt_required_missing",
            baseline_case_id: "approval-reference-unresolvable",
            role: CaseRole::Attack,
            analogue: Analogue::Direct,
            attack: "the call names an approval identifier the receiver does not hold, and presents nothing else",
            note: "This one holds, and the carrier is worth naming: the identifier travels as an argument of the tool, whose input schema the receiver publishes. It is the one open slot in the composition whose shape the receiver owns, and the only fact it can demand without extending any protocol. The requirement itself is still operator-authored: the composition supplies the place to write the rule, not the rule.",
            variant: StateVariant::Default,
            drive_name: "drive_approval_unknown",
            drive: Some(drive_approval_unknown),
        },
        Spec {
            threat_id: "PS-TH-15",
            chio_case_id: "replayed-continuation",
            chio_expected_code: "chio_treaty_continuation_replay",
            baseline_case_id: "message-id-replay",
            role: CaseRole::Attack,
            analogue: Analogue::Direct,
            attack: "the identical message is presented twice",
            note: "The replay table holds: a single-row insert on a primary key admits the first presentation and denies the second. The identifier it is keyed by is created by the message creator.",
            variant: StateVariant::Default,
            drive_name: "drive_message_id_replay",
            drive: Some(drive_message_id_replay),
        },
        Spec {
            threat_id: "PS-TH-15",
            chio_case_id: "replayed-continuation",
            chio_expected_code: "chio_treaty_continuation_replay",
            baseline_case_id: "token-replay-under-fresh-message-id",
            role: CaseRole::Attack,
            analogue: Analogue::Direct,
            attack: "the same credential is presented again under a message identifier the caller created freshly",
            note: "The composed wiring's replay table is keyed by a value the caller creates, so it makes a message single-use and leaves the credential multi-use. The hardened wiring claims a second row on the token identifier, which is what a jti table does for a bearer token, and the second presentation denies. What remains is not the mechanism, which is the same single-row insert Chio uses, but who mints the value it is keyed by: the issuer mints token identifiers and can mint as many as it likes, where a Chio continuation is minted by the receiver before the request and named by the statement.",
            variant: StateVariant::Default,
            drive_name: "drive_token_replay",
            drive: Some(drive_token_replay),
        },
        Spec {
            threat_id: "PS-TH-15",
            chio_case_id: "replayed-continuation",
            chio_expected_code: "chio_treaty_continuation_replay",
            baseline_case_id: "task-handle-reused-across-calls",
            role: CaseRole::Attack,
            analogue: Analogue::Direct,
            attack: "two calls name the same task the receiver minted, each with its own message identifier and its own credential",
            note: "This is the case that says what the one receiver-minted value in the composition is worth. A task identifier is generated by the server, and the caller echoes it, which is the shape of a receiver-minted continuation and is why it is worth driving. It bounds nothing: a task is a conversation that accepts many messages, no specification makes echoing one consume it, and nothing signs it. The same is true of the other receiver-minted value in the set, the opaque state an MCP server hands back for a retry, whose own specification says the measures that bound its replay window do not guarantee single use and that a server needing that must enforce it itself.",
            variant: StateVariant::Default,
            drive_name: "drive_task_handle_reuse",
            drive: Some(drive_task_handle_reuse),
        },
        Spec {
            threat_id: "PS-TH-16",
            chio_case_id: "request-smuggled-trust-root",
            chio_expected_code: "request_smuggled_trust_root",
            baseline_case_id: "request-supplied-assurance-attribute",
            role: CaseRole::Attack,
            analogue: Analogue::Direct,
            attack: "the message's own metadata carries the assurance level the receiver's record assigns, and the rule that gates the action reads it",
            note: "This is the composition's receiver-locality failure and it is not a defect in any part: a message carries a metadata map for exactly this, and handing the incoming request to the policy engine as its evaluation context is how a policy decision point is called. The hardened wiring refuses any supplied attribute whose name the receiver owns, in any of the slots the formats leave open, which is a denylist of exactly the kind the Chio receiver uses.",
            variant: StateVariant::DowngradedAssurance,
            drive_name: "drive_claimed_assurance",
            drive: Some(drive_claimed_assurance),
        },
        Spec {
            threat_id: "PS-TH-17",
            chio_case_id: "dynamic-trust-smuggling",
            chio_expected_code: "request_smuggled_dynamic_trust",
            baseline_case_id: "request-supplied-approval-object",
            role: CaseRole::Attack,
            analogue: Analogue::Direct,
            attack: "the message presents the approval record inline instead of naming one the receiver holds",
            note: "Presenting a claim rather than naming one is the ordinary way a claim travels, so the composed wiring accepts it. The hardened wiring refuses the supplied attribute at the context step, before it reaches the rule that would have resolved the identifier, so the denial code is the same one the assurance case produces.",
            variant: StateVariant::Default,
            drive_name: "drive_approval_smuggled",
            drive: Some(drive_approval_smuggled),
        },
        Spec {
            threat_id: "PS-TH-18",
            chio_case_id: "schema-mismatch",
            chio_expected_code: "dsse.malformed",
            baseline_case_id: "unrecognised-issued-token-type",
            role: CaseRole::Attack,
            analogue: Analogue::Direct,
            attack: "the credential declares a token type identifier the receiver does not accept",
            note: "Holds in both wirings. The token type identifier is a URI the exchange defines for exactly this: it says what was issued, so a receiver can refuse what it did not ask for.",
            variant: StateVariant::Default,
            drive_name: "drive_unrecognised_token_type",
            drive: Some(drive_unrecognised_token_type),
        },
        Spec {
            threat_id: "PS-TH-19",
            chio_case_id: "policy-disagreement",
            chio_expected_code: "policy.verdict_disagreement",
            baseline_case_id: "exchange-refused-call-sent-anyway",
            role: CaseRole::Attack,
            analogue: Analogue::Partial,
            attack: "the caller's authorization server refuses the exchange and the caller sends the call regardless",
            note: "The composition holds this, in the only form it can: a refusal is an error response at the token endpoint, so the caller has nothing to present and the receiver denies for absence. It is weaker than the Chio case in a way worth stating: the receiver learns that no authority was presented, never that the counterparty evaluated and said no, so a counterparty that never evaluated and one that refused are the same event here.",
            variant: StateVariant::Default,
            drive_name: "drive_no_credential",
            drive: Some(drive_no_credential),
        },
        Spec {
            threat_id: "PS-TH-20",
            chio_case_id: "signed-unanimous-deny",
            chio_expected_code: "chio_treaty_policy_denied",
            baseline_case_id: "no-signed-refusal",
            role: CaseRole::Attack,
            analogue: Analogue::None,
            attack: "none: no format in the set has a signed refusal, so there is no such object to present",
            note: "The Chio case presents a validly signed deny as authorization. A token exchange answers a refusal with an OAuth error response, which is not signed, not addressed to the receiver, and never travels beyond the caller. There is nothing to forge and nothing to mistake for an allow.",
            variant: StateVariant::Default,
            drive_name: "none",
            drive: None,
        },
        Spec {
            threat_id: "PS-EXTRA-01",
            chio_case_id: "audience-binding",
            chio_expected_code: "n/a",
            baseline_case_id: "cross-receiver-presentation",
            role: CaseRole::Attack,
            analogue: Analogue::Direct,
            attack: "the admissible call is presented unchanged to a second receiver that installed the same trust bundle and provisioned the same agreement identifier",
            note: "Both wirings refuse, and this is the property the composition holds outright rather than by operator effort. The audience of a credential is not optional in either half of this set: a JWT-SVID validator rejects a token whose audience does not carry its own identifier, and a protected resource must establish that a token was issued for it. A second route closes it again: resolving the agreement means reading a participant list, and a receiver absent from it is not a party to what it just resolved. What is established is narrower than the Chio statement, which also requires a receipt the composition has nothing to represent.",
            variant: StateVariant::SecondReceiver,
            drive_name: "drive_admissible",
            drive: Some(drive_admissible),
        },
        Spec {
            threat_id: "PS-EXTRA-02",
            chio_case_id: "null-case",
            chio_expected_code: "n/a",
            baseline_case_id: "unmodified-admissible-call",
            role: CaseRole::Null,
            analogue: Analogue::Direct,
            attack: "nothing is modified",
            note: "The null case. Without it the corpus could be denying everything for an unrelated reason.",
            variant: StateVariant::Default,
            drive_name: "drive_admissible",
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
            role: spec.role,
            analogue: spec.analogue,
            attack: spec.attack,
            note: spec.note,
            drive_id: spec
                .drive
                .map(|_| format!("{}@{}", spec.drive_name, spec.variant.as_str())),
            composed: composed_observed,
            hardened: hardened_observed,
        });
    }
    Ok(results)
}
