//! The four properties, evaluated against the composed alternative.
//!
//! A property's verdict is derived from cases the run actually drove, not
//! asserted. `holds` is true only when every case the property rests on denied
//! (or admitted, for the null case) under that wiring.

use crate::negative::NegativeResult;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The composed receiver enforces the property as stated.
    Holds,
    /// The composed receiver enforces a strictly weaker statement. `weakened_to`
    /// says what.
    HoldsWeakened,
    /// The composed receiver does not enforce it, and a driven case shows a
    /// dispatch that the property forbids.
    Fails,
}

#[derive(Debug, Clone, Serialize)]
pub struct PropertyResult {
    pub property: &'static str,
    pub statement: &'static str,
    pub composed: Verdict,
    pub hardened: Verdict,
    /// The step of the composed admission path at which the property is lost,
    /// or where it is decided when it holds.
    pub step: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weakened_to: Option<&'static str>,
    /// Baseline case identifiers the verdict rests on.
    pub witnesses: Vec<&'static str>,
    pub note: &'static str,
}

fn admitted(results: &[NegativeResult], case_id: &str, hardened: bool) -> Option<bool> {
    results
        .iter()
        .find(|result| result.baseline_case_id == case_id)
        .and_then(|result| {
            if hardened {
                result.hardened.as_ref()
            } else {
                result.composed.as_ref()
            }
        })
        .map(|observed| observed.dispatched)
}

/// Fail closed: a property whose witness case did not run cannot be reported.
fn require(results: &[NegativeResult], case_id: &str, hardened: bool) -> Result<bool, String> {
    admitted(results, case_id, hardened).ok_or_else(|| {
        format!("property evaluation needs case {case_id}, which the negative corpus did not drive")
    })
}

/// Whether any of the named cases dispatched under this wiring.
fn any_dispatched(
    results: &[NegativeResult],
    case_ids: &[&str],
    hardened: bool,
) -> Result<bool, String> {
    let mut dispatched = false;
    for case_id in case_ids {
        dispatched |= require(results, case_id, hardened)?;
    }
    Ok(dispatched)
}

const ADMISSION_BINDING_WITNESSES: &[&str] = &[
    "asserted-version-matches-receiver-record",
    "arguments-differ-from-authorized-call",
    "token-replay-under-fresh-message-id",
    "wrong-live-agreement",
    "superseded-agreement",
];

const RECEIVER_LOCALITY_WITNESSES: &[&str] = &[
    "request-supplied-assurance-attribute",
    "request-supplied-approval-object",
];

pub fn evaluate(results: &[NegativeResult]) -> Result<Vec<PropertyResult>, String> {
    let mut properties = Vec::new();

    // Admission binding. The property has a conjunct no wiring of these formats
    // can satisfy: the presented evidence must equal what the receiver computed
    // for this call from its own state, and every value that reaches this
    // receiver was minted by the caller or by the caller's own authorization
    // server.
    properties.push(PropertyResult {
        property: "admission binding",
        statement: "if the receiver dispatches, every binding field of the presented evidence equals the value the receiver computed for this request from its own state, and the continuation it names was unconsumed",
        composed: if any_dispatched(results, ADMISSION_BINDING_WITNESSES, false)? {
            Verdict::Fails
        } else {
            Verdict::HoldsWeakened
        },
        hardened: if any_dispatched(results, ADMISSION_BINDING_WITNESSES, true)? {
            Verdict::Fails
        } else {
            Verdict::HoldsWeakened
        },
        step: "no step. The fields the composed receiver does check resolve identifiers in its own tables (steps 20, 26 and 30), compare a claim against the channel or against another claim (steps 16 to 19), or compare a claim against a clock (step 14); the one comparison against a receiver-held record is step 24, and the value it compares was chosen by the caller",
        weakened_to: Some("the call is bound to a workload the receiver's trust bundle names, to a credential issued for this receiver by an issuer it pinned, and to an agreement identifier and an approval identifier that resolve in the receiver's own tables; nothing binds it to the state of those records at the moment the authority was granted, and nothing binds the credential to the call it arrived with"),
        witnesses: ADMISSION_BINDING_WITNESSES.to_vec(),
        note: "This is the one property the composition cannot reach by hardening, and the reason is structural. Eight of the fifteen binding fields have no field anywhere in the set, so for those facts there is nothing to compare. For the two that come closest, the hardened wiring does write the comparison: it refuses a retired agreement, and it refuses a credential whose scope asserts a version other than the one the receiver holds. Both comparisons are against values the caller's own authorization server minted, so an adversary asserts the version the receiver holds and passes, which is the case that dispatches under both wirings. The carrier ledger drives the same move once more with the operator's own invented field, and it ends the same way.",
    });

    // Receiver locality.
    properties.push(PropertyResult {
        property: "receiver locality",
        statement: "the roots, pins, agreements, tables and registries used to decide a request are a function of the receiver's state before the request arrived, and are independent of the request's content",
        composed: if any_dispatched(results, RECEIVER_LOCALITY_WITNESSES, false)? {
            Verdict::Fails
        } else {
            Verdict::Holds
        },
        hardened: if any_dispatched(results, RECEIVER_LOCALITY_WITNESSES, true)? {
            Verdict::Fails
        } else {
            Verdict::Holds
        },
        step: "step 25, where the policy context is assembled",
        weakened_to: None,
        witnesses: RECEIVER_LOCALITY_WITNESSES.to_vec(),
        note: "The composed wiring fails this and it is not a defect in any part. A message carries a metadata map for additional context, and handing the incoming request to the policy engine as its evaluation context is the documented way to call a policy decision point. The hardened wiring refuses any supplied attribute whose name the receiver owns, in every slot the formats leave open, which is a name denylist of exactly the kind Chio uses, and it then holds. The same parts yield either outcome and nothing in the composition records which one an operator deployed.",
    });

    // Single use. Evaluated per wiring, because the two wirings key their
    // replay tables by different values.
    let message_replay_composed = require(results, "message-id-replay", false)?;
    let message_replay_hardened = require(results, "message-id-replay", true)?;
    let token_replay_composed = require(results, "token-replay-under-fresh-message-id", false)?;
    let token_replay_hardened = require(results, "token-replay-under-fresh-message-id", true)?;
    let single_use = |identifier_replayed: bool, credential_replayed: bool| {
        if !credential_replayed && !identifier_replayed {
            Verdict::Holds
        } else if !identifier_replayed {
            Verdict::HoldsWeakened
        } else {
            Verdict::Fails
        }
    };
    properties.push(PropertyResult {
        property: "single use",
        statement: "for a continuation identifier c, at most one admission ever reaches dispatch with c bound to it",
        composed: single_use(message_replay_composed, token_replay_composed),
        hardened: single_use(message_replay_hardened, token_replay_hardened),
        step: "step 6 under both wirings, and step 11 under the hardened wiring: single-row inserts on a primary key",
        weakened_to: Some("under the composed wiring, at most one dispatch per message identifier, where the identifier is created by the caller, and the credential itself is reusable until it expires"),
        note: "The mechanism is identical to Chio's under either wiring, and what separates them is whose value it is keyed by. The composed table is keyed by an identifier the message creator chose, so the caller picks a new one and presents the same credential again. The hardened wiring claims a second row on the token identifier, and the credential is then single-use as stated. What no wiring reaches is receiver-side minting: the identifiers made single-use are the caller's and the issuer's. The composition does carry two identifiers the receiver minted, a task and an MCP request state, and the task-handle case shows what they bound, which was nothing.",
        witnesses: vec!["message-id-replay", "token-replay-under-fresh-message-id"],
    });

    // Audience binding.
    let cross_receiver_composed = require(results, "cross-receiver-presentation", false)?;
    let cross_receiver_hardened = require(results, "cross-receiver-presentation", true)?;
    properties.push(PropertyResult {
        property: "audience binding",
        statement: "a statement accepted by receiver R is not accepted by a different receiver R' unless R' separately pinned the same two keys, activated the same agreement, and holds the same receipt",
        composed: if cross_receiver_composed {
            Verdict::Fails
        } else {
            Verdict::Holds
        },
        hardened: if cross_receiver_hardened {
            Verdict::Fails
        } else {
            Verdict::Holds
        },
        step: "step 16 under both wirings, and step 21 as well",
        weakened_to: None,
        witnesses: vec!["cross-receiver-presentation"],
        note: "The composition holds this outright and it is not a differentiator, which is worth saying in the composition's favour: the audience of a credential is required rather than optional in this set, since a workload identity token without an audience is rejected and a protected resource must establish that a token was issued for it. A second route closes it again, because resolving an agreement means reading a participant list. The driven case is a second receiver holding the same trust bundle and the same agreement record, so it satisfies two of the statement's three conjuncts by construction and the composition has no receipt, which is the third.",
    });

    Ok(properties)
}
