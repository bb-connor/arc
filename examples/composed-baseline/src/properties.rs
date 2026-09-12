//! The four properties, evaluated against the composed alternative.
//!
//! A property's verdict is derived from cases the run actually drove, not
//! asserted. `holds` is true only when every case the property rests on denied
//! (or admitted, for the null case) under that profile.

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

pub fn evaluate(results: &[NegativeResult]) -> Result<Vec<PropertyResult>, String> {
    let mut properties = Vec::new();

    // Admission binding. The property has a conjunct no wiring of these parts
    // can satisfy: the presented evidence must equal what the receiver computed
    // for this request from its own state, and for most of the facts at stake
    // the composed request carries nothing to compare. The witness that
    // dispatches under both wirings is the agreement version, which the request
    // has no field for. The other three witnesses separate the wirings.
    let version_composed = require(results, "agreement-version-advanced-in-flight", false)?;
    let version_hardened = require(results, "agreement-version-advanced-in-flight", true)?;
    let replay_composed = require(
        results,
        "authorization-replay-under-fresh-identifier",
        false,
    )?;
    let replay_hardened = require(results, "authorization-replay-under-fresh-identifier", true)?;
    let wrong_agreement_composed = require(results, "wrong-live-agreement", false)?;
    let wrong_agreement_hardened = require(results, "wrong-live-agreement", true)?;
    let superseded_composed = require(results, "superseded-agreement", false)?;
    properties.push(PropertyResult {
        property: "admission binding",
        statement: "if the receiver dispatches, every binding field of the presented evidence equals the value the receiver computed for this request from its own state, and the continuation it names was unconsumed",
        composed: if version_composed
            || replay_composed
            || wrong_agreement_composed
            || superseded_composed
        {
            Verdict::Fails
        } else {
            Verdict::HoldsWeakened
        },
        hardened: if version_hardened || replay_hardened || wrong_agreement_hardened {
            Verdict::Fails
        } else {
            Verdict::HoldsWeakened
        },
        step: "no step. The fields the composed receiver does check resolve identifiers in its own tables (steps 1, 16 and 24) or recompute a digest from the request (step 15); none is a comparison against a value the receiver computed for this call before it arrived",
        weakened_to: Some("the request is bound to its own arguments, to a caller the receiver pinned, to an agreement identifier and an approval identifier that resolve in the receiver's own tables; nothing binds it to the state of the records it resolved against at the moment the authorization was issued"),
        witnesses: vec![
            "agreement-version-advanced-in-flight",
            "authorization-replay-under-fresh-identifier",
            "wrong-live-agreement",
            "superseded-agreement",
        ],
        note: "This is the one property the composition cannot reach by hardening, and the reason is structural rather than a missing check: ten of the sixteen substitution rows, covering nine of the fifteen binding fields, have no carrier in the composed request at all, so for those facts there is nothing to compare. The witness that stands under both wirings is the agreement version: the receiver holds one, the request pins none, and no operator check can compare a value the request does not carry. The hardened wiring does close the other three witnesses, one of them incidentally: it denies the wrong-live-agreement case because the approval record it resolves names the other agreement, and moving the approval would remove that denial.",
    });

    // Receiver locality.
    let smuggled_attribute_composed =
        require(results, "request-supplied-assurance-attribute", false)?;
    let smuggled_attribute_hardened =
        require(results, "request-supplied-assurance-attribute", true)?;
    let smuggled_approval_composed = require(results, "request-supplied-approval-object", false)?;
    let smuggled_approval_hardened = require(results, "request-supplied-approval-object", true)?;
    properties.push(PropertyResult {
        property: "receiver locality",
        statement: "the roots, pins, agreements, tables and registries used to decide a request are a function of the receiver's state before the request arrived, and are independent of the request's content",
        composed: if smuggled_attribute_composed || smuggled_approval_composed {
            Verdict::Fails
        } else {
            Verdict::Holds
        },
        hardened: if smuggled_attribute_hardened || smuggled_approval_hardened {
            Verdict::Fails
        } else {
            Verdict::Holds
        },
        step: "step 20, where the policy context is assembled",
        weakened_to: None,
        witnesses: vec!["request-supplied-assurance-attribute", "request-supplied-approval-object"],
        note: "The composed wiring fails this and it is not a defect in any component. Handing the incoming request to the policy engine as its evaluation context is the documented way to call a policy decision point, and it is what makes the decision a function of the request. The hardened wiring refuses any context attribute whose name the receiver owns, which is a name denylist of exactly the kind Chio uses, and it then holds. The same three components yield either outcome and nothing in the composition records which one an operator deployed.",
    });

    // Single use. Evaluated per wiring, because the two wirings key their
    // replay tables by different values.
    let request_id_replay_composed = require(results, "request-id-replay", false)?;
    let request_id_replay_hardened = require(results, "request-id-replay", true)?;
    let authorization_replay_composed = require(
        results,
        "authorization-replay-under-fresh-identifier",
        false,
    )?;
    let authorization_replay_hardened =
        require(results, "authorization-replay-under-fresh-identifier", true)?;
    let single_use = |identifier_replayed: bool, authorization_replayed: bool| {
        if !authorization_replayed && !identifier_replayed {
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
        composed: single_use(request_id_replay_composed, authorization_replay_composed),
        hardened: single_use(request_id_replay_hardened, authorization_replay_hardened),
        step: "step 4 under both wirings, and step 7 under the hardened wiring: single-row inserts on a primary key",
        weakened_to: Some("under the composed wiring, at most one dispatch per request identifier, where the identifier is chosen by the caller, and the authorization itself is reusable until it expires"),
        note: "The mechanism is identical to Chio's under either wiring, and what separates them is whose value it is keyed by. The composed table is keyed by a value the caller chooses outside the signed bytes, so the caller picks a new one and presents the same authorization again. The hardened wiring claims a second row on the identifier inside the signed bytes, and the authorization is then single-use as stated. What no wiring of these parts reaches is receiver-side minting: the identifier that is made single-use is one the signer chose, so the signer decides how many authorizations exist, where a Chio continuation is minted by the receiver before the request and named by the statement.",
        witnesses: vec!["request-id-replay", "authorization-replay-under-fresh-identifier"],
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
        step: "step 17 under both wirings, and step 12 as well under the hardened wiring",
        weakened_to: None,
        witnesses: vec!["cross-receiver-presentation"],
        note: "The composition holds this outright and it is not a differentiator. A receiver that resolves the agreement the decision names is reading a participant list, and a receiver absent from that list is not a party to what it just resolved; the hardened wiring closes the same hole a second time with an audience field. The driven case is a second receiver holding the same pins and the same agreement record, so it satisfies two of the statement's three conjuncts by construction and the composition has no receipt, which is the third. What it establishes is narrower than the statement and is the operational fact: the same bytes are not accepted unchanged at a second receiver.",
    });

    Ok(properties)
}
