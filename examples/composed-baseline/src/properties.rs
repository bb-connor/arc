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

    // Admission binding. The property has a conjunct the composition cannot
    // satisfy under any wiring: the evidence must name a single-use object the
    // receiver minted, and the composed decision names none. The witness that
    // dispatches under both profiles is the authorization presented a second
    // time under a fresh identifier. Two further witnesses separate the
    // wirings on the receiver-state half of the property.
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
        composed: if replay_composed || wrong_agreement_composed || superseded_composed {
            Verdict::Fails
        } else {
            Verdict::HoldsWeakened
        },
        hardened: if replay_hardened || wrong_agreement_hardened {
            Verdict::Fails
        } else {
            Verdict::HoldsWeakened
        },
        step: "no step. The fields the composed receiver does check resolve identifiers in its own tables (steps 1, 15 and 23) or recompute a digest from the request (step 14); none is a comparison against a value the receiver computed for this call before it arrived, and no step resolves a single-use object the receiver minted for it",
        weakened_to: Some("the request is bound to its own arguments, to a caller the receiver pinned, to an agreement identifier and an approval identifier that resolve in the receiver's own tables; nothing binds it to the authorization under which it was issued, and nothing makes that authorization single-use"),
        witnesses: vec![
            "authorization-replay-under-fresh-identifier",
            "wrong-live-agreement",
            "superseded-agreement",
            "signer-minted-decade-window",
        ],
        note: "This is the property the composition cannot reach by hardening, and the reason is structural rather than a missing check: ten of the sixteen substitution rows have no carrier in the composed request at all, so for those facts there is nothing to compare. The hardened profile does deny the wrong-live-agreement case, but incidentally, because the approval record it resolves names the other agreement; move the approval and the denial goes away.",
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
        step: "step 19, where the policy context is assembled",
        weakened_to: None,
        witnesses: vec!["request-supplied-assurance-attribute", "request-supplied-approval-object"],
        note: "This is the sharpest result of the comparison and it is not a defect in any component. Handing the incoming request to the policy engine as its evaluation context is the documented way to call a policy decision point, and it is what makes the decision a function of the request. The hardened profile refuses any context attribute whose name the receiver owns, which is a name denylist of exactly the kind Chio uses, and it then holds. The same three components yield either outcome and nothing in the composition records which one an operator deployed.",
    });

    // Single use.
    let request_id_replay_composed = require(results, "request-id-replay", false)?;
    let request_id_replay_hardened = require(results, "request-id-replay", true)?;
    let authorization_replay_composed = require(
        results,
        "authorization-replay-under-fresh-identifier",
        false,
    )?;
    let authorization_replay_hardened =
        require(results, "authorization-replay-under-fresh-identifier", true)?;
    let identifier_single_use = !request_id_replay_composed && !request_id_replay_hardened;
    let authorization_single_use = !authorization_replay_composed && !authorization_replay_hardened;
    properties.push(PropertyResult {
        property: "single use",
        statement: "for a continuation identifier c, at most one admission ever reaches dispatch with c bound to it",
        composed: if authorization_single_use {
            Verdict::Holds
        } else if identifier_single_use {
            Verdict::HoldsWeakened
        } else {
            Verdict::Fails
        },
        hardened: if authorization_single_use {
            Verdict::Holds
        } else if identifier_single_use {
            Verdict::HoldsWeakened
        } else {
            Verdict::Fails
        },
        step: "step 4, the replay table's single-row insert on a primary key",
        weakened_to: Some("at most one dispatch per request identifier, where the identifier is chosen by the caller; the authorization itself is reusable until it expires"),
        note: "The mechanism is identical to Chio's and the difference is whose value it is keyed by. Chio's continuation is minted by the receiver before the request and named by the statement, so the second presentation resolves a row already consumed. The composed table is keyed by a value the caller chooses, so the caller picks a new one. Both profiles behave the same way here, because the difference is in the protocol and not in how carefully the parts were wired.",
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
        step: "step 11, which only the hardened profile runs",
        weakened_to: None,
        witnesses: vec!["cross-receiver-presentation"],
        note: "A tool call has no audience field, so the composed wiring has nothing to check and a second receiver that pinned the same counterparty and provisioned the same agreement identifier admits the same call. Adding an audience to the signed decision closes it, and is the cheapest of the four repairs. Note that the composed receiver never asks whether it is itself a party to the agreement it resolved; checking the participant list would close the same hole.",
    });

    Ok(properties)
}
