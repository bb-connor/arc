//! The substitution corpus, asked of the composed alternative.
//!
//! For each of the fifteen fields of the Chio treaty binding reference, the
//! question is: what does the composed request carry for that fact, and if an
//! adversary substitutes it and re-signs every signature so the envelope stays
//! valid over the substituted bytes, does the receiver notice?
//!
//! The answers fall into five kinds, and the kind matters more than the count.
//! A field noticed by resolution fails a lookup in a table the receiver owned
//! before the request arrived, which is the same mechanism Chio uses. A field
//! noticed by recomputation is recomputed from the request and compared, which
//! binds the request to itself. A field noticed only by internal consistency is
//! compared against another field of the same request, so a consistent
//! substitution of both defeats it, and each such row is driven twice to show
//! whether anything is left when the adversary is consistent. A field that is
//! carried but never compared is the composition's counterpart of Chio's
//! admission report digest. A field that is not carried cannot be substituted
//! at all, and the substitution corpus has nothing to report about it, which is
//! the result.

use crate::harness::{Runner, StateVariant};
use crate::negative::ObservedJson;
use crate::scenario::{self, SealInputs};
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeBasis {
    /// The substituted value fails a lookup in a receiver-owned table.
    Resolution,
    /// The receiver recomputes the value from the request and compares.
    Recomputation,
    /// The substituted value is compared against another field of the same
    /// request, so a consistent substitution of both is what decides.
    InternalConsistency,
    /// The composed request carries the value and nothing compares it.
    CarriedNeverCompared,
    /// The composed request has no field for this fact.
    NotCarried,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubstitutionResult {
    pub chio_field: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_carrier: Option<&'static str>,
    pub basis: NoticeBasis,
    pub noticed_composed: bool,
    pub noticed_hardened: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub composed: Option<ObservedJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardened: Option<ObservedJson>,
    /// For an internal-consistency row, what happens when the adversary
    /// substitutes every field the comparison spans.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consistent_composed: Option<ObservedJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consistent_hardened: Option<ObservedJson>,
    pub note: &'static str,
}

type Drive = fn(&Runner<'_>, &str) -> Result<ObservedJson, String>;

struct Row {
    chio_field: &'static str,
    baseline_carrier: Option<&'static str>,
    basis: NoticeBasis,
    note: &'static str,
    drive: Option<Drive>,
    consistent: Option<Drive>,
}

fn sub_agreement_id(runner: &Runner<'_>, id: &str) -> Result<ObservedJson, String> {
    let args = scenario::refund_args();
    let mut decision = scenario::base_decision(id, &args)?;
    decision.agreement_id = "treaty-buyer-vendor-substituted".to_string();
    let envelope = scenario::seal(SealInputs {
        request_id: id,
        caller: scenario::BUYER,
        tool_name: scenario::ACTION,
        tool_args: args,
        context: BTreeMap::new(),
        decision,
        raw_authorization: None,
        policy_signer: &runner.keys.buyer_policy,
        channel_signer: Some(&runner.keys.buyer_channel),
    })?;
    Ok(ObservedJson::from(runner.drive_one(
        StateVariant::Default,
        &envelope,
        scenario::NOW_MS,
    )?))
}

fn sub_request_id(runner: &Runner<'_>, id: &str) -> Result<ObservedJson, String> {
    // The caller picks a different identifier. Nothing else changes, and every
    // signature is remade over the substituted bytes.
    let substituted = format!("{id}-substituted");
    let envelope = scenario::admissible(runner.keys, substituted.as_str())?;
    Ok(ObservedJson::from(runner.drive_one(
        StateVariant::Default,
        &envelope,
        scenario::NOW_MS,
    )?))
}

fn sub_action_one_field(runner: &Runner<'_>, id: &str) -> Result<ObservedJson, String> {
    let args = scenario::refund_args();
    let mut decision = scenario::base_decision(id, &args)?;
    decision.action = "refund.issue.unbounded".to_string();
    // The request still asks for the honest tool, so only the decision moved.
    let envelope = scenario::seal(SealInputs {
        request_id: id,
        caller: scenario::BUYER,
        tool_name: scenario::ACTION,
        tool_args: args,
        context: BTreeMap::new(),
        decision,
        raw_authorization: None,
        policy_signer: &runner.keys.buyer_policy,
        channel_signer: Some(&runner.keys.buyer_channel),
    })?;
    Ok(ObservedJson::from(runner.drive_one(
        StateVariant::Default,
        &envelope,
        scenario::NOW_MS,
    )?))
}

fn sub_action_consistent(runner: &Runner<'_>, id: &str) -> Result<ObservedJson, String> {
    let args = scenario::refund_args();
    let mut decision = scenario::base_decision(id, &args)?;
    decision.action = "refund.issue.unbounded".to_string();
    let envelope = scenario::seal(SealInputs {
        request_id: id,
        caller: scenario::BUYER,
        tool_name: "refund.issue.unbounded",
        tool_args: args,
        context: BTreeMap::new(),
        decision,
        raw_authorization: None,
        policy_signer: &runner.keys.buyer_policy,
        channel_signer: Some(&runner.keys.buyer_channel),
    })?;
    Ok(ObservedJson::from(runner.drive_one(
        StateVariant::Default,
        &envelope,
        scenario::NOW_MS,
    )?))
}

fn sub_args_digest(runner: &Runner<'_>, id: &str) -> Result<ObservedJson, String> {
    let signed_args = scenario::refund_args();
    let decision = scenario::base_decision(id, &signed_args)?;
    let mut sent = signed_args;
    sent["amount_minor"] = json!(9900u64);
    let envelope = scenario::seal(SealInputs {
        request_id: id,
        caller: scenario::BUYER,
        tool_name: scenario::ACTION,
        tool_args: sent,
        context: BTreeMap::new(),
        decision,
        raw_authorization: None,
        policy_signer: &runner.keys.buyer_policy,
        channel_signer: Some(&runner.keys.buyer_channel),
    })?;
    Ok(ObservedJson::from(runner.drive_one(
        StateVariant::Default,
        &envelope,
        scenario::NOW_MS,
    )?))
}

fn sub_approval_ref(runner: &Runner<'_>, id: &str) -> Result<ObservedJson, String> {
    let mut args = scenario::refund_args();
    args["approval_id"] = json!("approval-refund-substituted");
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
        channel_signer: Some(&runner.keys.buyer_channel),
    })?;
    Ok(ObservedJson::from(runner.drive_one(
        StateVariant::Default,
        &envelope,
        scenario::NOW_MS,
    )?))
}

fn sub_principal_one_field(runner: &Runner<'_>, id: &str) -> Result<ObservedJson, String> {
    let args = scenario::refund_args();
    let mut decision = scenario::base_decision(id, &args)?;
    decision.principal = "spiffe://buyer.example/kernel-substituted".to_string();
    let envelope = scenario::seal(SealInputs {
        request_id: id,
        caller: scenario::BUYER,
        tool_name: scenario::ACTION,
        tool_args: args,
        context: BTreeMap::new(),
        decision,
        raw_authorization: None,
        policy_signer: &runner.keys.buyer_policy,
        channel_signer: Some(&runner.keys.buyer_channel),
    })?;
    Ok(ObservedJson::from(runner.drive_one(
        StateVariant::Default,
        &envelope,
        scenario::NOW_MS,
    )?))
}

fn sub_principal_consistent(runner: &Runner<'_>, id: &str) -> Result<ObservedJson, String> {
    let substituted = "spiffe://buyer.example/kernel-substituted";
    let args = scenario::refund_args();
    let mut decision = scenario::base_decision(id, &args)?;
    decision.principal = substituted.to_string();
    let envelope = scenario::seal(SealInputs {
        request_id: id,
        caller: substituted,
        tool_name: scenario::ACTION,
        tool_args: args,
        context: BTreeMap::new(),
        decision,
        raw_authorization: None,
        policy_signer: &runner.keys.buyer_policy,
        channel_signer: Some(&runner.keys.buyer_channel),
    })?;
    Ok(ObservedJson::from(runner.drive_one(
        StateVariant::Default,
        &envelope,
        scenario::NOW_MS,
    )?))
}

#[allow(clippy::too_many_lines)]
fn rows() -> Vec<Row> {
    vec![
        Row {
            chio_field: "treaty_id",
            baseline_carrier: Some("policy_decision.agreement_id"),
            basis: NoticeBasis::Resolution,
            note: "The one field the composition already resolves against receiver-held state. A substituted identifier the receiver never provisioned denies; a substituted identifier that names a different live agreement with the same counterparty does not, which is the wrong-live-agreement case of the negative corpus.",
            drive: Some(sub_agreement_id),
            consistent: None,
        },
        Row {
            chio_field: "treaty_scope_sha256",
            baseline_carrier: None,
            basis: NoticeBasis::NotCarried,
            note: "The receiver holds an agreement record with a scope. The composed request pins no digest of it, so a sender and a receiver disagreeing about the content of the agreement they are operating under produces no observable event.",
            drive: None,
            consistent: None,
        },
        Row {
            chio_field: "ladder_intersection_sha256",
            baseline_carrier: None,
            basis: NoticeBasis::NotCarried,
            note: "No object stands for the bound two organizations jointly accept, so there is no digest to substitute.",
            drive: None,
            consistent: None,
        },
        Row {
            chio_field: "admission_report_sha256",
            baseline_carrier: None,
            basis: NoticeBasis::NotCarried,
            note: "The one row where the two systems agree in outcome and differ in why. Chio carries this field and never compares it. The composition does not carry it at all. Neither notices a substitution, and in neither case does anything rest on it.",
            drive: None,
            consistent: None,
        },
        Row {
            chio_field: "continuation_sha256",
            baseline_carrier: Some("request.request_id"),
            basis: NoticeBasis::CarriedNeverCompared,
            note: "The nearest carrier is the replay table's key, and it is tested for absence, never for equality with anything the receiver minted. Substituting it yields an identifier the table has not seen, so the substituted call is admitted and dispatches. The replay table makes an identifier single-use; it does not make an authorization single-use.",
            drive: Some(sub_request_id),
            consistent: None,
        },
        Row {
            chio_field: "lineage_bundle_sha256",
            baseline_carrier: None,
            basis: NoticeBasis::NotCarried,
            note: "The composition has no record of the chain of prior calls this one continues, so there is no bundle digest to substitute.",
            drive: None,
            consistent: None,
        },
        Row {
            chio_field: "action_class_id",
            baseline_carrier: Some("policy_decision.action against request.tool_name"),
            basis: NoticeBasis::InternalConsistency,
            note: "Substituting the decision's action alone is caught, but the comparison is between two fields the sender supplied. The consistent substitution, which moves both, is then decided by the receiver's own agreement record and rule table, so the composition does hold this field, by resolution rather than by the consistency check that fires first.",
            drive: Some(sub_action_one_field),
            consistent: Some(sub_action_consistent),
        },
        Row {
            chio_field: "consistency_model",
            baseline_carrier: None,
            basis: NoticeBasis::NotCarried,
            note: "The composition names no consistency model for cross-organization state, so there is nothing to substitute.",
            drive: None,
            consistent: None,
        },
        Row {
            chio_field: "request_sha256",
            baseline_carrier: Some("policy_decision.tool_args_sha256"),
            basis: NoticeBasis::Recomputation,
            note: "The receiver canonicalizes the arguments it received and compares. This binds the decision to the arguments and holds in both profiles. It is the composition's strongest binding and the only one that does not depend on an operator writing a rule.",
            drive: Some(sub_args_digest),
            consistent: None,
        },
        Row {
            chio_field: "outcome_sha256",
            baseline_carrier: None,
            basis: NoticeBasis::NotCarried,
            note: "A policy decision describes an intended action and carries nothing about what a prior call returned.",
            drive: None,
            consistent: None,
        },
        Row {
            chio_field: "local_receipt_sha256",
            baseline_carrier: None,
            basis: NoticeBasis::NotCarried,
            note: "The composition's audit record is written after the decision and is never named by a later request, so no receipt digest crosses the boundary and none can be substituted.",
            drive: None,
            consistent: None,
        },
        Row {
            chio_field: "remote_receipt_sha256",
            baseline_carrier: None,
            basis: NoticeBasis::NotCarried,
            note: "The counterparty's audit record is not visible to the receiver at all, so there is nothing for the request to point at.",
            drive: None,
            consistent: None,
        },
        Row {
            chio_field: "lease_refs",
            baseline_carrier: None,
            basis: NoticeBasis::NotCarried,
            note: "The validity window is a pair of timestamps the signer chose, not a reference the receiver resolves. There is no lease identifier to substitute, and correspondingly no receiver-side bound on the window: see the decade-window case of the negative corpus.",
            drive: None,
            consistent: None,
        },
        Row {
            chio_field: "governance_refs",
            baseline_carrier: Some("tool_args.approval_id"),
            basis: NoticeBasis::Resolution,
            note: "Held, on the condition that an operator wrote the rule requiring the approval. The composition supplies the place to write that rule and does not require it, and the composed profile is additionally satisfied by an approval the request presents rather than one it names.",
            drive: Some(sub_approval_ref),
            consistent: None,
        },
        Row {
            chio_field: "signer_kernel_ids, as a set",
            baseline_carrier: Some("policy_decision.principal against request.caller"),
            basis: NoticeBasis::InternalConsistency,
            note: "Substituting the decision's principal alone is caught by the consistency check. The consistent substitution, which moves the caller too, is caught by the pin table, so the composition holds this field by resolution. Channel authentication is the part of the composition that works.",
            drive: Some(sub_principal_one_field),
            consistent: Some(sub_principal_consistent),
        },
        Row {
            chio_field: "signer_kernel_ids, in order",
            baseline_carrier: None,
            basis: NoticeBasis::NotCarried,
            note: "One signature per role and no ordered signer list, so there is no order to reverse.",
            drive: None,
            consistent: None,
        },
    ]
}

pub fn run(
    composed: &Runner<'_>,
    hardened: &Runner<'_>,
) -> Result<Vec<SubstitutionResult>, String> {
    let mut results = Vec::new();
    for (index, row) in rows().into_iter().enumerate() {
        let base = format!("subst-{index}");
        let (composed_observed, hardened_observed) = match row.drive {
            Some(drive) => (
                Some(drive(composed, format!("{base}-c").as_str())?),
                Some(drive(hardened, format!("{base}-h").as_str())?),
            ),
            None => (None, None),
        };
        let (consistent_composed, consistent_hardened) = match row.consistent {
            Some(drive) => (
                Some(drive(composed, format!("{base}-cc").as_str())?),
                Some(drive(hardened, format!("{base}-ch").as_str())?),
            ),
            None => (None, None),
        };
        // A row is noticed when the profile that ran it denied, and for a row
        // with a consistent variant, when the consistent variant also denied.
        let noticed = |single: &Option<ObservedJson>, both: &Option<ObservedJson>| -> bool {
            match (single, both) {
                (Some(single), Some(both)) => !single.admitted && !both.admitted,
                (Some(single), None) => !single.admitted,
                _ => false,
            }
        };
        results.push(SubstitutionResult {
            chio_field: row.chio_field,
            baseline_carrier: row.baseline_carrier,
            basis: row.basis,
            noticed_composed: noticed(&composed_observed, &consistent_composed),
            noticed_hardened: noticed(&hardened_observed, &consistent_hardened),
            composed: composed_observed,
            hardened: hardened_observed,
            consistent_composed,
            consistent_hardened,
            note: row.note,
        });
    }
    Ok(results)
}
