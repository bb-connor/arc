//! The substitution corpus, asked of the composed alternative.
//!
//! For each of the fifteen fields of the Chio treaty binding reference, the
//! question is: what does the composed request carry for that fact, and if an
//! adversary substitutes it and re-signs everything so the call stays valid
//! over the substituted bytes, does the receiver notice?
//!
//! The answers fall into five kinds, and the kind matters more than the count.
//! A field noticed by resolution fails a lookup in a table the receiver owned
//! before the call arrived. A field noticed by recomputation is recomputed from
//! the call and compared, which binds the call to itself. A field noticed only
//! by internal consistency is compared against another part of the same call,
//! so a substitution that moves both is what decides, and such a row is driven
//! twice. A field carried without a receiver-held reference is one the formats
//! do transmit and nothing resolves. A field with no carrier cannot be
//! substituted at all, and the corpus has nothing to report about it, which is
//! the result.
//!
//! A row is noticed only when every substitution driven for it denied. A field
//! with no carrier is never noticed, and the run refuses to report one that is.

use crate::harness::{Runner, StateVariant};
use crate::negative::ObservedJson;
use crate::request::SCOPE_ACTION_PREFIX;
use crate::scenario::{self, CallBuilder};
use serde::Serialize;
use serde_json::json;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeBasis {
    /// The substituted value fails a lookup in a receiver-owned table.
    Resolution,
    /// The receiver recomputes the value from the call and compares.
    Recomputation,
    /// The substituted value is compared against another part of the same call,
    /// so a substitution that moves both is what decides.
    InternalConsistency,
    /// A format in the set transmits the value and nothing the receiver holds
    /// is compared against it.
    CarriedWithoutReceiverReference,
    /// No format in the set has a field for this fact.
    NotCarried,
}

/// Where a fact travels, when it travels at all.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Carrier {
    /// Identifier of the document, as `spec::DOCUMENTS` lists it.
    pub document: &'static str,
    /// The field, claim or value, named as that document names it.
    pub field: &'static str,
    pub section: &'static str,
    /// Whose signature covers the bytes this field sits in.
    pub attested_by: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct VariantResult {
    /// What this substitution moved.
    pub label: &'static str,
    pub composed: ObservedJson,
    pub hardened: ObservedJson,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubstitutionResult {
    pub chio_field: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub carrier: Option<Carrier>,
    pub basis: NoticeBasis,
    pub noticed_composed: bool,
    pub noticed_hardened: bool,
    pub variants: Vec<VariantResult>,
    pub note: &'static str,
}

type Drive = fn(&Runner<'_>, &str) -> Result<ObservedJson, String>;

struct Variant {
    label: &'static str,
    drive: Drive,
}

struct Row {
    chio_field: &'static str,
    carrier: Option<Carrier>,
    basis: NoticeBasis,
    note: &'static str,
    variants: &'static [Variant],
}

fn observe(
    runner: &Runner<'_>,
    envelope: &crate::request::ComposedEnvelope,
) -> Result<ObservedJson, String> {
    Ok(ObservedJson::from(runner.drive_one(
        StateVariant::Default,
        envelope,
        scenario::NOW_MS,
    )?))
}

fn sub_agreement_unprovisioned(runner: &Runner<'_>, id: &str) -> Result<ObservedJson, String> {
    let mut call = CallBuilder::new(runner.keys, id);
    call.claims.scope = scenario::refund_scope("treaty-buyer-vendor-substituted", 1);
    observe(runner, &call.build()?)
}

fn sub_agreement_other_live(runner: &Runner<'_>, id: &str) -> Result<ObservedJson, String> {
    let mut call = CallBuilder::new(runner.keys, id);
    call.claims.scope = scenario::refund_scope(scenario::AGREEMENT_PILOT, 1);
    observe(runner, &call.build()?)
}

fn sub_task_other_held(runner: &Runner<'_>, id: &str) -> Result<ObservedJson, String> {
    let mut call = CallBuilder::new(runner.keys, id);
    call.task_id = scenario::OTHER_TASK.to_string();
    observe(runner, &call.build()?)
}

fn sub_reference_other_held(runner: &Runner<'_>, id: &str) -> Result<ObservedJson, String> {
    let mut call = CallBuilder::new(runner.keys, id);
    call.reference_task_ids = vec![scenario::TASK.to_string()];
    observe(runner, &call.build()?)
}

fn sub_reference_unissued(runner: &Runner<'_>, id: &str) -> Result<ObservedJson, String> {
    let mut call = CallBuilder::new(runner.keys, id);
    call.reference_task_ids = vec!["task-refund-9999".to_string()];
    observe(runner, &call.build()?)
}

fn sub_action_scope_only(runner: &Runner<'_>, id: &str) -> Result<ObservedJson, String> {
    let mut call = CallBuilder::new(runner.keys, id);
    call.claims.scope = call.claims.scope.replace(
        format!("{SCOPE_ACTION_PREFIX}{}", scenario::ACTION).as_str(),
        format!("{SCOPE_ACTION_PREFIX}refund.issue.unbounded").as_str(),
    );
    observe(runner, &call.build()?)
}

fn sub_action_both(runner: &Runner<'_>, id: &str) -> Result<ObservedJson, String> {
    let mut call = CallBuilder::new(runner.keys, id);
    call.claims.scope = call.claims.scope.replace(
        format!("{SCOPE_ACTION_PREFIX}{}", scenario::ACTION).as_str(),
        format!("{SCOPE_ACTION_PREFIX}refund.issue.unbounded").as_str(),
    );
    call.tool_name = "refund.issue.unbounded".to_string();
    observe(runner, &call.build()?)
}

fn sub_window_extended(runner: &Runner<'_>, id: &str) -> Result<ObservedJson, String> {
    let mut call = CallBuilder::new(runner.keys, id);
    call.claims.exp = call.claims.iat + 315_360_000;
    observe(runner, &call.build()?)
}

fn sub_approval_reference(runner: &Runner<'_>, id: &str) -> Result<ObservedJson, String> {
    let mut call = CallBuilder::new(runner.keys, id);
    call.arguments["approval_id"] = json!("approval-refund-substituted");
    observe(runner, &call.build()?)
}

fn sub_actor_only(runner: &Runner<'_>, id: &str) -> Result<ObservedJson, String> {
    let mut call = CallBuilder::new(runner.keys, id);
    call.claims.act.sub = "spiffe://buyer.example/agent/other-bot".to_string();
    observe(runner, &call.build()?)
}

fn sub_actor_and_channel(runner: &Runner<'_>, id: &str) -> Result<ObservedJson, String> {
    let substituted = "spiffe://buyer.example/agent/other-bot";
    let mut call = CallBuilder::new(runner.keys, id);
    call.claims.act.sub = substituted.to_string();
    call.peer_spiffe_id = substituted.to_string();
    observe(runner, &call.build()?)
}

fn sub_delegation_order(runner: &Runner<'_>, id: &str) -> Result<ObservedJson, String> {
    // The two identities of the delegation exchanged: the agent becomes the
    // subject the authority belongs to and the kernel becomes the actor.
    let mut call = CallBuilder::new(runner.keys, id);
    call.claims.sub = scenario::BUYER_AGENT.to_string();
    call.claims.act.sub = scenario::BUYER_SUBJECT.to_string();
    observe(runner, &call.build()?)
}

const SCOPE_CARRIER: Carrier = Carrier {
    document: "rfc8693",
    field: "scope",
    section: "4.2, with the syntax of RFC 6749 section 3.3",
    attested_by: "issuing_authorization_server",
};

#[allow(clippy::too_many_lines)]
fn rows() -> Vec<Row> {
    vec![
        Row {
            chio_field: "treaty_id",
            carrier: Some(SCOPE_CARRIER),
            basis: NoticeBasis::Resolution,
            note: "The one fact the composition already resolves against receiver-held state, and the carrier is the only open slot a signature covers: scope values are strings the authorization server defines, so two organizations can agree that one of them names an agreement. An identifier the receiver never provisioned denies. An identifier naming a different agreement it does hold does not, under the composed wiring, because resolving is all the composition does: nothing ties the call to the agreement it was prepared under. The hardened wiring denies that one incidentally, through the approval record it resolves.",
            variants: &[
                Variant { label: "an agreement the receiver never provisioned", drive: sub_agreement_unprovisioned },
                Variant { label: "a different agreement the receiver does hold", drive: sub_agreement_other_live },
            ],
        },
        Row {
            chio_field: "treaty_scope_sha256",
            carrier: None,
            basis: NoticeBasis::NotCarried,
            note: "The receiver holds an agreement record with a scope. No field of any document in the set pins a digest of it, so a caller and a receiver disagreeing about the content of the agreement they are operating under produces no observable event.",
            variants: &[],
        },
        Row {
            chio_field: "ladder_intersection_sha256",
            carrier: None,
            basis: NoticeBasis::NotCarried,
            note: "No object stands for a bound two organizations jointly accept, so there is no digest to substitute.",
            variants: &[],
        },
        Row {
            chio_field: "admission_report_sha256",
            carrier: None,
            basis: NoticeBasis::NotCarried,
            note: "The one row where the two systems agree in outcome and differ in why. Chio carries this field and never compares it. No format in the set carries it at all. Neither notices a substitution, and in neither case does anything rest on it.",
            variants: &[],
        },
        Row {
            chio_field: "continuation_sha256",
            carrier: Some(Carrier {
                document: "a2a",
                field: "Message.task_id, naming a Task.id generated by the server",
                section: "Message, Task",
                attested_by: "caller",
            }),
            basis: NoticeBasis::CarriedWithoutReceiverReference,
            note: "The nearest carrier is real and is worth stating plainly: a task identifier is minted by this receiver and echoed by the caller, which is the shape of a receiver-minted continuation. It is not one. A task accepts many messages, so echoing it consumes nothing; no signature covers it, since it rides in the message body and the credential covers only its own claims; and it exists only after a first call created it, so the first call of any interaction has none. Moving it to another task the receiver also holds is admitted under both wirings.",
            variants: &[
                Variant { label: "a different task the receiver also holds", drive: sub_task_other_held },
            ],
        },
        Row {
            chio_field: "lineage_bundle_sha256",
            carrier: Some(Carrier {
                document: "a2a",
                field: "Message.reference_task_ids",
                section: "Message.reference_task_ids",
                attested_by: "caller",
            }),
            basis: NoticeBasis::CarriedWithoutReceiverReference,
            note: "A message may name the tasks it references, and those identifiers were minted by this receiver, so the hardened wiring refuses a reference to a task it never issued. What it cannot refuse is a reference moved to another task it did issue: the field carries identifiers and no digest of what happened in them, and the specification calls them additional context rather than evidence.",
            variants: &[
                Variant { label: "a reference moved to another task the receiver holds", drive: sub_reference_other_held },
                Variant { label: "a reference to a task the receiver never issued", drive: sub_reference_unissued },
            ],
        },
        Row {
            chio_field: "action_class_id",
            carrier: Some(Carrier {
                document: "mcp",
                field: "params.name, against the action value of scope",
                section: "server/tools, Calling Tools",
                attested_by: "caller",
            }),
            basis: NoticeBasis::InternalConsistency,
            note: "Substituting the scope's action alone is caught, but that comparison is between a claim and a tool name the same party chose. The substitution that moves both is then decided by the receiver's own agreement record and rule table, so the composition does hold this field, by resolution rather than by the consistency check that fires first.",
            variants: &[
                Variant { label: "the action value of scope alone", drive: sub_action_scope_only },
                Variant { label: "the action value and the tool name together", drive: sub_action_both },
            ],
        },
        Row {
            chio_field: "consistency_model",
            carrier: None,
            basis: NoticeBasis::NotCarried,
            note: "Nothing in the set names a consistency model for cross-organization state, so there is nothing to substitute.",
            variants: &[],
        },
        Row {
            chio_field: "request_sha256",
            carrier: None,
            basis: NoticeBasis::NotCarried,
            note: "The digest that would tie the authority to the call it arrived with, and nothing in the set carries it. No claim of a token exchange covers the body of the call, no field of a message or a tool call carries a digest of it, and the exchange request itself has no parameter through which one could reach the issuer. The arguments cross in the clear and nothing anywhere is compared against them.",
            variants: &[],
        },
        Row {
            chio_field: "outcome_sha256",
            carrier: None,
            basis: NoticeBasis::NotCarried,
            note: "A delegated credential describes authority to act and carries nothing about what a prior call returned.",
            variants: &[],
        },
        Row {
            chio_field: "local_receipt_sha256",
            carrier: None,
            basis: NoticeBasis::NotCarried,
            note: "The composition's audit record is written after the decision and is never named by a later call, so no receipt digest crosses the boundary and none can be substituted.",
            variants: &[],
        },
        Row {
            chio_field: "remote_receipt_sha256",
            carrier: None,
            basis: NoticeBasis::NotCarried,
            note: "The counterparty's audit record is not visible to the receiver at all, so there is nothing for the call to point at.",
            variants: &[],
        },
        Row {
            chio_field: "lease_refs",
            carrier: Some(Carrier {
                document: "rfc7519",
                field: "exp and nbf, with expires_in beside them",
                section: "4.1.4, 4.1.5",
                attested_by: "issuing_authorization_server",
            }),
            basis: NoticeBasis::CarriedWithoutReceiverReference,
            note: "The window is carried and is compared, against the receiver's clock. It is not a reference the receiver resolves, so nothing about it is per-counterparty, revocable between calls, or narrowable: the issuer chooses the window and the composed wiring accepts whatever it chose. The hardened wiring refuses an extended one against a constant it holds, which is the same bound for every credential it will ever see.",
            variants: &[
                Variant { label: "the issuer extends the window to a decade", drive: sub_window_extended },
            ],
        },
        Row {
            chio_field: "governance_refs",
            carrier: Some(Carrier {
                document: "mcp",
                field: "params.arguments, shaped by the tool's own inputSchema",
                section: "server/tools, Tool.inputSchema",
                attested_by: "caller",
            }),
            basis: NoticeBasis::Resolution,
            note: "Held, and the carrier is the one open slot whose shape the receiver owns: a tool's input schema is published by the server that runs it, so the receiver can require an approval identifier and resolve it locally. The requirement is still operator-authored, and the composed wiring is additionally satisfied by an approval the message presents rather than one it names.",
            variants: &[
                Variant { label: "an approval identifier the receiver does not hold", drive: sub_approval_reference },
            ],
        },
        Row {
            chio_field: "signer_kernel_ids, as a set",
            carrier: Some(Carrier {
                document: "rfc8693",
                field: "act.sub beside sub, over SPIFFE IDs",
                section: "4.1, with SPIFFE-ID and JWT-SVID for the values",
                attested_by: "issuing_authorization_server",
            }),
            basis: NoticeBasis::InternalConsistency,
            note: "Both identities of the delegation are carried, which is what the actor claim is for. Substituting the actor alone passes the composed wiring, because nothing in the exchange binds the credential to the workload presenting it; the hardened wiring adds that comparison, and the substitution that moves the presenting SVID too is then caught by the trust bundle. The standards-track way to get this without an operator writing it is a certificate-bound token, which is a further specification to adopt.",
            variants: &[
                Variant { label: "the actor claim alone", drive: sub_actor_only },
                Variant { label: "the actor claim and the presenting SVID together", drive: sub_actor_and_channel },
            ],
        },
        Row {
            chio_field: "signer_kernel_ids, in order",
            carrier: Some(Carrier {
                document: "rfc8693",
                field: "the nesting of act",
                section: "4.1",
                attested_by: "issuing_authorization_server",
            }),
            basis: NoticeBasis::InternalConsistency,
            note: "Order is carried, and this is the row where the composition does something Chio's envelope does not have to: the actor claim nests, outermost being the current actor, so the delegation chain has a direction. Exchanging the two identities is refused under both wirings, by the participant list under the composed wiring and by the actor comparison under the hardened one.",
            variants: &[
                Variant { label: "the subject and the actor exchanged", drive: sub_delegation_order },
            ],
        },
    ]
}

pub fn run(
    composed: &Runner<'_>,
    hardened: &Runner<'_>,
) -> Result<Vec<SubstitutionResult>, String> {
    let mut results = Vec::new();
    for (index, row) in rows().into_iter().enumerate() {
        let mut variants = Vec::new();
        for (position, variant) in row.variants.iter().enumerate() {
            let base = format!("subst-{index}-{position}");
            variants.push(VariantResult {
                label: variant.label,
                composed: (variant.drive)(composed, format!("{base}-c").as_str())?,
                hardened: (variant.drive)(hardened, format!("{base}-h").as_str())?,
            });
        }
        // A row is noticed only when every substitution driven for it denied,
        // and a row with nothing to substitute is never noticed.
        let noticed_composed =
            !variants.is_empty() && variants.iter().all(|entry| !entry.composed.admitted);
        let noticed_hardened =
            !variants.is_empty() && variants.iter().all(|entry| !entry.hardened.admitted);
        if row.basis == NoticeBasis::NotCarried && (noticed_composed || noticed_hardened) {
            return Err(format!(
                "{} has no carrier and cannot be noticed",
                row.chio_field
            ));
        }
        results.push(SubstitutionResult {
            chio_field: row.chio_field,
            carrier: row.carrier,
            basis: row.basis,
            noticed_composed,
            noticed_hardened,
            variants,
            note: row.note,
        });
    }
    Ok(results)
}
