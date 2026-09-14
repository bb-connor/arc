//! What an operator would have to build to carry a fact the formats do not.
//!
//! The substitution corpus reports which of the facts a Chio receiver binds
//! have a carrier here. This is the other half: for each fact that has none, or
//! whose carrier the receiver cannot resolve, the only slot in the set that
//! could hold it, whose signature covers that slot, and the work an operator
//! would have to do. Nothing here is an argument that the work is impossible.
//! The point is what the work is: fields and parameters that no document
//! defines, agreed bilaterally and implemented in the counterparty's
//! authorization server as well as the receiver.
//!
//! Three witnesses are driven rather than asserted, over the fact the
//! comparison turns on. An operator adds the version of the receiver's
//! agreement record to the one slot that can hold it, and the run records what
//! each step buys: nothing, while the name is one the receiver never agreed to
//! read; a denial, once it does and the caller reports honestly; and an
//! admission again, as soon as the caller asserts the value the receiver holds.

use crate::harness::{Runner, StateVariant};
use crate::negative::ObservedJson;
use crate::receiver::PRIVATE_AGREEMENT_VERSION_KEY;
use crate::scenario::{self, CallBuilder};
use serde::Serialize;
use serde_json::json;

/// Whether the set of formats carries the fact at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CarrierState {
    /// No field of any document in the set holds it.
    Absent,
    /// A field holds it and the receiver has nothing of its own to resolve it
    /// against.
    WithoutReceiverReference,
}

#[derive(Debug, Clone, Serialize)]
pub struct CarrierEntry {
    /// The Chio binding field this is about.
    pub fact: &'static str,
    pub state: CarrierState,
    /// The only place in the set a value for it could travel.
    pub slot: &'static str,
    /// Whose signature covers that slot.
    pub attested_by: &'static str,
    /// What an operator would have to build, in order.
    pub invention: &'static [&'static str],
    pub note: &'static str,
}

/// Steps shared by every fact that has to be attested by the party that issues
/// the credential, because a value the caller writes into the message body is
/// attested by the caller.
const INSIDE_THE_CREDENTIAL: &[&str] = &[
    "a parameter on the token exchange request, which the exchange does not define, so the counterparty's authorization server must be changed to accept one",
    "a private claim in the issued token, which that server must be changed to mint",
    "a name for both, agreed bilaterally, since no registry defines one",
    "a rule in the receiver that reads the claim and compares it against its own record",
];

/// Additional steps for a value the receiver must mint before the call.
const RECEIVER_MINTED: &[&str] = &[
    "a call before the call, since no method in the set returns a value for a caller to carry into its exchange",
    "a way to consume the value exactly once, which no specification in the set provides for any identifier it defines",
];

/// Steps for a fact that could ride in a slot the message body leaves open,
/// with what that costs.
const IN_THE_MESSAGE_BODY: &[&str] = &[
    "a vendor-prefixed key in the tool call's metadata, or a key in the message's metadata map",
    "a name agreed bilaterally, since the reserved prefixes belong to the protocol and the rest is vendor space",
    "a rule in the receiver that reads the key and compares it against its own record",
    "acceptance that the value is attested by the caller, because no signature in the set covers the message body",
];

pub const ENTRIES: &[CarrierEntry] = &[
    CarrierEntry {
        fact: "treaty_scope_sha256",
        state: CarrierState::Absent,
        slot: "a vendor-prefixed key in the tool call's metadata",
        attested_by: "caller",
        invention: IN_THE_MESSAGE_BODY,
        note: "Which text of the agreement the call was decided under, so that two parties operating under different ones cannot both be admitted. This is the fact the three witnesses below drive, by the cheaper of its two routes: a key in the message body, which the caller writes and no signature in the set covers. The other route is a private claim of the issued token, which costs what every entry below costs and puts the value in the hands of the caller's own authorization server instead.",
    },
    CarrierEntry {
        fact: "ladder_intersection_sha256",
        state: CarrierState::Absent,
        slot: "a private claim of the issued token",
        attested_by: "issuing_authorization_server",
        invention: INSIDE_THE_CREDENTIAL,
        note: "A digest of the bound both sides computed. Neither side of this composition computes one, so before the claim there would have to be an object for it to digest.",
    },
    CarrierEntry {
        fact: "admission_report_sha256",
        state: CarrierState::Absent,
        slot: "a private claim of the issued token",
        attested_by: "issuing_authorization_server",
        invention: INSIDE_THE_CREDENTIAL,
        note: "Chio carries this and compares nothing against it, so its absence here costs the same as its presence there.",
    },
    CarrierEntry {
        fact: "consistency_model",
        state: CarrierState::Absent,
        slot: "a private claim of the issued token",
        attested_by: "issuing_authorization_server",
        invention: INSIDE_THE_CREDENTIAL,
        note: "Which reading of cross-organization state the call was decided under. Nothing in the set names one, and a receiver cannot infer it.",
    },
    CarrierEntry {
        fact: "request_sha256",
        state: CarrierState::Absent,
        slot: "a private claim of the issued token",
        attested_by: "issuing_authorization_server",
        invention: INSIDE_THE_CREDENTIAL,
        note: "A digest of the arguments the authority was granted for. The obstacle is not the claim but the order of events: the exchange happens before the call is assembled and the authorization server never sees the arguments, so the parameter would have to carry a digest the caller computes of a body it has not sent yet. A sender-constrained token binds the method and the target of the request, and a rich authorization request carries structured detail the server minted; neither covers the body.",
    },
    CarrierEntry {
        fact: "outcome_sha256",
        state: CarrierState::Absent,
        slot: "a private claim of the issued token",
        attested_by: "issuing_authorization_server",
        invention: INSIDE_THE_CREDENTIAL,
        note: "What the prior call returned. There is no prior call in this composition's model of a request, so the claim would need a record that does not exist to digest.",
    },
    CarrierEntry {
        fact: "local_receipt_sha256",
        state: CarrierState::Absent,
        slot: "a private claim of the issued token",
        attested_by: "issuing_authorization_server",
        invention: INSIDE_THE_CREDENTIAL,
        note: "A digest of the receiver's own record of an earlier call, named by this one. The receiver writes such records; nothing in the set carries one back to the caller for it to name.",
    },
    CarrierEntry {
        fact: "remote_receipt_sha256",
        state: CarrierState::Absent,
        slot: "a private claim of the issued token",
        attested_by: "issuing_authorization_server",
        invention: INSIDE_THE_CREDENTIAL,
        note: "The counterparty's own record. It is not visible to the receiver and no format in the set makes it so.",
    },
    CarrierEntry {
        fact: "continuation_sha256",
        state: CarrierState::WithoutReceiverReference,
        slot: "a private claim of the issued token, over a value the receiver minted",
        attested_by: "issuing_authorization_server",
        invention: RECEIVER_MINTED,
        note: "The two receiver-minted values in the set, a task identifier and the opaque state an MCP server hands back for a retry, both ride in the message body, are covered by no signature, and are multi-use by their own specifications. To make one a continuation the receiver could rely on, it would have to reach the caller's authorization server and come back inside the credential, and consuming it would have to become a rule the receiver wrote.",
    },
    CarrierEntry {
        fact: "lineage_bundle_sha256",
        state: CarrierState::WithoutReceiverReference,
        slot: "a private claim of the issued token, or the message's reference list",
        attested_by: "issuing_authorization_server",
        invention: INSIDE_THE_CREDENTIAL,
        note: "The reference list carries identifiers of tasks this receiver issued, which is more than nothing. What it does not carry is a digest of what happened in them, so a chain of prior calls cannot be checked, only named.",
    },
    CarrierEntry {
        fact: "lease_refs",
        state: CarrierState::WithoutReceiverReference,
        slot: "a private claim of the issued token, naming a lease the receiver registered",
        attested_by: "issuing_authorization_server",
        invention: INSIDE_THE_CREDENTIAL,
        note: "The validity window is carried, as timestamps the issuer chose. A reference the receiver resolves would let it revoke and re-scope between calls; a timestamp lets it wait.",
    },
];

/// One wiring's observation of an invention witness.
#[derive(Debug, Clone, Serialize)]
pub struct WitnessObservation {
    pub wiring: &'static str,
    pub observed: ObservedJson,
}

#[derive(Debug, Clone, Serialize)]
pub struct InventionWitness {
    pub witness_id: &'static str,
    pub description: &'static str,
    pub note: &'static str,
    pub observations: Vec<WitnessObservation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CarrierLedger {
    /// The key an operator would have to agree on to carry the version of the
    /// receiver's agreement record in the message body.
    pub private_key_name: &'static str,
    pub entries: &'static [CarrierEntry],
    pub witnesses: Vec<InventionWitness>,
}

/// A call carrying the operator's invented key, against a receiver whose record
/// has moved on. `asserted_version` is what the caller puts in the key and in
/// the scope; the receiver holds one version higher than the fixture's.
fn call_with_private_version(
    runner: &Runner<'_>,
    id: &str,
    asserted_version: u64,
) -> Result<ObservedJson, String> {
    let mut call = CallBuilder::new(runner.keys, id);
    // The scope asserts the version the receiver holds, so that the check over
    // shipped fields passes and what is left is what the invented key adds.
    call.claims.scope =
        scenario::refund_scope(scenario::AGREEMENT, scenario::AGREEMENT_VERSION + 1);
    call.meta.insert(
        PRIVATE_AGREEMENT_VERSION_KEY.to_string(),
        json!(asserted_version),
    );
    Ok(ObservedJson::from(runner.drive_one(
        StateVariant::AgreementVersionAdvanced,
        &call.build()?,
        scenario::NOW_MS,
    )?))
}

/// Drive the three witnesses. `private` is the hardened wiring with the
/// operator's key installed; the other two are the wirings as they ship.
pub fn run(
    composed: &Runner<'_>,
    hardened: &Runner<'_>,
    private: &Runner<'_>,
) -> Result<CarrierLedger, String> {
    let honest_version = scenario::AGREEMENT_VERSION;
    let receiver_version = scenario::AGREEMENT_VERSION + 1;

    let witnesses = vec![
        InventionWitness {
            witness_id: "invented-key-unread",
            description: "the caller carries the version it decided under in a vendor-prefixed key of the tool call's metadata, against a receiver that never agreed to read that name",
            note: "Both wirings admit. A slot the formats leave open is not a carrier: until the two organizations agree the name and the receiver writes the rule, a value in it is a string nobody reads.",
            observations: vec![
                WitnessObservation {
                    wiring: "composed",
                    observed: call_with_private_version(composed, "invention-unread-c", honest_version)?,
                },
                WitnessObservation {
                    wiring: "hardened",
                    observed: call_with_private_version(hardened, "invention-unread-h", honest_version)?,
                },
            ],
        },
        InventionWitness {
            witness_id: "invented-key-read-honest-caller",
            description: "the same key, now one the receiver has agreed to read and compare, with the caller reporting the version it actually decided under",
            note: "The invention works, against a caller that tells the truth. This is what one field and one comparison buy.",
            observations: vec![WitnessObservation {
                wiring: "hardened_private_profile",
                observed: call_with_private_version(private, "invention-honest-p", honest_version)?,
            }],
        },
        InventionWitness {
            witness_id: "invented-key-value-chosen-by-caller",
            description: "the same key and the same rule, with the caller asserting the version the receiver holds while sending the call it prepared under the previous one",
            note: "Admitted. The invented field is written by the caller into a slot no signature in the set covers, so the comparison is against a value the adversary chooses. Adding the field moves the fact from absent to unverifiable, which is why the fifteen binding fields are not a list of fields to add: what the receiver has to bind is a value it minted, and nothing in these formats carries one back to it.",
            observations: vec![WitnessObservation {
                wiring: "hardened_private_profile",
                observed: call_with_private_version(private, "invention-chosen-p", receiver_version)?,
            }],
        },
    ];

    Ok(CarrierLedger {
        private_key_name: PRIVATE_AGREEMENT_VERSION_KEY,
        entries: ENTRIES,
        witnesses,
    })
}
