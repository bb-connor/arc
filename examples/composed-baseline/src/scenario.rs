//! The fixture: the same call, the same counterparties and the same agreement
//! configuration the Chio cross-organization corpus uses, expressed in what the
//! composed formats carry.
//!
//! A buyer organization's refund agent asks a vendor organization to issue a
//! refund. The vendor is the receiver. It has installed the buyer's trust
//! bundle, provisioned two agreements with that buyer (a production agreement
//! and a pilot agreement with a higher ceiling), retired an earlier agreement,
//! written one approval record, created one task for this counterparty, and
//! installed one rule for the refund action.
//!
//! The delegation is the one RFC 8693 describes: the authority belongs to the
//! buyer's kernel, and the agent acting on it is named by the `act` claim.

use crate::jose::base64url_encode;
use crate::receiver_state::{
    AgreementRecord, ApprovalRecord, PolicyRule, ReceiverState, TaskRecord, TrustBundleEntry,
};
use crate::request::{
    issue_credential, A2aMessage, A2aPart, A2aRole, A2aSendMessageConfiguration,
    A2aSendMessageRequest, ActorClaim, ComposedEnvelope, JoseHeader, McpCallToolParams, McpRequest,
    TokenClaims, TokenExchangeResponse, JSONRPC_VERSION, MCP_METHOD_TOOLS_CALL,
    MCP_PROTOCOL_VERSION, PART_MEDIA_TYPE, SCOPE_ACTION_PREFIX, SCOPE_AGREEMENT_PREFIX,
    SCOPE_AGREEMENT_VERSION_PREFIX,
};
use chio_core_types::crypto::{canonical_json_bytes, Keypair};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// The buyer workload whose authority is delegated.
pub const BUYER_SUBJECT: &str = "spiffe://buyer.example/kernel";
/// The buyer's agent, which presents the SVID and is the actor of the token.
pub const BUYER_AGENT: &str = "spiffe://buyer.example/agent/refund-bot";
pub const BUYER_ISSUER: &str = "https://auth.buyer.example";
pub const BUYER_CLIENT_ID: &str = "refund-agent";
pub const VENDOR: &str = "spiffe://vendor.example/kernel";
pub const VENDOR_URI: &str = "https://vendor.example.com/mcp";
pub const OTHER_VENDOR: &str = "spiffe://vendor-two.example/kernel";
pub const OTHER_VENDOR_URI: &str = "https://vendor-two.example.com/mcp";
pub const AGREEMENT: &str = "treaty-buyer-vendor";
pub const AGREEMENT_PILOT: &str = "treaty-buyer-vendor-pilot";
pub const AGREEMENT_RETIRED: &str = "treaty-buyer-vendor-v1";
pub const AGREEMENT_VERSION: u64 = 2;
pub const ACTION: &str = "refund.issue";
pub const APPROVAL: &str = "approval-refund-0001";
/// A task the vendor created for this counterparty and handed back.
pub const TASK: &str = "task-refund-0001";
pub const CONTEXT: &str = "context-refund-0001";
/// A second task the vendor also holds, for the substitution that moves a
/// reference from one held record to another.
pub const OTHER_TASK: &str = "task-refund-0002";

pub const NOW_MS: u64 = 1_760_000_000_000;
pub const NOW_S: u64 = NOW_MS / 1000;
/// When the receiver's current version of the production agreement took effect.
pub const VERSION_EFFECTIVE_AT_MS: u64 = NOW_MS - 86_400_000;

/// Deterministic seeds, so a rerun of the corpus produces the same keys and the
/// same bytes.
const SEED_BUYER_SVID: [u8; 32] = [0x11; 32];
const SEED_BUYER_ISSUER: [u8; 32] = [0x22; 32];
const SEED_VENDOR_DECISION: [u8; 32] = [0x33; 32];
const SEED_ADVERSARY: [u8; 32] = [0x44; 32];

pub struct Keys {
    /// The key in the buyer agent's X509-SVID.
    pub buyer_svid: Keypair,
    /// The key the buyer's authorization server signs issued tokens with.
    pub buyer_issuer: Keypair,
    /// The key the vendor signs its own decision records with.
    pub vendor_decision: Keypair,
    pub adversary: Keypair,
}

impl Keys {
    pub fn fixed() -> Self {
        Self {
            buyer_svid: Keypair::from_seed(&SEED_BUYER_SVID),
            buyer_issuer: Keypair::from_seed(&SEED_BUYER_ISSUER),
            vendor_decision: Keypair::from_seed(&SEED_VENDOR_DECISION),
            adversary: Keypair::from_seed(&SEED_ADVERSARY),
        }
    }
}

/// Build the vendor's state. `collapse_keys` installs one key for both the
/// counterparty's SVID and its token issuer, which is the one-party-holds-both
/// case.
pub fn vendor_state(keys: &Keys, collapse_keys: bool) -> ReceiverState {
    let issuer_key = if collapse_keys {
        keys.buyer_svid.public_key()
    } else {
        keys.buyer_issuer.public_key()
    };
    let mut bundle = BTreeMap::new();
    bundle.insert(
        BUYER_AGENT.to_string(),
        TrustBundleEntry {
            spiffe_id: BUYER_AGENT.to_string(),
            svid_key: keys.buyer_svid.public_key(),
            issuer: BUYER_ISSUER.to_string(),
            issuer_key,
        },
    );

    let mut agreements = BTreeMap::new();
    agreements.insert(
        AGREEMENT.to_string(),
        AgreementRecord {
            agreement_id: AGREEMENT.to_string(),
            version: AGREEMENT_VERSION,
            version_effective_at_unix_ms: VERSION_EFFECTIVE_AT_MS,
            superseded: false,
            participants: vec![BUYER_SUBJECT.to_string(), VENDOR.to_string()],
            allowed_actions: vec![ACTION.to_string()],
            max_amount_minor: 10_000,
            assurance_level: "attested".to_string(),
        },
    );
    agreements.insert(
        AGREEMENT_PILOT.to_string(),
        AgreementRecord {
            agreement_id: AGREEMENT_PILOT.to_string(),
            version: 1,
            version_effective_at_unix_ms: VERSION_EFFECTIVE_AT_MS,
            superseded: false,
            participants: vec![BUYER_SUBJECT.to_string(), VENDOR.to_string()],
            allowed_actions: vec![ACTION.to_string()],
            max_amount_minor: 100_000,
            assurance_level: "attested".to_string(),
        },
    );
    agreements.insert(
        AGREEMENT_RETIRED.to_string(),
        AgreementRecord {
            agreement_id: AGREEMENT_RETIRED.to_string(),
            version: 1,
            version_effective_at_unix_ms: VERSION_EFFECTIVE_AT_MS,
            superseded: true,
            participants: vec![BUYER_SUBJECT.to_string(), VENDOR.to_string()],
            allowed_actions: vec![ACTION.to_string()],
            max_amount_minor: 10_000,
            assurance_level: "attested".to_string(),
        },
    );

    let mut approvals = BTreeMap::new();
    approvals.insert(
        APPROVAL.to_string(),
        ApprovalRecord {
            approval_id: APPROVAL.to_string(),
            agreement_id: AGREEMENT.to_string(),
            action: ACTION.to_string(),
            max_amount_minor: 10_000,
        },
    );

    let mut tasks = BTreeMap::new();
    for task_id in [TASK, OTHER_TASK] {
        tasks.insert(
            task_id.to_string(),
            TaskRecord {
                task_id: task_id.to_string(),
                context_id: CONTEXT.to_string(),
                counterparty: BUYER_SUBJECT.to_string(),
            },
        );
    }

    ReceiverState {
        receiver_id: VENDOR.to_string(),
        receiver_uri: VENDOR_URI.to_string(),
        bundle,
        agreements,
        approvals,
        tasks,
        rules: vec![PolicyRule {
            rule_id: "rule-refund-issue".to_string(),
            action: ACTION.to_string(),
            required_assurance: "attested".to_string(),
            max_amount_minor: 10_000,
            requires_local_approval: true,
        }],
        policy_id: "vendor.refund-policy".to_string(),
        policy_version: "v1.4.0".to_string(),
    }
}

/// The arguments of the call under test. `approval_id` is an input of the
/// vendor's own tool, so its presence is a property of a schema the receiver
/// publishes rather than of any authorization format.
pub fn refund_arguments() -> Value {
    json!({
        "amount_minor": 2500u64,
        "currency": "USD",
        "order_id": "order-9001",
        "approval_id": APPROVAL,
    })
}

/// The scope of the issued token. RFC 6749 gives the syntax and leaves the
/// values to the authorization server; these three are what the two
/// organizations agreed this deployment means by them.
pub fn refund_scope(agreement_id: &str, agreement_version: u64) -> String {
    format!(
        "{SCOPE_ACTION_PREFIX}{ACTION} {SCOPE_AGREEMENT_PREFIX}{agreement_id} \
         {SCOPE_AGREEMENT_VERSION_PREFIX}{agreement_version}"
    )
}

/// The claim set the buyer's authorization server issues for this call.
pub fn base_claims(message_id: &str) -> TokenClaims {
    TokenClaims {
        iss: BUYER_ISSUER.to_string(),
        sub: BUYER_SUBJECT.to_string(),
        aud: vec![VENDOR_URI.to_string()],
        exp: NOW_S + 40,
        nbf: NOW_S - 1,
        iat: NOW_S - 1,
        jti: format!("jti-{message_id}"),
        scope: refund_scope(AGREEMENT, AGREEMENT_VERSION),
        client_id: BUYER_CLIENT_ID.to_string(),
        act: ActorClaim {
            sub: BUYER_AGENT.to_string(),
            iss: Some(BUYER_ISSUER.to_string()),
            act: None,
        },
    }
}

/// The required per-request metadata every MCP request carries.
pub fn required_meta() -> BTreeMap<String, Value> {
    let mut meta = BTreeMap::new();
    meta.insert(
        "io.modelcontextprotocol/protocolVersion".to_string(),
        json!(MCP_PROTOCOL_VERSION),
    );
    meta.insert(
        "io.modelcontextprotocol/clientCapabilities".to_string(),
        json!({}),
    );
    meta
}

/// Whether the call presents a credential, and which one.
pub enum Credential<'a> {
    /// Issue one from the claim set below, signed by `issuer_signer`.
    Issue(&'a Keypair),
    /// Present a credential built elsewhere, which is how the same token is
    /// presented twice.
    Reuse(TokenExchangeResponse),
    /// Present none, which is what a caller has after its authorization server
    /// refuses the exchange.
    None,
}

/// One call, with every part of it addressable so a case can move exactly one
/// fact. `new` returns the admissible call.
pub struct CallBuilder<'a> {
    pub message_id: String,
    pub context_id: String,
    pub task_id: String,
    pub reference_task_ids: Vec<String>,
    pub message_metadata: BTreeMap<String, Value>,
    pub request_metadata: BTreeMap<String, Value>,
    pub meta: BTreeMap<String, Value>,
    pub jsonrpc: String,
    pub method: String,
    pub tool_name: String,
    pub arguments: Value,
    pub peer_spiffe_id: String,
    pub header: JoseHeader,
    pub claims: TokenClaims,
    /// Bytes to transmit as the token payload instead of the canonical
    /// encoding of `claims`.
    pub raw_claims: Option<Vec<u8>>,
    pub credential: Credential<'a>,
    /// The key that proves possession of the peer's SVID, or none.
    pub channel_signer: Option<&'a Keypair>,
}

impl<'a> CallBuilder<'a> {
    pub fn new(keys: &'a Keys, message_id: &str) -> Self {
        Self {
            message_id: message_id.to_string(),
            context_id: CONTEXT.to_string(),
            task_id: TASK.to_string(),
            reference_task_ids: vec![OTHER_TASK.to_string()],
            message_metadata: BTreeMap::new(),
            request_metadata: BTreeMap::new(),
            meta: required_meta(),
            jsonrpc: JSONRPC_VERSION.to_string(),
            method: MCP_METHOD_TOOLS_CALL.to_string(),
            tool_name: ACTION.to_string(),
            arguments: refund_arguments(),
            peer_spiffe_id: BUYER_AGENT.to_string(),
            header: JoseHeader::ed25519("buyer-issuer-2026"),
            claims: base_claims(message_id),
            raw_claims: None,
            credential: Credential::Issue(&keys.buyer_issuer),
            channel_signer: Some(&keys.buyer_svid),
        }
    }

    pub fn build(self) -> Result<ComposedEnvelope, String> {
        let tool_call = McpRequest {
            jsonrpc: self.jsonrpc,
            id: 1,
            method: self.method,
            params: McpCallToolParams {
                name: self.tool_name,
                arguments: self.arguments,
                meta: self.meta,
            },
        };
        let data = serde_json::to_value(&tool_call).map_err(|error| error.to_string())?;
        let request = A2aSendMessageRequest {
            tenant: String::new(),
            message: A2aMessage {
                message_id: self.message_id,
                context_id: self.context_id,
                task_id: self.task_id,
                role: A2aRole::User,
                parts: vec![A2aPart {
                    data,
                    media_type: PART_MEDIA_TYPE.to_string(),
                    metadata: BTreeMap::new(),
                }],
                metadata: self.message_metadata,
                extensions: Vec::new(),
                reference_task_ids: self.reference_task_ids,
            },
            configuration: Some(A2aSendMessageConfiguration {
                accepted_output_modes: vec![PART_MEDIA_TYPE.to_string()],
                return_immediately: false,
            }),
            metadata: self.request_metadata,
        };
        let credential = match self.credential {
            Credential::Issue(signer) => Some(issue_credential(
                &self.header,
                &self.claims,
                self.raw_claims,
                signer,
            )?),
            Credential::Reuse(existing) => Some(existing),
            Credential::None => None,
        };
        let channel_proof = match self.channel_signer {
            Some(signer) => {
                let bytes = canonical_json_bytes(&request).map_err(|error| error.to_string())?;
                Some(signer.sign(&bytes).to_hex())
            }
            None => None,
        };
        Ok(ComposedEnvelope {
            request,
            credential,
            peer_spiffe_id: self.peer_spiffe_id,
            channel_proof,
        })
    }
}

/// The unmodified admissible call, which every case starts from.
pub fn admissible(keys: &Keys, message_id: &str) -> Result<ComposedEnvelope, String> {
    CallBuilder::new(keys, message_id).build()
}

/// A token payload encoded as transmitted bytes, for the cases that move the
/// encoding rather than the content.
pub fn encoded_payload(value: &Value) -> Result<Vec<u8>, String> {
    canonical_json_bytes(value).map_err(|error| error.to_string())
}

/// The base64url segment a payload occupies, for a case that needs to rewrite
/// a token's bytes directly.
pub fn payload_segment(bytes: &[u8]) -> String {
    base64url_encode(bytes)
}
