//! The composed receiver: the admission path an engineer gets today by putting
//! an agent-to-agent endpoint behind a SPIFFE trust bundle, a tool server, a
//! token exchange and a replay table.
//!
//! The path is numbered so a denial can be reported at a step, the way the Chio
//! conforming verifier is. Two wirings run over the same code. `Composed` is
//! what the parts produce when each is used the way its specification
//! documents: the tool call is well formed, the credential verifies against the
//! issuer the bundle names, its audience names this receiver, its scope covers
//! the action, and the policy engine is handed the message's own metadata as
//! its evaluation context. `Hardened` is the same parts with every check an
//! operator could add written in: the credential's own identifier is claimed in
//! a second replay table, its validity window is bounded by a receiver-held
//! constant, it must be in its canonical encoding, the SVID key and the issuer
//! key must be distinct, the acting party must be the workload the channel
//! authenticated, a retired agreement is refused, the version the scope asserts
//! must equal the version the receiver holds, request-supplied attributes whose
//! names the receiver owns are refused, referenced tasks must resolve in the
//! receiver's own table, and the rule that gates the action resolves its
//! approval locally.
//!
//! Both wirings are reported, and the distance between them is itself a result:
//! the same parts yield either, and nothing in the composition tells an
//! operator which one they deployed.
//!
//! A store failure is not a denial. It leaves this path as an error, so the
//! tool never runs and no record is written: an unavailable store refuses by
//! failing rather than by answering.

use crate::jose::CompactJws;
use crate::receiver_state::ReceiverState;
use crate::request::{
    ComposedEnvelope, JoseHeader, McpRequest, TokenClaims, ISSUED_TOKEN_TYPE_JWT, JOSE_ALG,
    JOSE_TYP, JSONRPC_VERSION, MCP_METHOD_TOOLS_CALL, MCP_PROTOCOL_VERSION, SCOPE_ACTION_PREFIX,
    SCOPE_AGREEMENT_PREFIX, SCOPE_AGREEMENT_VERSION_PREFIX, TOKEN_TYPE_BEARER,
};
use crate::store::{BaselineStore, NonceClaim, StoreError};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair, Signature};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{Duration, Instant};

/// Which wiring of the same parts is under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineProfile {
    /// The composition as its specifications document themselves.
    Composed,
    /// The composition with every operator-authored check written in.
    Hardened,
}

impl BaselineProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            BaselineProfile::Composed => "composed",
            BaselineProfile::Hardened => "hardened",
        }
    }
}

/// Whether the signed decision is made durable before the tool runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurabilityMode {
    /// The decision log is appended and flushed before dispatch.
    BeforeDispatch,
    /// The tool runs first and the decision log is appended afterwards, which
    /// is what an audit sink normally does.
    AfterDispatch,
}

/// The `_meta` key two organizations would have to agree on to carry a fact no
/// document in the set defines. The prefix is a vendor prefix because MCP
/// reserves every prefix whose second label is `modelcontextprotocol` or `mcp`.
pub const PRIVATE_AGREEMENT_VERSION_KEY: &str = "com.vendor.example/agreementVersion";

/// An operator's private profile: names the receiver has agreed to read out of
/// a slot the documents leave open. Absent from both wirings, because neither
/// is reachable by configuring the shipped parts; a case that supplies one is
/// measuring what the invention buys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateProfile {
    /// `_meta` key carrying the version of the receiver's agreement record the
    /// caller claims to have decided under.
    pub agreement_version_key: &'static str,
}

impl PrivateProfile {
    pub fn agreement_version() -> Self {
        Self {
            agreement_version_key: PRIVATE_AGREEMENT_VERSION_KEY,
        }
    }
}

/// Every denial the composed receiver can produce, in step order. Closed, so a
/// case that denies for an unlisted reason cannot be recorded as a denial.
pub const DENIAL_CODES: &[(&str, u32)] = &[
    ("peer.svid_unpinned", 1),
    ("peer.svid_proof_missing", 2),
    ("peer.svid_proof_invalid", 2),
    ("a2a.message_malformed", 3),
    ("mcp.request_malformed", 4),
    ("mcp.protocol_version_missing", 5),
    ("replay.message_id_seen", 6),
    ("token.absent", 7),
    ("token.malformed", 8),
    ("token.type_unrecognised", 9),
    ("token.signature_invalid", 10),
    ("replay.token_id_seen", 11),
    ("token.noncanonical", 12),
    ("signer.not_distinct", 13),
    ("token.not_yet_valid", 14),
    ("token.expired", 14),
    ("token.window_too_long", 15),
    ("token.audience_mismatch", 16),
    ("token.actor_mismatch", 17),
    ("token.issuer_mismatch", 18),
    ("scope.action_mismatch", 19),
    ("agreement.unnamed", 20),
    ("agreement.unknown", 20),
    ("agreement.receiver_not_party", 21),
    ("agreement.party_mismatch", 21),
    ("agreement.action_not_covered", 22),
    ("agreement.superseded", 23),
    ("agreement.version_mismatch", 24),
    ("private.agreement_version_mismatch", 24),
    ("context.request_supplied_attribute", 25),
    ("lineage.task_unknown", 26),
    ("policy.no_rule", 27),
    ("policy.assurance_insufficient", 28),
    ("policy.amount_over_ceiling", 29),
    ("policy.approval_missing", 30),
];

/// The signed record the composed receiver writes for every decision, admit or
/// deny. It is the composition's audit artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineDecisionRecord {
    pub schema: String,
    pub receiver_id: String,
    pub profile: String,
    pub message_id: String,
    pub actor: String,
    pub agreement_id: String,
    pub tool_name: String,
    pub arguments_sha256: String,
    pub verdict: String,
    pub denial_code: Option<String>,
    pub denial_step: Option<u32>,
    pub policy_id: String,
    pub policy_version: String,
    pub decided_at_unix_ms: u64,
}

pub const DECISION_RECORD_SCHEMA: &str = "composed-baseline.decision-record.v1";

/// What one admission attempt produced.
#[derive(Debug, Clone)]
pub struct AdmissionOutcome {
    pub admitted: bool,
    pub dispatched: bool,
    pub denial_code: Option<String>,
    pub denial_step: Option<u32>,
    /// Bytes the decision log grew by, record plus signature.
    pub decision_record_bytes: usize,
    pub record: BaselineDecisionRecord,
    /// Time from the arrival of the request to the point the caller could be
    /// answered.
    pub response_ready: Duration,
    /// Time to the end of the whole path, durable append included.
    pub total: Duration,
    /// The span from the start of peer resolution to the end of rule
    /// evaluation, less the durable replay claims that sit inside it.
    pub checks: Duration,
    /// Time spent in the durable replay claims alone.
    pub durable_claims: Duration,
}

#[derive(Debug)]
pub enum ReceiverError {
    Store(StoreError),
    Canonical(String),
}

impl std::fmt::Display for ReceiverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiverError::Store(error) => write!(f, "store: {error}"),
            ReceiverError::Canonical(message) => write!(f, "canonical json: {message}"),
        }
    }
}

impl std::error::Error for ReceiverError {}

impl From<StoreError> for ReceiverError {
    fn from(error: StoreError) -> Self {
        ReceiverError::Store(error)
    }
}

/// Attribute names the receiver owns. A request that supplies one of these,
/// in any of the slots the documents leave open, is deciding its own admission.
pub const RECEIVER_OWNED_ATTRIBUTES: &[&str] =
    &["assurance_level", "approval", "agreement_version"];

/// Longest validity window the hardened wiring accepts, from the credential's
/// own issuance to its own expiry. It is a receiver-held constant, which is
/// what a maximum token age is in every verifier that enforces one. Nothing in
/// the composed wiring bounds the window, so the only limit on it is the one
/// the issuing authorization server wrote.
pub const MAX_TOKEN_WINDOW_SECONDS: u64 = 300;

pub struct ComposedReceiver<'a> {
    pub state: &'a ReceiverState,
    pub profile: BaselineProfile,
    pub durability: DurabilityMode,
    pub signing_key: &'a Keypair,
    pub store: &'a BaselineStore,
    /// Names an operator agreed to read out of an open slot. Neither wiring
    /// carries one.
    pub private_profile: Option<PrivateProfile>,
}

struct Denial {
    code: &'static str,
    step: u32,
}

fn denial(code: &'static str, step: u32) -> Denial {
    Denial { code, step }
}

/// What the receiver managed to read out of the call before the checks ran.
struct Parsed {
    tool_call: Option<McpRequest>,
    header: Option<JoseHeader>,
    claims: Option<TokenClaims>,
    compact: Option<CompactJws>,
    arguments_sha256: String,
}

impl ComposedReceiver<'_> {
    /// Run one call through the composed admission path.
    pub fn admit(
        &self,
        envelope: &ComposedEnvelope,
        now_unix_ms: u64,
        dispatch: &mut dyn FnMut(&ComposedEnvelope),
    ) -> Result<AdmissionOutcome, ReceiverError> {
        let started = Instant::now();
        let parsed = self.parse(envelope)?;

        let checks_started = Instant::now();
        let mut claim_cost = Duration::ZERO;
        let verdict = self.evaluate(envelope, &parsed, now_unix_ms, &mut claim_cost)?;
        let checks = checks_started.elapsed().saturating_sub(claim_cost);

        let record = BaselineDecisionRecord {
            schema: DECISION_RECORD_SCHEMA.to_string(),
            receiver_id: self.state.receiver_id.clone(),
            profile: self.profile.as_str().to_string(),
            message_id: envelope.request.message.message_id.clone(),
            actor: parsed
                .claims
                .as_ref()
                .map(|claims| claims.act.sub.clone())
                .unwrap_or_else(|| envelope.peer_spiffe_id.clone()),
            agreement_id: parsed
                .claims
                .as_ref()
                .and_then(|claims| claims.scope_value(SCOPE_AGREEMENT_PREFIX))
                .unwrap_or_default()
                .to_string(),
            tool_name: parsed
                .tool_call
                .as_ref()
                .map(|call| call.params.name.clone())
                .unwrap_or_default(),
            arguments_sha256: parsed.arguments_sha256.clone(),
            verdict: if verdict.is_none() { "allow" } else { "deny" }.to_string(),
            denial_code: verdict.as_ref().map(|denial| denial.code.to_string()),
            denial_step: verdict.as_ref().map(|denial| denial.step),
            policy_id: self.state.policy_id.clone(),
            policy_version: self.state.policy_version.clone(),
            decided_at_unix_ms: now_unix_ms,
        };

        let record_json = serde_json::to_string(&record)
            .map_err(|error| ReceiverError::Canonical(error.to_string()))?;
        let record_sig = self.signing_key.sign(record_json.as_bytes()).to_hex();
        let decision_record_bytes = record_json.len() + record_sig.len();

        let admitted = verdict.is_none();
        let mut dispatched = false;

        let response_ready = match self.durability {
            DurabilityMode::BeforeDispatch => {
                self.store.append_decision(
                    &envelope.request.message.message_id,
                    &record_json,
                    &record_sig,
                )?;
                if admitted {
                    dispatch(envelope);
                    dispatched = true;
                }
                started.elapsed()
            }
            DurabilityMode::AfterDispatch => {
                if admitted {
                    dispatch(envelope);
                    dispatched = true;
                }
                let ready = started.elapsed();
                self.store.append_decision(
                    &envelope.request.message.message_id,
                    &record_json,
                    &record_sig,
                )?;
                ready
            }
        };

        Ok(AdmissionOutcome {
            admitted,
            dispatched,
            denial_code: verdict.as_ref().map(|denial| denial.code.to_string()),
            denial_step: verdict.as_ref().map(|denial| denial.step),
            decision_record_bytes,
            record,
            response_ready,
            total: started.elapsed(),
            checks,
            durable_claims: claim_cost,
        })
    }

    fn parse(&self, envelope: &ComposedEnvelope) -> Result<Parsed, ReceiverError> {
        let tool_call = envelope.tool_call();
        let arguments_sha256 = match tool_call.as_ref() {
            Some(call) => {
                let bytes = canonical_json_bytes(&call.params.arguments)
                    .map_err(|error| ReceiverError::Canonical(error.to_string()))?;
                sha256_hex(&bytes)
            }
            None => String::new(),
        };
        let compact = envelope
            .credential
            .as_ref()
            .and_then(|credential| credential.compact().ok());
        let header = compact.as_ref().and_then(|compact| {
            compact
                .header_bytes()
                .ok()
                .and_then(|bytes| serde_json::from_slice::<JoseHeader>(&bytes).ok())
        });
        let claims = compact.as_ref().and_then(|compact| {
            compact
                .payload_bytes()
                .ok()
                .and_then(|bytes| serde_json::from_slice::<TokenClaims>(&bytes).ok())
        });
        Ok(Parsed {
            tool_call,
            header,
            claims,
            compact,
            arguments_sha256,
        })
    }

    #[allow(clippy::too_many_lines)]
    fn evaluate(
        &self,
        envelope: &ComposedEnvelope,
        parsed: &Parsed,
        now_unix_ms: u64,
        claim_cost: &mut Duration,
    ) -> Result<Option<Denial>, ReceiverError> {
        let request = &envelope.request;
        let now_seconds = now_unix_ms / 1000;

        // Step 1. The workload the channel authenticated must be one the trust
        // bundle names. A SPIFFE ID the bundle does not carry resolves to
        // nothing.
        let Some(peer) = self.state.peer(&envelope.peer_spiffe_id) else {
            return Ok(Some(denial("peer.svid_unpinned", 1)));
        };

        // Step 2. Channel authentication: possession of the key in that SVID.
        let Some(proof_hex) = envelope.channel_proof.as_deref() else {
            return Ok(Some(denial("peer.svid_proof_missing", 2)));
        };
        let request_bytes = canonical_json_bytes(request)
            .map_err(|error| ReceiverError::Canonical(error.to_string()))?;
        let Ok(proof) = Signature::from_hex(proof_hex) else {
            return Ok(Some(denial("peer.svid_proof_invalid", 2)));
        };
        if !peer.svid_key.verify_strict(&request_bytes, &proof) {
            return Ok(Some(denial("peer.svid_proof_invalid", 2)));
        }

        // Step 3. The message. Deserialization already refused unknown fields;
        // what is left is what a message must carry.
        if request.message.message_id.is_empty() || request.message.parts.is_empty() {
            return Ok(Some(denial("a2a.message_malformed", 3)));
        }

        // Step 4. The tool call inside the message's data part.
        let Some(tool_call) = parsed.tool_call.as_ref() else {
            return Ok(Some(denial("mcp.request_malformed", 4)));
        };
        if tool_call.jsonrpc != JSONRPC_VERSION
            || tool_call.method != MCP_METHOD_TOOLS_CALL
            || tool_call.params.name.is_empty()
        {
            return Ok(Some(denial("mcp.request_malformed", 4)));
        }

        // Step 5. The per-request protocol fields MCP requires on every
        // request. A request missing one is malformed.
        let declared_version = tool_call
            .params
            .meta
            .get("io.modelcontextprotocol/protocolVersion")
            .and_then(Value::as_str);
        if declared_version != Some(MCP_PROTOCOL_VERSION)
            || !tool_call
                .params
                .meta
                .contains_key("io.modelcontextprotocol/clientCapabilities")
        {
            return Ok(Some(denial("mcp.protocol_version_missing", 5)));
        }

        // Step 6. The replay table, keyed by the message identifier. A
        // single-row insert on a primary key, so exactly one of any set of
        // concurrent claims wins. The identifier is created by the message
        // creator, so this makes an identifier single-use and says nothing
        // about the credential presented with it.
        let claim_started = Instant::now();
        let claim = self.store.claim_request_id(
            &request.message.message_id,
            &envelope.peer_spiffe_id,
            now_unix_ms,
        )?;
        *claim_cost += claim_started.elapsed();
        if claim == NonceClaim::Seen {
            return Ok(Some(denial("replay.message_id_seen", 6)));
        }

        // Step 7. A credential at all. A caller whose token exchange was
        // refused has no token to present: a refusal is an error response at
        // the token endpoint, not an object that travels.
        let Some(credential) = envelope.credential.as_ref() else {
            return Ok(Some(denial("token.absent", 7)));
        };

        // Step 8. The credential parses as what it claims to be.
        let (Some(compact), Some(header), Some(claims)) = (
            parsed.compact.as_ref(),
            parsed.header.as_ref(),
            parsed.claims.as_ref(),
        ) else {
            return Ok(Some(denial("token.malformed", 8)));
        };

        // Step 9. Type. The issued token type identifies what was issued, and
        // the header types the container and names the algorithm.
        if credential.issued_token_type != ISSUED_TOKEN_TYPE_JWT
            || credential.token_type != TOKEN_TYPE_BEARER
            || header.typ != JOSE_TYP
            || header.alg != JOSE_ALG
        {
            return Ok(Some(denial("token.type_unrecognised", 9)));
        }

        // Step 10. The issuer's signature, over the signing input the token
        // arrived in.
        if !compact
            .verify(&peer.issuer_key)
            .map_err(|error| ReceiverError::Canonical(error.to_string()))?
        {
            return Ok(Some(denial("token.signature_invalid", 10)));
        }

        // Step 11. The credential's own replay table, keyed by the identifier
        // inside the signed claims rather than by the one the caller chose
        // outside them. Only the hardened wiring claims it: nothing in the
        // formats requires a token identifier to be single-use, and RFC 7519
        // offers `jti` without obliging anyone to track it.
        if self.profile == BaselineProfile::Hardened {
            let claim_started = Instant::now();
            let claim = self.store.claim_authorization(
                claims.jti.as_str(),
                &envelope.peer_spiffe_id,
                now_unix_ms,
            )?;
            *claim_cost += claim_started.elapsed();
            if claim == NonceClaim::Seen {
                return Ok(Some(denial("replay.token_id_seen", 11)));
            }
        }

        // Step 12. Canonical encoding. Only the hardened wiring requires the
        // received claim bytes to be the canonical encoding of what they parse
        // to, which is what would make a reordering visible.
        if self.profile == BaselineProfile::Hardened {
            let canonical = canonical_json_bytes(claims)
                .map_err(|error| ReceiverError::Canonical(error.to_string()))?;
            let received = compact
                .payload_bytes()
                .map_err(|error| ReceiverError::Canonical(error.to_string()))?;
            if canonical != received {
                return Ok(Some(denial("token.noncanonical", 12)));
            }
        }

        // Step 13. Distinctness of the SVID key and the issuer key. Only the
        // hardened wiring refuses one party holding both.
        if self.profile == BaselineProfile::Hardened
            && peer.svid_key.to_hex() == peer.issuer_key.to_hex()
        {
            return Ok(Some(denial("signer.not_distinct", 13)));
        }

        // Step 14. Validity window. Both wirings refuse a credential that is
        // not yet valid or has expired.
        if claims.nbf > now_seconds {
            return Ok(Some(denial("token.not_yet_valid", 14)));
        }
        if claims.exp <= now_seconds {
            return Ok(Some(denial("token.expired", 14)));
        }

        // Step 15. How long a window the issuer may open. Only the hardened
        // wiring bounds it, against a constant the receiver holds.
        if self.profile == BaselineProfile::Hardened
            && claims.exp.saturating_sub(claims.iat) > MAX_TOKEN_WINDOW_SECONDS
        {
            return Ok(Some(denial("token.window_too_long", 15)));
        }

        // Step 16. Audience. Both wirings require the credential to have been
        // issued for this receiver: a JWT-SVID validator rejects a token whose
        // audience does not carry its own identifier, and a resource server
        // accepting a token issued for someone else is the confused deputy the
        // resource indicator exists to prevent.
        if !claims
            .aud
            .iter()
            .any(|audience| audience == &self.state.receiver_uri)
        {
            return Ok(Some(denial("token.audience_mismatch", 16)));
        }

        // Step 17. The acting party. Only the hardened wiring requires the
        // actor named in the credential to be the workload the channel
        // authenticated; nothing in the exchange binds the two.
        if self.profile == BaselineProfile::Hardened && claims.act.sub != envelope.peer_spiffe_id {
            return Ok(Some(denial("token.actor_mismatch", 17)));
        }

        // Step 18. The issuer must be the one the bundle names for this peer,
        // which is how the verifying key was chosen in the first place.
        if claims.iss != peer.issuer {
            return Ok(Some(denial("token.issuer_mismatch", 18)));
        }

        // Step 19. Scope must cover the action being called.
        if claims.scope_value(SCOPE_ACTION_PREFIX) != Some(tool_call.params.name.as_str()) {
            return Ok(Some(denial("scope.action_mismatch", 19)));
        }

        // Step 20. The agreement the scope names, resolved in the receiver's
        // own table. This is the one fact the composition already resolves
        // against receiver-held state.
        let Some(agreement_id) = claims.scope_value(SCOPE_AGREEMENT_PREFIX) else {
            return Ok(Some(denial("agreement.unnamed", 20)));
        };
        let Some(agreement) = self.state.agreement(agreement_id) else {
            return Ok(Some(denial("agreement.unknown", 20)));
        };

        // Step 21. Resolving an agreement means reading its participant list,
        // so both wirings ask whether this receiver is a party to it and
        // whether the subject of the credential is.
        if !agreement
            .participants
            .iter()
            .any(|participant| participant == &self.state.receiver_id)
        {
            return Ok(Some(denial("agreement.receiver_not_party", 21)));
        }
        if !agreement
            .participants
            .iter()
            .any(|participant| participant == &claims.sub)
        {
            return Ok(Some(denial("agreement.party_mismatch", 21)));
        }

        // Step 22. The action must be one the agreement covers.
        if !agreement
            .allowed_actions
            .iter()
            .any(|action| action == &tool_call.params.name)
        {
            return Ok(Some(denial("agreement.action_not_covered", 22)));
        }

        // Step 23. Only the hardened wiring refuses an agreement its own record
        // marks retired.
        if self.profile == BaselineProfile::Hardened && agreement.superseded {
            return Ok(Some(denial("agreement.superseded", 23)));
        }

        // Step 24. The version. The hardened wiring compares the version the
        // scope asserts against the version its own record carries. The
        // comparison is real and it is worth exactly what the asserted value is
        // worth: the string was minted by the counterparty's authorization
        // server, so it reports what that server believed, and a caller that
        // asserts the receiver's current version passes whatever it decided
        // under.
        if self.profile == BaselineProfile::Hardened {
            let asserted = claims
                .scope_value(SCOPE_AGREEMENT_VERSION_PREFIX)
                .and_then(|value| value.parse::<u64>().ok());
            if asserted != Some(agreement.version) {
                return Ok(Some(denial("agreement.version_mismatch", 24)));
            }
        }
        if let Some(private) = self.private_profile {
            let supplied = tool_call
                .params
                .meta
                .get(private.agreement_version_key)
                .and_then(Value::as_u64);
            if supplied != Some(agreement.version) {
                return Ok(Some(denial("private.agreement_version_mismatch", 24)));
            }
        }

        // Step 25. The policy context. The composed wiring reads it from the
        // message's own metadata, which is what that map is for and how a
        // policy decision point is called. The hardened wiring reads it from
        // receiver-held records only, and refuses a request that supplies an
        // attribute the receiver owns in any slot the formats leave open.
        let assurance = match self.profile {
            BaselineProfile::Composed => match request.message.metadata.get("assurance_level") {
                Some(Value::String(level)) => level.clone(),
                _ => agreement.assurance_level.clone(),
            },
            BaselineProfile::Hardened => {
                for owned in RECEIVER_OWNED_ATTRIBUTES {
                    if request.message.metadata.contains_key(*owned)
                        || request.metadata.contains_key(*owned)
                        || tool_call.params.meta.contains_key(*owned)
                    {
                        return Ok(Some(denial("context.request_supplied_attribute", 25)));
                    }
                }
                agreement.assurance_level.clone()
            }
        };

        // Step 26. Continuity. Only the hardened wiring resolves the task the
        // message names, and the tasks it references, in its own table. A task
        // identifier is the one value in this composition the receiver minted,
        // and resolving it establishes that the receiver created it, not that
        // this call is the one it was created for.
        if self.profile == BaselineProfile::Hardened {
            let referenced = std::iter::once(&request.message.task_id)
                .chain(request.message.reference_task_ids.iter())
                .filter(|task_id| !task_id.is_empty());
            for task_id in referenced {
                let resolved = self.state.task(task_id);
                let held = resolved
                    .map(|task| task.counterparty == claims.sub)
                    .unwrap_or(false);
                if !held {
                    return Ok(Some(denial("lineage.task_unknown", 26)));
                }
            }
        }

        // Steps 27 to 30. The receiver's own rule set.
        let Some(rule) = self.state.rule_for(&tool_call.params.name) else {
            return Ok(Some(denial("policy.no_rule", 27)));
        };
        if assurance != rule.required_assurance {
            return Ok(Some(denial("policy.assurance_insufficient", 28)));
        }
        let amount = tool_call
            .params
            .arguments
            .get("amount_minor")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if amount > rule.max_amount_minor || amount > agreement.max_amount_minor {
            return Ok(Some(denial("policy.amount_over_ceiling", 29)));
        }
        if rule.requires_local_approval {
            let approval_id = tool_call
                .params
                .arguments
                .get("approval_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let resolved = self.state.approval(approval_id);
            let satisfied = match self.profile {
                // The composed wiring is satisfied by an approval the request
                // presented, which is the ordinary way a claim travels.
                BaselineProfile::Composed => {
                    resolved.is_some() || request.message.metadata.contains_key("approval")
                }
                // The hardened wiring resolves the identifier in its own table
                // and takes nothing from the request.
                BaselineProfile::Hardened => resolved
                    .map(|approval| {
                        approval.agreement_id == agreement.agreement_id
                            && approval.action == tool_call.params.name
                            && amount <= approval.max_amount_minor
                    })
                    .unwrap_or(false),
            };
            if !satisfied {
                return Ok(Some(denial("policy.approval_missing", 30)));
            }
        }

        Ok(None)
    }
}
