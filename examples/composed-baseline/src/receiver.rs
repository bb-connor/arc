//! The composed receiver: the admission path an engineer gets today by wiring
//! a tool server behind a pinned peer identity, a signing policy engine and a
//! replay table.
//!
//! The path is numbered so a denial can be reported at a step, the way the
//! Chio conforming verifier is. Two profiles run over the same code. `Composed`
//! is the wiring the parts produce when assembled the way each documents:
//! the policy engine is handed a context built from the incoming request, the
//! decision is verified over the bytes it arrived in, and there is no audience
//! field on a tool call to check. `Hardened` is the same three parts with every
//! check an operator could add written in: the policy context is taken only
//! from receiver-held records, request-supplied attributes that collide with
//! receiver-owned names are refused, the decision is required to be in its
//! canonical encoding, the two keys are required to be distinct, the decision
//! must name this receiver, and the rule that gates the action requires an
//! approval record the receiver already holds.
//!
//! Neither profile is a straw man and neither is Chio. The distance between
//! them is the point: the same three components yield either, and nothing in
//! the composition tells an operator which one they deployed.

use crate::receiver_state::ReceiverState;
use crate::request::{ComposedEnvelope, PolicyDecision, AUTHORIZATION_SCHEMA};
use crate::store::{BaselineStore, NonceClaim, StoreError};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair, Signature};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{Duration, Instant};

/// Which wiring of the same three parts is under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineProfile {
    /// The composition as its parts document themselves.
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
    /// is what a policy engine's audit sink normally does.
    AfterDispatch,
}

/// Every denial the composed receiver can produce, in step order. Closed, so a
/// case that denies for an unlisted reason cannot be recorded as a denial.
pub const DENIAL_CODES: &[(&str, u32)] = &[
    ("peer.unpinned", 1),
    ("peer.signature_missing", 2),
    ("peer.signature_invalid", 2),
    ("request.schema_invalid", 3),
    ("replay.request_id_seen", 4),
    ("authorization.malformed", 5),
    ("authorization.schema_unrecognised", 5),
    ("authorization.signature_invalid", 6),
    ("authorization.noncanonical", 7),
    ("signer.not_distinct", 8),
    ("authorization.expired", 9),
    ("authorization.verdict_deny", 10),
    ("authorization.audience_mismatch", 11),
    ("authorization.principal_mismatch", 12),
    ("authorization.action_mismatch", 13),
    ("authorization.args_digest_mismatch", 14),
    ("agreement.unknown", 15),
    ("agreement.party_mismatch", 16),
    ("agreement.action_not_covered", 17),
    ("agreement.superseded", 18),
    ("context.request_supplied_attribute", 19),
    ("policy.no_rule", 20),
    ("policy.assurance_insufficient", 21),
    ("policy.amount_over_ceiling", 22),
    ("policy.approval_missing", 23),
    ("store.unavailable", 24),
];

/// The signed record the composed receiver writes for every decision, admit or
/// deny. It is the composition's audit artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineDecisionRecord {
    pub schema: String,
    pub receiver_id: String,
    pub profile: String,
    pub request_id: String,
    pub caller: String,
    pub agreement_id: String,
    pub tool_name: String,
    pub tool_args_sha256: String,
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
    /// answered. Under `BeforeDispatch` that is after the durable append;
    /// under `AfterDispatch` it is after the tool ran and before it. The
    /// difference between the two is the cost of the ordering.
    pub response_ready: Duration,
    /// Time to the end of the whole path, durable append included.
    pub total: Duration,
    /// Time spent in the checks alone: signature verification, canonical
    /// encoding, the consistency comparisons, the table lookups and the rule
    /// evaluation, with the two durable writes excluded. This is the span in
    /// which the two profiles differ, and it is the only one small enough for
    /// that difference to be resolvable.
    pub checks: Duration,
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

/// Attribute names the receiver owns. A request that supplies one of these is
/// trying to decide its own admission.
pub const RECEIVER_OWNED_ATTRIBUTES: &[&str] =
    &["assurance_level", "approval", "agreement_version"];

pub struct ComposedReceiver<'a> {
    pub state: &'a ReceiverState,
    pub profile: BaselineProfile,
    pub durability: DurabilityMode,
    pub signing_key: &'a Keypair,
    pub store: &'a BaselineStore,
}

struct Denial {
    code: &'static str,
    step: u32,
}

fn denial(code: &'static str, step: u32) -> Denial {
    Denial { code, step }
}

impl ComposedReceiver<'_> {
    /// Run one request through the composed admission path. Returns what the
    /// receiver decided, whether the tool ran, and what the decision cost in
    /// durable bytes.
    pub fn admit(
        &self,
        envelope: &ComposedEnvelope,
        now_unix_ms: u64,
        dispatch: &mut dyn FnMut(&ComposedEnvelope),
    ) -> Result<AdmissionOutcome, ReceiverError> {
        let started = Instant::now();
        let request = &envelope.request;
        let args_digest = self.canonical_digest(&request.tool_args)?;

        let decision = self.parse_decision(request.authorization_json.as_str());
        let agreement_id = decision
            .as_ref()
            .map(|parsed| parsed.agreement_id.clone())
            .unwrap_or_default();

        // The checks span is every comparison, signature verification and table
        // lookup the receiver performs, less the durable claim that sits in the
        // middle of them. It is the only span small enough for the difference
        // between the two profiles to be resolvable against a store that
        // fsyncs, so it is timed apart from the whole path.
        let checks_started = Instant::now();
        let mut claim_cost = Duration::ZERO;
        let verdict = self.evaluate(
            envelope,
            decision.as_ref(),
            &args_digest,
            now_unix_ms,
            &mut claim_cost,
        )?;
        let checks = checks_started.elapsed().saturating_sub(claim_cost);

        let record = BaselineDecisionRecord {
            schema: DECISION_RECORD_SCHEMA.to_string(),
            receiver_id: self.state.receiver_id.clone(),
            profile: self.profile.as_str().to_string(),
            request_id: request.request_id.clone(),
            caller: request.caller.clone(),
            agreement_id,
            tool_name: request.tool_name.clone(),
            tool_args_sha256: args_digest.clone(),
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
                self.store
                    .append_decision(&request.request_id, &record_json, &record_sig)?;
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
                // The caller is answered here; the audit sink is appended after.
                let ready = started.elapsed();
                self.store
                    .append_decision(&request.request_id, &record_json, &record_sig)?;
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
        })
    }

    fn canonical_digest(&self, value: &Value) -> Result<String, ReceiverError> {
        let bytes = canonical_json_bytes(value)
            .map_err(|error| ReceiverError::Canonical(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }

    fn parse_decision(&self, raw: &str) -> Option<PolicyDecision> {
        serde_json::from_str::<PolicyDecision>(raw).ok()
    }

    #[allow(clippy::too_many_lines)]
    fn evaluate(
        &self,
        envelope: &ComposedEnvelope,
        decision: Option<&PolicyDecision>,
        args_digest: &str,
        now_unix_ms: u64,
        // The durable claim's cost, which the caller subtracts from the span it
        // timed around this call to leave the checks alone.
        claim_cost: &mut Duration,
    ) -> Result<Option<Denial>, ReceiverError> {
        let request = &envelope.request;

        // Step 1. The caller must be a principal the receiver pinned. A name
        // the pin set does not carry resolves to nothing.
        let Some(pin) = self.state.pin(&request.caller) else {
            return Ok(Some(denial("peer.unpinned", 1)));
        };

        // Step 2. Channel authentication: possession of the pinned key.
        let Some(peer_sig_hex) = envelope.peer_sig.as_deref() else {
            return Ok(Some(denial("peer.signature_missing", 2)));
        };
        let request_bytes = canonical_json_bytes(request)
            .map_err(|error| ReceiverError::Canonical(error.to_string()))?;
        let Ok(peer_sig) = Signature::from_hex(peer_sig_hex) else {
            return Ok(Some(denial("peer.signature_invalid", 2)));
        };
        if !pin.channel_key.verify_strict(&request_bytes, &peer_sig) {
            return Ok(Some(denial("peer.signature_invalid", 2)));
        }

        // Step 3. The request shape. Deserialization already refused unknown
        // fields; what is left is the fields a tool call must carry.
        if request.request_id.is_empty() || request.tool_name.is_empty() {
            return Ok(Some(denial("request.schema_invalid", 3)));
        }

        // Step 4. The replay table. A single-row insert on a primary key, so
        // exactly one of any set of concurrent claims wins. The insert is
        // durable, and its cost is reported separately from the checks.
        let claim_started = Instant::now();
        let claim =
            self.store
                .claim_request_id(&request.request_id, &request.caller, now_unix_ms)?;
        *claim_cost = claim_started.elapsed();
        if claim == NonceClaim::Seen {
            return Ok(Some(denial("replay.request_id_seen", 4)));
        }

        // Step 5. The signed decision.
        let Some(decision) = decision else {
            return Ok(Some(denial("authorization.malformed", 5)));
        };
        if decision.schema != AUTHORIZATION_SCHEMA {
            return Ok(Some(denial("authorization.schema_unrecognised", 5)));
        }

        // Step 6. The decision's signature, over the bytes it arrived in.
        let Ok(authorization_sig) = Signature::from_hex(&request.authorization_sig) else {
            return Ok(Some(denial("authorization.signature_invalid", 6)));
        };
        if !pin
            .policy_key
            .verify_strict(request.authorization_json.as_bytes(), &authorization_sig)
        {
            return Ok(Some(denial("authorization.signature_invalid", 6)));
        }

        // Step 7. Canonical encoding. Only the hardened profile requires the
        // received bytes to be the canonical encoding of what they parse to,
        // which is what would make a reordering visible.
        if self.profile == BaselineProfile::Hardened {
            let canonical = canonical_json_bytes(decision)
                .map_err(|error| ReceiverError::Canonical(error.to_string()))?;
            if canonical.as_slice() != request.authorization_json.as_bytes() {
                return Ok(Some(denial("authorization.noncanonical", 7)));
            }
        }

        // Step 8. Distinctness of the two keys. Only the hardened profile
        // refuses one party holding both.
        if self.profile == BaselineProfile::Hardened
            && pin.channel_key.to_hex() == pin.policy_key.to_hex()
        {
            return Ok(Some(denial("signer.not_distinct", 8)));
        }

        // Step 9. Validity window.
        if decision.expires_at_unix_ms <= now_unix_ms {
            return Ok(Some(denial("authorization.expired", 9)));
        }

        // Step 10. The verdict the signer reached.
        if decision.verdict != "allow" {
            return Ok(Some(denial("authorization.verdict_deny", 10)));
        }

        // Step 11. Audience. A tool call has no audience field, so only the
        // hardened profile carries and checks one.
        if self.profile == BaselineProfile::Hardened && decision.audience != self.state.receiver_id
        {
            return Ok(Some(denial("authorization.audience_mismatch", 11)));
        }

        // Steps 12 to 14. Internal consistency: the decision must be about
        // this caller, this action and these arguments. The first two are
        // comparisons between fields the sender supplied; the third recomputes
        // from the request.
        if decision.principal != request.caller {
            return Ok(Some(denial("authorization.principal_mismatch", 12)));
        }
        if decision.action != request.tool_name {
            return Ok(Some(denial("authorization.action_mismatch", 13)));
        }
        if decision.tool_args_sha256 != args_digest {
            return Ok(Some(denial("authorization.args_digest_mismatch", 14)));
        }

        // Steps 15 to 18. The agreement the decision names, resolved in the
        // receiver's own table.
        let Some(agreement) = self.state.agreement(&decision.agreement_id) else {
            return Ok(Some(denial("agreement.unknown", 15)));
        };
        if !agreement
            .participants
            .iter()
            .any(|participant| participant == &request.caller)
        {
            return Ok(Some(denial("agreement.party_mismatch", 16)));
        }
        if !agreement
            .allowed_actions
            .iter()
            .any(|action| action == &request.tool_name)
        {
            return Ok(Some(denial("agreement.action_not_covered", 17)));
        }
        // Only the hardened profile refuses an agreement its own record marks
        // superseded. The request carries no version, so neither profile can
        // tell which version the sender decided under.
        if self.profile == BaselineProfile::Hardened && agreement.superseded {
            return Ok(Some(denial("agreement.superseded", 18)));
        }

        // Step 19. The policy context. The composed wiring builds it from the
        // incoming request, which is how a policy decision point is called.
        // The hardened wiring builds it from receiver-held records only, and
        // refuses a request that supplies an attribute the receiver owns.
        let assurance = match self.profile {
            BaselineProfile::Composed => match request.context.get("assurance_level") {
                Some(Value::String(level)) => level.clone(),
                _ => agreement.assurance_level.clone(),
            },
            BaselineProfile::Hardened => {
                for owned in RECEIVER_OWNED_ATTRIBUTES {
                    if request.context.contains_key(*owned) {
                        return Ok(Some(denial("context.request_supplied_attribute", 19)));
                    }
                }
                agreement.assurance_level.clone()
            }
        };

        // Steps 20 to 23. The receiver's own rule set.
        let Some(rule) = self.state.rule_for(&request.tool_name) else {
            return Ok(Some(denial("policy.no_rule", 20)));
        };
        if assurance != rule.required_assurance {
            return Ok(Some(denial("policy.assurance_insufficient", 21)));
        }
        let amount = request
            .tool_args
            .get("amount_minor")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if amount > rule.max_amount_minor || amount > agreement.max_amount_minor {
            return Ok(Some(denial("policy.amount_over_ceiling", 22)));
        }
        if rule.requires_local_approval {
            let approval_id = request
                .tool_args
                .get("approval_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let resolved = self.state.approval(approval_id);
            let satisfied = match self.profile {
                // The composed wiring is satisfied by an approval the request
                // presented, which is the ordinary way a claim travels.
                BaselineProfile::Composed => {
                    resolved.is_some() || request.context.contains_key("approval")
                }
                // The hardened wiring resolves the identifier in its own table
                // and takes nothing from the request.
                BaselineProfile::Hardened => resolved
                    .map(|approval| {
                        approval.agreement_id == agreement.agreement_id
                            && approval.action == request.tool_name
                            && amount <= approval.max_amount_minor
                    })
                    .unwrap_or(false),
            };
            if !satisfied {
                return Ok(Some(denial("policy.approval_missing", 23)));
            }
        }

        Ok(None)
    }
}
