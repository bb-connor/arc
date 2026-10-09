//! Durable control-plane boundary for the cognition-market finding status
//! feed. Public reads return the exact signed epoch and portable proof bytes
//! that the trusted verifier persisted. The only HTTP mutation is an
//! operator-signed voluntary retraction intent. Epoch advancement has no HTTP
//! request shape, so an untrusted caller can never propose a "latest" root.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use chio_core::receipt::lineage::SignedExportEnvelope;
use chio_finding::verify_pinned_envelope;
use chio_store_sqlite::{
    FindingRetractionIntentCommitLiveness, FindingRetractionIntentInput,
    FindingRetractionIntentRecord, FindingRetractionIntentSource, FindingStatusEpochRecord,
    FindingStatusProofKind, FindingStatusProofRecord, FindingStatusStoreError,
    FindingStatusWriteOutcome, FindingStickyStatus, SqliteFindingStatusStore,
};

use super::report_validation::validate_service_auth;
use super::*;

/// Status intent requests remain far below the service-wide body cap. Keeping
/// the exact signed request bounded also bounds the durable outbox record.
pub(crate) const FINDING_STATUS_INTENT_MAX_BODY_BYTES: usize = 256 * 1024;

const FINDING_STATUS_INTENT_SCHEMA: &str = "chio.finding.status-intent-submission.v1";
const FINDING_STATUS_INTENT_ID_DOMAIN: &str = "chio.finding.status-intent-id.v1";
const FINDING_VOLUNTARY_RETRACTION_RECEIPT_SCHEMA: &str =
    "chio.finding.voluntary-retraction-receipt.v1";

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum FindingStatusIntentSource {
    Voluntary,
    Enforcement,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct FindingVoluntaryRetractionReceipt {
    schema: String,
    feed_id: String,
    key_domain_nonce: u64,
    finding_id: String,
    source_authority_id: String,
    issued_at: u64,
}

impl FindingStatusIntentSource {
    const fn store_source(self) -> FindingRetractionIntentSource {
        match self {
            Self::Voluntary => FindingRetractionIntentSource::Voluntary,
            Self::Enforcement => FindingRetractionIntentSource::Enforcement,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Voluntary => "voluntary",
            Self::Enforcement => "enforcement",
        }
    }
}

/// Operator countersignature over one authenticated source receipt. For a
/// voluntary request the source receipt is the seller's signed retraction
/// intent. Enforced intents are created only by the challenge finality
/// coordinator and
/// are deliberately refused at this HTTP boundary.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct FindingStatusIntentSubmission {
    schema: String,
    intent_id: String,
    feed_id: String,
    key_domain_nonce: u64,
    finding_id: String,
    source: FindingStatusIntentSource,
    source_authority_id: String,
    source_receipt_sha256: String,
    source_receipt: SignedExportEnvelope<FindingVoluntaryRetractionReceipt>,
    operator_id: String,
    operator_key_epoch: u64,
    issued_at: u64,
    inclusion_deadline: u64,
}

type SignedFindingStatusIntentSubmission = SignedExportEnvelope<FindingStatusIntentSubmission>;

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
struct FindingStatusRootResponse {
    feed_id: String,
    key_domain_nonce: u64,
    map_epoch: u64,
    epoch_id: String,
    root_hash: String,
    signed_epoch_sha256: String,
    signed_epoch_b64: String,
    valid_until: u64,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
struct FindingStatusProofResponse {
    feed_id: String,
    key_domain_nonce: u64,
    map_epoch: u64,
    epoch_id: String,
    root_hash: String,
    finding_id: String,
    proof_kind: &'static str,
    proof_sha256: String,
    proof_input_b64: String,
    signed_epoch_sha256: String,
    signed_epoch_b64: String,
    service_bond_evidence_sha256: String,
    checked_at: u64,
    valid_until: u64,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
struct FindingStatusIntentResponse {
    intent_id: String,
    feed_id: String,
    finding_id: String,
    intent_sha256: String,
    status: &'static str,
    exact_replay: bool,
    inclusion_deadline: u64,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
struct FindingStatusIntentIdPreimage<'a> {
    domain: &'static str,
    feed_id: &'a str,
    key_domain_nonce: u64,
    finding_id: &'a str,
    source: &'a str,
    source_authority_id: &'a str,
    source_receipt_sha256: &'a str,
    operator_id: &'a str,
    operator_key_epoch: u64,
    issued_at: u64,
    inclusion_deadline: u64,
}

fn compute_intent_id(body: &FindingStatusIntentSubmission) -> Result<String, Response> {
    let preimage = FindingStatusIntentIdPreimage {
        domain: FINDING_STATUS_INTENT_ID_DOMAIN,
        feed_id: &body.feed_id,
        key_domain_nonce: body.key_domain_nonce,
        finding_id: &body.finding_id,
        source: body.source.name(),
        source_authority_id: &body.source_authority_id,
        source_receipt_sha256: &body.source_receipt_sha256,
        operator_id: &body.operator_id,
        operator_key_epoch: body.operator_key_epoch,
        issued_at: body.issued_at,
        inclusion_deadline: body.inclusion_deadline,
    };
    let bytes = canonical_json_bytes(&preimage).map_err(|_| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            "status intent id preimage is not canonical",
        )
    })?;
    Ok(sha256_hex(&bytes))
}

/// Build the exact seller-signed, operator-countersigned voluntary retraction
/// submitted to the status outbox. The caller still has to send it through
/// the authenticated route, which reloads the retained Finding and proves the
/// seller key is its issuer.
pub fn build_operator_voluntary_retraction(
    market: &FindingMarketConfig,
    seller: &chio_core::crypto::Keypair,
    status_operator: &chio_core::crypto::Keypair,
    finding_id: &str,
    issued_at: u64,
) -> Result<Vec<u8>, String> {
    market.validate().map_err(|error| error.to_string())?;
    require_hex64(finding_id, "finding_id").map_err(|_| "finding_id is invalid".to_owned())?;
    let expected_operator = market
        .status_feed_operator
        .authority
        .key()
        .map_err(|error| error.to_string())?;
    if status_operator.public_key() != expected_operator {
        return Err("status operator key does not match the configured pin".to_owned());
    }
    let source_authority_id = seller.public_key().to_hex();
    let source_receipt = SignedExportEnvelope::sign(
        FindingVoluntaryRetractionReceipt {
            schema: FINDING_VOLUNTARY_RETRACTION_RECEIPT_SCHEMA.to_owned(),
            feed_id: market.status_feed_operator.feed_id.clone(),
            key_domain_nonce: FINDING_STATUS_KEY_DOMAIN_NONCE,
            finding_id: finding_id.to_owned(),
            source_authority_id: source_authority_id.clone(),
            issued_at,
        },
        seller,
    )
    .map_err(|error| error.to_string())?;
    let source_receipt_sha256 =
        chio_finding::signed_envelope_sha256(&source_receipt).map_err(|error| error.to_string())?;
    let inclusion_deadline = issued_at
        .checked_add(market.status_feed_service_bond.inclusion_sla_secs)
        .ok_or_else(|| "status intent inclusion deadline overflowed".to_owned())?;
    let mut body = FindingStatusIntentSubmission {
        schema: FINDING_STATUS_INTENT_SCHEMA.to_owned(),
        intent_id: String::new(),
        feed_id: market.status_feed_operator.feed_id.clone(),
        key_domain_nonce: FINDING_STATUS_KEY_DOMAIN_NONCE,
        finding_id: finding_id.to_owned(),
        source: FindingStatusIntentSource::Voluntary,
        source_authority_id,
        source_receipt_sha256,
        source_receipt,
        operator_id: market.status_feed_operator.authority.authority_id.clone(),
        operator_key_epoch: market.status_feed_operator.authority.key_epoch,
        issued_at,
        inclusion_deadline,
    };
    body.intent_id = compute_intent_id(&body)
        .map_err(|_| "status intent identity cannot be derived".to_owned())?;
    let signed =
        SignedExportEnvelope::sign(body, status_operator).map_err(|error| error.to_string())?;
    canonical_json_bytes(&signed).map_err(|error| error.to_string())
}

fn require_hex64(value: &str, label: &'static str) -> Result<(), Response> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            &format!("{label} must be lowercase hex with length 64"),
        ));
    }
    Ok(())
}

fn strict_intent_ingress(raw: &str) -> Result<SignedFindingStatusIntentSubmission, Response> {
    if raw.len() > FINDING_STATUS_INTENT_MAX_BODY_BYTES {
        return Err(plain_http_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "status intent exceeds the ingress size bound",
        ));
    }
    let canonical = chio_core::canonical::canonical_json_bytes_from_str(raw).map_err(|_| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            "status intent is not strict canonical I-JSON",
        )
    })?;
    if canonical.as_slice() != raw.as_bytes() {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "status intent bytes are not the canonical serialization",
        ));
    }
    let signed: SignedFindingStatusIntentSubmission =
        chio_core::canonical::UntrustedJsonText::from_wire((raw).as_bytes(), 64 * 1024 * 1024)
            .and_then(|input| input.decode_signed())
            .map_err(|_| {
                plain_http_error(
                    StatusCode::BAD_REQUEST,
                    "status intent failed typed deserialization",
                )
            })?;
    let typed = canonical_json_bytes(&signed).map_err(|_| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            "status intent failed canonicalization",
        )
    })?;
    if typed != canonical {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "status intent typed bytes drift from the accepted bytes",
        ));
    }
    Ok(signed)
}

fn status_context(
    state: &TrustServiceState,
    feed_id: &str,
    now: u64,
) -> Result<(FindingMarketConfig, SqliteFindingStatusStore), Response> {
    let config = live_status_config(state, feed_id, now)?;
    let store = status_store(state)?;
    Ok((config, store))
}

fn live_status_config(
    state: &TrustServiceState,
    feed_id: &str,
    now: u64,
) -> Result<FindingMarketConfig, Response> {
    let Some(config) = state.config.finding_market.clone() else {
        return Err(plain_http_error(
            StatusCode::CONFLICT,
            "finding market is not configured on this control plane",
        ));
    };
    config
        .require_live_status_feed(feed_id, now)
        .map_err(|error| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()))?;
    Ok(config)
}

fn status_store(state: &TrustServiceState) -> Result<SqliteFindingStatusStore, Response> {
    let Some(store) = state
        .joint_authority_store
        .as_ref()
        .map(|authority| authority.finding_status_store())
    else {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "finding status feed requires the durable joint authority store",
        ));
    };
    Ok(store)
}

fn require_current_epoch(
    operator: &FindingStatusOperatorPin,
    service_bond: &FindingStatusServiceBond,
    max_epoch_age_secs: u64,
    epoch: &FindingStatusEpochRecord,
    now: u64,
) -> Result<(), Response> {
    super::finding_status_verifier::verify_epoch_record(
        operator,
        service_bond,
        max_epoch_age_secs,
        epoch,
        now,
    )
    .map_err(|error| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()))
}

fn require_current_proof_material(
    operator: &FindingStatusOperatorPin,
    service_bond: &FindingStatusServiceBond,
    max_epoch_age_secs: u64,
    epoch: &FindingStatusEpochRecord,
    proof: &FindingStatusProofRecord,
    now: u64,
) -> Result<(), Response> {
    super::finding_status_verifier::verify_proof_record(
        operator,
        service_bond,
        max_epoch_age_secs,
        proof,
        now,
    )
    .map_err(|error| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()))?;
    if proof.feed_id != epoch.feed_id
        || proof.operator_id != epoch.operator_id
        || proof.key_domain_nonce != FINDING_STATUS_KEY_DOMAIN_NONCE
        || proof.map_epoch != epoch.map_epoch
        || proof.epoch_id != epoch.epoch_id
        || proof.root_hash != epoch.root_hash
        || proof.signed_epoch_sha256 != epoch.signed_epoch_sha256
        || proof.signed_epoch_bytes != epoch.signed_epoch_bytes
        || proof.proof_sha256 != sha256_hex(&proof.proof_bytes)
        || proof.checked_at > now
        || now >= proof.valid_until
    {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "finding status proof is not current at the durable feed floor",
        ));
    }

    Ok(())
}

fn require_proof_sticky_state(
    store: &SqliteFindingStatusStore,
    proof: &FindingStatusProofRecord,
) -> Result<(), Response> {
    let sticky = store
        .get_finding_status(&proof.feed_id, &proof.finding_id)
        .map_err(status_read_error)?;
    match (proof.kind, sticky.as_ref().map(|status| status.state)) {
        (FindingStatusProofKind::NonInclusion, None) => Ok(()),
        (FindingStatusProofKind::Inclusion, Some(FindingStickyStatus::Retracted)) => Ok(()),
        (FindingStatusProofKind::NonInclusion, Some(_)) => Err(plain_http_error(
            StatusCode::CONFLICT,
            "non-inclusion contradicts sticky pending or retracted status",
        )),
        (FindingStatusProofKind::Inclusion, _) => Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "inclusion proof is missing sticky retracted state",
        )),
    }
}

fn observe_status_route_time(
    store: &SqliteFindingStatusStore,
    feed_id: &str,
    read_now: impl FnOnce() -> Result<u64, chio_security_types::clock::ClockError>,
) -> Result<u64, Response> {
    store
        .observe_trusted_time_with_clock(feed_id, read_now)
        .map(|(_, observed_at)| observed_at)
        .map_err(status_read_error)
}

fn validate_intent_submission(
    signed: &SignedFindingStatusIntentSubmission,
    operator: &FindingStatusOperatorPin,
    service_bond: &FindingStatusServiceBond,
    feed_id: &str,
    now: u64,
) -> Result<(), Response> {
    let body = &signed.body;
    if body.schema != FINDING_STATUS_INTENT_SCHEMA
        || body.feed_id != feed_id
        || body.key_domain_nonce != FINDING_STATUS_KEY_DOMAIN_NONCE
        || body.operator_id != operator.authority.authority_id
        || body.operator_key_epoch != operator.authority.key_epoch
    {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "status intent does not match the configured feed domain or operator",
        ));
    }
    if body.source != FindingStatusIntentSource::Voluntary {
        return Err(plain_http_error(
            StatusCode::FORBIDDEN,
            "enforced status intents require the appeal-final coordinator",
        ));
    }
    require_hex64(&body.finding_id, "finding_id")?;
    require_hex64(&body.source_receipt_sha256, "source_receipt_sha256")?;
    if body.source_authority_id.trim().is_empty()
        || body.source_authority_id.trim() != body.source_authority_id
    {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "status intent source authority id is invalid",
        ));
    }
    let deadline = body
        .issued_at
        .checked_add(service_bond.inclusion_sla_secs)
        .ok_or_else(|| {
            plain_http_error(StatusCode::BAD_REQUEST, "status intent deadline overflowed")
        })?;
    if body.issued_at == 0
        || body.issued_at > now
        || body.inclusion_deadline != deadline
        || now >= body.inclusion_deadline
    {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "status intent is stale or has the wrong inclusion deadline",
        ));
    }
    if body.intent_id != compute_intent_id(body)? {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "status intent id does not match its canonical preimage",
        ));
    }
    let pinned_key = require_status_feed_through(
        operator,
        service_bond,
        feed_id,
        now,
        body.inclusion_deadline,
    )
    .map_err(|error| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()))?;
    verify_pinned_envelope(signed, &pinned_key, "status intent operator").map_err(|_| {
        plain_http_error(
            StatusCode::UNAUTHORIZED,
            "status intent operator signature is invalid",
        )
    })?;
    let source = &body.source_receipt;
    if source.body.schema != FINDING_VOLUNTARY_RETRACTION_RECEIPT_SCHEMA
        || source.body.feed_id != body.feed_id
        || source.body.key_domain_nonce != body.key_domain_nonce
        || source.body.finding_id != body.finding_id
        || source.body.source_authority_id != body.source_authority_id
        || source.body.issued_at != body.issued_at
        || source.signer_key.to_hex() != body.source_authority_id
    {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "voluntary retraction source receipt bindings are invalid",
        ));
    }
    if !matches!(source.verify_signature(), Ok(true)) {
        return Err(plain_http_error(
            StatusCode::UNAUTHORIZED,
            "voluntary retraction source receipt signature is invalid",
        ));
    }
    let source_digest = chio_finding::signed_envelope_sha256(source).map_err(|_| {
        plain_http_error(
            StatusCode::BAD_REQUEST,
            "voluntary retraction source receipt is not canonical",
        )
    })?;
    if source_digest != body.source_receipt_sha256 {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "voluntary retraction source receipt digest differs",
        ));
    }
    Ok(())
}

fn intent_persistence_time(
    signed: &SignedFindingStatusIntentSubmission,
    operator: &FindingStatusOperatorPin,
    service_bond: &FindingStatusServiceBond,
    feed_id: &str,
    read_now: impl FnOnce() -> Result<u64, chio_security_types::clock::ClockError>,
) -> Result<u64, Response> {
    let persistence_now = read_now()
        .map_err(|error| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()))?;
    validate_intent_submission(signed, operator, service_bond, feed_id, persistence_now)?;
    Ok(persistence_now)
}

fn intent_response(record: FindingRetractionIntentRecord, exact_replay: bool) -> Response {
    let status = match record.state {
        chio_store_sqlite::FindingRetractionIntentState::WaitingFinality => "waiting_finality",
        chio_store_sqlite::FindingRetractionIntentState::DispatchEligible => "dispatch_eligible",
        chio_store_sqlite::FindingRetractionIntentState::Published => "published",
    };
    Json(FindingStatusIntentResponse {
        intent_id: record.intent_id,
        feed_id: record.feed_id,
        finding_id: record.finding_id,
        intent_sha256: record.intent_sha256,
        status,
        exact_replay,
        inclusion_deadline: record.inclusion_deadline,
    })
    .into_response()
}

fn recover_exact_intent_replay(
    store: &SqliteFindingStatusStore,
    intent_id: &str,
    raw: &[u8],
) -> Result<Option<Response>, Response> {
    match store.get_retraction_intent(intent_id) {
        Ok(Some(record)) if record.intent_bytes == raw => Ok(Some(intent_response(record, true))),
        Ok(_) => Ok(None),
        Err(error) => Err(status_read_error(error)),
    }
}

fn require_authorized_voluntary_source(
    state: &TrustServiceState,
    signed: &SignedFindingStatusIntentSubmission,
) -> Result<(), Response> {
    let Some(authority) = state.joint_authority_store.as_ref() else {
        return Err(plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "voluntary retraction authorization requires the durable finding market",
        ));
    };
    let raw = authority
        .finding_market_store()
        .get_finding_bytes(&signed.body.finding_id)
        .map_err(|error| plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()))?
        .ok_or_else(|| {
            plain_http_error(
                StatusCode::FORBIDDEN,
                "voluntary retraction source is not authorized for the retained finding",
            )
        })?;
    let finding: chio_finding::Finding =
        chio_core::canonical::UntrustedJsonText::from_wire(raw.as_bytes(), 64 * 1024 * 1024)
            .and_then(|input| input.decode_signed())
            .map_err(|_| {
                plain_http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "retained finding cannot be authenticated for voluntary retraction",
                )
            })?;
    chio_finding::verify_finding(&finding).map_err(|_| {
        plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "retained finding cannot be authenticated for voluntary retraction",
        )
    })?;
    if finding.finding_id != signed.body.finding_id
        || finding.status_feed_ref != signed.body.feed_id
        || finding.issuer.to_hex() != signed.body.source_authority_id
        || signed.body.source_receipt.signer_key != finding.issuer
    {
        return Err(plain_http_error(
            StatusCode::FORBIDDEN,
            "voluntary retraction source is not authorized for the retained finding",
        ));
    }
    Ok(())
}

fn status_read_error(error: FindingStatusStoreError) -> Response {
    plain_http_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string())
}

fn status_write_error(error: FindingStatusStoreError) -> Response {
    let status = match error {
        FindingStatusStoreError::Conflict(_)
        | FindingStatusStoreError::Rollback { .. }
        | FindingStatusStoreError::Equivocation { .. }
        | FindingStatusStoreError::ContradictoryNonInclusion { .. } => StatusCode::CONFLICT,
        FindingStatusStoreError::Fenced => StatusCode::FORBIDDEN,
        FindingStatusStoreError::Clock(_)
        | FindingStatusStoreError::Unavailable(_)
        | FindingStatusStoreError::Invariant(_)
        | FindingStatusStoreError::OutcomeUnknown(_)
        | FindingStatusStoreError::MissingFloor { .. }
        | FindingStatusStoreError::MissingState { .. }
        | FindingStatusStoreError::ClockRollback { .. }
        | FindingStatusStoreError::StaleProof { .. } => StatusCode::SERVICE_UNAVAILABLE,
    };
    plain_http_error(status, &error.to_string())
}

/// GET /v1/findings/status/{feed}/root.
pub(crate) async fn handle_get_finding_status_root(
    State(state): State<TrustServiceState>,
    AxumPath(feed_id): AxumPath<String>,
) -> Response {
    let clock_now = match unix_timestamp_now() {
        Ok(now) => now,
        Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
    };
    let request_started_at = clock_now;
    let (_, store) = match status_context(&state, &feed_id, request_started_at) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let epoch = match store.get_current_epoch(&feed_id) {
        Ok(epoch) => epoch,
        Err(error) => return status_read_error(error),
    };
    let verification_now = match observe_status_route_time(&store, &feed_id, status_clock_now) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let config = match live_status_config(&state, &feed_id, verification_now) {
        Ok(config) => config,
        Err(response) => return response,
    };
    if let Err(response) = require_current_epoch(
        &config.status_feed_operator,
        &config.status_feed_service_bond,
        config.status_max_epoch_age_secs,
        &epoch,
        verification_now,
    ) {
        return response;
    }
    Json(FindingStatusRootResponse {
        feed_id: epoch.feed_id,
        key_domain_nonce: epoch.key_domain_nonce,
        map_epoch: epoch.map_epoch,
        epoch_id: epoch.epoch_id,
        root_hash: epoch.root_hash,
        signed_epoch_sha256: epoch.signed_epoch_sha256,
        signed_epoch_b64: STANDARD.encode(epoch.signed_epoch_bytes),
        valid_until: epoch.valid_until,
    })
    .into_response()
}

/// GET /v1/findings/status/{feed}/proof/{finding_id}.
pub(crate) async fn handle_get_finding_status_proof(
    State(state): State<TrustServiceState>,
    AxumPath((feed_id, finding_id)): AxumPath<(String, String)>,
) -> Response {
    let clock_now = match unix_timestamp_now() {
        Ok(now) => now,
        Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
    };
    let request_started_at = clock_now;
    let (_, store) = match status_context(&state, &feed_id, request_started_at) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let epoch = match store.get_current_epoch(&feed_id) {
        Ok(epoch) => epoch,
        Err(error) => return status_read_error(error),
    };
    let proof = match store.get_latest_proof(&feed_id, &finding_id) {
        Ok(Some(proof)) => proof,
        Ok(None) => {
            return plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "current portable finding status proof is unavailable",
            );
        }
        Err(error) => return status_read_error(error),
    };
    let verification_now = match observe_status_route_time(&store, &feed_id, status_clock_now) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let config = match live_status_config(&state, &feed_id, verification_now) {
        Ok(config) => config,
        Err(response) => return response,
    };
    if let Err(response) = require_current_epoch(
        &config.status_feed_operator,
        &config.status_feed_service_bond,
        config.status_max_epoch_age_secs,
        &epoch,
        verification_now,
    ) {
        return response;
    }
    if let Err(response) = require_current_proof_material(
        &config.status_feed_operator,
        &config.status_feed_service_bond,
        config.status_max_epoch_age_secs,
        &epoch,
        &proof,
        verification_now,
    ) {
        return response;
    }
    if let Err(response) = require_proof_sticky_state(&store, &proof) {
        return response;
    }
    let final_now = match observe_status_route_time(&store, &feed_id, status_clock_now) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let config = match live_status_config(&state, &feed_id, final_now) {
        Ok(config) => config,
        Err(response) => return response,
    };
    if let Err(response) = require_current_epoch(
        &config.status_feed_operator,
        &config.status_feed_service_bond,
        config.status_max_epoch_age_secs,
        &epoch,
        final_now,
    ) {
        return response;
    }
    if let Err(response) = require_current_proof_material(
        &config.status_feed_operator,
        &config.status_feed_service_bond,
        config.status_max_epoch_age_secs,
        &epoch,
        &proof,
        final_now,
    ) {
        return response;
    }
    if let Err(response) = require_proof_sticky_state(&store, &proof) {
        return response;
    }
    let proof_kind = match proof.kind {
        FindingStatusProofKind::Inclusion => "inclusion",
        FindingStatusProofKind::NonInclusion => "non_inclusion",
    };
    Json(FindingStatusProofResponse {
        feed_id: proof.feed_id,
        key_domain_nonce: proof.key_domain_nonce,
        map_epoch: proof.map_epoch,
        epoch_id: proof.epoch_id,
        root_hash: proof.root_hash,
        finding_id: proof.finding_id,
        proof_kind,
        proof_sha256: proof.proof_sha256,
        proof_input_b64: STANDARD.encode(proof.proof_bytes),
        signed_epoch_sha256: proof.signed_epoch_sha256,
        signed_epoch_b64: STANDARD.encode(proof.signed_epoch_bytes),
        service_bond_evidence_sha256: config.status_feed_service_bond.evidence_sha256,
        checked_at: proof.checked_at,
        valid_until: proof.valid_until,
    })
    .into_response()
}

/// POST /v1/findings/status/{feed}/intents. This accepts voluntary intent
/// receipts only. The exact canonical signed request is retained in the
/// durable outbox and immediately makes the finding sticky pending.
pub(crate) async fn handle_submit_finding_status_intent(
    State(state): State<TrustServiceState>,
    AxumPath(feed_id): AxumPath<String>,
    headers: HeaderMap,
    raw: String,
) -> Response {
    let clock_now = match unix_timestamp_now() {
        Ok(now) => now,
        Err(error) => return plain_http_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
    };
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let signed = match strict_intent_ingress(&raw) {
        Ok(signed) => signed,
        Err(response) => return response,
    };
    let body = &signed.body;
    if let Err(response) = require_hex64(&body.intent_id, "intent_id") {
        return response;
    }
    if body.feed_id != feed_id {
        return plain_http_error(
            StatusCode::BAD_REQUEST,
            "status intent does not match the route feed",
        );
    }
    let store = match status_store(&state) {
        Ok(store) => store,
        Err(response) => return response,
    };
    match recover_exact_intent_replay(&store, &body.intent_id, raw.as_bytes()) {
        Ok(Some(response)) => return response,
        Ok(None) => {}
        Err(response) => return response,
    }
    let now = clock_now;
    let config = match live_status_config(&state, &feed_id, now) {
        Ok(config) => config,
        Err(response) => return response,
    };
    if let Err(response) = validate_intent_submission(
        &signed,
        &config.status_feed_operator,
        &config.status_feed_service_bond,
        &feed_id,
        now,
    ) {
        return response;
    }
    if let Err(response) = require_authorized_voluntary_source(&state, &signed) {
        return response;
    }
    let persistence_now = match intent_persistence_time(
        &signed,
        &config.status_feed_operator,
        &config.status_feed_service_bond,
        &feed_id,
        || {
            chio_security_types::clock::Clock::unix_millis(&chio_security_types::clock::SystemClock)
                .map(|now| now.as_secs())
        },
    ) {
        Ok(now) => now,
        Err(response) => return response,
    };
    let operator_valid_until = config
        .status_feed_operator
        .revoked_from
        .unwrap_or(config.status_feed_operator.authority.valid_until)
        .min(config.status_feed_operator.authority.valid_until);
    let commit_liveness = FindingRetractionIntentCommitLiveness {
        valid_from: config
            .status_feed_operator
            .authority
            .valid_from
            .max(config.status_feed_service_bond.valid_from),
        valid_until: operator_valid_until.min(config.status_feed_service_bond.valid_until),
    };
    let outcome = match store.issue_retraction_intent_with_commit_clock(
        &FindingRetractionIntentInput {
            intent_id: &body.intent_id,
            feed_id: &body.feed_id,
            operator_id: &body.operator_id,
            finding_id: &body.finding_id,
            source: body.source.store_source(),
            intent_bytes: raw.as_bytes(),
            issued_at: body.issued_at,
            inclusion_deadline: body.inclusion_deadline,
            created_at: persistence_now,
        },
        commit_liveness,
        || {
            chio_security_types::clock::Clock::unix_millis(&chio_security_types::clock::SystemClock)
                .map(|now| now.as_secs())
        },
    ) {
        Ok(outcome) => outcome,
        Err(error) => return status_write_error(error),
    };
    let record = match store.get_retraction_intent(&body.intent_id) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "persisted status intent cannot be recovered",
            );
        }
        Err(error) => return status_read_error(error),
    };
    intent_response(record, outcome == FindingStatusWriteOutcome::ExactReplay)
}

fn status_clock_now() -> Result<u64, chio_security_types::clock::ClockError> {
    chio_security_types::clock::Clock::unix_millis(&chio_security_types::clock::SystemClock)
        .map(|now| now.as_secs())
}

#[cfg(test)]
fn service_state(
    authority: Arc<chio_store_sqlite::SqliteAuthorityStore>,
    market: FindingMarketConfig,
) -> TrustServiceState {
    use std::collections::BTreeMap;
    use std::time::Duration;
    TrustServiceState {
        finding_challenge_clock: Arc::new(chio_security_types::clock::SystemClock),
        config: TrustServiceConfig {
            transport: Default::default(),
            listen: std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
            service_token: "service-secret".to_string(),
            tenant_read_tokens: BTreeMap::new(),
            authority_workload_token: None,
            receipt_db_path: None,
            receipt_query_snapshot_quota_bytes: 2 * 1024 * 1024 * 1024,
            revocation_db_path: None,
            authority_seed_path: None,
            authority_db_path: None,
            authority_keyring_config_path: None,
            authority_keyring_receipt_anchor_root: None,
            budget_db_path: None,
            joint_authority_db_path: None,
            fiscal_runtime: None,
            enterprise_providers_file: None,
            federation_policies_file: None,
            scim_lifecycle_file: None,
            verifier_policies_file: None,
            verifier_challenge_db_path: None,
            passport_statuses_file: None,
            passport_issuance_offers_file: None,
            certification_registry_file: None,
            certification_discovery_file: None,
            issuance_policy: None,
            runtime_assurance_policy: None,
            advertise_url: None,
            allow_local_peer_urls: true,
            certification_public_metadata_ttl_seconds: 300,
            peer_urls: Vec::new(),
            cluster_sync_interval: Duration::from_millis(25),
            roster_policy: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            finding_market: Some(market),
        },
        authority_keyring: None,
        authority_keyring_seed_path: None,
        joint_authority_store: Some(authority),
        fiscal_runtime: None,
        budget_store: None,
        revocation_store: None,
        receipt_store: None,
        receipt_query_snapshots: None,
        receipt_query_lane: Arc::new(tokio::sync::Semaphore::new(4)),
        evidence_export_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        enterprise_provider_registry: None,
        verifier_policy_registry: None,
        federation_admission_rate_limiter: Arc::default(),
        cluster: None,
        cluster_progress: None,
        leader_forward_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        finding_rail: None,
        finding_purchase_executor: None,
        finding_purchase_execution_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        finding_proof_egress_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        finding_seller_submission_executor: None,
        finding_seller_submission_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        finding_challenge_submission_lane: Arc::new(tokio::sync::Semaphore::new(1)),
        finding_authority_status_resolver: None,
        finding_challenge_executor: None,
    }
}

#[cfg(test)]
#[path = "finding_status_handlers/tests.rs"]
mod tests;
