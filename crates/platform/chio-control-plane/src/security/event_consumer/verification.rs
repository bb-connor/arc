use super::{
    canonical_json_bytes, json, sha256, Arc, BTreeMap, BoundaryClass, ChioReceipt, Clock,
    CorrelationEventVerifier, Deserialize, Digest32, Error, NativeSecurityEventVerifier,
    ObservationOutcome, PortError, PortResult, ProducerId, ProducerTrustClass, PublicKey,
    ReceiptKind, RecordId, RedactionMode, SecurityEventBody, SecurityEventVerificationRecord,
    SecurityEventVerifierPort, Serialize, SignedSecurityEvent, TenantId, ToolCallAction,
    ToolOrigin, TrustLevel, UnverifiedSecurityEvent,
};

pub(super) const EVENT_EVIDENCE_HASH_DOMAIN: &[u8] = b"chio.verified-security-event-evidence.v1\0";
pub(super) const RECEIPT_EVENT_EVIDENCE_HASH_DOMAIN: &[u8] =
    b"chio.verified-security-event-receipt-evidence.v1\0";
pub const SECURITY_EVENT_RECEIPT_PROJECTION_VERSION: &str =
    "chio.security-event-receipt-projection.v1";

#[derive(Clone, Debug)]
pub struct TrustedSecurityEventProducer {
    pub tenant_id: TenantId,
    pub producer_id: ProducerId,
    pub producer_key_id: RecordId,
    pub policy_version: RecordId,
    pub producer_key: PublicKey,
}

#[derive(Clone, Debug)]
pub struct TrustedSecurityEventReceiptProducer {
    pub tenant_id: TenantId,
    pub producer_id: ProducerId,
    pub signer_key_id: RecordId,
    pub signer_key: PublicKey,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityEventReceiptProjection {
    pub version: String,
    pub body: SecurityEventBody,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecurityEventVerifierConfigError {
    #[error("security event verifier requires at least one trusted producer")]
    MissingTrustedProducer,
    #[error("security event verifier has a duplicate tenant and producer binding")]
    DuplicateProducerBinding,
    #[error("security event verifier has a duplicate receipt tenant and producer binding")]
    DuplicateReceiptProducerBinding,
    #[error("security event verifier freshness bounds are invalid")]
    InvalidFreshnessBounds,
}

impl NativeSecurityEventVerifier {
    pub fn new(
        clock: Arc<dyn Clock>,
        producers: Vec<TrustedSecurityEventProducer>,
        receipt_producers: Vec<TrustedSecurityEventReceiptProducer>,
        max_event_age_ms: u64,
        max_future_skew_ms: u64,
    ) -> Result<Self, SecurityEventVerifierConfigError> {
        if producers.is_empty() && receipt_producers.is_empty() {
            return Err(SecurityEventVerifierConfigError::MissingTrustedProducer);
        }
        if max_event_age_ms == 0 || max_future_skew_ms > max_event_age_ms {
            return Err(SecurityEventVerifierConfigError::InvalidFreshnessBounds);
        }
        let mut trusted = BTreeMap::new();
        for producer in producers {
            let key = (producer.tenant_id.clone(), producer.producer_id.clone());
            if trusted.insert(key, producer).is_some() {
                return Err(SecurityEventVerifierConfigError::DuplicateProducerBinding);
            }
        }
        let mut trusted_receipts = BTreeMap::new();
        for producer in receipt_producers {
            let key = (producer.tenant_id.clone(), producer.producer_id.clone());
            if trusted_receipts.insert(key, producer).is_some() {
                return Err(SecurityEventVerifierConfigError::DuplicateReceiptProducerBinding);
            }
        }
        Ok(Self {
            clock,
            trusted,
            trusted_receipts,
            max_event_age_ms,
            max_future_skew_ms,
        })
    }

    pub fn ensure_ready(&self) -> PortResult<()> {
        if self.trusted.is_empty() && self.trusted_receipts.is_empty() {
            return Err(PortError::integrity_failure());
        }
        self.clock
            .unix_millis()
            .map(chio_security_types::clock::UnixMillis::get)
            .map(|_| ())
            .map_err(PortError::from)
    }

    fn verify_time_bounds(
        &self,
        event_time_unix_ms: u64,
        received_at_unix_ms: u64,
    ) -> PortResult<()> {
        let now_unix_ms = self
            .clock
            .unix_millis()
            .map(chio_security_types::clock::UnixMillis::get)?;
        let latest = now_unix_ms
            .checked_add(self.max_future_skew_ms)
            .ok_or_else(PortError::invalid_data)?;
        if event_time_unix_ms > latest
            || received_at_unix_ms > latest
            || now_unix_ms.saturating_sub(event_time_unix_ms) > self.max_event_age_ms
            || received_at_unix_ms.saturating_sub(event_time_unix_ms) > self.max_event_age_ms
        {
            return Err(PortError::invalid_data());
        }
        Ok(())
    }

    fn verified_event(
        &self,
        event: &UnverifiedSecurityEvent,
        trust_class: ProducerTrustClass,
        evidence_hash: Digest32,
    ) -> SecurityEventVerificationRecord {
        SecurityEventVerificationRecord {
            tenant_id: event.tenant_id.clone(),
            event_id: event.event_id.clone(),
            producer_id: event.producer_id.clone(),
            trust_class,
            event_time_unix_ms: event.event_time_unix_ms,
            received_at_unix_ms: event.received_at_unix_ms,
            canonical_body: event.canonical_body.clone(),
            body_hash: event.body_hash,
            evidence_hash,
        }
    }

    fn parse_bound_body(&self, event: &UnverifiedSecurityEvent) -> PortResult<SecurityEventBody> {
        let body: SecurityEventBody = chio_core::canonical::UntrustedJsonText::from_wire(
            event.canonical_body.as_bytes(),
            64 * 1024 * 1024,
        )
        .and_then(|input| input.decode_signed())
        .map_err(|error| {
            PortError::with_source(
                chio_security_types::ports::PortErrorKind::InvalidData,
                error.code(),
                error,
            )
        })?;
        body.validate().map_err(|_| PortError::invalid_data())?;
        let canonical_body = canonical_json_bytes(&body).map_err(|_| PortError::invalid_data())?;
        let body_hash = Digest32::new(*sha256(&canonical_body).as_bytes());
        if canonical_body.as_slice() != event.canonical_body.as_bytes()
            || body_hash != event.body_hash
            || body.tenant_id != event.tenant_id
            || body.event_id != event.event_id
            || body.producer_id != event.producer_id
            || body.event_time_unix_ms != event.event_time_unix_ms
            || body.ingest_time_unix_ms != event.received_at_unix_ms
        {
            return Err(PortError::integrity_failure());
        }
        Ok(body)
    }

    fn verify_internal_event(
        &self,
        event: &UnverifiedSecurityEvent,
        body: &SecurityEventBody,
        enforce_freshness: bool,
    ) -> PortResult<SecurityEventVerificationRecord> {
        let signed: SignedSecurityEvent = chio_core::canonical::UntrustedJsonText::from_wire(
            event.source_evidence.as_bytes(),
            64 * 1024 * 1024,
        )
        .and_then(|input| input.decode_signed())
        .map_err(|error| {
            PortError::with_source(
                chio_security_types::ports::PortErrorKind::InvalidData,
                error.code(),
                error,
            )
        })?;
        let canonical_signed =
            canonical_json_bytes(&signed).map_err(|_| PortError::invalid_data())?;
        let trusted = self
            .trusted
            .get(&(event.tenant_id.clone(), event.producer_id.clone()))
            .ok_or_else(PortError::integrity_failure)?;
        let signature_valid = signed
            .verify_trusted_producer(
                &trusted.producer_id,
                &trusted.producer_key_id,
                &trusted.producer_key,
            )
            .map_err(|_| PortError::integrity_failure())?;
        if canonical_signed.as_slice() != event.source_evidence.as_bytes()
            || !signature_valid
            || signed.body() != body
            || body.policy_version != trusted.policy_version
            || body.trust_class != ProducerTrustClass::InternalDetector
        {
            return Err(PortError::integrity_failure());
        }
        if enforce_freshness {
            self.verify_time_bounds(event.event_time_unix_ms, event.received_at_unix_ms)?;
        }
        Ok(self.verified_event(
            event,
            ProducerTrustClass::InternalDetector,
            domain_hash(EVENT_EVIDENCE_HASH_DOMAIN, &canonical_signed),
        ))
    }

    fn verify_receipt_event(
        &self,
        event: &UnverifiedSecurityEvent,
        body: &SecurityEventBody,
        enforce_freshness: bool,
    ) -> PortResult<SecurityEventVerificationRecord> {
        let receipt: ChioReceipt = chio_core::canonical::UntrustedJsonText::from_wire(
            event.source_evidence.as_bytes(),
            64 * 1024 * 1024,
        )
        .and_then(|input| input.decode_signed())
        .map_err(|error| {
            PortError::with_source(
                chio_security_types::ports::PortErrorKind::InvalidData,
                error.code(),
                error,
            )
        })?;
        let canonical_receipt =
            canonical_json_bytes(&receipt).map_err(|_| PortError::invalid_data())?;
        let trusted = self
            .trusted_receipts
            .get(&(event.tenant_id.clone(), event.producer_id.clone()))
            .ok_or_else(PortError::integrity_failure)?;
        let signature_valid = receipt
            .verify_signature()
            .map_err(|_| PortError::integrity_failure())?;
        let projection_value = receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("security_event_projection"))
            .cloned()
            .ok_or_else(PortError::integrity_failure)?;
        let projection: SecurityEventReceiptProjection =
            serde_json::from_value(projection_value).map_err(|_| PortError::integrity_failure())?;
        let expected_action = ToolCallAction::from_parameters(json!({
            "event_id": body.event_id.as_str(),
            "producer_id": body.producer_id.as_str(),
            "projection_version": SECURITY_EVENT_RECEIPT_PROJECTION_VERSION,
        }))
        .map_err(|_| PortError::invalid_data())?;
        let expected_metadata = json!({"security_event_projection": projection});
        let expected_content_hash = hex::encode(event.body_hash.as_bytes());
        if canonical_receipt.as_slice() != event.source_evidence.as_bytes()
            || !signature_valid
            || receipt.kernel_key != trusted.signer_key
            || body.producer_key_id != trusted.signer_key_id
            || body.trust_class != ProducerTrustClass::VerifiedReceipt
            || projection.version != SECURITY_EVENT_RECEIPT_PROJECTION_VERSION
            || projection.body != *body
            || receipt.timestamp != body.ingest_time_unix_ms / 1_000
            || receipt.capability_id != "chio.security-event.projection"
            || receipt.tool_server != "chio.kernel"
            || receipt.tool_name != "security_event"
            || receipt.action.parameters != expected_action.parameters
            || receipt.action.parameter_hash != expected_action.parameter_hash
            || receipt.decision.is_some()
            || receipt.receipt_kind != ReceiptKind::TraceObservation
            || receipt.boundary_class != BoundaryClass::DetectOnly
            || receipt.observation_outcome != Some(ObservationOutcome::Observed)
            || receipt.tool_origin != ToolOrigin::ChioInternal
            || receipt.redaction_mode != RedactionMode::Redacted
            || !receipt.actor_chain.is_empty()
            || !receipt.evidence.is_empty()
            || receipt.metadata.as_ref() != Some(&expected_metadata)
            || receipt.trust_level != TrustLevel::Verified
            || receipt.tenant_id.as_deref() != Some(body.tenant_id.as_str())
            || receipt.content_hash != expected_content_hash
            || receipt.bbs_projection_version.is_some()
            || receipt.bbs_signature.is_some()
        {
            return Err(PortError::integrity_failure());
        }
        if enforce_freshness {
            self.verify_time_bounds(event.event_time_unix_ms, event.received_at_unix_ms)?;
        }
        Ok(self.verified_event(
            event,
            ProducerTrustClass::VerifiedReceipt,
            domain_hash(RECEIPT_EVENT_EVIDENCE_HASH_DOMAIN, &canonical_receipt),
        ))
    }

    fn verify_durable(
        &self,
        event: &UnverifiedSecurityEvent,
    ) -> PortResult<SecurityEventVerificationRecord> {
        self.ensure_ready()?;
        let body = self.parse_bound_body(event)?;
        match body.trust_class {
            ProducerTrustClass::InternalDetector => self.verify_internal_event(event, &body, false),
            ProducerTrustClass::VerifiedReceipt => self.verify_receipt_event(event, &body, false),
        }
    }
}

impl SecurityEventVerifierPort for NativeSecurityEventVerifier {
    fn verify(
        &self,
        event: &UnverifiedSecurityEvent,
    ) -> PortResult<SecurityEventVerificationRecord> {
        self.ensure_ready()?;
        let body = self.parse_bound_body(event)?;
        match body.trust_class {
            ProducerTrustClass::InternalDetector => self.verify_internal_event(event, &body, true),
            ProducerTrustClass::VerifiedReceipt => self.verify_receipt_event(event, &body, true),
        }
    }
}

pub(super) fn domain_hash(domain: &[u8], bytes: &[u8]) -> Digest32 {
    let mut preimage = Vec::with_capacity(domain.len() + bytes.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(bytes);
    Digest32::new(*sha256(&preimage).as_bytes())
}

impl CorrelationEventVerifier for NativeSecurityEventVerifier {
    fn ensure_ready(&self) -> PortResult<()> {
        NativeSecurityEventVerifier::ensure_ready(self)
    }

    fn now_unix_ms(&self) -> PortResult<u64> {
        self.clock
            .unix_millis()
            .map(chio_security_types::clock::UnixMillis::get)
            .map_err(PortError::from)
    }

    fn verify(
        &self,
        event: &UnverifiedSecurityEvent,
    ) -> PortResult<SecurityEventVerificationRecord> {
        SecurityEventVerifierPort::verify(self, event)
    }

    fn verify_durable(
        &self,
        event: &UnverifiedSecurityEvent,
    ) -> PortResult<SecurityEventVerificationRecord> {
        NativeSecurityEventVerifier::verify_durable(self, event)
    }
}
