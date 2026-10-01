use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt;

use chio_core_types::{canonical_json_bytes, sha256, PublicKey, SignedDeclassificationGrant};
use chio_security_types::flow::{DeclassificationPurpose, InformationLabel, PrincipalId};
use chio_security_types::ports::{
    CanonicalBody, DestinationId, Digest32, GrantId, RecordId, SessionId, TenantId,
};
#[cfg(any(feature = "std", test))]
use chio_security_types::ports::{
    DeclassificationConsume, DeclassificationConsumeRequest, DeclassificationOutcomeRequest,
    DeclassificationUseState, DeclassificationUseStore,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclassificationVerificationRequest {
    pub capability_id: RecordId,
    pub tenant_id: TenantId,
    pub subject_id: PrincipalId,
    pub agent_id: RecordId,
    pub session_id: SessionId,
    pub source_label: InformationLabel,
    pub destination_id: DestinationId,
    pub tool_name: RecordId,
    pub purpose: DeclassificationPurpose,
    pub policy_purposes: BTreeSet<DeclassificationPurpose>,
    pub manifest_purposes: BTreeSet<DeclassificationPurpose>,
    pub canonical_request: CanonicalBody,
    pub now_unix_ms: u64,
    pub trusted_authorities: BTreeMap<RecordId, PublicKey>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedDeclassification {
    grant_id: GrantId,
    capability_id: RecordId,
    tenant_id: TenantId,
    subject_id: PrincipalId,
    agent_id: RecordId,
    session_id: SessionId,
    request_hash: Digest32,
    source_label_hash: Digest32,
    target_label: InformationLabel,
    destination_id: DestinationId,
    tool_name: RecordId,
    purpose: DeclassificationPurpose,
    authority_key_id: RecordId,
    authority_key: PublicKey,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

#[cfg(any(feature = "std", test))]
#[derive(Debug, Eq, PartialEq)]
pub struct ConsumedDeclassification {
    grant_id: GrantId,
    tenant_id: TenantId,
    request_hash: Digest32,
    source_label_hash: Digest32,
    target_label: InformationLabel,
    destination_id: DestinationId,
    purpose: DeclassificationPurpose,
}

#[cfg(any(feature = "std", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeclassificationDispatchOutcome {
    /// Connector execution completed and output release was authorized.
    Released,
    /// Connector entry was never reached, so non-delivery is established.
    DispatchFailed,
    /// Connector entry occurred, but delivery or side effects are not known.
    OutcomeUnknownAfterDispatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeclassificationError {
    InvalidGrant,
    InvalidRequestRepresentation,
    BindingMismatch,
    PurposeDenied,
    NotYetValid,
    Expired,
    UntrustedAuthority,
    InvalidSignature,
    TopSource,
    InvalidTarget,
    NoOpTarget,
    AlreadyConsumed,
    StoreFailure,
}

impl fmt::Display for DeclassificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidGrant => "declassification grant is invalid",
            Self::InvalidRequestRepresentation => {
                "declassification request representation is not canonical"
            }
            Self::BindingMismatch => "declassification grant binding does not match",
            Self::PurposeDenied => "declassification purpose is not effective",
            Self::NotYetValid => "declassification grant is not yet valid",
            Self::Expired => "declassification grant is expired",
            Self::UntrustedAuthority => "declassification authority is not trusted",
            Self::InvalidSignature => "declassification signature is invalid",
            Self::TopSource => "top cannot be declassified",
            Self::InvalidTarget => "declassification target is not a strict downgrade",
            Self::NoOpTarget => "declassification target equals the source",
            Self::AlreadyConsumed => "declassification grant is already consumed",
            Self::StoreFailure => "declassification state store failed",
        })
    }
}

impl core::error::Error for DeclassificationError {}

impl VerifiedDeclassification {
    #[must_use]
    pub const fn grant_id(&self) -> &GrantId {
        &self.grant_id
    }

    #[must_use]
    pub const fn capability_id(&self) -> &RecordId {
        &self.capability_id
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn subject_id(&self) -> &PrincipalId {
        &self.subject_id
    }

    #[must_use]
    pub const fn agent_id(&self) -> &RecordId {
        &self.agent_id
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn request_hash(&self) -> Digest32 {
        self.request_hash
    }

    #[must_use]
    pub const fn source_label_hash(&self) -> Digest32 {
        self.source_label_hash
    }

    #[must_use]
    pub const fn target_label(&self) -> &InformationLabel {
        &self.target_label
    }

    #[must_use]
    pub const fn destination_id(&self) -> &DestinationId {
        &self.destination_id
    }

    #[must_use]
    pub const fn tool_name(&self) -> &RecordId {
        &self.tool_name
    }

    #[must_use]
    pub const fn purpose(&self) -> &DeclassificationPurpose {
        &self.purpose
    }

    #[must_use]
    pub const fn authority_key_id(&self) -> &RecordId {
        &self.authority_key_id
    }

    #[must_use]
    pub const fn authority_key(&self) -> &PublicKey {
        &self.authority_key
    }

    #[must_use]
    pub const fn issued_at_unix_seconds(&self) -> u64 {
        self.issued_at_unix_seconds
    }

    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    #[cfg(any(feature = "std", test))]
    pub(crate) fn consume(
        self,
        store: &dyn DeclassificationUseStore,
        consumed_at_unix_ms: u64,
    ) -> Result<ConsumedDeclassification, DeclassificationError> {
        let grant_expires_at_unix_ms = self
            .expires_at_unix_seconds
            .checked_mul(1_000)
            .ok_or(DeclassificationError::StoreFailure)?;
        let outcome = store
            .consume(&DeclassificationConsumeRequest {
                tenant_id: self.tenant_id.clone(),
                grant_id: self.grant_id.clone(),
                request_hash: self.request_hash,
                consumed_at_unix_ms,
                grant_expires_at_unix_ms,
            })
            .map_err(|_| DeclassificationError::StoreFailure)?;
        if !declassification_consume_is_fresh(&outcome) {
            return Err(DeclassificationError::AlreadyConsumed);
        }
        Ok(ConsumedDeclassification {
            grant_id: self.grant_id,
            tenant_id: self.tenant_id,
            request_hash: self.request_hash,
            source_label_hash: self.source_label_hash,
            target_label: self.target_label,
            destination_id: self.destination_id,
            purpose: self.purpose,
        })
    }
}

#[cfg(any(feature = "std", test))]
fn declassification_consume_is_fresh(outcome: &DeclassificationConsume) -> bool {
    matches!(outcome, DeclassificationConsume::Consumed)
}

#[cfg(any(feature = "std", test))]
impl ConsumedDeclassification {
    #[must_use]
    pub const fn grant_id(&self) -> &GrantId {
        &self.grant_id
    }

    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    #[must_use]
    pub const fn request_hash(&self) -> Digest32 {
        self.request_hash
    }

    #[must_use]
    pub const fn source_label_hash(&self) -> Digest32 {
        self.source_label_hash
    }

    #[must_use]
    pub const fn target_label(&self) -> &InformationLabel {
        &self.target_label
    }

    #[must_use]
    pub const fn destination_id(&self) -> &DestinationId {
        &self.destination_id
    }

    #[must_use]
    pub const fn purpose(&self) -> &DeclassificationPurpose {
        &self.purpose
    }

    pub fn record_dispatch_outcome(
        &self,
        store: &dyn DeclassificationUseStore,
        outcome: DeclassificationDispatchOutcome,
        transition_id: RecordId,
    ) -> Result<(), DeclassificationError> {
        let new_state = match outcome {
            DeclassificationDispatchOutcome::Released => DeclassificationUseState::Released,
            DeclassificationDispatchOutcome::DispatchFailed => {
                DeclassificationUseState::DispatchFailed
            }
            DeclassificationDispatchOutcome::OutcomeUnknownAfterDispatch => {
                DeclassificationUseState::OutcomeUnknown
            }
        };
        store
            .record_outcome(&DeclassificationOutcomeRequest {
                tenant_id: self.tenant_id.clone(),
                grant_id: self.grant_id.clone(),
                request_hash: self.request_hash,
                expected_state: DeclassificationUseState::ConsumedPendingDispatch,
                new_state,
                transition_id,
            })
            .map_err(|_| DeclassificationError::StoreFailure)
    }
}

pub fn verify_declassification(
    grant: &SignedDeclassificationGrant,
    request: &DeclassificationVerificationRequest,
) -> Result<VerifiedDeclassification, DeclassificationError> {
    let body = grant.body();
    body.validate()
        .map_err(|_| DeclassificationError::InvalidGrant)?;
    let request_hash = canonical_request_hash(&request.canonical_request)?;
    let source_label_hash = information_label_hash(&request.source_label)?;
    if body.capability_id() != &request.capability_id
        || body.tenant_id() != &request.tenant_id
        || body.subject_id() != &request.subject_id
        || body.agent_id() != &request.agent_id
        || body.session_id() != &request.session_id
        || body.source_label_hash() != source_label_hash
        || body.destination_id() != &request.destination_id
        || body.tool_name() != &request.tool_name
        || body.purpose() != &request.purpose
        || body.request_hash() != request_hash
    {
        return Err(DeclassificationError::BindingMismatch);
    }
    if !request.policy_purposes.contains(body.purpose())
        || !request.manifest_purposes.contains(body.purpose())
    {
        return Err(DeclassificationError::PurposeDenied);
    }
    let now_unix_seconds = request.now_unix_ms / 1_000;
    if now_unix_seconds < body.issued_at_unix_seconds() {
        return Err(DeclassificationError::NotYetValid);
    }
    if now_unix_seconds >= body.expires_at_unix_seconds() {
        return Err(DeclassificationError::Expired);
    }
    if matches!(request.source_label, InformationLabel::Top) {
        return Err(DeclassificationError::TopSource);
    }
    if body.target_label() == &request.source_label {
        return Err(DeclassificationError::NoOpTarget);
    }
    if !body.target_label().flows_to(&request.source_label) {
        return Err(DeclassificationError::InvalidTarget);
    }
    let trusted_key = request
        .trusted_authorities
        .get(body.authority_key_id())
        .ok_or(DeclassificationError::UntrustedAuthority)?;
    if trusted_key != grant.authority_key() {
        return Err(DeclassificationError::UntrustedAuthority);
    }
    if !grant
        .verify_signature()
        .map_err(|_| DeclassificationError::InvalidSignature)?
    {
        return Err(DeclassificationError::InvalidSignature);
    }
    Ok(VerifiedDeclassification {
        grant_id: body.grant_id().clone(),
        capability_id: body.capability_id().clone(),
        tenant_id: request.tenant_id.clone(),
        subject_id: body.subject_id().clone(),
        agent_id: body.agent_id().clone(),
        session_id: body.session_id().clone(),
        request_hash,
        source_label_hash,
        target_label: body.target_label().clone(),
        destination_id: body.destination_id().clone(),
        tool_name: body.tool_name().clone(),
        purpose: body.purpose().clone(),
        authority_key_id: body.authority_key_id().clone(),
        authority_key: grant.authority_key().clone(),
        issued_at_unix_seconds: body.issued_at_unix_seconds(),
        expires_at_unix_seconds: body.expires_at_unix_seconds(),
    })
}

pub fn canonical_request_hash(body: &CanonicalBody) -> Result<Digest32, DeclassificationError> {
    let value: serde_json::Value = serde_json::from_slice(body.as_bytes())
        .map_err(|_| DeclassificationError::InvalidRequestRepresentation)?;
    let canonical = canonical_json_bytes(&value)
        .map_err(|_| DeclassificationError::InvalidRequestRepresentation)?;
    if canonical.as_slice() != body.as_bytes() {
        return Err(DeclassificationError::InvalidRequestRepresentation);
    }
    Ok(Digest32::new(*sha256(&canonical).as_bytes()))
}

pub fn information_label_hash(label: &InformationLabel) -> Result<Digest32, DeclassificationError> {
    let canonical = canonical_json_bytes(label).map_err(|_| DeclassificationError::InvalidGrant)?;
    Ok(Digest32::new(*sha256(&canonical).as_bytes()))
}

#[cfg(test)]
mod tests {
    use alloc::collections::{BTreeMap, BTreeSet};
    use alloc::vec::Vec;
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    use chio_core_types::{Keypair, SignedDeclassificationGrant};
    use chio_security_types::flow::{
        Compartment, DeclassificationPurpose, InformationLabel, PrincipalId,
    };
    use chio_security_types::ports::{
        CanonicalBody, DeclassificationConsume, DeclassificationConsumeRequest,
        DeclassificationOutcomeRequest, DeclassificationUseState, DeclassificationUseStore,
        DestinationId, Digest32, GrantId, PortError, PortResult, RecordId, SessionId, TenantId,
    };
    use chio_security_types::{DeclassificationGrantBody, DeclassificationGrantClaims};

    use super::{
        canonical_request_hash, information_label_hash, verify_declassification,
        ConsumedDeclassification, DeclassificationDispatchOutcome, DeclassificationError,
        DeclassificationVerificationRequest,
    };

    #[derive(Default)]
    struct MemoryStore {
        state: Mutex<BTreeMap<(TenantId, GrantId), (Digest32, DeclassificationUseState)>>,
        unavailable: bool,
    }

    impl DeclassificationUseStore for MemoryStore {
        fn consume(
            &self,
            request: &DeclassificationConsumeRequest,
        ) -> PortResult<DeclassificationConsume> {
            if self.unavailable {
                return Err(PortError::unavailable());
            }
            let mut state = self.state.lock().map_err(|_| PortError::unavailable())?;
            let key = (request.tenant_id.clone(), request.grant_id.clone());
            if let Some((request_hash, use_state)) = state.get(&key) {
                return Ok(DeclassificationConsume::AlreadyConsumed {
                    request_hash: *request_hash,
                    state: *use_state,
                });
            }
            state.insert(
                key,
                (
                    request.request_hash,
                    DeclassificationUseState::ConsumedPendingDispatch,
                ),
            );
            Ok(DeclassificationConsume::Consumed)
        }

        fn record_outcome(&self, request: &DeclassificationOutcomeRequest) -> PortResult<()> {
            if self.unavailable {
                return Err(PortError::unavailable());
            }
            let mut state = self.state.lock().map_err(|_| PortError::unavailable())?;
            let value = state
                .get_mut(&(request.tenant_id.clone(), request.grant_id.clone()))
                .ok_or_else(PortError::invalid_data)?;
            if value.0 != request.request_hash || value.1 != request.expected_state {
                return Err(PortError::conflict());
            }
            value.1 = request.new_state;
            Ok(())
        }
    }

    fn id(value: &str) -> RecordId {
        RecordId::new(value).unwrap_or_else(|error| panic!("identifier: {error}"))
    }

    fn label(compartments: &[&str]) -> InformationLabel {
        let owner = PrincipalId::new("owner-a").unwrap_or_else(|error| panic!("owner: {error}"));
        InformationLabel::try_known(
            BTreeMap::from([(owner.clone(), BTreeSet::from([owner]))]),
            compartments
                .iter()
                .map(|value| {
                    Compartment::new(*value).unwrap_or_else(|error| panic!("compartment: {error}"))
                })
                .collect(),
        )
        .unwrap_or_else(|error| panic!("label: {error}"))
    }

    fn request(key: &Keypair) -> DeclassificationVerificationRequest {
        DeclassificationVerificationRequest {
            capability_id: id("capability-a"),
            tenant_id: TenantId::new("tenant-a").unwrap_or_else(|error| panic!("tenant: {error}")),
            subject_id: PrincipalId::new("subject-a")
                .unwrap_or_else(|error| panic!("subject: {error}")),
            agent_id: id("agent-a"),
            session_id: SessionId::new("session-a")
                .unwrap_or_else(|error| panic!("session: {error}")),
            source_label: label(&["pii", "secret"]),
            destination_id: DestinationId::new("server-a")
                .unwrap_or_else(|error| panic!("destination: {error}")),
            tool_name: id("tool-a"),
            purpose: DeclassificationPurpose::new("support")
                .unwrap_or_else(|error| panic!("purpose: {error}")),
            policy_purposes: BTreeSet::from([DeclassificationPurpose::new("support")
                .unwrap_or_else(|error| panic!("purpose: {error}"))]),
            manifest_purposes: BTreeSet::from([DeclassificationPurpose::new("support")
                .unwrap_or_else(|error| panic!("purpose: {error}"))]),
            canonical_request: CanonicalBody::new(br#"{"amount":1}"#.to_vec())
                .unwrap_or_else(|error| panic!("request body: {error}")),
            now_unix_ms: 150_000,
            trusted_authorities: BTreeMap::from([(id("authority-a"), key.public_key())]),
        }
    }

    fn grant_with_target(
        request: &DeclassificationVerificationRequest,
        key: &Keypair,
        target_label: InformationLabel,
    ) -> SignedDeclassificationGrant {
        let body = DeclassificationGrantBody::new(DeclassificationGrantClaims {
            grant_id: GrantId::new("grant-a").unwrap_or_else(|error| panic!("grant: {error}")),
            capability_id: request.capability_id.clone(),
            tenant_id: request.tenant_id.clone(),
            subject_id: request.subject_id.clone(),
            agent_id: request.agent_id.clone(),
            session_id: request.session_id.clone(),
            source_label_hash: information_label_hash(&request.source_label)
                .unwrap_or_else(|error| panic!("source hash: {error}")),
            target_label,
            destination_id: request.destination_id.clone(),
            tool_name: request.tool_name.clone(),
            purpose: request.purpose.clone(),
            request_hash: canonical_request_hash(&request.canonical_request)
                .unwrap_or_else(|error| panic!("request hash: {error}")),
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 200,
            authority_key_id: id("authority-a"),
        })
        .unwrap_or_else(|error| panic!("grant body: {error}"));
        SignedDeclassificationGrant::sign(body, key)
            .unwrap_or_else(|error| panic!("sign grant: {error}"))
    }

    fn grant(
        request: &DeclassificationVerificationRequest,
        key: &Keypair,
    ) -> SignedDeclassificationGrant {
        grant_with_target(request, key, label(&["pii"]))
    }

    fn verify_and_consume_declassification(
        grant: &SignedDeclassificationGrant,
        request: &DeclassificationVerificationRequest,
        store: &dyn DeclassificationUseStore,
    ) -> Result<ConsumedDeclassification, DeclassificationError> {
        verify_declassification(grant, request)?.consume(store, request.now_unix_ms)
    }

    #[test]
    fn exact_grant_consumes_once_and_persists_terminal_dispatch_outcomes() {
        let key = Keypair::from_seed(&[7; 32]);
        let request = request(&key);
        let grant = grant(&request, &key);
        let store = MemoryStore::default();
        let verified = verify_and_consume_declassification(&grant, &request, &store)
            .unwrap_or_else(|error| panic!("verify: {error}"));
        assert_eq!(verified.target_label(), &label(&["pii"]));
        verified
            .record_dispatch_outcome(
                &store,
                DeclassificationDispatchOutcome::DispatchFailed,
                id("dispatch-failed-a"),
            )
            .unwrap_or_else(|error| panic!("record outcome: {error}"));
        assert_eq!(
            store
                .state
                .lock()
                .unwrap_or_else(|_| panic!("declassification state lock"))
                .values()
                .next()
                .map(|(_, state)| *state),
            Some(DeclassificationUseState::DispatchFailed)
        );
        assert_eq!(
            verify_and_consume_declassification(&grant, &request, &store),
            Err(DeclassificationError::AlreadyConsumed)
        );

        let released_store = MemoryStore::default();
        let released = verify_and_consume_declassification(&grant, &request, &released_store)
            .unwrap_or_else(|error| panic!("verify released grant: {error}"));
        released
            .record_dispatch_outcome(
                &released_store,
                DeclassificationDispatchOutcome::Released,
                id("released-a"),
            )
            .unwrap_or_else(|error| panic!("record released outcome: {error}"));
        assert_eq!(
            released_store
                .state
                .lock()
                .unwrap_or_else(|_| panic!("declassification state lock"))
                .values()
                .next()
                .map(|(_, state)| *state),
            Some(DeclassificationUseState::Released)
        );

        let unknown_store = MemoryStore::default();
        let unknown = verify_and_consume_declassification(&grant, &request, &unknown_store)
            .unwrap_or_else(|error| panic!("verify unknown-outcome grant: {error}"));
        unknown
            .record_dispatch_outcome(
                &unknown_store,
                DeclassificationDispatchOutcome::OutcomeUnknownAfterDispatch,
                id("outcome-unknown-after-dispatch-a"),
            )
            .unwrap_or_else(|error| panic!("record unknown dispatch outcome: {error}"));
        assert_eq!(
            unknown_store
                .state
                .lock()
                .unwrap_or_else(|_| panic!("declassification state lock"))
                .values()
                .next()
                .map(|(_, state)| *state),
            Some(DeclassificationUseState::OutcomeUnknown)
        );
    }

    #[test]
    fn all_static_bindings_and_store_failure_deny_before_release() {
        let key = Keypair::from_seed(&[7; 32]);
        let base = request(&key);
        let base_grant = grant(&base, &key);

        let mut mutations = Vec::new();
        let mut changed = base.clone();
        changed.capability_id = id("capability-b");
        mutations.push(changed);
        let mut changed = base.clone();
        changed.tenant_id =
            TenantId::new("tenant-b").unwrap_or_else(|error| panic!("tenant: {error}"));
        mutations.push(changed);
        let mut changed = base.clone();
        changed.subject_id =
            PrincipalId::new("subject-b").unwrap_or_else(|error| panic!("subject: {error}"));
        mutations.push(changed);
        let mut changed = base.clone();
        changed.agent_id = id("agent-b");
        mutations.push(changed);
        let mut changed = base.clone();
        changed.session_id =
            SessionId::new("session-b").unwrap_or_else(|error| panic!("session: {error}"));
        mutations.push(changed);
        let mut changed = base.clone();
        changed.destination_id =
            DestinationId::new("server-b").unwrap_or_else(|error| panic!("destination: {error}"));
        mutations.push(changed);
        let mut changed = base.clone();
        changed.tool_name = id("tool-b");
        mutations.push(changed);
        let mut changed = base.clone();
        changed.purpose = DeclassificationPurpose::new("billing")
            .unwrap_or_else(|error| panic!("purpose: {error}"));
        mutations.push(changed);
        let mut changed = base.clone();
        changed.canonical_request = CanonicalBody::new(br#"{"amount":2}"#.to_vec())
            .unwrap_or_else(|error| panic!("request body: {error}"));
        mutations.push(changed);
        let mut changed = base.clone();
        changed.source_label = label(&["pii", "secret", "tenant"]);
        mutations.push(changed);

        for mutation in mutations {
            assert_eq!(
                verify_and_consume_declassification(
                    &base_grant,
                    &mutation,
                    &MemoryStore::default()
                ),
                Err(DeclassificationError::BindingMismatch)
            );
        }

        let unavailable = MemoryStore {
            state: Mutex::new(BTreeMap::new()),
            unavailable: true,
        };
        assert_eq!(
            verify_and_consume_declassification(&base_grant, &base, &unavailable),
            Err(DeclassificationError::StoreFailure)
        );
    }

    #[test]
    fn time_purpose_trust_signature_and_label_fail_closed() {
        let key = Keypair::from_seed(&[7; 32]);
        let base = request(&key);
        let base_grant = grant(&base, &key);

        let mut not_yet_valid = base.clone();
        not_yet_valid.now_unix_ms = 99_999;
        assert_eq!(
            verify_and_consume_declassification(
                &base_grant,
                &not_yet_valid,
                &MemoryStore::default()
            ),
            Err(DeclassificationError::NotYetValid)
        );
        let mut expired = base.clone();
        expired.now_unix_ms = 200_000;
        assert_eq!(
            verify_and_consume_declassification(&base_grant, &expired, &MemoryStore::default()),
            Err(DeclassificationError::Expired)
        );
        let mut denied_purpose = base.clone();
        denied_purpose.policy_purposes.clear();
        assert_eq!(
            verify_and_consume_declassification(
                &base_grant,
                &denied_purpose,
                &MemoryStore::default()
            ),
            Err(DeclassificationError::PurposeDenied)
        );
        let mut denied_manifest_purpose = base.clone();
        denied_manifest_purpose.manifest_purposes.clear();
        assert_eq!(
            verify_and_consume_declassification(
                &base_grant,
                &denied_manifest_purpose,
                &MemoryStore::default()
            ),
            Err(DeclassificationError::PurposeDenied)
        );
        let mut untrusted = base.clone();
        untrusted.trusted_authorities.clear();
        assert_eq!(
            verify_and_consume_declassification(&base_grant, &untrusted, &MemoryStore::default()),
            Err(DeclassificationError::UntrustedAuthority)
        );
        let mut substituted = base.clone();
        substituted
            .trusted_authorities
            .insert(id("authority-a"), Keypair::from_seed(&[8; 32]).public_key());
        assert_eq!(
            verify_and_consume_declassification(&base_grant, &substituted, &MemoryStore::default()),
            Err(DeclassificationError::UntrustedAuthority)
        );

        let mut invalid_signature_value = serde_json::to_value(&base_grant)
            .unwrap_or_else(|error| panic!("serialize grant: {error}"));
        invalid_signature_value["signature"] =
            serde_json::to_value(key.sign(b"invalid declassification signature"))
                .unwrap_or_else(|error| panic!("serialize signature: {error}"));
        let invalid_signature: SignedDeclassificationGrant =
            serde_json::from_value(invalid_signature_value)
                .unwrap_or_else(|error| panic!("decode invalid signature grant: {error}"));
        assert_eq!(
            verify_and_consume_declassification(&invalid_signature, &base, &MemoryStore::default()),
            Err(DeclassificationError::InvalidSignature)
        );

        let mut target_mutation_value = serde_json::to_value(&base_grant)
            .unwrap_or_else(|error| panic!("serialize grant: {error}"));
        target_mutation_value["body"]["target_label"] = serde_json::to_value(label(&[]))
            .unwrap_or_else(|error| panic!("serialize target label: {error}"));
        let target_mutation: SignedDeclassificationGrant =
            serde_json::from_value(target_mutation_value)
                .unwrap_or_else(|error| panic!("decode target mutation: {error}"));
        assert_eq!(
            verify_and_consume_declassification(&target_mutation, &base, &MemoryStore::default()),
            Err(DeclassificationError::InvalidSignature)
        );

        let mut top_source = base.clone();
        top_source.source_label = InformationLabel::Top;
        let top_grant = grant(&top_source, &key);
        assert_eq!(
            verify_and_consume_declassification(&top_grant, &top_source, &MemoryStore::default()),
            Err(DeclassificationError::TopSource)
        );

        let no_op_grant = grant_with_target(&base, &key, base.source_label.clone());
        assert_eq!(
            verify_and_consume_declassification(&no_op_grant, &base, &MemoryStore::default()),
            Err(DeclassificationError::NoOpTarget)
        );
        let invalid_target = grant_with_target(&base, &key, label(&["pii", "secret", "extra"]));
        assert_eq!(
            verify_and_consume_declassification(&invalid_target, &base, &MemoryStore::default()),
            Err(DeclassificationError::InvalidTarget)
        );

        let mut noncanonical_request = base.clone();
        noncanonical_request.canonical_request = CanonicalBody::new(br#"{ "amount": 1 }"#.to_vec())
            .unwrap_or_else(|error| panic!("request body: {error}"));
        assert_eq!(
            verify_and_consume_declassification(
                &base_grant,
                &noncanonical_request,
                &MemoryStore::default()
            ),
            Err(DeclassificationError::InvalidRequestRepresentation)
        );
    }

    #[test]
    fn concurrent_consumers_produce_exactly_one_verified_result() {
        let key = Keypair::from_seed(&[7; 32]);
        let request = Arc::new(request(&key));
        let grant = Arc::new(grant(&request, &key));
        let store = Arc::new(MemoryStore::default());
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let request = Arc::clone(&request);
                let grant = Arc::clone(&grant);
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    verify_and_consume_declassification(&grant, &request, store.as_ref())
                })
            })
            .collect();
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|_| panic!("declassification thread panicked"))
            })
            .collect();
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| matches!(result, Err(DeclassificationError::AlreadyConsumed)))
                .count(),
            1
        );
    }
}
