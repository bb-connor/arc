use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chio_core_types::{
    canonical_json_bytes, leaf_hash, sha256, Hash, PublicKey, Signature, SigningAlgorithm,
    SigningBackend,
};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{KeyringError, Result};

pub const KEY_LOG_EVENT_SCHEMA: &str = "chio.key-log.event.v1";
const KEY_ID_SCHEMA: &str = "chio.key-log.key-id.v1";
const KEY_ID_DOMAIN: &[u8] = b"chio.key-log.key-id.v1\0";
const EVENT_SIGNATURE_DOMAIN: &[u8] = b"chio.key-log.event-signature.v1\0";
const EVENT_ENVELOPE_HASH_DOMAIN: &[u8] = b"chio.key-log.event-envelope.v1\0";
const MAX_IDENTIFIER_LENGTH: usize = 128;
const MAX_REASON_LENGTH: usize = 512;
pub const MAX_RECOVERY_AUTHORIZATIONS: usize = 64;

macro_rules! identifier_type {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                validate_identifier(&value, $kind)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct IdentifierVisitor;

                impl Visitor<'_> for IdentifierVisitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str(concat!("a valid ", $kind))
                    }

                    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        $name::new(value.to_string()).map_err(E::custom)
                    }
                }

                deserializer.deserialize_str(IdentifierVisitor)
            }
        }
    };
}

identifier_type!(LogId, "log identifier");
identifier_type!(EventId, "event identifier");
identifier_type!(AuthorityId, "authority identifier");
identifier_type!(WitnessRosterId, "witness roster identifier");
identifier_type!(WitnessId, "witness identifier");
identifier_type!(RecoveryPolicyId, "recovery policy identifier");
identifier_type!(RecoveryAuthorizerId, "recovery authorizer identifier");
identifier_type!(AnchorId, "time anchor identifier");

fn validate_identifier(value: &str, kind: &'static str) -> Result<()> {
    if value.is_empty() {
        return Err(KeyringError::InvalidIdentifier {
            kind,
            reason: "value is empty",
        });
    }
    if value.len() > MAX_IDENTIFIER_LENGTH {
        return Err(KeyringError::InvalidIdentifier {
            kind,
            reason: "value exceeds 128 bytes",
        });
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
    }) {
        return Err(KeyringError::InvalidIdentifier {
            kind,
            reason: "value contains an unsupported character",
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyId(Hash);

impl KeyId {
    #[must_use]
    pub fn from_hash(hash: Hash) -> Self {
        Self(hash)
    }

    #[must_use]
    pub fn hash(&self) -> Hash {
        self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl PartialOrd for KeyId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KeyId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct EventReason(String);

impl EventReason {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_REASON_LENGTH
            || value.chars().any(char::is_control)
        {
            return Err(KeyringError::InvalidIdentifier {
                kind: "event reason",
                reason: "value must contain 1 to 512 printable bytes",
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for EventReason {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ReasonVisitor;

        impl Visitor<'_> for ReasonVisitor {
            type Value = EventReason;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a printable event reason of at most 512 bytes")
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                EventReason::new(value.to_string()).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(ReasonVisitor)
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct KeyIdInput<'a> {
    schema: &'static str,
    algorithm: SigningAlgorithm,
    public_key: &'a PublicKey,
}

pub fn derive_key_id(algorithm: SigningAlgorithm, public_key: &PublicKey) -> Result<KeyId> {
    if public_key.algorithm() != algorithm {
        return Err(KeyringError::AlgorithmMismatch);
    }
    let canonical = canonical_json_bytes(&KeyIdInput {
        schema: KEY_ID_SCHEMA,
        algorithm,
        public_key,
    })?;
    Ok(KeyId(domain_hash(KEY_ID_DOMAIN, &canonical)?))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeyLogOperation {
    Genesis,
    Rotate {
        previous_key_id: KeyId,
        witness_roster_id: WitnessRosterId,
        witness_roster_binding: Hash,
    },
    AbortRotation {
        previous_key_id: KeyId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recovery_policy_id: Option<RecoveryPolicyId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recovery_policy_binding: Option<Hash>,
    },
    Retire,
    Revoke,
    Recover {
        previous_key_id: KeyId,
        witness_roster_id: WitnessRosterId,
        witness_roster_binding: Hash,
        recovery_policy_id: RecoveryPolicyId,
        recovery_policy_binding: Hash,
    },
}

impl KeyLogOperation {
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Genesis => "genesis",
            Self::Rotate { .. } => "rotate",
            Self::AbortRotation { .. } => "abort_rotation",
            Self::Retire => "retire",
            Self::Revoke => "revoke",
            Self::Recover { .. } => "recover",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyLogEventBody {
    pub schema: String,
    pub log_id: LogId,
    pub sequence: u64,
    pub event_id: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_event_hash: Option<Hash>,
    pub authority_id: AuthorityId,
    pub key_id: KeyId,
    pub algorithm: SigningAlgorithm,
    pub public_key: PublicKey,
    pub operation: KeyLogOperation,
    pub effective_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_until: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<EventReason>,
    pub issued_at: u64,
}

impl KeyLogEventBody {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        domain_canonical_bytes(EVENT_SIGNATURE_DOMAIN, self)
    }
}

macro_rules! key_authorization {
    ($name:ident) => {
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            pub key_id: KeyId,
            pub algorithm: SigningAlgorithm,
            pub signature: Signature,
        }

        impl $name {
            pub fn sign(body: &KeyLogEventBody, backend: &dyn SigningBackend) -> Result<Self> {
                let outcome = backend.sign_bytes_with_identity(&body.signing_bytes()?)?;
                let key_id = derive_key_id(outcome.algorithm, &outcome.public_key)?;
                if outcome.signature.algorithm() != outcome.algorithm {
                    return Err(KeyringError::AlgorithmMismatch);
                }
                Ok(Self {
                    key_id,
                    algorithm: outcome.algorithm,
                    signature: outcome.signature,
                })
            }
        }
    };
}

key_authorization!(BootstrapAuthorization);
key_authorization!(OldKeyAuthorization);
key_authorization!(NewKeyProofOfPossession);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAuthorization {
    pub authorizer_id: RecoveryAuthorizerId,
    pub algorithm: SigningAlgorithm,
    pub signature: Signature,
}

impl RecoveryAuthorization {
    pub fn sign(
        body: &KeyLogEventBody,
        authorizer_id: RecoveryAuthorizerId,
        backend: &dyn SigningBackend,
    ) -> Result<Self> {
        let outcome = backend.sign_bytes_with_identity(&body.signing_bytes()?)?;
        let algorithm = outcome.algorithm;
        let signature = outcome.signature;
        if signature.algorithm() != algorithm {
            return Err(KeyringError::AlgorithmMismatch);
        }
        Ok(Self {
            authorizer_id,
            algorithm,
            signature,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyLogAuthorizations {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap: Option<BootstrapAuthorization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_key: Option<OldKeyAuthorization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_key: Option<NewKeyProofOfPossession>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recovery: Vec<RecoveryAuthorization>,
}

impl KeyLogAuthorizations {
    #[must_use]
    pub fn bootstrap(authorization: BootstrapAuthorization) -> Self {
        Self {
            bootstrap: Some(authorization),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn rotation(old_key: OldKeyAuthorization, new_key: NewKeyProofOfPossession) -> Self {
        Self {
            old_key: Some(old_key),
            new_key: Some(new_key),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn recovery(mut authorizations: Vec<RecoveryAuthorization>) -> Self {
        authorizations.sort_by(|left, right| left.authorizer_id.cmp(&right.authorizer_id));
        Self {
            recovery: authorizations,
            ..Self::default()
        }
    }

    fn is_bootstrap_only(&self) -> bool {
        self.bootstrap.is_some()
            && self.old_key.is_none()
            && self.new_key.is_none()
            && self.recovery.is_empty()
    }

    fn is_rotation_only(&self) -> bool {
        self.bootstrap.is_none()
            && self.old_key.is_some()
            && self.new_key.is_some()
            && self.recovery.is_empty()
    }

    fn is_active_key_only(&self) -> bool {
        self.bootstrap.is_none()
            && self.old_key.is_some()
            && self.new_key.is_none()
            && self.recovery.is_empty()
    }

    fn is_recovery_only(&self) -> bool {
        self.bootstrap.is_none()
            && self.old_key.is_none()
            && self.new_key.is_none()
            && !self.recovery.is_empty()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyLogAuthorizationsWire {
    #[serde(default)]
    bootstrap: Option<BootstrapAuthorization>,
    #[serde(default)]
    old_key: Option<OldKeyAuthorization>,
    #[serde(default)]
    new_key: Option<NewKeyProofOfPossession>,
    #[serde(default, deserialize_with = "deserialize_recovery_authorizations")]
    recovery: Vec<RecoveryAuthorization>,
}

impl<'de> Deserialize<'de> for KeyLogAuthorizations {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = KeyLogAuthorizationsWire::deserialize(deserializer)?;
        if wire
            .recovery
            .windows(2)
            .any(|pair| pair[0].authorizer_id >= pair[1].authorizer_id)
        {
            return Err(serde::de::Error::custom(
                "recovery authorizations must be unique and sorted by authorizer identifier",
            ));
        }
        Ok(Self {
            bootstrap: wire.bootstrap,
            old_key: wire.old_key,
            new_key: wire.new_key,
            recovery: wire.recovery,
        })
    }
}

fn deserialize_recovery_authorizations<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<RecoveryAuthorization>, D::Error>
where
    D: Deserializer<'de>,
{
    struct RecoveryVisitor;

    impl<'de> Visitor<'de> for RecoveryVisitor {
        type Value = Vec<RecoveryAuthorization>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("at most 64 sorted recovery authorizations")
        }

        fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence
                .size_hint()
                .is_some_and(|size| size > MAX_RECOVERY_AUTHORIZATIONS)
            {
                return Err(serde::de::Error::custom(
                    "recovery authorization count exceeds 64",
                ));
            }
            let capacity = sequence
                .size_hint()
                .unwrap_or(0)
                .min(MAX_RECOVERY_AUTHORIZATIONS);
            let mut authorizations = Vec::with_capacity(capacity);
            while let Some(authorization) = sequence.next_element()? {
                if authorizations.len() == MAX_RECOVERY_AUTHORIZATIONS {
                    return Err(serde::de::Error::custom(
                        "recovery authorization count exceeds 64",
                    ));
                }
                authorizations.push(authorization);
            }
            Ok(authorizations)
        }
    }

    deserializer.deserialize_seq(RecoveryVisitor)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedKeyLogEvent {
    pub body: KeyLogEventBody,
    pub authorizations: KeyLogAuthorizations,
}

impl SignedKeyLogEvent {
    pub fn from_canonical_envelope_bytes(bytes: &[u8]) -> Result<Self> {
        crate::from_bounded_json(bytes)
    }

    pub fn canonical_envelope_bytes(&self) -> Result<Vec<u8>> {
        Ok(canonical_json_bytes(self)?)
    }

    pub fn envelope_hash(&self) -> Result<Hash> {
        domain_hash(
            EVENT_ENVELOPE_HASH_DOMAIN,
            &self.canonical_envelope_bytes()?,
        )
    }

    pub fn merkle_leaf_hash(&self) -> Result<Hash> {
        Ok(leaf_hash(&self.canonical_envelope_bytes()?))
    }

    pub fn validate_common(
        &self,
        expected_sequence: u64,
        expected_previous: Option<&Hash>,
        expected_log_id: &LogId,
        expected_authority_id: &AuthorityId,
        last_issued_at: Option<u64>,
    ) -> Result<()> {
        if self.body.schema != KEY_LOG_EVENT_SCHEMA {
            return Err(KeyringError::UnsupportedSchema(self.body.schema.clone()));
        }
        if &self.body.log_id != expected_log_id || &self.body.authority_id != expected_authority_id
        {
            return Err(KeyringError::IdentityMismatch);
        }
        if self.body.sequence != expected_sequence {
            return Err(KeyringError::SequenceMismatch {
                expected: expected_sequence,
                actual: self.body.sequence,
            });
        }
        if self.body.previous_event_hash.as_ref() != expected_previous {
            return Err(KeyringError::PredecessorMismatch);
        }
        if self.body.effective_at < self.body.issued_at
            || self
                .body
                .verify_until
                .is_some_and(|until| until <= self.body.effective_at)
            || last_issued_at.is_some_and(|last| self.body.issued_at < last)
        {
            return Err(KeyringError::InvalidTimeOrdering);
        }
        if self.body.public_key.algorithm() != self.body.algorithm {
            return Err(KeyringError::AlgorithmMismatch);
        }
        if derive_key_id(self.body.algorithm, &self.body.public_key)? != self.body.key_id {
            return Err(KeyringError::KeyIdMismatch);
        }
        Ok(())
    }

    pub fn verify_genesis(&self, bootstrap_key: &PublicKey) -> Result<()> {
        if !matches!(self.body.operation, KeyLogOperation::Genesis)
            || !self.authorizations.is_bootstrap_only()
        {
            return Err(KeyringError::InvalidAuthorizationSet);
        }
        let authorization = self
            .authorizations
            .bootstrap
            .as_ref()
            .ok_or(KeyringError::InvalidAuthorizationSet)?;
        verify_key_authorization(
            bootstrap_key,
            authorization.key_id,
            authorization.algorithm,
            &authorization.signature,
            &self.body.signing_bytes()?,
        )
    }

    pub fn verify_rotation(&self, old_key: &PublicKey) -> Result<()> {
        let KeyLogOperation::Rotate {
            previous_key_id, ..
        } = &self.body.operation
        else {
            return Err(KeyringError::InvalidAuthorizationSet);
        };
        if !self.authorizations.is_rotation_only()
            || derive_key_id(old_key.algorithm(), old_key)? != *previous_key_id
        {
            return Err(KeyringError::InvalidAuthorizationSet);
        }
        let bytes = self.body.signing_bytes()?;
        let old_authorization = self
            .authorizations
            .old_key
            .as_ref()
            .ok_or(KeyringError::InvalidAuthorizationSet)?;
        verify_key_authorization(
            old_key,
            old_authorization.key_id,
            old_authorization.algorithm,
            &old_authorization.signature,
            &bytes,
        )?;
        let new_authorization = self
            .authorizations
            .new_key
            .as_ref()
            .ok_or(KeyringError::InvalidAuthorizationSet)?;
        verify_key_authorization(
            &self.body.public_key,
            new_authorization.key_id,
            new_authorization.algorithm,
            &new_authorization.signature,
            &bytes,
        )
    }

    pub(crate) fn verify_active_key_authorization(&self, active_key: &PublicKey) -> Result<()> {
        if !self.authorizations.is_active_key_only() {
            return Err(KeyringError::InvalidAuthorizationSet);
        }
        let authorization = self
            .authorizations
            .old_key
            .as_ref()
            .ok_or(KeyringError::InvalidAuthorizationSet)?;
        verify_key_authorization(
            active_key,
            authorization.key_id,
            authorization.algorithm,
            &authorization.signature,
            &self.body.signing_bytes()?,
        )
    }

    pub(crate) fn verify_dual_key_authorization(
        &self,
        old_key: &PublicKey,
        new_key: &PublicKey,
    ) -> Result<()> {
        if !self.authorizations.is_rotation_only() {
            return Err(KeyringError::InvalidAuthorizationSet);
        }
        let bytes = self.body.signing_bytes()?;
        let old_authorization = self
            .authorizations
            .old_key
            .as_ref()
            .ok_or(KeyringError::InvalidAuthorizationSet)?;
        verify_key_authorization(
            old_key,
            old_authorization.key_id,
            old_authorization.algorithm,
            &old_authorization.signature,
            &bytes,
        )?;
        let new_authorization = self
            .authorizations
            .new_key
            .as_ref()
            .ok_or(KeyringError::InvalidAuthorizationSet)?;
        verify_key_authorization(
            new_key,
            new_authorization.key_id,
            new_authorization.algorithm,
            &new_authorization.signature,
            &bytes,
        )
    }

    pub(crate) fn verify_recovery(
        &self,
        recovery_keys: &BTreeMap<RecoveryAuthorizerId, PublicKey>,
        threshold: usize,
    ) -> Result<()> {
        if !self.authorizations.is_recovery_only()
            || threshold == 0
            || threshold > recovery_keys.len()
            || self.authorizations.recovery.len() > recovery_keys.len()
            || self.authorizations.recovery.len() > MAX_RECOVERY_AUTHORIZATIONS
            || self
                .authorizations
                .recovery
                .windows(2)
                .any(|pair| pair[0].authorizer_id >= pair[1].authorizer_id)
        {
            return Err(KeyringError::InvalidAuthorizationSet);
        }
        let bytes = self.body.signing_bytes()?;
        let mut verified = BTreeSet::new();
        for authorization in &self.authorizations.recovery {
            if !verified.insert(authorization.authorizer_id.clone()) {
                return Err(KeyringError::DuplicateIdentifier);
            }
            let key = recovery_keys
                .get(&authorization.authorizer_id)
                .ok_or(KeyringError::InvalidSignature)?;
            verify_signature(
                key,
                authorization.algorithm,
                &authorization.signature,
                &bytes,
            )?;
        }
        if verified.len() < threshold {
            return Err(KeyringError::InvalidSignature);
        }
        Ok(())
    }
}

fn verify_key_authorization(
    key: &PublicKey,
    claimed_key_id: KeyId,
    algorithm: SigningAlgorithm,
    signature: &Signature,
    bytes: &[u8],
) -> Result<()> {
    if derive_key_id(key.algorithm(), key)? != claimed_key_id {
        return Err(KeyringError::InvalidSignature);
    }
    verify_signature(key, algorithm, signature, bytes)
}

fn verify_signature(
    key: &PublicKey,
    algorithm: SigningAlgorithm,
    signature: &Signature,
    bytes: &[u8],
) -> Result<()> {
    if key.algorithm() != algorithm || signature.algorithm() != algorithm {
        return Err(KeyringError::AlgorithmMismatch);
    }
    if !key.verify(bytes, signature) {
        return Err(KeyringError::InvalidSignature);
    }
    Ok(())
}

fn domain_canonical_bytes<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>> {
    let canonical = canonical_json_bytes(value)?;
    let capacity = domain
        .len()
        .checked_add(canonical.len())
        .ok_or(KeyringError::NumericRange)?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> Result<Hash> {
    let capacity = domain
        .len()
        .checked_add(bytes.len())
        .ok_or(KeyringError::NumericRange)?;
    let mut input = Vec::with_capacity(capacity);
    input.extend_from_slice(domain);
    input.extend_from_slice(bytes);
    Ok(sha256(&input))
}
