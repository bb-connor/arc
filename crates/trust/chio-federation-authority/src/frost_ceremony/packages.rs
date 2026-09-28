use super::*;

/// Public, authenticated-on-use round-one broadcast. Deserialization does not
/// grant trust; the ceremony verifier checks its transport signature and roster.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FrostRound1Package(pub(super) DkgPackage);

/// Plaintext participant-to-participant secret material. It has no wire serde
/// implementation. Only encrypted custody persistence may extract its bytes.
///
/// ```compile_fail
/// use chio_federation_authority::FrostRound2Package;
/// fn serialize(package: &FrostRound2Package) {
///     let _ = serde_json::to_vec(package);
/// }
/// ```
/// ```compile_fail
/// use chio_federation_authority::FrostRound2Package;
/// fn deserialize(bytes: &[u8]) {
///     let _ = serde_json::from_slice::<FrostRound2Package>(bytes);
/// }
/// ```
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FrostRound2Package(pub(super) DkgPackage);

/// Nonsecret metadata authenticated together with the round-two package digest.
/// This is a storage record, not evidence that its signature has been verified.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostRound2Metadata {
    schema: String,
    ceremony_id: String,
    participant_set_digest: String,
    key_epoch: u64,
    round: FrostDkgRound,
    sender_participant_id: String,
    recipient_participant_id: Option<String>,
    package_digest: String,
    transport_key_id: String,
    transport_signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Round1Wire {
    schema: String,
    ceremony_id: String,
    participant_set_digest: String,
    key_epoch: u64,
    round: FrostDkgRound,
    sender_participant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recipient_participant_id: Option<String>,
    package_digest: String,
    package_hex: String,
    transport_key_id: String,
    transport_signature: String,
}

impl Serialize for FrostRound1Package {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let package = &self.0;
        Round1Wire {
            schema: package.schema.clone(),
            ceremony_id: package.ceremony_id.clone(),
            participant_set_digest: package.participant_set_digest.clone(),
            key_epoch: package.key_epoch,
            round: package.round,
            sender_participant_id: package.sender_participant_id.clone(),
            recipient_participant_id: package.recipient_participant_id.clone(),
            package_digest: package.package_digest.clone(),
            package_hex: hex::encode(&package.package_bytes),
            transport_key_id: package.transport_key_id.clone(),
            transport_signature: package.transport_signature.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FrostRound1Package {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = Round1Wire::deserialize(deserializer)?;
        if wire.schema != DKG_PACKAGE_SCHEMA
            || wire.round != FrostDkgRound::Round1
            || wire.recipient_participant_id.is_some()
        {
            return Err(serde::de::Error::custom("expected a round-one broadcast"));
        }
        if wire.package_hex.is_empty() || wire.package_hex.len() > MAX_DKG_PACKAGE_BYTES * 2 {
            return Err(serde::de::Error::custom(
                "round-one package length is outside the supported range",
            ));
        }
        let bytes = hex::decode(&wire.package_hex).map_err(serde::de::Error::custom)?;
        round1::Package::deserialize(&bytes).map_err(serde::de::Error::custom)?;
        Ok(Self(DkgPackage {
            schema: wire.schema,
            ceremony_id: wire.ceremony_id,
            participant_set_digest: wire.participant_set_digest,
            key_epoch: wire.key_epoch,
            round: wire.round,
            sender_participant_id: wire.sender_participant_id,
            recipient_participant_id: wire.recipient_participant_id,
            package_digest: wire.package_digest,
            package_bytes: Zeroizing::new(bytes),
            transport_key_id: wire.transport_key_id,
            transport_signature: wire.transport_signature,
        }))
    }
}

impl FrostRound2Package {
    /// Extract a zeroizing copy for the encrypted persistence boundary. This is
    /// intentionally conspicuous and must not be used by transport serializers.
    #[must_use]
    pub fn secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        self.0.package_bytes.clone()
    }

    #[must_use]
    pub fn metadata(&self) -> FrostRound2Metadata {
        let package = &self.0;
        FrostRound2Metadata {
            schema: package.schema.clone(),
            ceremony_id: package.ceremony_id.clone(),
            participant_set_digest: package.participant_set_digest.clone(),
            key_epoch: package.key_epoch,
            round: package.round,
            sender_participant_id: package.sender_participant_id.clone(),
            recipient_participant_id: package.recipient_participant_id.clone(),
            package_digest: package.package_digest.clone(),
            transport_key_id: package.transport_key_id.clone(),
            transport_signature: package.transport_signature.clone(),
        }
    }

    /// Restore a local outbound package after authenticated custody decryption.
    /// Rechecks ceremony, sender, recipient, digest, signature and FROST encoding.
    pub fn from_custody(
        config: &FrostCeremonyConfig,
        metadata: FrostRound2Metadata,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<Self, FrostCeremonyError> {
        let context = ValidatedCeremony::new_without_key(config)?;
        if metadata.sender_participant_id != config.local_participant_id {
            return Err(package_authentication_error(
                &metadata.sender_participant_id,
                "custody package belongs to another participant",
            ));
        }
        let package = DkgPackage {
            schema: metadata.schema,
            ceremony_id: metadata.ceremony_id,
            participant_set_digest: metadata.participant_set_digest,
            key_epoch: metadata.key_epoch,
            round: metadata.round,
            sender_participant_id: metadata.sender_participant_id,
            recipient_participant_id: metadata.recipient_participant_id,
            package_digest: metadata.package_digest,
            package_bytes: bytes,
            transport_key_id: metadata.transport_key_id,
            transport_signature: metadata.transport_signature,
        };
        validate_package(&context, &package, FrostDkgRound::Round2)?;
        round2::Package::deserialize(&package.package_bytes).map_err(|_| {
            package_authentication_error(
                &package.sender_participant_id,
                "round-two package does not decode",
            )
        })?;
        Ok(Self(package))
    }
}

macro_rules! package_accessors {
    ($ty:ty) => {
        impl $ty {
            #[must_use]
            pub const fn round(&self) -> FrostDkgRound {
                self.0.round()
            }
            #[must_use]
            pub fn sender_participant_id(&self) -> &str {
                self.0.sender_participant_id()
            }
            #[must_use]
            pub fn recipient_participant_id(&self) -> Option<&str> {
                self.0.recipient_participant_id()
            }
            #[must_use]
            pub fn package_digest(&self) -> &str {
                self.0.package_digest()
            }
        }
    };
}
package_accessors!(FrostRound1Package);
package_accessors!(FrostRound2Package);
