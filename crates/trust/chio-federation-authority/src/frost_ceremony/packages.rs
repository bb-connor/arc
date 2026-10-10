use super::*;

/// Public, authenticated-on-use round-one broadcast. Deserialization does not
/// grant trust; the ceremony verifier checks its transport signature and roster.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FrostRound1Package(pub(super) DkgPackage);

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
