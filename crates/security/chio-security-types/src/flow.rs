use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use core::fmt;
use core::str::FromStr;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const MAX_IDENTIFIER_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PrincipalId(String);

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Compartment(String);

#[derive(Clone, Debug, Eq, PartialEq)]
/// The enclosing wire input must be byte-bounded before deserialization. These limits bound
/// decoded identifiers and collection cardinalities.
pub enum InformationLabel {
    #[non_exhaustive]
    Known {
        owners: BTreeMap<PrincipalId, BTreeSet<PrincipalId>>,
        compartments: BTreeSet<Compartment>,
    },
    Top,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LabelLimits {
    max_owners: usize,
    max_readers_per_owner: usize,
    max_compartments: usize,
}

pub const DEFAULT_LABEL_LIMITS: LabelLimits = LabelLimits {
    max_owners: 64,
    max_readers_per_owner: 256,
    max_compartments: 64,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LabelValidationError {
    BlankIdentifier,
    NonCanonicalIdentifier,
    IdentifierTooLong,
    OwnerMissingSelfReader,
    TooManyOwners,
    TooManyReaders,
    TooManyCompartments,
    LimitsExceedProtocol,
}

impl LabelLimits {
    pub fn new(
        max_owners: usize,
        max_readers_per_owner: usize,
        max_compartments: usize,
    ) -> Result<Self, LabelValidationError> {
        if max_owners > DEFAULT_LABEL_LIMITS.max_owners
            || max_readers_per_owner > DEFAULT_LABEL_LIMITS.max_readers_per_owner
            || max_compartments > DEFAULT_LABEL_LIMITS.max_compartments
        {
            return Err(LabelValidationError::LimitsExceedProtocol);
        }
        Ok(Self {
            max_owners,
            max_readers_per_owner,
            max_compartments,
        })
    }

    #[must_use]
    pub const fn max_owners(self) -> usize {
        self.max_owners
    }

    #[must_use]
    pub const fn max_readers_per_owner(self) -> usize {
        self.max_readers_per_owner
    }

    #[must_use]
    pub const fn max_compartments(self) -> usize {
        self.max_compartments
    }
}

impl fmt::Display for LabelValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::BlankIdentifier => "identifier is blank",
            Self::NonCanonicalIdentifier => {
                "identifier has leading or trailing whitespace or a control character"
            }
            Self::IdentifierTooLong => "identifier exceeds the byte limit",
            Self::OwnerMissingSelfReader => "owner reader set omits the owner",
            Self::TooManyOwners => "label has too many owners",
            Self::TooManyReaders => "owner policy has too many readers",
            Self::TooManyCompartments => "label has too many compartments",
            Self::LimitsExceedProtocol => "configured label limits exceed protocol ceilings",
        };
        formatter.write_str(message)
    }
}

impl core::error::Error for LabelValidationError {}

fn validate_identifier(value: &str) -> Result<(), LabelValidationError> {
    if value.is_empty() {
        return Err(LabelValidationError::BlankIdentifier);
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(LabelValidationError::IdentifierTooLong);
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(LabelValidationError::NonCanonicalIdentifier);
    }
    Ok(())
}

macro_rules! identifier_type {
    ($type:ident) => {
        impl $type {
            pub fn new(value: impl Into<String>) -> Result<Self, LabelValidationError> {
                let value = value.into();
                validate_identifier(&value)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $type {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $type {
            type Err = LabelValidationError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl TryFrom<String> for $type {
            type Error = LabelValidationError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct IdentifierVisitor;

                impl<'de> Visitor<'de> for IdentifierVisitor {
                    type Value = $type;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str("a bounded canonical identifier")
                    }

                    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        validate_identifier(value).map_err(E::custom)?;
                        Ok($type(String::from(value)))
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        validate_identifier(value).map_err(E::custom)?;
                        Ok($type(String::from(value)))
                    }

                    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        validate_identifier(&value).map_err(E::custom)?;
                        Ok($type(value))
                    }
                }

                deserializer.deserialize_str(IdentifierVisitor)
            }
        }
    };
}

identifier_type!(PrincipalId);
identifier_type!(Compartment);

impl InformationLabel {
    #[must_use]
    pub fn bottom() -> Self {
        Self::Known {
            owners: BTreeMap::new(),
            compartments: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn is_bottom(&self) -> bool {
        matches!(
            self,
            Self::Known {
                owners,
                compartments
            } if owners.is_empty() && compartments.is_empty()
        )
    }

    pub fn try_known(
        owners: BTreeMap<PrincipalId, BTreeSet<PrincipalId>>,
        compartments: BTreeSet<Compartment>,
    ) -> Result<Self, LabelValidationError> {
        Self::try_known_with_limits(owners, compartments, DEFAULT_LABEL_LIMITS)
    }

    pub fn try_known_with_limits(
        owners: BTreeMap<PrincipalId, BTreeSet<PrincipalId>>,
        compartments: BTreeSet<Compartment>,
        limits: LabelLimits,
    ) -> Result<Self, LabelValidationError> {
        validate_known(&owners, &compartments, limits)?;
        Ok(Self::Known {
            owners,
            compartments,
        })
    }

    #[must_use]
    pub fn owners(&self) -> Option<&BTreeMap<PrincipalId, BTreeSet<PrincipalId>>> {
        match self {
            Self::Known { owners, .. } => Some(owners),
            Self::Top => None,
        }
    }

    #[must_use]
    pub fn compartments(&self) -> Option<&BTreeSet<Compartment>> {
        match self {
            Self::Known { compartments, .. } => Some(compartments),
            Self::Top => None,
        }
    }
}

fn validate_known(
    owners: &BTreeMap<PrincipalId, BTreeSet<PrincipalId>>,
    compartments: &BTreeSet<Compartment>,
    limits: LabelLimits,
) -> Result<(), LabelValidationError> {
    if owners.len() > limits.max_owners {
        return Err(LabelValidationError::TooManyOwners);
    }
    if compartments.len() > limits.max_compartments {
        return Err(LabelValidationError::TooManyCompartments);
    }
    for (owner, readers) in owners {
        if readers.len() > limits.max_readers_per_owner {
            return Err(LabelValidationError::TooManyReaders);
        }
        if !readers.contains(owner) {
            return Err(LabelValidationError::OwnerMissingSelfReader);
        }
    }
    Ok(())
}

impl Serialize for InformationLabel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Known {
                owners,
                compartments,
            } => {
                let mut state = serializer.serialize_struct("InformationLabel", 3)?;
                state.serialize_field("kind", "known")?;
                state.serialize_field("owners", owners)?;
                state.serialize_field("compartments", compartments)?;
                state.end()
            }
            Self::Top => {
                let mut state = serializer.serialize_struct("InformationLabel", 1)?;
                state.serialize_field("kind", "top")?;
                state.end()
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum LabelKind {
    Known,
    Top,
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum LabelField {
    Kind,
    Owners,
    Compartments,
}

struct DistinctReaders(BTreeSet<PrincipalId>);

impl<'de> Deserialize<'de> for DistinctReaders {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ReadersVisitor;

        impl<'de> Visitor<'de> for ReadersVisitor {
            type Value = DistinctReaders;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded array of distinct principal ids")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut readers = BTreeSet::new();
                while let Some(reader) = sequence.next_element::<PrincipalId>()? {
                    if readers.len() >= DEFAULT_LABEL_LIMITS.max_readers_per_owner {
                        return Err(de::Error::custom(LabelValidationError::TooManyReaders));
                    }
                    if !readers.insert(reader.clone()) {
                        return Err(de::Error::custom(format!(
                            "duplicate reader principal `{reader}`"
                        )));
                    }
                }
                Ok(DistinctReaders(readers))
            }
        }

        deserializer.deserialize_seq(ReadersVisitor)
    }
}

struct OwnerPolicies(BTreeMap<PrincipalId, BTreeSet<PrincipalId>>);

impl<'de> Deserialize<'de> for OwnerPolicies {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OwnerPoliciesVisitor;

        impl<'de> Visitor<'de> for OwnerPoliciesVisitor {
            type Value = OwnerPolicies;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded object of distinct owner policies")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut owners = BTreeMap::new();
                while let Some(owner) = map.next_key::<PrincipalId>()? {
                    if owners.len() >= DEFAULT_LABEL_LIMITS.max_owners {
                        return Err(de::Error::custom(LabelValidationError::TooManyOwners));
                    }
                    if owners.contains_key(&owner) {
                        return Err(de::Error::custom(format!(
                            "duplicate owner policy `{owner}`"
                        )));
                    }
                    let DistinctReaders(readers) = map.next_value::<DistinctReaders>()?;
                    if !readers.contains(&owner) {
                        return Err(de::Error::custom(
                            LabelValidationError::OwnerMissingSelfReader,
                        ));
                    }
                    owners.insert(owner, readers);
                }
                Ok(OwnerPolicies(owners))
            }
        }

        deserializer.deserialize_map(OwnerPoliciesVisitor)
    }
}

struct DistinctCompartments(BTreeSet<Compartment>);

impl<'de> Deserialize<'de> for DistinctCompartments {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CompartmentsVisitor;

        impl<'de> Visitor<'de> for CompartmentsVisitor {
            type Value = DistinctCompartments;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded array of distinct compartments")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut compartments = BTreeSet::new();
                while let Some(compartment) = sequence.next_element::<Compartment>()? {
                    if compartments.len() >= DEFAULT_LABEL_LIMITS.max_compartments {
                        return Err(de::Error::custom(LabelValidationError::TooManyCompartments));
                    }
                    if !compartments.insert(compartment.clone()) {
                        return Err(de::Error::custom(format!(
                            "duplicate compartment `{compartment}`"
                        )));
                    }
                }
                Ok(DistinctCompartments(compartments))
            }
        }

        deserializer.deserialize_seq(CompartmentsVisitor)
    }
}

impl<'de> Deserialize<'de> for InformationLabel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct InformationLabelVisitor;

        impl<'de> Visitor<'de> for InformationLabelVisitor {
            type Value = InformationLabel;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a strict known or top information label")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut kind = None;
                let mut owners = None;
                let mut compartments = None;
                while let Some(field) = map.next_key::<LabelField>()? {
                    match field {
                        LabelField::Kind => {
                            if kind.is_some() {
                                return Err(de::Error::duplicate_field("kind"));
                            }
                            kind = Some(map.next_value::<LabelKind>()?);
                        }
                        LabelField::Owners => {
                            if owners.is_some() {
                                return Err(de::Error::duplicate_field("owners"));
                            }
                            owners = Some(map.next_value::<OwnerPolicies>()?.0);
                        }
                        LabelField::Compartments => {
                            if compartments.is_some() {
                                return Err(de::Error::duplicate_field("compartments"));
                            }
                            compartments = Some(map.next_value::<DistinctCompartments>()?.0);
                        }
                    }
                }

                match kind.ok_or_else(|| de::Error::missing_field("kind"))? {
                    LabelKind::Known => {
                        let owners = owners.ok_or_else(|| de::Error::missing_field("owners"))?;
                        let compartments =
                            compartments.ok_or_else(|| de::Error::missing_field("compartments"))?;
                        InformationLabel::try_known(owners, compartments).map_err(de::Error::custom)
                    }
                    LabelKind::Top => {
                        if owners.is_some() || compartments.is_some() {
                            return Err(de::Error::custom("top label has payload fields"));
                        }
                        Ok(InformationLabel::Top)
                    }
                }
            }
        }

        deserializer.deserialize_struct(
            "InformationLabel",
            &["kind", "owners", "compartments"],
            InformationLabelVisitor,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Compartment, InformationLabel, LabelLimits, LabelValidationError, PrincipalId,
        DEFAULT_LABEL_LIMITS, MAX_IDENTIFIER_BYTES,
    };
    use alloc::collections::{BTreeMap, BTreeSet};
    use alloc::format;
    use alloc::vec::Vec;
    use serde_json::{from_str, json, to_string, Value};

    struct BorrowedIdentifierDeserializer<'de>(&'de str);

    impl<'de> serde::Deserializer<'de> for BorrowedIdentifierDeserializer<'de> {
        type Error = serde::de::value::Error;

        fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            visitor.visit_borrowed_str(self.0)
        }

        fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            visitor.visit_borrowed_str(self.0)
        }

        fn deserialize_string<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            Err(<Self::Error as serde::de::Error>::custom(
                "owned identifier decoding is disabled",
            ))
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char bytes byte_buf option
            unit unit_struct newtype_struct seq tuple tuple_struct map struct enum identifier
            ignored_any
        }
    }

    fn principal(value: &str) -> PrincipalId {
        PrincipalId::new(value).unwrap_or_else(|error| panic!("valid principal: {error}"))
    }

    #[test]
    fn bottom_is_unique_public_label() {
        let empty = InformationLabel::try_known(BTreeMap::new(), BTreeSet::new())
            .unwrap_or_else(|error| panic!("empty label is valid: {error}"));
        assert_eq!(InformationLabel::bottom(), empty);
        assert!(empty.is_bottom());
    }

    #[test]
    fn owner_must_be_its_own_reader() {
        let alice = principal("alice");
        let mut owners = BTreeMap::new();
        owners.insert(alice, BTreeSet::from([principal("bob")]));
        assert_eq!(
            InformationLabel::try_known(owners, BTreeSet::new()),
            Err(LabelValidationError::OwnerMissingSelfReader)
        );
    }

    #[test]
    fn duplicate_owner_json_is_rejected() {
        let json =
            r#"{"kind":"known","owners":{"alice":["alice"],"alice":["alice"]},"compartments":[]}"#;
        assert!(from_str::<InformationLabel>(json).is_err());
    }

    #[test]
    fn duplicate_reader_and_compartment_values_are_rejected() {
        let duplicate_reader =
            r#"{"kind":"known","owners":{"alice":["alice","alice"]},"compartments":[]}"#;
        let duplicate_compartment = r#"{"kind":"known","owners":{},"compartments":["pii","pii"]}"#;
        assert!(from_str::<InformationLabel>(duplicate_reader).is_err());
        assert!(from_str::<InformationLabel>(duplicate_compartment).is_err());
    }

    #[test]
    fn blank_principal_and_compartment_are_rejected() {
        for value in ["", " ", " alice", "alice ", "alice\n"] {
            assert!(PrincipalId::new(value).is_err(), "principal {value:?}");
            assert!(Compartment::new(value).is_err(), "compartment {value:?}");
        }
    }

    #[test]
    fn borrowed_identifier_is_validated_before_owned_allocation() {
        let identifier = <PrincipalId as serde::Deserialize>::deserialize(
            BorrowedIdentifierDeserializer("alice"),
        )
        .unwrap_or_else(|error| panic!("borrowed identifier: {error}"));
        assert_eq!(identifier.as_str(), "alice");
    }

    #[test]
    fn known_and_top_canonical_vectors_round_trip() {
        let vectors = [
            r#"{"kind":"known","owners":{"alice":["alice","bob"],"carol":["carol"]},"compartments":["finance","pii"]}"#,
            r#"{"kind":"top"}"#,
        ];
        for vector in vectors {
            let label: InformationLabel =
                from_str(vector).unwrap_or_else(|error| panic!("canonical vector parses: {error}"));
            let encoded = to_string(&label)
                .unwrap_or_else(|error| panic!("canonical vector serializes: {error}"));
            assert_eq!(encoded, vector);
        }
    }

    #[test]
    fn noncanonical_input_normalizes_to_identical_canonical_bytes() {
        let reordered = r#"{"compartments":["pii","finance"],"owners":{"carol":["carol"],"alice":["bob","alice"]},"kind":"known"}"#;
        let canonical = r#"{"kind":"known","owners":{"alice":["alice","bob"],"carol":["carol"]},"compartments":["finance","pii"]}"#;
        let label: InformationLabel =
            from_str(reordered).unwrap_or_else(|error| panic!("reordered vector parses: {error}"));
        let encoded = to_string(&label)
            .unwrap_or_else(|error| panic!("reordered vector serializes: {error}"));
        assert_eq!(encoded, canonical);
    }

    #[test]
    fn unknown_and_variant_payload_fields_are_rejected() {
        let unknown = r#"{"kind":"known","owners":{},"compartments":[],"extra":true}"#;
        let top_payload = r#"{"kind":"top","owners":{}}"#;
        assert!(from_str::<InformationLabel>(unknown).is_err());
        assert!(from_str::<InformationLabel>(top_payload).is_err());
    }

    #[test]
    fn configured_cardinality_overflow_is_rejected() {
        let limits = LabelLimits::new(1, 1, 1)
            .unwrap_or_else(|error| panic!("narrow label limits: {error}"));
        let alice = principal("alice");
        let mut owners = BTreeMap::new();
        owners.insert(alice.clone(), BTreeSet::from([alice, principal("bob")]));
        assert_eq!(
            InformationLabel::try_known_with_limits(owners, BTreeSet::new(), limits),
            Err(LabelValidationError::TooManyReaders)
        );
        assert!(DEFAULT_LABEL_LIMITS.max_owners() > 1);
    }

    #[test]
    fn configured_limits_cannot_widen_protocol_limits() {
        assert_eq!(
            LabelLimits::new(
                DEFAULT_LABEL_LIMITS.max_owners() + 1,
                DEFAULT_LABEL_LIMITS.max_readers_per_owner(),
                DEFAULT_LABEL_LIMITS.max_compartments(),
            ),
            Err(LabelValidationError::LimitsExceedProtocol)
        );
    }

    #[test]
    fn information_label_schema_positive_and_negative_vectors() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../../spec/schemas/chio-wire/v1/security/information-label.schema.json"
        ))
        .unwrap_or_else(|error| panic!("schema parses: {error}"));
        let validator = jsonschema::validator_for(&schema)
            .unwrap_or_else(|error| panic!("schema compiles: {error}"));

        let positive = [
            json!({"kind": "top"}),
            json!({"kind": "known", "owners": {}, "compartments": []}),
            json!({"kind": "known", "owners": {"alice": ["alice"]}, "compartments": ["pii"]}),
        ];
        for vector in positive {
            assert!(validator.is_valid(&vector), "positive vector: {vector}");
        }

        let negative = [
            json!({"kind": "top", "owners": {}}),
            json!({"kind": "unknown"}),
            json!({"kind": "known", "owners": {}, "compartments": [], "extra": true}),
            json!({"kind": "known", "owners": {"": [""]}, "compartments": []}),
            json!({"kind": "known", "owners": {" alice": [" alice"]}, "compartments": []}),
            json!({"kind": "known", "owners": {"alice": ["bob"]}, "compartments": []}),
            json!({"kind": "known", "owners": {"alice": ["alice", "alice"]}, "compartments": []}),
            json!({"kind": "known", "owners": {}, "compartments": [""]}),
            json!({"kind": "known", "owners": {}, "compartments": ["pii", "pii"]}),
        ];
        for vector in negative {
            let structural_rejection = !validator.is_valid(&vector);
            let semantic_rejection =
                serde_json::from_value::<InformationLabel>(vector.clone()).is_err();
            assert!(
                structural_rejection || semantic_rejection,
                "negative vector: {vector}"
            );
        }

        let owner_missing_self =
            json!({"kind": "known", "owners": {"alice": ["bob"]}, "compartments": []});
        assert!(
            validator.is_valid(&owner_missing_self),
            "JSON Schema cannot compare a property name with an array member"
        );
        assert!(
            serde_json::from_value::<InformationLabel>(owner_missing_self).is_err(),
            "portable semantic validation must enforce owner self readership"
        );
    }

    #[test]
    fn schema_and_runtime_enforce_every_default_cardinality_bound() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../../spec/schemas/chio-wire/v1/security/information-label.schema.json"
        ))
        .unwrap_or_else(|error| panic!("schema parses: {error}"));
        let validator = jsonschema::validator_for(&schema)
            .unwrap_or_else(|error| panic!("schema compiles: {error}"));

        let oversized_ascii_id = "a".repeat(MAX_IDENTIFIER_BYTES + 1);
        let oversized_id =
            json!({"kind": "known", "owners": {}, "compartments": [oversized_ascii_id]});
        assert!(!validator.is_valid(&oversized_id));
        assert!(serde_json::from_value::<InformationLabel>(oversized_id).is_err());

        let mut owner_object = serde_json::Map::new();
        for value in 0..=DEFAULT_LABEL_LIMITS.max_owners() {
            let owner = format!("owner-{value}");
            owner_object.insert(owner.clone(), json!([owner]));
        }
        let too_many_owners = json!({
            "kind": "known",
            "owners": owner_object,
            "compartments": []
        });
        assert!(!validator.is_valid(&too_many_owners));
        assert!(serde_json::from_value::<InformationLabel>(too_many_owners).is_err());

        let readers = (0..=DEFAULT_LABEL_LIMITS.max_readers_per_owner())
            .map(|value| Value::String(format!("reader-{value}")))
            .collect::<Vec<_>>();
        let too_many_readers = json!({
            "kind": "known",
            "owners": {"reader-0": readers},
            "compartments": []
        });
        assert!(!validator.is_valid(&too_many_readers));
        assert!(serde_json::from_value::<InformationLabel>(too_many_readers).is_err());

        let compartments = (0..=DEFAULT_LABEL_LIMITS.max_compartments())
            .map(|value| Value::String(format!("compartment-{value}")))
            .collect::<Vec<_>>();
        let too_many_compartments = json!({
            "kind": "known",
            "owners": {},
            "compartments": compartments
        });
        assert!(!validator.is_valid(&too_many_compartments));
        assert!(serde_json::from_value::<InformationLabel>(too_many_compartments).is_err());
    }

    #[test]
    fn utf8_identifier_limit_is_normative_in_bytes() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../../spec/schemas/chio-wire/v1/security/information-label.schema.json"
        ))
        .unwrap_or_else(|error| panic!("schema parses: {error}"));
        let validator = jsonschema::validator_for(&schema)
            .unwrap_or_else(|error| panic!("schema compiles: {error}"));
        let multibyte = "é".repeat((MAX_IDENTIFIER_BYTES / 2) + 1);
        let vector = json!({
            "kind": "known",
            "owners": {},
            "compartments": [multibyte]
        });
        assert!(
            validator.is_valid(&vector),
            "JSON Schema maxLength counts Unicode scalar values"
        );
        assert!(serde_json::from_value::<InformationLabel>(vector).is_err());
        assert_eq!(
            Compartment::new("é".repeat(MAX_IDENTIFIER_BYTES / 2 + 1)),
            Err(LabelValidationError::IdentifierTooLong)
        );
    }

    #[test]
    fn internal_control_identifier_is_rejected_by_schema_and_runtime() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../../spec/schemas/chio-wire/v1/security/information-label.schema.json"
        ))
        .unwrap_or_else(|error| panic!("schema parses: {error}"));
        let validator = jsonschema::validator_for(&schema)
            .unwrap_or_else(|error| panic!("schema compiles: {error}"));
        let vector = json!({
            "kind": "known",
            "owners": {},
            "compartments": ["pii\u{1}restricted"]
        });
        assert!(!validator.is_valid(&vector));
        assert!(serde_json::from_value::<InformationLabel>(vector).is_err());
    }

    #[test]
    fn c1_control_identifier_is_rejected_by_schema_and_runtime() {
        let schema: Value = serde_json::from_str(include_str!(
            "../../../../spec/schemas/chio-wire/v1/security/information-label.schema.json"
        ))
        .unwrap_or_else(|error| panic!("schema parses: {error}"));
        let validator = jsonschema::validator_for(&schema)
            .unwrap_or_else(|error| panic!("schema compiles: {error}"));
        let vector = json!({
            "kind": "known",
            "owners": {},
            "compartments": ["pii\u{85}restricted"]
        });
        assert!(!validator.is_valid(&vector));
        assert!(serde_json::from_value::<InformationLabel>(vector).is_err());
    }
}
