use super::{
    de, fmt, Deserialize, Deserializer, DestinationId, EffectId, RecordId, SeqAccess, Serialize,
    Vec, Visitor,
};

const MAX_CANONICAL_BODY_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CanonicalBody(Vec<u8>);

impl CanonicalBody {
    pub fn new(bytes: Vec<u8>) -> Result<Self, BodyError> {
        if bytes.len() > MAX_CANONICAL_BODY_BYTES {
            return Err(BodyError::TooLarge);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyError {
    TooLarge,
}

impl fmt::Display for BodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("canonical body exceeds the byte limit")
    }
}

impl core::error::Error for BodyError {}

impl<'de> Deserialize<'de> for CanonicalBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BodyVisitor;

        impl<'de> Visitor<'de> for BodyVisitor {
            type Value = CanonicalBody;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded byte array")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let capacity = sequence
                    .size_hint()
                    .unwrap_or(0)
                    .min(MAX_CANONICAL_BODY_BYTES);
                let mut bytes = Vec::with_capacity(capacity);
                while let Some(byte) = sequence.next_element::<u8>()? {
                    if bytes.len() == MAX_CANONICAL_BODY_BYTES {
                        return Err(de::Error::custom("canonical body exceeds the byte limit"));
                    }
                    bytes.push(byte);
                }
                Ok(CanonicalBody(bytes))
            }
        }

        deserializer.deserialize_seq(BodyVisitor)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct BoundedVec<T, const MAX: usize>(Vec<T>);

impl<T, const MAX: usize> BoundedVec<T, MAX> {
    pub fn new(values: Vec<T>) -> Result<Self, CollectionError> {
        if values.len() > MAX {
            return Err(CollectionError::TooManyItems);
        }
        Ok(Self(values))
    }

    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        self.0.as_slice()
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<T> {
        self.0
    }

    #[must_use]
    pub fn map_ref<U>(&self, map: impl FnMut(&T) -> U) -> BoundedVec<U, MAX> {
        BoundedVec(self.0.iter().map(map).collect())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectionError {
    TooManyItems,
}

impl fmt::Display for CollectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("collection exceeds the item limit")
    }
}

impl core::error::Error for CollectionError {}

impl<'de, T, const MAX: usize> Deserialize<'de> for BoundedVec<T, MAX>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BoundedVisitor<T, const MAX: usize>(core::marker::PhantomData<T>);

        impl<'de, T, const MAX: usize> Visitor<'de> for BoundedVisitor<T, MAX>
        where
            T: Deserialize<'de>,
        {
            type Value = BoundedVec<T, MAX>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "an array with at most {MAX} items")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let capacity = sequence.size_hint().unwrap_or(0).min(MAX);
                let mut values = Vec::with_capacity(capacity);
                while let Some(value) = sequence.next_element::<T>()? {
                    if values.len() == MAX {
                        return Err(de::Error::custom("collection exceeds the item limit"));
                    }
                    values.push(value);
                }
                Ok(BoundedVec(values))
            }
        }

        deserializer.deserialize_seq(BoundedVisitor::<T, MAX>(core::marker::PhantomData))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RecordIdSet(BoundedVec<RecordId, 4_096>);

impl RecordIdSet {
    pub fn new(values: Vec<RecordId>) -> Result<Self, RecordIdSetError> {
        if values.array_windows::<2>().any(|pair| pair[0] >= pair[1]) {
            return Err(RecordIdSetError::NotStrictlySorted);
        }
        BoundedVec::new(values)
            .map(Self)
            .map_err(|_| RecordIdSetError::TooManyItems)
    }

    #[must_use]
    pub fn as_slice(&self) -> &[RecordId] {
        self.0.as_slice()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordIdSetError {
    TooManyItems,
    NotStrictlySorted,
}

impl fmt::Display for RecordIdSetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyItems => formatter.write_str("record id set exceeds the item limit"),
            Self::NotStrictlySorted => {
                formatter.write_str("record ids are not strictly sorted and unique")
            }
        }
    }
}

impl core::error::Error for RecordIdSetError {}

impl<'de> Deserialize<'de> for RecordIdSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = BoundedVec::<RecordId, 4_096>::deserialize(deserializer)?.into_vec();
        Self::new(values).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalSetError {
    Empty,
    TooManyItems,
    NotStrictlySorted,
}

impl fmt::Display for CanonicalSetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("canonical set is empty"),
            Self::TooManyItems => formatter.write_str("canonical set exceeds the item limit"),
            Self::NotStrictlySorted => {
                formatter.write_str("canonical set is not strictly sorted and unique")
            }
        }
    }
}

impl core::error::Error for CanonicalSetError {}

fn validate_canonical_set<T: Ord>(
    values: &[T],
    maximum: usize,
    allow_empty: bool,
) -> Result<(), CanonicalSetError> {
    if !allow_empty && values.is_empty() {
        return Err(CanonicalSetError::Empty);
    }
    if values.len() > maximum {
        return Err(CanonicalSetError::TooManyItems);
    }
    if values.array_windows::<2>().any(|pair| pair[0] >= pair[1]) {
        return Err(CanonicalSetError::NotStrictlySorted);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct EgressDestinationSet(BoundedVec<DestinationId, 64>);

impl EgressDestinationSet {
    pub fn new(values: Vec<DestinationId>) -> Result<Self, CanonicalSetError> {
        validate_canonical_set(&values, 64, false)?;
        BoundedVec::new(values)
            .map(Self)
            .map_err(|_| CanonicalSetError::TooManyItems)
    }

    #[must_use]
    pub fn as_slice(&self) -> &[DestinationId] {
        self.0.as_slice()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de> Deserialize<'de> for EgressDestinationSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = BoundedVec::<DestinationId, 64>::deserialize(deserializer)?.into_vec();
        Self::new(values).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct EgressDeniedDestinations(BoundedVec<DestinationId, 4_096>);

impl EgressDeniedDestinations {
    pub fn new(values: Vec<DestinationId>) -> Result<Self, CanonicalSetError> {
        validate_canonical_set(&values, 4_096, true)?;
        BoundedVec::new(values)
            .map(Self)
            .map_err(|_| CanonicalSetError::TooManyItems)
    }

    #[must_use]
    pub fn as_slice(&self) -> &[DestinationId] {
        self.0.as_slice()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de> Deserialize<'de> for EgressDeniedDestinations {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = BoundedVec::<DestinationId, 4_096>::deserialize(deserializer)?.into_vec();
        Self::new(values).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct EgressRestrictionEffectIds(BoundedVec<EffectId, 256>);

impl EgressRestrictionEffectIds {
    pub fn new(values: Vec<EffectId>) -> Result<Self, CanonicalSetError> {
        validate_canonical_set(&values, 256, true)?;
        BoundedVec::new(values)
            .map(Self)
            .map_err(|_| CanonicalSetError::TooManyItems)
    }

    #[must_use]
    pub fn as_slice(&self) -> &[EffectId] {
        self.0.as_slice()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de> Deserialize<'de> for EgressRestrictionEffectIds {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = BoundedVec::<EffectId, 256>::deserialize(deserializer)?.into_vec();
        Self::new(values).map_err(de::Error::custom)
    }
}
