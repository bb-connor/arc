use alloc::string::String;
use alloc::vec::Vec;
use core::{fmt, marker::PhantomData};
use serde::{
    de::{self, DeserializeSeed, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};

/// Bounded public categories. No protected input or parser text is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractError {
    Malformed,
    UnsupportedVersion,
    InvalidIdentifier,
    LimitExceeded,
    UnsafeInteger,
    InvalidState,
    UnsupportedProfile,
    BindingMismatch,
    DuplicateIdentity,
    MissingDependency,
    DependencyCycle,
    WorkBudgetExceeded,
    ArithmeticOverflow,
    NonCanonical,
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "recovery.malformed",
            Self::UnsupportedVersion => "recovery.unsupported_version",
            Self::InvalidIdentifier => "recovery.invalid_identifier",
            Self::LimitExceeded => "recovery.limit_exceeded",
            Self::UnsafeInteger => "recovery.unsafe_integer",
            Self::InvalidState => "recovery.invalid_state",
            Self::UnsupportedProfile => "recovery.unsupported_profile",
            Self::BindingMismatch => "recovery.binding_mismatch",
            Self::DuplicateIdentity => "recovery.duplicate_identity",
            Self::MissingDependency => "recovery.missing_dependency",
            Self::DependencyCycle => "recovery.dependency_cycle",
            Self::WorkBudgetExceeded => "recovery.work_budget_exceeded",
            Self::ArithmeticOverflow => "recovery.arithmetic_overflow",
            Self::NonCanonical => "recovery.non_canonical",
        })
    }
}
impl core::error::Error for ContractError {}

/// No mutation API can grow a checked list beyond its protocol ceiling.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct BoundedList<T, const N: usize>(Vec<T>);

impl<T, const N: usize> BoundedList<T, N> {
    pub fn new(values: Vec<T>) -> Result<Self, ContractError> {
        if values.len() > N {
            return Err(ContractError::LimitExceeded);
        }
        Ok(Self(values))
    }
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }
}

impl<T, const N: usize> fmt::Debug for BoundedList<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundedList")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

struct Element<T> {
    available: bool,
    marker: PhantomData<T>,
}
impl<'de, T: Deserialize<'de>> DeserializeSeed<'de> for Element<T> {
    type Value = T;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<T, D::Error> {
        if !self.available {
            return Err(de::Error::custom(ContractError::LimitExceeded));
        }
        T::deserialize(d)
    }
}

impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for BoundedList<T, N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct ListVisitor<T, const N: usize>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for ListVisitor<T, N> {
            type Value = BoundedList<T, N>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a bounded list")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element_seed(Element::<T> {
                    available: values.len() < N,
                    marker: PhantomData,
                })? {
                    values.push(value);
                }
                Ok(BoundedList(values))
            }
        }
        d.deserialize_seq(ListVisitor::<T, N>(PhantomData))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct NonEmptyBoundedList<T, const N: usize>(BoundedList<T, N>);
impl<T, const N: usize> NonEmptyBoundedList<T, N> {
    pub fn new(values: Vec<T>) -> Result<Self, ContractError> {
        if values.is_empty() {
            return Err(ContractError::InvalidState);
        }
        BoundedList::new(values).map(Self)
    }
    pub fn as_slice(&self) -> &[T] {
        self.0.as_slice()
    }
}
impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for NonEmptyBoundedList<T, N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let list = BoundedList::<T, N>::deserialize(d)?;
        if list.as_slice().is_empty() {
            return Err(de::Error::custom(ContractError::InvalidState));
        }
        Ok(Self(list))
    }
}

/// Integers with an identical meaning in every generated JSON consumer.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SafeInteger(u64);
impl SafeInteger {
    pub const MAX: u64 = (1 << 53) - 1;
    pub const ZERO: Self = Self(0);
    pub fn new(value: u64) -> Result<Self, ContractError> {
        if value > Self::MAX {
            return Err(ContractError::UnsafeInteger);
        }
        Ok(Self(value))
    }
    pub const fn get(self) -> u64 {
        self.0
    }
    pub fn checked_add(self, other: Self) -> Result<Self, ContractError> {
        let value = self
            .0
            .checked_add(other.0)
            .ok_or(ContractError::ArithmeticOverflow)?;
        Self::new(value).map_err(|_| ContractError::ArithmeticOverflow)
    }
}
impl<'de> Deserialize<'de> for SafeInteger {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(u64::deserialize(d)?).map_err(de::Error::custom)
    }
}

/// A required version, never a defaulted or nullable extension.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VersionV1;
impl Serialize for VersionV1 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(1)
    }
}
impl<'de> Deserialize<'de> for VersionV1 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if u8::deserialize(d)? != 1 {
            return Err(de::Error::custom(ContractError::UnsupportedVersion));
        }
        Ok(Self)
    }
}

/// A protected exact-byte textual envelope. Its enclosing reader checks JSON
/// resource bounds; the owning embedded protocol checks canonical contents.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ProtectedText<const N: usize>(String);
impl<const N: usize> ProtectedText<N> {
    pub fn new(text: &str) -> Result<Self, ContractError> {
        if text.is_empty() || text.len() > N {
            return Err(ContractError::LimitExceeded);
        }
        Ok(Self(text.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl<const N: usize> fmt::Debug for ProtectedText<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProtectedText([redacted])")
    }
}
impl<'de, const N: usize> Deserialize<'de> for ProtectedText<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct TextVisitor<const N: usize>;
        impl<const N: usize> Visitor<'_> for TextVisitor<N> {
            type Value = ProtectedText<N>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded protected text")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                ProtectedText::new(value).map_err(de::Error::custom)
            }
        }
        d.deserialize_str(TextVisitor::<N>)
    }
}
