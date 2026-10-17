//! Decoders that refuse input their derived serde form would discard.

use serde::de::{Deserialize, Deserializer, Error as _};
use serde_json::Value;

/// The refusal when a decoded value does not reserialize to its input.
pub const DROPPED_INPUT: &str = "decoded value drops input fields";

/// Unit variants of internally tagged enums ignore fields beside the tag even
/// under `deny_unknown_fields`, so the typed value must reserialize to the
/// exact input.
pub fn lossless<'de, D, T>(
    deserializer: D,
    decode: impl FnOnce(Value) -> Result<T, serde_json::Error>,
    encode: impl FnOnce(&T) -> Result<Value, serde_json::Error>,
) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    let typed = decode(value.clone()).map_err(D::Error::custom)?;
    if encode(&typed).map_err(D::Error::custom)? != value {
        return Err(D::Error::custom(DROPPED_INPUT));
    }
    Ok(typed)
}

#[doc(hidden)]
pub mod __private {
    pub use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub use serde_json::value::Serializer as ValueSerializer;
}

/// Implements serde for a type derived with `#[serde(remote = "Self")]`,
/// decoding through [`lossless`].
#[macro_export]
macro_rules! lossless_serde {
    ($ty:ident) => {
        impl $crate::strict_serde::__private::Serialize for $ty {
            fn serialize<S: $crate::strict_serde::__private::Serializer>(
                &self,
                serializer: S,
            ) -> ::core::result::Result<S::Ok, S::Error> {
                $ty::serialize(self, serializer)
            }
        }

        impl<'de> $crate::strict_serde::__private::Deserialize<'de> for $ty {
            fn deserialize<D: $crate::strict_serde::__private::Deserializer<'de>>(
                deserializer: D,
            ) -> ::core::result::Result<Self, D::Error> {
                $crate::strict_serde::lossless(
                    deserializer,
                    |value| $ty::deserialize(value),
                    |typed| $ty::serialize(typed, $crate::strict_serde::__private::ValueSerializer),
                )
            }
        }
    };
}
