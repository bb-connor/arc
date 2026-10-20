//! Decoders that refuse input their derived serde form would discard.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

/// The refusal when a decoded value does not reserialize to its input.
pub const DROPPED_INPUT: &str = "decoded value drops input fields";

/// The refusal when a JSON object repeats a key.
pub const DUPLICATE_KEY: &str = "duplicate object key";

/// A `serde_json::Value` decoded from any deserializer, refusing a repeated
/// object key at every depth instead of keeping the last one.
struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictValueVisitor).map(Self)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Value, E> {
        Ok(Number::from_f64(value).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(String::from(value)))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        StrictValue::deserialize(deserializer).map(|value| value.0)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(StrictValue(item)) = sequence.next_element()? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Value, A::Error> {
        let mut members = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if members.contains_key(&key) {
                return Err(A::Error::custom(format!("{DUPLICATE_KEY}: {key:?}")));
            }
            let StrictValue(member) = object.next_value()?;
            members.insert(key, member);
        }
        Ok(Value::Object(members))
    }
}

/// Unit variants of internally tagged enums ignore fields beside the tag even
/// under `deny_unknown_fields`, so the typed value must reserialize to the
/// exact input. The input is read refusing repeated keys, so a raw decode
/// cannot keep the last of two duplicates.
pub fn lossless<'de, D, T>(
    deserializer: D,
    decode: impl FnOnce(Value) -> Result<T, serde_json::Error>,
    encode: impl FnOnce(&T) -> Result<Value, serde_json::Error>,
) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
{
    let StrictValue(value) = StrictValue::deserialize(deserializer)?;
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

/// Defines an enum whose `Deserialize` decodes through [`lossless`].
///
/// The enum derives `Serialize` from its own attributes. Decoding runs a
/// derived remote mirror that is private to the expansion, so the strict
/// trait implementation is the only public decoder.
#[macro_export]
macro_rules! lossless_serde {
    (
        $(#[doc = $doc:literal])*
        #[derive($($derive:path),* $(,)?)]
        $(#[$meta:meta])*
        $vis:vis enum $name:ident { $($body:tt)* }
    ) => {
        $(#[doc = $doc])*
        #[derive($($derive),*)]
        $(#[$meta])*
        $vis enum $name { $($body)* }

        const _: () = {
            type LosslessTarget = $name;

            #[allow(dead_code)]
            #[derive($crate::strict_serde::__private::Deserialize)]
            $(#[$meta])*
            #[serde(remote = "LosslessTarget")]
            enum LosslessRaw { $($body)* }

            impl<'de> $crate::strict_serde::__private::Deserialize<'de> for $name {
                fn deserialize<D: $crate::strict_serde::__private::Deserializer<'de>>(
                    deserializer: D,
                ) -> ::core::result::Result<Self, D::Error> {
                    $crate::strict_serde::lossless(
                        deserializer,
                        |value| LosslessRaw::deserialize(value),
                        |typed| {
                            $crate::strict_serde::__private::Serialize::serialize(
                                typed,
                                $crate::strict_serde::__private::ValueSerializer,
                            )
                        },
                    )
                }
            }
        };
    };
}
