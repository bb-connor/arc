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
