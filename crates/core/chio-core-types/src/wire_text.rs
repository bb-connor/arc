//! Deserialize textual wire values without requesting an owned string copy.

use core::fmt;
use serde::de::{Deserializer, Visitor};

use crate::Result;

pub(crate) fn deserialize<'de, D, T>(
    deserializer: D,
    description: &'static str,
    parse: fn(&str) -> Result<T>,
) -> core::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
{
    struct WireVisitor<T> {
        description: &'static str,
        parse: fn(&str) -> Result<T>,
    }

    impl<'de, T> Visitor<'de> for WireVisitor<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.description)
        }

        fn visit_str<E: serde::de::Error>(self, value: &str) -> core::result::Result<T, E> {
            (self.parse)(value).map_err(E::custom)
        }
    }

    deserializer.deserialize_str(WireVisitor { description, parse })
}
