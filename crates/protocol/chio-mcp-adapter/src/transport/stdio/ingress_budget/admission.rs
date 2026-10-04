//! Structural accounting only. The canonical document decoder still decides
//! whether duplicate keys and the resulting JSON document are acceptable.

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};

use super::Footprint;

#[derive(Debug)]
pub(super) enum AdmissionError {
    Limit(&'static str),
    Input(serde_json::Error),
}

pub(super) fn measure(text: &str) -> Result<Footprint, AdmissionError> {
    let mut counter = Counter {
        footprint: Footprint {
            wire_bytes: text.len(),
            ..Footprint::default()
        },
        limit: None,
    };
    if let Some(limit) = counter.footprint.exceeded() {
        return Err(AdmissionError::Limit(limit));
    }
    let mut decoder = serde_json::Deserializer::from_str(text);
    let result = ValueSeed(&mut counter)
        .deserialize(&mut decoder)
        .and_then(|()| decoder.end());
    match result {
        Ok(()) => Ok(counter.footprint),
        Err(error) => Err(match counter.limit {
            Some(limit) => AdmissionError::Limit(limit),
            None => AdmissionError::Input(error),
        }),
    }
}

struct Counter {
    footprint: Footprint,
    limit: Option<&'static str>,
}

impl Counter {
    fn add<E: de::Error>(&mut self, nodes: usize, text_bytes: usize) -> Result<(), E> {
        let Some(next) = self.footprint.checked_add(Footprint {
            nodes,
            text_bytes,
            ..Footprint::default()
        }) else {
            self.limit = Some("accounting overflow");
            return Err(E::custom("MCP ingress accounting overflow"));
        };
        if let Some(limit) = next.exceeded() {
            self.limit = Some(limit);
            return Err(E::custom("MCP ingress structural limit exceeded"));
        }
        self.footprint = next;
        Ok(())
    }
}

struct ValueSeed<'a>(&'a mut Counter);

impl<'de> DeserializeSeed<'de> for ValueSeed<'_> {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        self.0.add(1, 0)?;
        deserializer.deserialize_any(ValueVisitor(self.0))
    }
}

struct ValueVisitor<'a>(&'a mut Counter);

impl<'de> Visitor<'de> for ValueVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded MCP JSON document")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<(), E> {
        if value.is_finite() {
            Ok(())
        } else {
            Err(E::custom("non-finite MCP JSON number"))
        }
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<(), E> {
        self.0.add(0, value.len())
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        while sequence.next_element_seed(ValueSeed(self.0))?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while map.next_key_seed(KeySeed(self.0))?.is_some() {
            map.next_value_seed(ValueSeed(self.0))?;
        }
        Ok(())
    }
}

struct KeySeed<'a>(&'a mut Counter);

impl<'de> DeserializeSeed<'de> for KeySeed<'_> {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_str(self)
    }
}

impl Visitor<'_> for KeySeed<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MCP JSON object key")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<(), E> {
        self.0.add(0, value.len())
    }
}
