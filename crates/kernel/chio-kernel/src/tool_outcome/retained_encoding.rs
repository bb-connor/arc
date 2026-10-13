//! Byte preflight for the existing closed retained DTOs.
//! Build the same serde JSON value while bounding clones of borrowed fields.
//! This is DATA validation, with no native purpose or physical loan authority.

use serde::ser::{
    Error as _, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant,
    SerializeTuple, SerializeTupleStruct, SerializeTupleVariant,
};
use serde::{Serialize, Serializer};
use serde_json::Value;

#[derive(Debug)]
pub(super) enum BorrowedEncodingError {
    Exhausted { minimum: usize },
    Serialization(serde_json::Error),
}

/// All callers are closed retained DTOs or serde JSON values. Their object
/// fields are unique and they do not embed raw JSON fragments. Native shape,
/// interoperable-number and depth restrictions do not apply to this helper.
pub(super) fn to_value_bounded(
    value: &impl Serialize,
    maximum: usize,
) -> Result<Value, BorrowedEncodingError> {
    let mut budget = ByteBudget {
        maximum,
        remaining: maximum,
        exhausted: None,
    };
    let encoded = value.serialize(TrackedSerializer {
        inner: serde_json::value::Serializer,
        budget: &mut budget,
        map_key: false,
    });
    // Custom serialization code cannot suppress a capacity failure and mint a
    // supposedly bounded value. No content or exact size is in this error.
    if let Some(minimum) = budget.exhausted {
        return Err(BorrowedEncodingError::Exhausted { minimum });
    }
    encoded.map_err(BorrowedEncodingError::Serialization)
}

struct ByteBudget {
    maximum: usize,
    remaining: usize,
    exhausted: Option<usize>,
}

impl ByteBudget {
    fn claim<E: serde::ser::Error>(&mut self, bytes: usize) -> Result<(), E> {
        if self.exhausted.is_some() || bytes > self.remaining {
            self.exhausted
                .get_or_insert_with(|| (self.maximum - self.remaining).saturating_add(bytes));
            return Err(E::custom("retained envelope byte budget exhausted"));
        }
        self.remaining -= bytes;
        Ok(())
    }

    fn string<E: serde::ser::Error>(&mut self, value: &str) -> Result<(), E> {
        // The unescaped UTF-8 length is a lower bound, so reject a very large
        // borrowed string before scanning it or allocating an owned copy.
        let Some(minimum) = value.len().checked_add(2) else {
            self.exhausted = Some(usize::MAX);
            return Err(E::custom("retained envelope byte budget exhausted"));
        };
        if minimum > self.remaining {
            return self.claim::<E>(minimum);
        }
        let mut bytes = minimum;
        for byte in value.bytes() {
            let padding = match byte {
                b'"' | b'\\' | b'\x08' | b'\t' | b'\n' | b'\x0c' | b'\r' => 1,
                0..=0x1f => 5,
                _ => 0,
            };
            let Some(next) = bytes.checked_add(padding) else {
                self.exhausted = Some(usize::MAX);
                return Err(E::custom("retained envelope byte budget exhausted"));
            };
            bytes = next;
            if bytes > self.remaining {
                return self.claim::<E>(bytes);
            }
        }
        self.claim(bytes)
    }

    fn member<E: serde::ser::Error>(&mut self, first: &mut bool) -> Result<(), E> {
        if *first {
            *first = false;
            Ok(())
        } else {
            self.claim(1)
        }
    }
}

struct TrackedValue<'a, T: ?Sized> {
    value: &'a T,
    budget: std::cell::RefCell<&'a mut ByteBudget>,
    map_key: bool,
}

impl<T: Serialize + ?Sized> Serialize for TrackedValue<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut budget = self
            .budget
            .try_borrow_mut()
            .map_err(|_| S::Error::custom("retained envelope serialization is reentrant"))?;
        self.value.serialize(TrackedSerializer {
            inner: serializer,
            budget: &mut budget,
            map_key: self.map_key,
        })
    }
}

struct TrackedSerializer<'a, S> {
    inner: S,
    budget: &'a mut ByteBudget,
    map_key: bool,
}

macro_rules! scalar {
    ($method:ident, $ty:ty) => {
        fn $method(self, value: $ty) -> Result<Self::Ok, Self::Error> {
            // Every valid canonical number occupies at least one byte. Avoid
            // changing legacy number acceptance or float formatting here.
            self.budget
                .claim::<S::Error>(if self.map_key { 3 } else { 1 })?;
            self.inner.$method(value)
        }
    };
}

impl<'a, S: Serializer> Serializer for TrackedSerializer<'a, S> {
    type Ok = S::Ok;
    type Error = S::Error;
    type SerializeSeq = TrackedSequence<'a, S::SerializeSeq>;
    type SerializeTuple = TrackedSequence<'a, S::SerializeTuple>;
    type SerializeTupleStruct = TrackedSequence<'a, S::SerializeTupleStruct>;
    type SerializeTupleVariant = TrackedSequence<'a, S::SerializeTupleVariant>;
    type SerializeMap = TrackedMap<'a, S::SerializeMap>;
    type SerializeStruct = TrackedStruct<'a, S::SerializeStruct>;
    type SerializeStructVariant = TrackedStruct<'a, S::SerializeStructVariant>;

    fn serialize_bool(self, value: bool) -> Result<Self::Ok, Self::Error> {
        self.budget.claim::<S::Error>(if value { 4 } else { 5 })?;
        self.inner.serialize_bool(value)
    }

    scalar!(serialize_i8, i8);
    scalar!(serialize_i16, i16);
    scalar!(serialize_i32, i32);
    scalar!(serialize_i64, i64);
    scalar!(serialize_i128, i128);
    scalar!(serialize_u8, u8);
    scalar!(serialize_u16, u16);
    scalar!(serialize_u32, u32);
    scalar!(serialize_u64, u64);
    scalar!(serialize_u128, u128);
    scalar!(serialize_f32, f32);
    scalar!(serialize_f64, f64);

    fn serialize_char(self, value: char) -> Result<Self::Ok, Self::Error> {
        let mut utf8 = [0; 4];
        self.serialize_str(value.encode_utf8(&mut utf8))
    }

    fn serialize_str(self, value: &str) -> Result<Self::Ok, Self::Error> {
        self.budget.string::<S::Error>(value)?;
        self.inner.serialize_str(value)
    }

    fn serialize_bytes(self, value: &[u8]) -> Result<Self::Ok, Self::Error> {
        let mut sequence = self.serialize_seq(None)?;
        for byte in value {
            sequence.serialize_element(byte)?;
        }
        sequence.end()
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        self.budget.claim::<S::Error>(4)?;
        self.inner.serialize_none()
    }

    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        self.budget.claim::<S::Error>(4)?;
        self.inner.serialize_unit()
    }

    fn serialize_unit_struct(self, name: &'static str) -> Result<Self::Ok, Self::Error> {
        self.budget.claim::<S::Error>(4)?;
        self.inner.serialize_unit_struct(name)
    }

    fn serialize_unit_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        self.budget.string::<S::Error>(variant)?;
        self.inner.serialize_unit_variant(name, index, variant)
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        self.inner.serialize_newtype_struct(
            name,
            &TrackedValue {
                value,
                budget: std::cell::RefCell::new(&mut *self.budget),
                map_key: self.map_key,
            },
        )
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        self.budget.claim::<S::Error>(3)?;
        self.budget.string::<S::Error>(variant)?;
        self.inner.serialize_newtype_variant(
            name,
            index,
            variant,
            &TrackedValue {
                value,
                budget: std::cell::RefCell::new(&mut *self.budget),
                map_key: false,
            },
        )
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        self.budget.claim::<S::Error>(2)?;
        Ok(TrackedSequence {
            // No unverified capacity hint may allocate before byte validation.
            inner: self.inner.serialize_seq(None)?,
            budget: self.budget,
            first: true,
        })
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        self.budget.claim::<S::Error>(2)?;
        Ok(TrackedSequence {
            inner: self.inner.serialize_tuple(0)?,
            budget: self.budget,
            first: true,
        })
    }

    fn serialize_tuple_struct(
        self,
        name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.budget.claim::<S::Error>(2)?;
        Ok(TrackedSequence {
            inner: self.inner.serialize_tuple_struct(name, 0)?,
            budget: self.budget,
            first: true,
        })
    }

    fn serialize_tuple_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        self.budget.claim::<S::Error>(5)?;
        self.budget.string::<S::Error>(variant)?;
        Ok(TrackedSequence {
            inner: self
                .inner
                .serialize_tuple_variant(name, index, variant, 0)?,
            budget: self.budget,
            first: true,
        })
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        self.budget.claim::<S::Error>(2)?;
        Ok(TrackedMap {
            inner: self.inner.serialize_map(None)?,
            budget: self.budget,
            first: true,
        })
    }

    fn serialize_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        self.budget.claim::<S::Error>(2)?;
        Ok(TrackedStruct {
            inner: self.inner.serialize_struct(name, len)?,
            budget: self.budget,
            first: true,
        })
    }

    fn serialize_struct_variant(
        self,
        name: &'static str,
        index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        self.budget.claim::<S::Error>(5)?;
        self.budget.string::<S::Error>(variant)?;
        Ok(TrackedStruct {
            inner: self
                .inner
                .serialize_struct_variant(name, index, variant, len)?,
            budget: self.budget,
            first: true,
        })
    }

    fn collect_str<T: std::fmt::Display + ?Sized>(
        self,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        let mut formatted = DisplayBuffer {
            value: String::new(),
            maximum: self.budget.remaining,
            exhausted: false,
        };
        let result = std::fmt::write(&mut formatted, format_args!("{value}"));
        if formatted.exhausted {
            self.budget.exhausted = Some(self.budget.maximum.saturating_add(1));
            return Err(S::Error::custom("retained envelope byte budget exhausted"));
        }
        if result.is_err() {
            return Err(S::Error::custom("retained envelope display failed"));
        }
        self.serialize_str(&formatted.value)
    }
}

struct DisplayBuffer {
    value: String,
    maximum: usize,
    exhausted: bool,
}

impl std::fmt::Write for DisplayBuffer {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        let Some(next) = self.value.len().checked_add(value.len()) else {
            self.exhausted = true;
            return Err(std::fmt::Error);
        };
        if self.exhausted || next > self.maximum {
            self.exhausted = true;
            return Err(std::fmt::Error);
        }
        self.value.push_str(value);
        Ok(())
    }
}

struct TrackedSequence<'a, S> {
    inner: S,
    budget: &'a mut ByteBudget,
    first: bool,
}

macro_rules! sequence {
    ($trait:ident, $method:ident) => {
        impl<S: $trait> $trait for TrackedSequence<'_, S> {
            type Ok = S::Ok;
            type Error = S::Error;

            fn $method<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
                self.budget.member::<S::Error>(&mut self.first)?;
                self.inner.$method(&TrackedValue {
                    value,
                    budget: std::cell::RefCell::new(&mut *self.budget),
                    map_key: false,
                })
            }

            fn end(self) -> Result<Self::Ok, Self::Error> {
                self.inner.end()
            }
        }
    };
}

sequence!(SerializeSeq, serialize_element);
sequence!(SerializeTuple, serialize_element);
sequence!(SerializeTupleStruct, serialize_field);
sequence!(SerializeTupleVariant, serialize_field);

struct TrackedMap<'a, S> {
    inner: S,
    budget: &'a mut ByteBudget,
    first: bool,
}

impl<S: SerializeMap> SerializeMap for TrackedMap<'_, S> {
    type Ok = S::Ok;
    type Error = S::Error;

    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Self::Error> {
        self.budget.member::<S::Error>(&mut self.first)?;
        self.budget.claim::<S::Error>(1)?;
        self.inner.serialize_key(&TrackedValue {
            value: key,
            budget: std::cell::RefCell::new(&mut *self.budget),
            map_key: true,
        })
    }

    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.inner.serialize_value(&TrackedValue {
            value,
            budget: std::cell::RefCell::new(&mut *self.budget),
            map_key: false,
        })
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        self.inner.end()
    }
}

struct TrackedStruct<'a, S> {
    inner: S,
    budget: &'a mut ByteBudget,
    first: bool,
}

macro_rules! structure {
    ($trait:ident) => {
        impl<S: $trait> $trait for TrackedStruct<'_, S> {
            type Ok = S::Ok;
            type Error = S::Error;

            fn serialize_field<T: Serialize + ?Sized>(
                &mut self,
                key: &'static str,
                value: &T,
            ) -> Result<(), Self::Error> {
                self.budget.member::<S::Error>(&mut self.first)?;
                self.budget.string::<S::Error>(key)?;
                self.budget.claim::<S::Error>(1)?;
                self.inner.serialize_field(
                    key,
                    &TrackedValue {
                        value,
                        budget: std::cell::RefCell::new(&mut *self.budget),
                        map_key: false,
                    },
                )
            }

            fn end(self) -> Result<Self::Ok, Self::Error> {
                self.inner.end()
            }
        }
    };
}

structure!(SerializeStruct);
structure!(SerializeStructVariant);
