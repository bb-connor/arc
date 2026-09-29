use super::{de, fmt, Deserialize, Deserializer, Serialize, String, Visitor};

pub(super) const MAX_ID_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdError {
    Blank,
    TooLong,
    NonCanonical,
}

impl fmt::Display for IdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Blank => "identifier is blank",
            Self::TooLong => "identifier exceeds the byte limit",
            Self::NonCanonical => "identifier is not canonical",
        };
        formatter.write_str(message)
    }
}

impl core::error::Error for IdError {}

fn validate_id(value: &str) -> Result<(), IdError> {
    if value.is_empty() {
        return Err(IdError::Blank);
    }
    if value.len() > MAX_ID_BYTES {
        return Err(IdError::TooLong);
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(IdError::NonCanonical);
    }
    Ok(())
}

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
                let value = value.into();
                validate_id(&value)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct IdVisitor;

                impl<'de> Visitor<'de> for IdVisitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str("a bounded canonical identifier")
                    }

                    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        validate_id(value).map_err(E::custom)?;
                        Ok($name(String::from(value)))
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        validate_id(value).map_err(E::custom)?;
                        Ok($name(String::from(value)))
                    }

                    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        validate_id(&value).map_err(E::custom)?;
                        Ok($name(value))
                    }
                }

                deserializer.deserialize_str(IdVisitor)
            }
        }
    };
}

pub(super) fn validate_nonzero_id(value: &str) -> Result<(), IdError> {
    validate_id(value)?;
    if value.bytes().all(|byte| byte == b'0') {
        return Err(IdError::NonCanonical);
    }
    Ok(())
}

macro_rules! nonzero_id_type {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
                let value = value.into();
                validate_nonzero_id(&value)?;
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct IdVisitor;

                impl<'de> Visitor<'de> for IdVisitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str("a bounded canonical nonzero identifier")
                    }

                    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        validate_nonzero_id(value).map_err(E::custom)?;
                        Ok($name(String::from(value)))
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        validate_nonzero_id(value).map_err(E::custom)?;
                        Ok($name(String::from(value)))
                    }

                    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        validate_nonzero_id(&value).map_err(E::custom)?;
                        Ok($name(value))
                    }
                }

                deserializer.deserialize_str(IdVisitor)
            }
        }
    };
}

id_type!(TenantId);
id_type!(RecordId);
id_type!(LineageId);
id_type!(SessionId);
id_type!(IsolationEpochId);
id_type!(RequestId);
id_type!(EventId);
id_type!(RuleId);
id_type!(ArtifactId);
nonzero_id_type!(AdmissionArtifactRef);
id_type!(GrantId);
id_type!(ActionId);
id_type!(EffectId);
id_type!(LeaseOwnerId);
id_type!(ClassifierId);
id_type!(ClassifierVersion);
id_type!(ProducerId);
id_type!(PurposeId);
id_type!(DestinationId);
id_type!(ErrorCode);
id_type!(OpaqueReceiptRef);

#[path = "error.rs"]
mod error;
pub use error::{PortError, PortErrorKind, PortResult};
