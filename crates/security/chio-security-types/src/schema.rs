use alloc::string::String;
use core::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemaRefusal {
    InvalidCreationPlan,
    MissingSchema { store_key: String },
    CreationNotAllowed,
    MalformedMetadata,
    UnexpectedNamespaces,
    CatalogMismatch,
    ForeignDatabase { found: i32, expected: i32 },
    StaleSchema { found: i32, current: i32 },
}

impl fmt::Display for SchemaRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCreationPlan => f.write_str("schema creation requires distinct nonempty namespace keys"),
            Self::MissingSchema { store_key } => write!(f, "schema namespace {store_key} is missing"),
            Self::CreationNotAllowed => f.write_str("schema creation is not allowed for this namespace"),
            Self::MalformedMetadata => f.write_str("schema metadata differs from its canonical definition"),
            Self::UnexpectedNamespaces => f.write_str("schema metadata contains undeclared namespaces"),
            Self::CatalogMismatch => f.write_str("schema catalog differs from its canonical definition"),
            Self::ForeignDatabase { found, expected } => write!(f, "database application_id {found:#x} is not a Chio store (expected {expected:#x})"),
            Self::StaleSchema { found, current } => write!(f, "database schema version {found} is not the current schema version {current}; refusing to open"),
        }
    }
}

impl core::error::Error for SchemaRefusal {}
