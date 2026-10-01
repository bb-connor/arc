use chio_core::{canonical_json_bytes, sha256_hex};
use chio_security_types::ports::RecordId;
use chio_sqlite_file_identity::SqliteFileIdentity;
use serde::{Deserialize, Serialize};

use super::{schema, Error, Result};

pub(super) const MAX_ROWS: u64 = 16_384;
pub(super) const MAX_INVENTORY_BYTES: u64 = 64 * 1024 * 1024;
const SCHEMA: &str = "chio.security-participant-source-fingerprint.v1";

/// Operator-selected labels bind a pinned migration expectation. Labels alone
/// do not establish an authority, a destination UUID or a live source seal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityParticipantSourceBinding {
    source_id: RecordId,
    security_authority_id: RecordId,
    destination_store_uuid: RecordId,
}

impl SecurityParticipantSourceBinding {
    pub fn new(
        source_id: &str,
        security_authority_id: &str,
        destination_store_uuid: &str,
    ) -> Result<Self> {
        Ok(Self {
            source_id: RecordId::new(source_id)
                .map_err(|_| Error::Invalid("invalid source identifier"))?,
            security_authority_id: RecordId::new(security_authority_id)
                .map_err(|_| Error::Invalid("invalid security authority identifier"))?,
            destination_store_uuid: RecordId::new(destination_store_uuid)
                .map_err(|_| Error::Invalid("invalid destination identifier"))?,
        })
    }

    #[must_use]
    pub const fn source_id(&self) -> &RecordId {
        &self.source_id
    }

    #[must_use]
    pub const fn security_authority_id(&self) -> &RecordId {
        &self.security_authority_id
    }

    #[must_use]
    pub const fn destination_store_uuid(&self) -> &RecordId {
        &self.destination_store_uuid
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TableFingerprint {
    pub table: String,
    pub row_count: u64,
    pub encoded_bytes: u64,
    pub digest: String,
}

/// Bounded canonical data describing the complete retained critical-table
/// inventory. Rows remain in the source; this is not an importable row snapshot
/// or proof that any historical invocation owns those rows. Debug omits labels.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityParticipantSourceSnapshot {
    schema: String,
    binding: SecurityParticipantSourceBinding,
    device: String,
    inode: String,
    link_count: u8,
    catalog_digest: String,
    tables: Vec<TableFingerprint>,
}

impl SecurityParticipantSourceSnapshot {
    pub(crate) fn tables(&self) -> &[TableFingerprint] {
        &self.tables
    }

    pub(crate) fn file_identity(&self) -> Result<SqliteFileIdentity> {
        self.validate()?;
        Ok(SqliteFileIdentity {
            device: self
                .device
                .parse()
                .map_err(|_| Error::Invalid("invalid device"))?,
            inode: self
                .inode
                .parse()
                .map_err(|_| Error::Invalid("invalid inode"))?,
            link_count: u64::from(self.link_count),
        })
    }

    pub(super) fn new(
        binding: SecurityParticipantSourceBinding,
        identity: SqliteFileIdentity,
        catalog_digest: String,
        tables: Vec<TableFingerprint>,
    ) -> Result<Self> {
        let result = Self {
            schema: SCHEMA.into(),
            binding,
            device: identity.device.to_string(),
            inode: identity.inode.to_string(),
            link_count: u8::try_from(identity.link_count)
                .map_err(|_| Error::Invalid("invalid link count"))?,
            catalog_digest,
            tables,
        };
        result.validate()?;
        Ok(result)
    }

    #[must_use]
    pub const fn binding(&self) -> &SecurityParticipantSourceBinding {
        &self.binding
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = canonical_json_bytes(self)
            .map_err(|_| Error::Invalid("fingerprint cannot be encoded"))?;
        if bytes.len() > 65_536 {
            return Err(Error::Invalid("fingerprint exceeds bounds"));
        }
        Ok(bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(Error::Invalid("fingerprint size is invalid"));
        }
        let decoded: Self = serde_json::from_slice(bytes)
            .map_err(|_| Error::Invalid("invalid fingerprint encoding"))?;
        if decoded.canonical_bytes()? != bytes {
            return Err(Error::Invalid("fingerprint is not exact canonical JSON"));
        }
        Ok(decoded)
    }

    pub fn digest(&self) -> Result<String> {
        let mut bytes = b"chio.security-participant-source.fingerprint.v1\0".to_vec();
        bytes.extend(self.canonical_bytes()?);
        Ok(sha256_hex(&bytes))
    }

    pub(super) fn validate(&self) -> Result<()> {
        if self.schema != SCHEMA
            || self.link_count != 1
            || self.tables.len() != schema::TABLES.len()
            || !valid_digest(&self.catalog_digest)
        {
            return Err(Error::Invalid("fingerprint shape is invalid"));
        }
        SecurityParticipantSourceBinding::new(
            self.binding.source_id.as_str(),
            self.binding.security_authority_id.as_str(),
            self.binding.destination_store_uuid.as_str(),
        )?;
        for integer in [&self.device, &self.inode] {
            let value: u64 = integer
                .parse()
                .map_err(|_| Error::Invalid("invalid file identity integer"))?;
            if value.to_string() != *integer {
                return Err(Error::Invalid("noncanonical file identity integer"));
            }
        }
        let mut rows = 0_u64;
        let mut bytes = 0_u64;
        for (entry, expected) in self.tables.iter().zip(schema::TABLES) {
            if entry.table != *expected || !valid_digest(&entry.digest) {
                return Err(Error::Invalid("fingerprint table inventory is invalid"));
            }
            rows = rows
                .checked_add(entry.row_count)
                .ok_or(Error::Invalid("row count overflow"))?;
            bytes = bytes
                .checked_add(entry.encoded_bytes)
                .ok_or(Error::Invalid("inventory size overflow"))?;
            if rows > MAX_ROWS || bytes > MAX_INVENTORY_BYTES {
                return Err(Error::Invalid("inventory exceeds source bounds"));
            }
        }
        Ok(())
    }
}

fn valid_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl std::fmt::Debug for SecurityParticipantSourceSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityParticipantSourceSnapshot")
            .field("schema", &self.schema)
            .field("table_count", &self.tables.len())
            .finish_non_exhaustive()
    }
}
