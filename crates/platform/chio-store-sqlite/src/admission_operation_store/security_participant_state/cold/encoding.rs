//! Bounded, domain-separated encodings. Retained images keep their exact bytes.

use super::{Digest, Error, Result};
use crate::security_state::{decode_retained_security_row, retained_security_columns};
use rusqlite::types::Value;
use sha2::{Digest as _, Sha256};

const KEY_DOMAIN: &[u8] = b"chio.native-cold.key.v1\0";
const VALUE_DOMAIN: &[u8] = b"chio.native-cold.value.v1\0";
const POINTER_DOMAIN: &[u8] = b"chio.native-cold.pointer.v1\0";
const FACT_DOMAIN: &[u8] = b"chio.native-cold.fact.v1\0";
const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_VALUE_BYTES: usize = 16_777_216;
const MAX_PAYLOAD_BYTES: usize = 256;
const USES: &str = "security_declassification_uses";
const IDENTITIES: &str = "security_declassification_evidence_identity";
const OUTBOX: &str = "security_declassification_receipt_outbox";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(super) enum Class {
    Lineage = 1,
    Principal = 2,
    Epoch = 3,
    Membership = 4,
    HasHistory = 5,
    EpochTransition = 6,
    Grant = 7,
    EvidenceId = 8,
    EvidenceTransition = 9,
}

impl Class {
    pub(super) fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::Lineage),
            2 => Ok(Self::Principal),
            3 => Ok(Self::Epoch),
            4 => Ok(Self::Membership),
            5 => Ok(Self::HasHistory),
            6 => Ok(Self::EpochTransition),
            7 => Ok(Self::Grant),
            8 => Ok(Self::EvidenceId),
            9 => Ok(Self::EvidenceTransition),
            _ => Err(Error::Encoding),
        }
    }

    fn field_count(self) -> usize {
        match self {
            Self::Principal | Self::Membership => 3,
            Self::Epoch => 4,
            _ => 2,
        }
    }

    fn fact_size(self) -> Result<usize> {
        match self {
            Self::Membership => Ok(64),
            Self::HasHistory
            | Self::EpochTransition
            | Self::EvidenceId
            | Self::EvidenceTransition => Ok(32),
            _ => Err(Error::Encoding),
        }
    }

    fn tables(self) -> Result<&'static [&'static str]> {
        match self {
            Self::Lineage => Ok(&["security_lineage_flow_state"]),
            Self::Principal => Ok(&["security_principal_flow_state"]),
            Self::Epoch => Ok(&["security_isolation_epochs"]),
            Self::Grant => Ok(&[USES, IDENTITIES, OUTBOX]),
            _ => Err(Error::Encoding),
        }
    }

    fn key_columns(self) -> Result<&'static [&'static str]> {
        match self {
            Self::Lineage => Ok(&["tenant_id", "lineage_id"]),
            Self::Principal => Ok(&["tenant_id", "principal_id", "isolation_epoch_id"]),
            Self::Epoch => Ok(&[
                "tenant_id",
                "principal_id",
                "lineage_id",
                "isolation_epoch_id",
            ]),
            Self::Grant => Ok(&["tenant_id", "grant_id"]),
            _ => Err(Error::Encoding),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Tier {
    Cold,
    Hot,
}

impl Tier {
    pub(super) fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::Cold),
            2 => Ok(Self::Hot),
            _ => Err(Error::Encoding),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Payload {
    Pointer {
        tier: Tier,
        version: u64,
        value_digest: Digest,
    },
    Fact {
        class: Class,
        body: Vec<u8>,
    },
}

impl Payload {
    pub(super) fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        match self {
            Self::Pointer {
                tier,
                version,
                value_digest,
            } => {
                if *version == 0 {
                    return Err(Error::Encoding);
                }
                bytes.extend(POINTER_DOMAIN);
                bytes.push(match tier {
                    Tier::Cold => 1,
                    Tier::Hot => 2,
                });
                bytes.extend(version.to_be_bytes());
                bytes.extend(value_digest);
            }
            Self::Fact { class, body } => {
                if body.len() != class.fact_size()? {
                    return Err(Error::Encoding);
                }
                bytes.extend(FACT_DOMAIN);
                bytes.push(*class as u8);
                bytes.extend(body);
            }
        }
        Ok(bytes)
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_PAYLOAD_BYTES {
            return Err(Error::Encoding);
        }
        if let Some(rest) = bytes.strip_prefix(POINTER_DOMAIN) {
            let mut cursor = Cursor::new(rest);
            let tier = Tier::from_tag(cursor.take(1)?[0])?;
            let version = cursor.count()?;
            let value_digest = cursor.take(32)?.try_into().map_err(|_| Error::Encoding)?;
            if version == 0 || !cursor.finished() {
                return Err(Error::Encoding);
            }
            Ok(Self::Pointer {
                tier,
                version,
                value_digest,
            })
        } else if let Some(rest) = bytes.strip_prefix(FACT_DOMAIN) {
            let mut cursor = Cursor::new(rest);
            let class = Class::from_tag(cursor.take(1)?[0])?;
            let body = cursor.take(class.fact_size()?)?.to_vec();
            if !cursor.finished() {
                return Err(Error::Encoding);
            }
            Ok(Self::Fact { class, body })
        } else {
            Err(Error::Encoding)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Row {
    pub(super) table: String,
    pub(super) image: Vec<u8>,
}

pub(super) fn key_encoding(authority: &str, class: Class, fields: &[&str]) -> Result<Vec<u8>> {
    if fields.len() != class.field_count()
        || std::iter::once(authority)
            .chain(fields.iter().copied())
            .any(|field| field.is_empty() || field.len() > MAX_IDENTIFIER_BYTES)
    {
        return Err(Error::Encoding);
    }
    let mut bytes = KEY_DOMAIN.to_vec();
    append_field(&mut bytes, authority.as_bytes())?;
    bytes.push(class as u8);
    bytes.push(u8::try_from(fields.len()).map_err(|_| Error::Encoding)?);
    for field in fields {
        append_field(&mut bytes, field.as_bytes())?;
    }
    Ok(bytes)
}

pub(super) fn key_digest(authority: &str, class: Class, fields: &[&str]) -> Result<Digest> {
    Ok(Sha256::digest(key_encoding(authority, class, fields)?).into())
}

pub(super) fn encode_value(class: Class, rows: &[Row]) -> Result<Vec<u8>> {
    validate_rows(class, rows)?;
    let mut rows = rows.to_vec();
    rows.sort_by(|a, b| a.table.cmp(&b.table).then_with(|| a.image.cmp(&b.image)));
    if rows.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(Error::Encoding);
    }
    let mut bytes = u64::try_from(rows.len())
        .map_err(|_| Error::Encoding)?
        .to_be_bytes()
        .to_vec();
    for row in rows {
        append_field(&mut bytes, row.table.as_bytes())?;
        append_field(&mut bytes, &row.image)?;
    }
    Ok(bytes)
}

pub(super) fn decode_value(class: Class, bytes: &[u8]) -> Result<Vec<Row>> {
    if bytes.len() > MAX_VALUE_BYTES {
        return Err(Error::Encoding);
    }
    let mut cursor = Cursor::new(bytes);
    let count = usize::try_from(cursor.count()?).map_err(|_| Error::Encoding)?;
    if !(1..=5).contains(&count) {
        return Err(Error::Encoding);
    }
    let mut rows = Vec::with_capacity(count);
    for _ in 0..count {
        let table = std::str::from_utf8(cursor.field()?)
            .map_err(|_| Error::Encoding)?
            .to_owned();
        let image = cursor.field()?.to_vec();
        rows.push(Row { table, image });
    }
    if !cursor.finished()
        || rows
            .windows(2)
            .any(|pair| (&pair[0].table, &pair[0].image) >= (&pair[1].table, &pair[1].image))
    {
        return Err(Error::Encoding);
    }
    validate_rows(class, &rows)?;
    Ok(rows)
}

pub(super) fn value_digest(class: Class, bytes: &[u8]) -> Result<Digest> {
    decode_value(class, bytes)?;
    let mut hash = Sha256::new();
    hash.update(VALUE_DOMAIN);
    hash.update([class as u8]);
    hash.update(bytes);
    Ok(hash.finalize().into())
}

pub(super) fn verify_value_key(
    authority: &str,
    class: Class,
    key: Digest,
    bytes: &[u8],
) -> Result<()> {
    for row in decode_value(class, bytes)? {
        let columns = retained_security_columns(&row.table).map_err(|_| Error::Encoding)?;
        let values =
            decode_retained_security_row(&row.table, &row.image).map_err(|_| Error::Encoding)?;
        let fields = class
            .key_columns()?
            .iter()
            .map(|field| {
                let position = columns
                    .iter()
                    .position(|column| column == field)
                    .ok_or(Error::Encoding)?;
                match values.get(position) {
                    Some(Value::Text(value)) => Ok(value.as_str()),
                    _ => Err(Error::Encoding),
                }
            })
            .collect::<Result<Vec<_>>>()?;
        if key_digest(authority, class, &fields)? != key {
            return Err(Error::Binding);
        }
    }
    Ok(())
}

fn validate_rows(class: Class, rows: &[Row]) -> Result<()> {
    let allowed = class.tables()?;
    let expected = if class == Class::Grant {
        rows.len() == 3 || rows.len() == 5
    } else {
        rows.len() == 1
    };
    if !expected {
        return Err(Error::Encoding);
    }
    let mut bytes = 8_usize;
    for row in rows {
        if !allowed.contains(&row.table.as_str())
            || row.image.is_empty()
            || row.image.len() > MAX_VALUE_BYTES
        {
            return Err(Error::Encoding);
        }
        bytes = bytes
            .checked_add(16)
            .and_then(|size| size.checked_add(row.table.len()))
            .and_then(|size| size.checked_add(row.image.len()))
            .ok_or(Error::Encoding)?;
        if bytes > MAX_VALUE_BYTES {
            return Err(Error::Encoding);
        }
        decode_retained_security_row(&row.table, &row.image).map_err(|_| Error::Encoding)?;
    }
    if class == Class::Grant {
        let phases = (rows.len() - 1) / 2;
        for (table, count) in [(USES, 1), (IDENTITIES, phases), (OUTBOX, phases)] {
            if rows.iter().filter(|row| row.table == table).count() != count {
                return Err(Error::Encoding);
            }
        }
    }
    Ok(())
}

fn append_field(bytes: &mut Vec<u8>, field: &[u8]) -> Result<()> {
    bytes.extend(
        u64::try_from(field.len())
            .map_err(|_| Error::Encoding)?
            .to_be_bytes(),
    );
    bytes.extend(field);
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(count).ok_or(Error::Encoding)?;
        let bytes = self.bytes.get(self.offset..end).ok_or(Error::Encoding)?;
        self.offset = end;
        Ok(bytes)
    }

    fn count(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| Error::Encoding)?,
        ))
    }

    fn field(&mut self) -> Result<&'a [u8]> {
        let count = usize::try_from(self.count()?).map_err(|_| Error::Encoding)?;
        self.take(count)
    }

    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
