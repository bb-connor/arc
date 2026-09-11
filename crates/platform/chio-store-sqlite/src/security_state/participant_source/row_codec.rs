//! Lossless, bounded decoding of the persisted v1 source-row format.
//!
//! Decoded values are data for hydration, never source verification, activation
//! or operation custody. The caller must still verify the pinned row stream.

use std::sync::OnceLock;

use chio_core::canonical_json_bytes;
use chio_security_types::ports::BoundedVec;
use rusqlite::{types::Value, types::ValueRef, Connection};
use serde::{Deserialize, Serialize};

use super::{schema, Error, Result};

const MAX_ENCODED_ROW_BYTES: usize = 16 * 1024 * 1024;
const MAX_CELL_BYTES: usize = 1024 * 1024;
const MAX_ROW_BYTES: usize = 2 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum Cell {
    Null,
    Integer(String),
    Text(String),
    Blob(String),
}

struct Column {
    name: String,
    kind: String,
    nullable: bool,
}

type Layouts = Vec<(&'static str, Vec<Column>)>;

fn layout(table: &str) -> Result<&'static [Column]> {
    static LAYOUTS: OnceLock<Result<Layouts>> = OnceLock::new();
    let layouts = LAYOUTS
        .get_or_init(|| {
            let connection = Connection::open_in_memory()?;
            // Cache only the compiled predecessor layout, not observed state.
            super::super::migrate(&connection)
                .map_err(|_| Error::Invalid("canonical row layout is unavailable"))?;
            schema::TABLES
                .iter()
                .map(|table| {
                    let mut statement =
                        connection.prepare(&format!("PRAGMA table_info({table})"))?;
                    let columns = statement
                        .query_map([], |row| {
                            Ok(Column {
                                name: row.get(1)?,
                                kind: row.get(2)?,
                                nullable: row.get::<_, i64>(3)? == 0 && row.get::<_, i64>(5)? == 0,
                            })
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    if columns.is_empty() || columns.len() > 64 {
                        return Err(Error::Invalid("canonical column count exceeds bounds"));
                    }
                    Ok((*table, columns))
                })
                .collect()
        })
        .as_ref()
        .map_err(|_| Error::Invalid("canonical row layout is unavailable"))?;
    layouts
        .iter()
        .find(|(name, _)| *name == table)
        .map(|(_, columns)| columns.as_slice())
        .ok_or(Error::Invalid("retained row names an unknown table"))
}

pub(crate) fn retained_security_columns(table: &str) -> Result<Vec<&'static str>> {
    Ok(layout(table)?
        .iter()
        .map(|column| column.name.as_str())
        .collect())
}

pub(crate) fn encode_retained_security_values(
    table: &str,
    values: &[ValueRef<'_>],
) -> Result<Vec<u8>> {
    validate_values(table, values)?;
    let cells = values
        .iter()
        .map(|value| match value {
            ValueRef::Null => Ok(Cell::Null),
            ValueRef::Integer(value) => Ok(Cell::Integer(value.to_string())),
            ValueRef::Text(value) => Ok(Cell::Text(
                std::str::from_utf8(value)
                    .map_err(|_| Error::Invalid("source text is not UTF-8"))?
                    .to_owned(),
            )),
            ValueRef::Blob(value) => Ok(Cell::Blob(hex::encode(value))),
            ValueRef::Real(_) => Err(Error::Invalid("source real cell is unsupported")),
        })
        .collect::<Result<Vec<_>>>()?;
    let encoded =
        canonical_json_bytes(&cells).map_err(|_| Error::Invalid("source row cannot be encoded"))?;
    if encoded.len() > MAX_ENCODED_ROW_BYTES {
        return Err(Error::Invalid("source encoded row exceeds bounds"));
    }
    Ok(encoded)
}

pub(crate) fn decode_retained_security_row(table: &str, bytes: &[u8]) -> Result<Vec<Value>> {
    if bytes.is_empty() || bytes.len() > MAX_ENCODED_ROW_BYTES {
        return Err(Error::Invalid("retained encoded row exceeds bounds"));
    }
    let columns = layout(table)?;
    let cells: BoundedVec<Cell, 64> = serde_json::from_slice(bytes)
        .map_err(|_| Error::Invalid("retained row is not a bounded cell array"))?;
    if cells.len() != columns.len() {
        return Err(Error::Invalid("retained column count differs from schema"));
    }
    let values = cells
        .as_slice()
        .iter()
        .map(|cell| match cell {
            Cell::Null => Ok(Value::Null),
            Cell::Integer(text) => {
                let value = text
                    .parse::<i64>()
                    .map_err(|_| Error::Invalid("retained integer is out of range"))?;
                if value.to_string() != *text {
                    return Err(Error::Invalid("retained integer is not canonical"));
                }
                Ok(Value::Integer(value))
            }
            Cell::Text(text) if text.len() <= MAX_CELL_BYTES => Ok(Value::Text(text.clone())),
            Cell::Blob(text)
                if text.len() <= MAX_CELL_BYTES * 2
                    && text.len() % 2 == 0
                    && text
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
            {
                Ok(Value::Blob(hex::decode(text).map_err(|_| {
                    Error::Invalid("retained blob is not canonical")
                })?))
            }
            _ => Err(Error::Invalid(
                "retained cell exceeds its type or byte bound",
            )),
        })
        .collect::<Result<Vec<_>>>()?;
    let references = values.iter().map(ValueRef::from).collect::<Vec<_>>();
    validate_values(table, &references)?;
    if canonical_json_bytes(&cells).map_err(|_| Error::Invalid("retained row cannot be encoded"))?
        != bytes
    {
        return Err(Error::Invalid("retained row JSON is not canonical"));
    }
    Ok(values)
}

pub(super) fn validate_values(table: &str, values: &[ValueRef<'_>]) -> Result<()> {
    let columns = layout(table)?;
    if columns.len() != values.len() {
        return Err(Error::Invalid("source column count differs from schema"));
    }
    let mut bytes = 0_usize;
    for (column, value) in columns.iter().zip(values) {
        let size = match (column.kind.as_str(), value) {
            (_, ValueRef::Null) if column.nullable => 0,
            ("INTEGER", ValueRef::Integer(value)) => value.to_string().len(),
            ("TEXT", ValueRef::Text(value)) if value.len() <= MAX_CELL_BYTES => {
                std::str::from_utf8(value)
                    .map_err(|_| Error::Invalid("source text is not UTF-8"))?;
                value.len()
            }
            ("BLOB", ValueRef::Blob(value)) if value.len() <= MAX_CELL_BYTES => value.len(),
            _ => {
                return Err(Error::Invalid(
                    "source cell differs from its declared storage type",
                ))
            }
        };
        bytes = bytes
            .checked_add(size)
            .ok_or(Error::Invalid("source row size overflow"))?;
        if bytes > MAX_ROW_BYTES {
            return Err(Error::Invalid("source decoded row exceeds bounds"));
        }
    }
    if table == "security_egress_fences" {
        super::super::flow_state::verify_retained_egress_values(values)
            .map_err(|_| Error::Invalid("retained egress fence integrity failed"))?;
    }
    Ok(())
}
