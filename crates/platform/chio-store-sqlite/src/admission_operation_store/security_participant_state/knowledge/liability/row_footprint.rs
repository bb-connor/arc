//! Exact SQLite record payload sizes for the closed native cell vocabulary.
use super::*;

/// WITHOUT ROWID moves primary-key fields ahead of other fields. Reordering
/// preserves the total serial-type header and cell payload length. This is
/// record DATA; page allocation, overflow and balancing are priced separately.
pub(super) fn record_bytes(
    authority: &str,
    values: &[Value],
) -> Result<u64, AdmissionOperationStoreError> {
    let (authority_serial, authority_bytes) = text_cell(authority.len())?;
    let mut header = varint_bytes(authority_serial);
    let mut body = authority_bytes;
    for value in values {
        let (serial, bytes) = match value {
            Value::Null => (0, 0),
            Value::Integer(value) => integer_cell(*value),
            Value::Text(text) => text_cell(text.len())?,
            Value::Blob(blob) => {
                let bytes = u64::try_from(blob.len()).map_err(invalid)?;
                let serial = bytes
                    .checked_mul(2)
                    .and_then(|value| value.checked_add(12))
                    .ok_or_else(|| invalid("native blob serial type overflow"))?;
                (serial, bytes)
            }
            Value::Real(_) => {
                return Err(invalid("native row footprint contains a real-valued cell"))
            }
        };
        header = header
            .checked_add(varint_bytes(serial))
            .ok_or_else(|| invalid("native record serial header overflow"))?;
        body = body
            .checked_add(bytes)
            .ok_or_else(|| invalid("native record body overflow"))?;
    }
    let serial_header = header;
    header = header
        .checked_add(1)
        .ok_or_else(|| invalid("native record header overflow"))?;
    loop {
        let next = serial_header
            .checked_add(varint_bytes(header))
            .ok_or_else(|| invalid("native record header overflow"))?;
        if next == header {
            break;
        }
        header = next;
    }
    header
        .checked_add(body)
        .ok_or_else(|| invalid("native record footprint overflow"))
}

fn text_cell(length: usize) -> Result<(u64, u64), AdmissionOperationStoreError> {
    let bytes = u64::try_from(length).map_err(invalid)?;
    let serial = bytes
        .checked_mul(2)
        .and_then(|value| value.checked_add(13))
        .ok_or_else(|| invalid("native text serial type overflow"))?;
    Ok((serial, bytes))
}

fn integer_cell(value: i64) -> (u64, u64) {
    // The exact compiled modern SQLite/native catalog uses schema format 4.
    // Serial types 8 and 9 retain integer zero and one without body bytes.
    match value {
        0 => (8, 0),
        1 => (9, 0),
        -128..=127 => (1, 1),
        -32_768..=32_767 => (2, 2),
        -8_388_608..=8_388_607 => (3, 3),
        -2_147_483_648..=2_147_483_647 => (4, 4),
        -140_737_488_355_328..=140_737_488_355_327 => (5, 6),
        _ => (6, 8),
    }
}

fn varint_bytes(value: u64) -> u64 {
    if value >= 1_u64 << 56 {
        9
    } else {
        u64::from((64 - value.leading_zeros()).max(1)).div_ceil(7)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_integer_and_blob_record_sizes_match_actual_sqlite_payloads(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "CREATE TABLE measured(authority TEXT NOT NULL,tenant TEXT NOT NULL,
             generation INTEGER NOT NULL,payload BLOB NOT NULL,
             PRIMARY KEY(authority,tenant)) STRICT,WITHOUT ROWID;",
        )?;
        for generation in [
            0,
            1,
            -128,
            127,
            128,
            -129,
            32_767,
            32_768,
            8_388_607,
            8_388_608,
            2_147_483_647,
            2_147_483_648,
            140_737_488_355_327,
            140_737_488_355_328,
            i64::MIN,
            i64::MAX,
        ] {
            for size in [0, 57, 58, 127, 128, 1024] {
                let payload = vec![7_u8; size];
                connection.execute("DELETE FROM measured", [])?;
                connection.execute(
                    "INSERT INTO measured VALUES(?1,?2,?3,?4)",
                    params!["actual-authority", "actual-tenant", generation, &payload],
                )?;
                let actual: i64 = connection.query_row(
                    "SELECT sum(payload) FROM main.dbstat WHERE name='measured'",
                    [],
                    |row| row.get(0),
                )?;
                let actual = u64::try_from(actual)?;
                let proposed = record_bytes(
                    "actual-authority",
                    &[
                        Value::Text("actual-tenant".into()),
                        Value::Integer(generation),
                        Value::Blob(payload),
                    ],
                )?;
                assert_eq!(proposed, actual, "generation {generation}, blob {size}");
            }
        }
        Ok(())
    }

    #[test]
    fn native_record_header_growth_matches_an_actual_wide_sqlite_row(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        let columns = (0..64)
            .map(|index| format!("cell{index} BLOB NOT NULL"))
            .collect::<Vec<_>>()
            .join(",");
        connection.execute_batch(&format!(
            "CREATE TABLE measured(authority TEXT PRIMARY KEY,{columns}) STRICT,WITHOUT ROWID"
        ))?;
        let values = vec![Value::Blob(vec![9_u8; 128]); 64];
        let parameters = std::iter::once(Value::Text("wide-authority".into()))
            .chain(values.iter().cloned())
            .collect::<Vec<_>>();
        let slots = vec!["?"; parameters.len()].join(",");
        connection.execute(
            &format!("INSERT INTO measured VALUES({slots})"),
            rusqlite::params_from_iter(parameters.iter()),
        )?;
        let actual: i64 = connection.query_row(
            "SELECT sum(payload) FROM main.dbstat WHERE name='measured'",
            [],
            |row| row.get(0),
        )?;
        let actual = u64::try_from(actual)?;
        assert_eq!(record_bytes("wide-authority", &values)?, actual);
        Ok(())
    }
}
