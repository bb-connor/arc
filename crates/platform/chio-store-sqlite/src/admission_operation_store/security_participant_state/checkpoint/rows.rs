use super::delta::Image;
use super::*;
use crate::security_state::{
    decode_retained_security_row, encode_retained_security_values, retained_security_columns,
};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store::security_participant_state) struct Fingerprint {
    pub table: String,
    pub row_count: u64,
    pub encoded_bytes: u64,
    pub digest: String,
}

struct Hasher {
    table: String,
    hash: Sha256,
    count: u64,
    bytes: u64,
}

impl Hasher {
    fn new(table: &str) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"chio.native-security-checkpoint.table.v1\0");
        hash.update(crate::integer::count(table.len()).to_be_bytes());
        hash.update(table.as_bytes());
        Self {
            table: table.into(),
            hash,
            count: 0,
            bytes: 0,
        }
    }

    fn push(&mut self, row: &[u8]) -> Result<(), AdmissionOperationStoreError> {
        if row.is_empty() || row.len() > 16 * 1024 * 1024 {
            return Err(invalid("native checkpoint row exceeds bounds"));
        }
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| invalid("native checkpoint row overflow"))?;
        self.bytes = self
            .bytes
            .checked_add(u64::try_from(row.len()).map_err(invalid)?)
            .ok_or_else(|| invalid("native checkpoint byte overflow"))?;
        if self.count > 65_536 || self.bytes > 67_108_864 {
            return Err(invalid("native checkpoint table exceeds bounds"));
        }
        self.hash
            .update(u64::try_from(row.len()).map_err(invalid)?.to_be_bytes());
        self.hash.update(row);
        Ok(())
    }

    fn finish(mut self) -> Fingerprint {
        self.hash.update(self.count.to_be_bytes());
        self.hash.update(self.bytes.to_be_bytes());
        Fingerprint {
            table: self.table,
            row_count: self.count,
            encoded_bytes: self.bytes,
            digest: hex::encode(self.hash.finalize()),
        }
    }
}

/// Fingerprint of one table image from its rows in stored order.
pub(super) fn fingerprint<'a>(
    table: &str,
    rows: impl IntoIterator<Item = &'a Vec<u8>>,
) -> Result<Fingerprint, AdmissionOperationStoreError> {
    let mut hasher = Hasher::new(table);
    for row in rows {
        hasher.push(row)?;
    }
    Ok(hasher.finish())
}

/// The authority's current native rows after compaction: in keyframe order
/// (schema table, then column values) and as a digest-keyed image.
pub(super) struct Current {
    rows: Vec<(usize, Vec<u8>)>,
    pub image: Image,
}

impl Current {
    pub(super) fn rows(&self) -> impl Iterator<Item = (usize, &[u8])> {
        self.rows
            .iter()
            .map(|(table, row)| (*table, row.as_slice()))
    }

    /// Keyframe fingerprints over the rows in stored order.
    pub(super) fn fingerprints(&self) -> Result<Vec<Fingerprint>, AdmissionOperationStoreError> {
        super::super::schema::TABLES
            .iter()
            .enumerate()
            .map(|(index, table)| {
                fingerprint(
                    table.source,
                    self.rows
                        .iter()
                        .filter(|(row_table, _)| *row_table == index)
                        .map(|(_, row)| row),
                )
            })
            .collect()
    }
}

pub(super) fn read(
    tx: &Transaction<'_>,
    authority: &str,
) -> Result<Current, AdmissionOperationStoreError> {
    #[cfg(feature = "admission-test-support")]
    let mut copy_probe =
        super::super::image_visit_test_support::ImageVisitProbe::start(tx, "copy")?;
    let mut current = Current {
        rows: Vec::new(),
        image: Image::new(),
    };
    for (index, table) in super::super::schema::TABLES.iter().enumerate() {
        let fields = retained_security_columns(table.source).map_err(invalid)?;
        let columns = fields
            .iter()
            .map(|field| format!("\"{field}\""))
            .collect::<Vec<_>>()
            .join(",");
        let mut statement = tx
            .prepare(&format!(
                "SELECT {columns} FROM {} WHERE security_authority_id = ?1 ORDER BY {columns} LIMIT 65537",
                table.native,
            ))
            .map_err(sqlite_error)?;
        let mut rows = statement.query([authority]).map_err(sqlite_error)?;
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            #[cfg(feature = "admission-test-support")]
            copy_probe.advance(tx)?;
            let values = (0..fields.len())
                .map(|index| row.get_ref(index))
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(sqlite_error)?;
            let bytes = encode_retained_security_values(table.source, &values).map_err(invalid)?;
            if bytes.is_empty() || bytes.len() > 16 * 1024 * 1024 {
                return Err(invalid("native checkpoint row exceeds bounds"));
            }
            current.image.insert(index, bytes.clone())?;
            current.rows.push((index, bytes));
        }
    }
    Ok(current)
}

/// Store rows under `sequence`, numbered per table in the given order.
pub(super) fn write<'r>(
    tx: &Transaction<'_>,
    authority: &str,
    sequence: u64,
    rows: impl IntoIterator<Item = (usize, &'r [u8])>,
) -> Result<(), AdmissionOperationStoreError> {
    let mut insert = tx.prepare(
        "INSERT INTO security_participant_checkpoint_rows
         (security_authority_id,checkpoint_sequence,table_name,row_index,canonical_row) VALUES (?1,?2,?3,?4,?5)"
    ).map_err(sqlite_error)?;
    let sequence = i64::try_from(sequence).map_err(invalid)?;
    let mut indexes = vec![0_i64; super::super::schema::TABLES.len()];
    for (table, row) in rows {
        let (index, table) = indexes
            .get_mut(table)
            .zip(super::super::schema::TABLES.get(table))
            .ok_or_else(|| invalid("native checkpoint table is out of range"))?;
        insert
            .execute(params![authority, sequence, table.source, *index, row])
            .map_err(sqlite_error)?;
        *index = index
            .checked_add(1)
            .ok_or_else(|| invalid("native checkpoint row index overflow"))?;
        super::super::cutpoint(70)?;
    }
    Ok(())
}

/// Visit the rows stored under `record` itself, table by table in row-index
/// order, after bounding them to exactly `expected` rows and bytes.
fn stored(
    connection: &Connection,
    record: &Record,
    expected: (u64, u64),
    mut each: impl FnMut(usize, &[u8]) -> Result<(), AdmissionOperationStoreError>,
) -> Result<(), AdmissionOperationStoreError> {
    // Bound the whole snapshot before allocating any stored BLOB. The capped
    // subquery also refuses excess relational rows without scanning an archive.
    let (count, bytes, malformed): (i64, i64, bool) = connection
        .query_row(
            "SELECT COUNT(*),COALESCE(SUM(length(canonical_row)),0),COALESCE(MAX(
            typeof(canonical_row) <> 'blob' OR length(canonical_row) NOT BETWEEN 1 AND 16777216
            OR typeof(row_index) <> 'integer' OR row_index NOT BETWEEN 0 AND 65535
            OR length(CAST(table_name AS BLOB)) NOT BETWEEN 1 AND 128),0)
         FROM (SELECT table_name,row_index,canonical_row FROM security_participant_checkpoint_rows
               WHERE security_authority_id = ?1 AND checkpoint_sequence = ?2 LIMIT 65537)",
            params![
                record.authority.as_str(),
                i64::try_from(record.sequence).map_err(invalid)?
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(sqlite_error)?;
    if !(0..=65_536).contains(&count)
        || !(0..=67_108_864).contains(&bytes)
        || malformed
        || (
            u64::try_from(count).map_err(invalid)?,
            u64::try_from(bytes).map_err(invalid)?,
        ) != expected
    {
        return Err(invalid("native checkpoint snapshot bounds differ"));
    }
    #[cfg(feature = "admission-test-support")]
    let mut snapshot_probe =
        super::super::image_visit_test_support::ImageVisitProbe::start(connection, "snapshot")?;
    let mut seen = 0_u64;
    for (index, table) in super::super::schema::TABLES.iter().enumerate() {
        let mut statement = connection.prepare(
            "SELECT row_index,canonical_row FROM security_participant_checkpoint_rows
             WHERE security_authority_id = ?1 AND checkpoint_sequence = ?2 AND table_name = ?3 ORDER BY row_index"
        ).map_err(sqlite_error)?;
        let mut rows = statement
            .query(params![
                record.authority.as_str(),
                i64::try_from(record.sequence).map_err(invalid)?,
                table.source
            ])
            .map_err(sqlite_error)?;
        let mut next = 0_i64;
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            #[cfg(feature = "admission-test-support")]
            snapshot_probe.advance(connection)?;
            if row.get::<_, i64>(0).map_err(sqlite_error)? != next {
                return Err(invalid("native checkpoint row sequence has gaps"));
            }
            next = next
                .checked_add(1)
                .ok_or_else(|| invalid("native checkpoint row index overflow"))?;
            let bytes = row
                .get_ref(1)
                .map_err(sqlite_error)?
                .as_blob()
                .map_err(invalid)?;
            decode_retained_security_row(table.source, bytes).map_err(invalid)?;
            each(index, bytes)?;
            seen = seen
                .checked_add(1)
                .ok_or_else(|| invalid("native checkpoint inventory overflow"))?;
        }
    }
    if seen != expected.0 {
        return Err(invalid("native checkpoint snapshot contains foreign rows"));
    }
    Ok(())
}

/// The full image a keyframe stores, checked against its fingerprints in
/// stored order.
pub(super) fn keyframe(
    connection: &Connection,
    record: &Record,
) -> Result<Image, AdmissionOperationStoreError> {
    if record.delta.is_some() {
        return Err(invalid("native checkpoint delta is not a keyframe"));
    }
    let mut hashers = super::super::schema::TABLES
        .iter()
        .map(|table| Hasher::new(table.source))
        .collect::<Vec<_>>();
    let mut image = Image::new();
    stored(
        connection,
        record,
        (record.current_rows, record.current_bytes),
        |index, bytes| {
            hashers
                .get_mut(index)
                .ok_or_else(|| invalid("native checkpoint table is out of range"))?
                .push(bytes)?;
            image.insert(index, bytes.to_vec())
        },
    )?;
    for (hasher, expected) in hashers.into_iter().zip(&record.tables) {
        if &hasher.finish() != expected {
            return Err(invalid("native checkpoint snapshot fingerprint differs"));
        }
    }
    Ok(image)
}

/// The rows a delta adds, bounded to its declared totals and authenticated by
/// its committed digest.
pub(super) fn added(
    connection: &Connection,
    record: &Record,
) -> Result<Vec<(usize, Vec<u8>)>, AdmissionOperationStoreError> {
    let delta = record
        .delta
        .as_ref()
        .ok_or_else(|| invalid("native checkpoint keyframe is not a delta"))?;
    let mut added = Vec::new();
    stored(
        connection,
        record,
        (delta.added_rows, delta.added_bytes),
        |index, bytes| {
            added.push((index, bytes.to_vec()));
            Ok(())
        },
    )?;
    let digest =
        super::delta::added_digest(added.iter().map(|(table, row)| (*table, row.as_slice())))?;
    if digest != delta.added_digest {
        return Err(invalid("native checkpoint delta added rows digest differs"));
    }
    Ok(added)
}
