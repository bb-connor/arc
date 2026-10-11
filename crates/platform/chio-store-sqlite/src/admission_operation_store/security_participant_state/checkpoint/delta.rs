//! Delta checkpoints: the rows added since the previous seal plus tombstones
//! for the rows it removed, folded onto the latest full keyframe. Each record
//! still commits to the fingerprints of its complete resulting image.
//!
//! Reconstruction bound, in row payload: the keyframe's rows plus the rows
//! charged to every seal since stay within twice the current image's rows,
//! and the same holds for canonical row bytes, counting an empty image as one
//! row and one byte (`base + charged changes <= 2 * max(current, 1)`, with
//! identical predicates when planning and when validating a persisted
//! delta). Each seal is charged at least one row and one byte, so the chain
//! also bounds the number of records a fold reads: one keyframe plus at most
//! twice the current rows of deltas. Each of those records is a canonical
//! record of at most 64 KiB that is parsed and hashed, and each stored row is
//! hashed for its fingerprint and, for a delta, its added-row digest; that
//! record overhead is not part of the row-payload bound. A global projection
//! reference reads only the referenced record's own stored rows.
//!
//! Retained storage is separate: a delta stores only its added rows, and a
//! keyframe copies the whole current image. A keyframe is taken for the first
//! seal, when the row or the byte budget above would be exceeded, or when one
//! seal removes more than `MAX_TOMBSTONES` rows. Each such copy is retained.
use super::*;
use super::{record, rows};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Tombstones one delta may carry. More force a keyframe, which keeps the
/// canonical record within its 64 KiB bound.
const MAX_TOMBSTONES: usize = 256;

/// The keyframe plus the chain a fold reads stay within this multiple of the
/// current image, in rows and in row bytes.
const READ_FACTOR: u64 = 2;

fn within_budget(base: u64, chain: u64, current: u64) -> bool {
    base.checked_add(chain)
        .zip(current.max(1).checked_mul(READ_FACTOR))
        .is_some_and(|(read, budget)| read <= budget)
}

/// SHA-256 over a delta's added rows in stored order: schema table, then row
/// index. Each row is bound to its table and length, and the count and total
/// bytes close the stream.
pub(super) fn added_digest<'r>(
    rows: impl IntoIterator<Item = (usize, &'r [u8])>,
) -> Result<String, AdmissionOperationStoreError> {
    let mut hash = Sha256::new();
    hash.update(b"chio.native-security-checkpoint.delta-added.v1\0");
    let (mut count, mut bytes) = (0_u64, 0_u64);
    for (table, row) in rows {
        let table = super::super::schema::TABLES
            .get(table)
            .ok_or_else(|| invalid("native checkpoint table is out of range"))?
            .source;
        let length = u64::try_from(row.len()).map_err(invalid)?;
        hash.update(u64::try_from(table.len()).map_err(invalid)?.to_be_bytes());
        hash.update(table.as_bytes());
        hash.update(length.to_be_bytes());
        hash.update(row);
        count = count
            .checked_add(1)
            .ok_or_else(|| invalid("native checkpoint delta row overflow"))?;
        bytes = bytes
            .checked_add(length)
            .ok_or_else(|| invalid("native checkpoint delta byte overflow"))?;
    }
    hash.update(count.to_be_bytes());
    hash.update(bytes.to_be_bytes());
    Ok(hex::encode(hash.finalize()))
}

fn removed_bytes(removed: &[Tombstone]) -> Result<u64, AdmissionOperationStoreError> {
    removed.iter().try_fold(0_u64, |total, tombstone| {
        total
            .checked_add(tombstone.encoded_bytes)
            .ok_or_else(|| invalid("native checkpoint tombstone byte overflow"))
    })
}

/// Rows and bytes one seal adds to its chain, each at least one.
fn charge(
    added_rows: u64,
    added_bytes: u64,
    removed: &[Tombstone],
) -> Result<(u64, u64), AdmissionOperationStoreError> {
    let rows = added_rows
        .checked_add(u64::try_from(removed.len()).map_err(invalid)?)
        .ok_or_else(|| invalid("native checkpoint delta row overflow"))?;
    let bytes = added_bytes
        .checked_add(removed_bytes(removed)?)
        .ok_or_else(|| invalid("native checkpoint delta byte overflow"))?;
    Ok((rows.max(1), bytes.max(1)))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store::security_participant_state) struct Delta {
    /// Sequence of the keyframe this delta folds onto.
    pub base: u64,
    /// Rows and row bytes of that keyframe's image.
    pub base_rows: u64,
    pub base_bytes: u64,
    /// Row changes from the keyframe through this delta, each seal charged
    /// at least one.
    pub chain_rows: u64,
    /// Added plus removed row bytes from the keyframe through this delta,
    /// each seal charged at least one.
    pub chain_bytes: u64,
    pub added_rows: u64,
    pub added_bytes: u64,
    /// `added_digest` of this record's stored added rows.
    pub added_digest: String,
    /// Removed rows in schema table order, then digest order.
    pub removed: Vec<Tombstone>,
}

/// Authenticated deletion of one exact row image of the previous seal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store::security_participant_state) struct Tombstone {
    pub table: String,
    /// SHA-256 of the removed canonical row bytes.
    pub digest: String,
    pub encoded_bytes: u64,
}

impl Delta {
    /// Bounds a persisted delta before any of its rows are read: its own
    /// charge fits its chain and the chain fits the reconstruction budget of
    /// the image the record commits to.
    pub(super) fn validate(
        &self,
        sequence: u64,
        current_rows: u64,
        current_bytes: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        let span = sequence
            .checked_sub(self.base)
            .ok_or_else(|| invalid("native checkpoint delta base follows its record"))?;
        if self.base == 0
            || span == 0
            || self.base_rows > 65_536
            || self.base_bytes > 67_108_864
            || self.added_rows > 65_536
            || self.added_bytes > 67_108_864
            || self.removed.len() > MAX_TOMBSTONES
        {
            return Err(invalid("native checkpoint delta metadata is malformed"));
        }
        AdmissionDigest::try_new("native_checkpoint_delta_added", &self.added_digest)?;
        let (rows, bytes) = charge(self.added_rows, self.added_bytes, &self.removed)?;
        if self.chain_rows < rows.max(span)
            || self.chain_bytes < bytes.max(span)
            || !within_budget(self.base_rows, self.chain_rows, current_rows)
            || !within_budget(self.base_bytes, self.chain_bytes, current_bytes)
        {
            return Err(invalid("native checkpoint delta exceeds its read budget"));
        }
        let mut previous: Option<(usize, &str)> = None;
        for tombstone in &self.removed {
            let key = (table_index(&tombstone.table)?, tombstone.digest.as_str());
            AdmissionDigest::try_new("native_checkpoint_tombstone", &tombstone.digest)?;
            if !(1..=16 * 1024 * 1024).contains(&tombstone.encoded_bytes)
                || previous.is_some_and(|previous| previous >= key)
            {
                return Err(invalid("native checkpoint tombstones are malformed"));
            }
            previous = Some(key);
        }
        Ok(())
    }
}

fn table_index(table: &str) -> Result<usize, AdmissionOperationStoreError> {
    super::super::schema::TABLES
        .iter()
        .position(|candidate| candidate.source == table)
        .ok_or_else(|| invalid("native checkpoint names an unknown table"))
}

/// One authority's native rows per schema table, keyed by row digest.
pub(super) struct Image {
    tables: Vec<BTreeMap<String, Vec<u8>>>,
    /// Tables changed since the last verified fingerprint.
    dirty: Vec<bool>,
    rows: u64,
    bytes: u64,
}

impl Image {
    pub(super) fn new() -> Self {
        let tables = super::super::schema::TABLES.len();
        Self {
            tables: vec![BTreeMap::new(); tables],
            dirty: vec![true; tables],
            rows: 0,
            bytes: 0,
        }
    }

    pub(super) fn insert(
        &mut self,
        table: usize,
        row: Vec<u8>,
    ) -> Result<(), AdmissionOperationStoreError> {
        let length = u64::try_from(row.len()).map_err(invalid)?;
        self.rows = self
            .rows
            .checked_add(1)
            .ok_or_else(|| invalid("native checkpoint image row overflow"))?;
        self.bytes = self
            .bytes
            .checked_add(length)
            .ok_or_else(|| invalid("native checkpoint image byte overflow"))?;
        if self.rows > 65_536 || self.bytes > 67_108_864 {
            return Err(invalid("native checkpoint image exceeds bounds"));
        }
        let rows = self
            .tables
            .get_mut(table)
            .ok_or_else(|| invalid("native checkpoint table is out of range"))?;
        if rows.insert(sha256_hex(&row), row).is_some() {
            return Err(invalid("native checkpoint image repeats a row"));
        }
        self.mark(table)
    }

    fn remove(&mut self, tombstone: &Tombstone) -> Result<(), AdmissionOperationStoreError> {
        let table = table_index(&tombstone.table)?;
        let removed = self
            .tables
            .get_mut(table)
            .and_then(|rows| rows.remove(&tombstone.digest))
            .ok_or_else(|| invalid("native checkpoint tombstone has no exact row"))?;
        if u64::try_from(removed.len()).map_err(invalid)? != tombstone.encoded_bytes {
            return Err(invalid("native checkpoint tombstone length differs"));
        }
        self.rows = self
            .rows
            .checked_sub(1)
            .ok_or_else(|| invalid("native checkpoint image row underflow"))?;
        self.bytes = self
            .bytes
            .checked_sub(tombstone.encoded_bytes)
            .ok_or_else(|| invalid("native checkpoint image byte underflow"))?;
        self.mark(table)
    }

    fn mark(&mut self, table: usize) -> Result<(), AdmissionOperationStoreError> {
        *self
            .dirty
            .get_mut(table)
            .ok_or_else(|| invalid("native checkpoint table is out of range"))? = true;
        Ok(())
    }

    pub(super) fn totals(&self) -> (u64, u64) {
        (self.rows, self.bytes)
    }

    pub(super) fn rows(&self) -> impl Iterator<Item = (&'static str, &[u8])> {
        super::super::schema::TABLES
            .iter()
            .zip(&self.tables)
            .flat_map(|(table, rows)| rows.values().map(|row| (table.source, row.as_slice())))
    }

    pub(super) fn fingerprints(
        &self,
    ) -> Result<Vec<rows::Fingerprint>, AdmissionOperationStoreError> {
        super::super::schema::TABLES
            .iter()
            .zip(&self.tables)
            .map(|(table, rows)| rows::fingerprint(table.source, rows.values()))
            .collect()
    }

    /// Require `record` to commit to exactly this image. Tables unchanged
    /// since `unchanged` was verified must carry its fingerprints unchanged.
    pub(super) fn verify(
        &mut self,
        record: &Record,
        unchanged: Option<&Record>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if self.totals() != (record.current_rows, record.current_bytes) {
            return Err(invalid("native checkpoint image totals differ"));
        }
        for (index, ((table, rows), dirty)) in super::super::schema::TABLES
            .iter()
            .zip(&self.tables)
            .zip(&self.dirty)
            .enumerate()
        {
            let expected = record
                .tables
                .get(index)
                .ok_or_else(|| invalid("native checkpoint table is out of range"))?;
            let matches = match unchanged.and_then(|previous| previous.tables.get(index)) {
                Some(previous) if !dirty => previous == expected,
                _ => &rows::fingerprint(table.source, rows.values())? == expected,
            };
            if !matches {
                return Err(invalid("native checkpoint image fingerprint differs"));
            }
        }
        self.dirty.fill(false);
        Ok(())
    }
}

/// Position of a delta fold: the keyframe it started from and the last
/// sequence applied.
pub(super) struct Chain {
    base: u64,
    base_rows: u64,
    base_bytes: u64,
    sequence: u64,
    chain_rows: u64,
    chain_bytes: u64,
}

impl Chain {
    pub(super) fn start(keyframe: &Record) -> Result<Self, AdmissionOperationStoreError> {
        if keyframe.delta.is_some() {
            return Err(invalid("native checkpoint delta base is not a keyframe"));
        }
        Ok(Self {
            base: keyframe.sequence,
            base_rows: keyframe.current_rows,
            base_bytes: keyframe.current_bytes,
            sequence: keyframe.sequence,
            chain_rows: 0,
            chain_bytes: 0,
        })
    }

    /// Apply the next delta: its tombstones must remove exact rows of the
    /// image and its added rows must be new to it.
    pub(super) fn apply(
        &mut self,
        image: &mut Image,
        step: &Record,
        added: Vec<(usize, Vec<u8>)>,
    ) -> Result<(), AdmissionOperationStoreError> {
        let delta = step
            .delta
            .as_ref()
            .ok_or_else(|| invalid("native checkpoint delta chain crosses a keyframe"))?;
        if delta.base != self.base
            || (delta.base_rows, delta.base_bytes) != (self.base_rows, self.base_bytes)
        {
            return Err(invalid("native checkpoint delta chain mixes keyframes"));
        }
        if Some(step.sequence) != self.sequence.checked_add(1) {
            return Err(invalid("native checkpoint delta chain is out of order"));
        }
        let added_bytes = added.iter().try_fold(0_u64, |total, (_, row)| {
            total
                .checked_add(u64::try_from(row.len()).map_err(invalid)?)
                .ok_or_else(|| invalid("native checkpoint delta byte overflow"))
        })?;
        let (rows, bytes) = charge(
            u64::try_from(added.len()).map_err(invalid)?,
            added_bytes,
            &delta.removed,
        )?;
        if Some(delta.chain_rows) != self.chain_rows.checked_add(rows)
            || Some(delta.chain_bytes) != self.chain_bytes.checked_add(bytes)
        {
            return Err(invalid("native checkpoint delta chain size differs"));
        }
        for tombstone in &delta.removed {
            image.remove(tombstone)?;
        }
        for (table, row) in added {
            image.insert(table, row)?;
        }
        self.sequence = step.sequence;
        self.chain_rows = delta.chain_rows;
        self.chain_bytes = delta.chain_bytes;
        Ok(())
    }
}

/// Exact image `record` commits to: a keyframe directly, or its keyframe with
/// every intervening delta applied in order.
pub(super) fn image(
    connection: &Connection,
    record: &Record,
) -> Result<Image, AdmissionOperationStoreError> {
    let Some(delta) = &record.delta else {
        return rows::keyframe(connection, record);
    };
    let authority = record.authority.as_str();
    let keyframe = record::load_local(connection, authority, delta.base)?
        .ok_or_else(|| invalid("native checkpoint delta base is absent"))?;
    let mut chain = Chain::start(&keyframe)?;
    let mut image = rows::keyframe(connection, &keyframe)?;
    for sequence in delta.base.saturating_add(1)..record.sequence {
        let step = record::load_local(connection, authority, sequence)?
            .ok_or_else(|| invalid("native checkpoint delta chain has a gap"))?;
        chain.apply(&mut image, &step, rows::added(connection, &step)?)?;
    }
    chain.apply(&mut image, record, rows::added(connection, record)?)?;
    image.verify(record, None)?;
    Ok(image)
}

/// What the next seal stores.
pub(super) enum Seal {
    Keyframe,
    Delta {
        delta: Delta,
        added: Vec<(usize, Vec<u8>)>,
    },
}

/// Store a delta unless there is no earlier seal, one seal would remove more
/// than `MAX_TOMBSTONES` rows, or the keyframe plus the chain would exceed
/// the reconstruction budget in rows or in row bytes. `Delta::validate`
/// enforces the same budget on every persisted delta.
pub(super) fn plan(
    previous: Option<(&Record, &Image)>,
    current: &Image,
) -> Result<Seal, AdmissionOperationStoreError> {
    let Some((record, before)) = previous else {
        return Ok(Seal::Keyframe);
    };
    let mut added = Vec::new();
    let mut added_bytes = 0_u64;
    let mut removed = Vec::new();
    for (index, ((table, old), new)) in super::super::schema::TABLES
        .iter()
        .zip(&before.tables)
        .zip(&current.tables)
        .enumerate()
    {
        for (digest, row) in new {
            if !old.contains_key(digest) {
                added_bytes = added_bytes
                    .checked_add(u64::try_from(row.len()).map_err(invalid)?)
                    .ok_or_else(|| invalid("native checkpoint delta byte overflow"))?;
                added.push((index, row.clone()));
            }
        }
        for (digest, row) in old {
            if !new.contains_key(digest) {
                removed.push(Tombstone {
                    table: table.source.into(),
                    digest: digest.clone(),
                    encoded_bytes: u64::try_from(row.len()).map_err(invalid)?,
                });
            }
        }
    }
    if removed.len() > MAX_TOMBSTONES {
        return Ok(Seal::Keyframe);
    }
    let added_rows = u64::try_from(added.len()).map_err(invalid)?;
    let (rows, bytes) = charge(added_rows, added_bytes, &removed)?;
    let (base, base_rows, base_bytes, stored_rows, stored_bytes) = match &record.delta {
        None => (
            record.sequence,
            record.current_rows,
            record.current_bytes,
            0,
            0,
        ),
        Some(delta) => (
            delta.base,
            delta.base_rows,
            delta.base_bytes,
            delta.chain_rows,
            delta.chain_bytes,
        ),
    };
    let chain_rows = stored_rows
        .checked_add(rows)
        .ok_or_else(|| invalid("native checkpoint delta chain overflow"))?;
    let chain_bytes = stored_bytes
        .checked_add(bytes)
        .ok_or_else(|| invalid("native checkpoint delta chain overflow"))?;
    if !within_budget(base_rows, chain_rows, current.rows)
        || !within_budget(base_bytes, chain_bytes, current.bytes)
    {
        return Ok(Seal::Keyframe);
    }
    let added_digest = added_digest(added.iter().map(|(table, row)| (*table, row.as_slice())))?;
    Ok(Seal::Delta {
        delta: Delta {
            base,
            base_rows,
            base_bytes,
            chain_rows,
            chain_bytes,
            added_rows,
            added_bytes,
            added_digest,
            removed,
        },
        added,
    })
}

#[cfg(test)]
#[path = "delta_tests.rs"]
mod tests;
