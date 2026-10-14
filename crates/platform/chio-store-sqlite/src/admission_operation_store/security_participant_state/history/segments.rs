//! Sealed native journal segments. Every family keeps its own sequence and hash
//! chain across seals. The segment bounds apply to the live tail above the
//! latest seal, and each seal commits the exact rows of the segment it closes.
use super::super::super::recovery::storage as protected;
use super::super::finishing_plan::{NativeSealAllowanceData, VerifiedNativeSealAllowance};
use super::super::{egress, knowledge, nonce_preflight, output};
use super::*;
use crate::admission_operation_store::knowledge::encoding::write::VerifiedKnowledgeEncodingWrite;
use std::collections::BTreeSet;
use std::ops::Deref;

#[cfg(feature = "admission-test-support")]
mod seal_fault;

const SCHEMA: &str = "chio.native-journal-seal.v1";
const SEAL_NAMESPACE: &str = "native-journal-seal:";
const SEAL_DIGEST_DOMAIN: &[u8] = b"chio.native-journal-seal.commit.v1\0";
const SEAL_SCOPE_DOMAIN: &[u8] = b"chio.native-journal-seal.scope.v1\0";
const SEAL_KIND: &str = "command";
const MAX_SEGMENT_ENTRIES: u64 = 65_536;
const MAX_SEGMENT_BYTES: u64 = 67_108_864;
const MAX_SEGMENT_KNOWLEDGE: u64 = 4096;
const OPEN: u64 = 9_007_199_254_740_991;

/// One relational native journal family. Knowledge joins are protected
/// recovery roots and are handled separately.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::admission_operation_store::security_participant_state) enum Family {
    Mutations,
    Egress,
    Output,
    NoncePreflight,
}

const FAMILIES: [Family; 4] = [
    Family::Mutations,
    Family::Egress,
    Family::Output,
    Family::NoncePreflight,
];

impl Family {
    /// Sequence 1 of the mutation family is the initialization itself.
    fn initial(self) -> u64 {
        match self {
            Self::Mutations => 1,
            Self::Egress | Self::Output | Self::NoncePreflight => 0,
        }
    }
    fn index(self) -> usize {
        match self {
            Self::Mutations => 0,
            Self::Egress => 1,
            Self::Output => 2,
            Self::NoncePreflight => 3,
        }
    }
    fn present(self, connection: &Connection) -> Result<bool, AdmissionOperationStoreError> {
        match self {
            Self::Mutations => Ok(true),
            Self::Egress => egress::exists(connection),
            Self::Output => output::exists(connection),
            Self::NoncePreflight => nonce_preflight::exists(connection),
        }
    }
    fn range_sql(self) -> &'static str {
        match self {
            Self::Mutations => "SELECT COUNT(*), COALESCE(MIN(sequence),0), COALESCE(MAX(sequence),0), COALESCE(SUM(length(canonical_record)),0)
                FROM security_participant_state_mutations WHERE security_authority_id = ?1 AND sequence > ?2 AND sequence <= ?3",
            Self::Egress => "SELECT COUNT(*), COALESCE(MIN(sequence),0), COALESCE(MAX(sequence),0), COALESCE(SUM(length(canonical_record)),0)
                FROM security_participant_egress_events WHERE security_authority_id = ?1 AND sequence > ?2 AND sequence <= ?3",
            Self::Output => "SELECT COUNT(*), COALESCE(MIN(sequence),0), COALESCE(MAX(sequence),0), COALESCE(SUM(length(canonical_record)),0)
                FROM security_participant_output_events WHERE security_authority_id = ?1 AND sequence > ?2 AND sequence <= ?3",
            Self::NoncePreflight => "SELECT COUNT(*), COALESCE(MIN(sequence),0), COALESCE(MAX(sequence),0), COALESCE(SUM(length(canonical_record)),0)
                FROM security_participant_nonce_preflight_events WHERE security_authority_id = ?1 AND sequence > ?2 AND sequence <= ?3",
        }
    }
    fn row_sql(self) -> &'static str {
        match self {
            Self::Mutations => "SELECT (SELECT length(canonical_record) FROM security_participant_state_mutations WHERE security_authority_id = ?1 AND sequence = ?2),
                EXISTS(SELECT 1 FROM security_participant_state_mutations WHERE security_authority_id = ?1 AND sequence > ?2)",
            Self::Egress => "SELECT (SELECT length(canonical_record) FROM security_participant_egress_events WHERE security_authority_id = ?1 AND sequence = ?2),
                EXISTS(SELECT 1 FROM security_participant_egress_events WHERE security_authority_id = ?1 AND sequence > ?2)",
            Self::Output => "SELECT (SELECT length(canonical_record) FROM security_participant_output_events WHERE security_authority_id = ?1 AND sequence = ?2),
                EXISTS(SELECT 1 FROM security_participant_output_events WHERE security_authority_id = ?1 AND sequence > ?2)",
            Self::NoncePreflight => "SELECT (SELECT length(canonical_record) FROM security_participant_nonce_preflight_events WHERE security_authority_id = ?1 AND sequence = ?2),
                EXISTS(SELECT 1 FROM security_participant_nonce_preflight_events WHERE security_authority_id = ?1 AND sequence > ?2)",
        }
    }
    fn rowid_sql(self) -> &'static str {
        match self {
            Self::Mutations => "SELECT MAX(rowid) FROM security_participant_state_mutations",
            Self::Egress => "SELECT MAX(rowid) FROM security_participant_egress_events",
            Self::Output => "SELECT MAX(rowid) FROM security_participant_output_events",
            Self::NoncePreflight => {
                "SELECT MAX(rowid) FROM security_participant_nonce_preflight_events"
            }
        }
    }
    fn digest_sql(self) -> &'static str {
        match self {
            Self::Mutations => "SELECT mutation_digest FROM security_participant_state_mutations WHERE security_authority_id = ?1 AND sequence = ?2",
            Self::Egress => "SELECT event_digest FROM security_participant_egress_events WHERE security_authority_id = ?1 AND sequence = ?2",
            Self::Output => "SELECT event_digest FROM security_participant_output_events WHERE security_authority_id = ?1 AND sequence = ?2",
            Self::NoncePreflight => "SELECT event_digest FROM security_participant_nonce_preflight_events WHERE security_authority_id = ?1 AND sequence = ?2",
        }
    }
    fn projection_kind(self) -> &'static str {
        match self {
            Self::Mutations => "security_participant_state",
            Self::Egress => "security_participant_egress",
            Self::Output => "security_participant_output",
            Self::NoncePreflight => "security_participant_nonce_preflight",
        }
    }
    fn exhausted(self) -> &'static str {
        match self {
            Self::Mutations => "native mutation history is incomplete or exceeds bounds",
            Self::Egress => "native egress chain exceeds bounds or has gaps",
            Self::Output => "native output chain exceeds bounds or has gaps",
            Self::NoncePreflight => "native nonce preflight chain exceeds bounds or has gaps",
        }
    }
}

/// Exact rows of one family within one closed segment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FamilyCut {
    last_sequence: u64,
    last_digest: String,
    count: u64,
    bytes: u64,
}

/// Closed protected commitment to one complete native journal segment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeJournalSeal {
    schema: String,
    authority: String,
    initialization: String,
    segment: u64,
    previous: String,
    mutations: FamilyCut,
    egress: FamilyCut,
    output: FamilyCut,
    nonce_preflight: FamilyCut,
    knowledge: FamilyCut,
    last_global_commit: u64,
}

impl NativeJournalSeal {
    fn cut(&self, family: Family) -> &FamilyCut {
        match family {
            Family::Mutations => &self.mutations,
            Family::Egress => &self.egress,
            Family::Output => &self.output,
            Family::NoncePreflight => &self.nonce_preflight,
        }
    }
    fn digest(&self) -> Result<String, AdmissionOperationStoreError> {
        let mut bytes = SEAL_DIGEST_DOMAIN.to_vec();
        bytes.extend(canonical_json_bytes(self).map_err(invalid)?);
        Ok(sha256_hex(&bytes))
    }
    fn totals(&self) -> Result<(u64, u64), AdmissionOperationStoreError> {
        let mut count = self.knowledge.count;
        let mut bytes = self.knowledge.bytes;
        for family in FAMILIES {
            let cut = self.cut(family);
            count = count
                .checked_add(cut.count)
                .ok_or_else(|| invalid("native journal seal count overflow"))?;
            bytes = bytes
                .checked_add(cut.bytes)
                .ok_or_else(|| invalid("native journal seal byte overflow"))?;
        }
        Ok((count, bytes))
    }
}

/// Largest key and canonical payload of one seal of this authority: every
/// number at the widest value a seal can carry, every digest at its length.
pub(in crate::admission_operation_store::security_participant_state) fn seal_bounds(
    authority: &str,
) -> Result<(u64, u64), AdmissionOperationStoreError> {
    let digest = "0".repeat(64);
    let cut = FamilyCut {
        last_sequence: OPEN,
        last_digest: digest.clone(),
        count: OPEN,
        bytes: OPEN,
    };
    let widest = NativeJournalSeal {
        schema: SCHEMA.to_owned(),
        authority: authority.to_owned(),
        initialization: digest.clone(),
        segment: OPEN,
        previous: digest,
        mutations: cut.clone(),
        egress: cut.clone(),
        output: cut.clone(),
        nonce_preflight: cut.clone(),
        knowledge: cut,
        last_global_commit: OPEN,
    };
    Ok((
        u64::try_from(seal_key(authority, OPEN).len()).map_err(invalid)?,
        u64::try_from(protected::encode(&widest)?.len()).map_err(invalid)?,
    ))
}

/// The band a seal is admitted under: the band of the append it precedes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::admission_operation_store) enum NativeSealAdmission {
    /// Precedes a pre-effect append; priced by the physical intake band.
    Intake,
    /// Precedes an owed post-effect append; funded by its plan's allowance.
    Owed,
}

enum SealBand {
    Intake,
    Owed(NativeSealAllowanceData),
}

/// Affine proof minted only by the sealing native writer from its own verified
/// segment. The protected store persists exactly this key, scope and payload,
/// under the band of the append the seal precedes.
pub(in crate::admission_operation_store) struct VerifiedNativeJournalSeal<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    key: String,
    scope: String,
    payload: Vec<u8>,
    band: SealBand,
}

impl<'conn> VerifiedNativeJournalSeal<'_, 'conn> {
    pub(in crate::admission_operation_store) fn key(&self) -> &str {
        &self.key
    }
    pub(in crate::admission_operation_store) fn scope(&self) -> &str {
        &self.scope
    }
    pub(in crate::admission_operation_store) fn payload(&self) -> &[u8] {
        &self.payload
    }
    pub(in crate::admission_operation_store) fn admission(&self) -> NativeSealAdmission {
        match self.band {
            SealBand::Intake => NativeSealAdmission::Intake,
            SealBand::Owed(_) => NativeSealAdmission::Owed,
        }
    }
    /// The proof is spent in its own writer transaction, at an absent key, with
    /// the exact canonical seal its key and scope commit to. An owed seal stays
    /// within the allowance priced for its authority before the effect.
    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.transaction), Deref::deref(tx)) {
            return Err(invalid("native journal seal changed its writer"));
        }
        let seal: NativeJournalSeal = protected::decode(&self.payload)?;
        if seal.schema != SCHEMA
            || self.key != seal_key(&seal.authority, seal.segment)
            || self.scope != seal_scope(&seal.authority)
            || protected::raw_checked(tx, &self.key)?.is_some()
        {
            return Err(invalid("native journal seal proof differs from its seal"));
        }
        if let SealBand::Owed(allowance) = &self.band {
            allowance.covers(&seal.authority, &self.payload)?;
        }
        Ok(())
    }
}

fn seal_prefix(authority: &str) -> String {
    format!("{SEAL_NAMESPACE}{}:", sha256_hex(authority.as_bytes()))
}

fn seal_key(authority: &str, segment: u64) -> String {
    format!("{}{segment:016}", seal_prefix(authority))
}

fn seal_scope(authority: &str) -> String {
    let mut bytes = SEAL_SCOPE_DOMAIN.to_vec();
    bytes.extend(authority.as_bytes());
    sha256_hex(&bytes)
}

fn join_key(authority: &str, sequence: u64) -> String {
    format!("{}{sequence:016}", knowledge::prefix(authority))
}

fn recovery_records(connection: &Connection) -> Result<bool, AdmissionOperationStoreError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='admission_operation_recovery_records')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

fn stored(value: i64) -> Result<u64, AdmissionOperationStoreError> {
    u64::try_from(value).map_err(invalid)
}

fn param(value: u64) -> Result<i64, AdmissionOperationStoreError> {
    i64::try_from(value).map_err(invalid)
}

/// The authenticated latest seal of an authority.
struct Floor {
    seal: Option<NativeJournalSeal>,
}

impl Floor {
    fn sequence(&self, family: Family) -> u64 {
        self.seal
            .as_ref()
            .map_or(family.initial(), |seal| seal.cut(family).last_sequence)
    }
    fn knowledge(&self) -> u64 {
        self.seal
            .as_ref()
            .map_or(0, |seal| seal.knowledge.last_sequence)
    }
    fn segment(&self) -> Result<u64, AdmissionOperationStoreError> {
        self.seal.as_ref().map_or(Ok(0), |seal| {
            seal.segment
                .checked_add(1)
                .ok_or_else(|| invalid("native journal segment overflow"))
        })
    }
    fn previous(&self, initialization: &str) -> Result<String, AdmissionOperationStoreError> {
        self.seal
            .as_ref()
            .map_or_else(|| Ok(initialization.to_owned()), NativeJournalSeal::digest)
    }
    fn digest(&self, family: Family, initialization: &str) -> String {
        self.seal.as_ref().map_or_else(
            || initialization.to_owned(),
            |seal| seal.cut(family).last_digest.clone(),
        )
    }
    fn knowledge_digest(&self, initialization: &str) -> String {
        self.seal.as_ref().map_or_else(
            || initialization.to_owned(),
            |seal| seal.knowledge.last_digest.clone(),
        )
    }
}

/// An immutable seal whose current bytes equal its authenticated original.
fn load_seal(
    connection: &Connection,
    authority: &str,
    key: &str,
) -> Result<NativeJournalSeal, AdmissionOperationStoreError> {
    let row = protected::raw_checked(connection, key)?
        .ok_or_else(|| invalid("native journal seal disappeared"))?;
    let source = protected::source_reference(connection, key)?;
    if row.version != 1
        || row.kind != SEAL_KIND
        || row.scope != seal_scope(authority)
        || source.version() != 1
        || source.kind() != SEAL_KIND
        || !protected::matches_historical_source_command_payload(
            connection,
            &source,
            1,
            &row.payload,
        )?
    {
        return Err(invalid("native journal seal is not its immutable original"));
    }
    let seal: NativeJournalSeal = protected::decode(&row.payload)?;
    if seal.schema != SCHEMA
        || seal.authority != authority
        || key != seal_key(authority, seal.segment)
    {
        return Err(invalid("native journal seal differs from its key"));
    }
    Ok(seal)
}

/// The latest seal, trusted only with its initialization, its previous link
/// and the exact actual last row of every cut.
fn floor(connection: &Connection, authority: &str) -> Result<Floor, AdmissionOperationStoreError> {
    if !recovery_records(connection)? {
        return Ok(Floor { seal: None });
    }
    let latest: Option<String> = connection
        .query_row(
            "SELECT record_key FROM admission_operation_recovery_records
             WHERE record_key GLOB ?1 ORDER BY record_key DESC LIMIT 1",
            [format!("{}*", seal_prefix(authority))],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some(key) = latest else {
        return Ok(Floor { seal: None });
    };
    let seal = load_seal(connection, authority, &key)?;
    // The immutable initialization row is authenticated cold at open.
    let initialization: String = connection
        .query_row(
            "SELECT initialization_digest FROM security_participant_state_initializations
             WHERE security_authority_id = ?1",
            [authority],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| invalid("native journal seal has no initialized authority"))?;
    let previous = match seal.segment.checked_sub(1) {
        None => initialization.clone(),
        Some(segment) => {
            load_seal(connection, authority, &seal_key(authority, segment))?.digest()?
        }
    };
    if seal.initialization != initialization || seal.previous != previous {
        return Err(invalid("native journal seal breaks its previous link"));
    }
    for family in FAMILIES {
        let cut = seal.cut(family);
        if cut.count != 0
            && family_digest(connection, family, authority, cut.last_sequence)? != cut.last_digest
        {
            return Err(invalid("native journal seal differs from its family rows"));
        }
    }
    if seal.knowledge.count != 0
        && knowledge_digest(connection, authority, seal.knowledge.last_sequence)?
            != seal.knowledge.last_digest
    {
        return Err(invalid(
            "native journal seal differs from its knowledge rows",
        ));
    }
    Ok(Floor { seal: Some(seal) })
}

#[derive(Clone, Copy)]
struct Range {
    count: u64,
    last: u64,
    bytes: u64,
}

impl Range {
    fn empty(last: u64) -> Self {
        Self {
            count: 0,
            last,
            bytes: 0,
        }
    }
}

/// Rows of one family in `(after, through]`, required to be contiguous.
fn family_range(
    connection: &Connection,
    family: Family,
    authority: &str,
    after: u64,
    through: u64,
) -> Result<Range, AdmissionOperationStoreError> {
    if !family.present(connection)? {
        return Ok(Range::empty(after));
    }
    let (count, first, last, bytes): (i64, i64, i64, i64) = connection
        .query_row(
            family.range_sql(),
            params![authority, param(after)?, param(through)?],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(sqlite_error)?;
    let (count, first, last, bytes) = (
        stored(count)?,
        stored(first)?,
        stored(last)?,
        stored(bytes)?,
    );
    if count == 0 {
        return Ok(Range::empty(after));
    }
    if Some(first) != after.checked_add(1) || Some(last) != after.checked_add(count) {
        return Err(invalid(family.exhausted()));
    }
    Ok(Range { count, last, bytes })
}

/// Knowledge join roots in `(after, through]`, required to be contiguous.
fn knowledge_rows(
    connection: &Connection,
    authority: &str,
    after: u64,
    through: u64,
) -> Result<Range, AdmissionOperationStoreError> {
    let (count, first, last, bytes): (i64, String, String, i64) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(MIN(record_key),''), COALESCE(MAX(record_key),''), COALESCE(SUM(length(payload)),0)
             FROM admission_operation_recovery_records WHERE record_key > ?1 AND record_key <= ?2 AND record_key GLOB ?3",
            params![
                join_key(authority, after),
                join_key(authority, through),
                format!("{}*", knowledge::prefix(authority))
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(sqlite_error)?;
    let (count, bytes) = (stored(count)?, stored(bytes)?);
    if count == 0 {
        return Ok(Range::empty(after));
    }
    let first_sequence = after
        .checked_add(1)
        .ok_or_else(|| invalid("knowledge history exhausted"))?;
    let last_sequence = after
        .checked_add(count)
        .ok_or_else(|| invalid("knowledge history exhausted"))?;
    if first != join_key(authority, first_sequence) || last != join_key(authority, last_sequence) {
        return Err(invalid("knowledge history exhausted"));
    }
    Ok(Range {
        count,
        last: last_sequence,
        bytes,
    })
}

/// The first key after every key under a `:`-terminated prefix.
fn prefix_end(prefix: &str) -> Result<String, AdmissionOperationStoreError> {
    prefix
        .strip_suffix(':')
        .map(|stem| format!("{stem};"))
        .ok_or_else(|| invalid("native journal key prefix is malformed"))
}

/// Exact payload bytes of the complete chunk set one join root commits to:
/// every ordinal below its count under its owner and body prefix, and no
/// other record under that prefix.
fn chunk_set_bytes(
    connection: &Connection,
    prefix: &str,
    count: u32,
) -> Result<u64, AdmissionOperationStoreError> {
    let end = prefix_end(prefix)?;
    let mut statement = connection
        .prepare(
            "SELECT record_key, length(payload) FROM admission_operation_recovery_records
             WHERE record_key > ?1 AND record_key < ?2 ORDER BY record_key",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement
        .query(params![prefix, end])
        .map_err(sqlite_error)?;
    let (mut ordinal, mut bytes) = (0_u32, 0_u64);
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let key: String = row.get(0).map_err(sqlite_error)?;
        if ordinal >= count || key != format!("{prefix}{ordinal:04}") {
            return Err(invalid("native journal chunk set is not its root's"));
        }
        bytes = bytes
            .checked_add(stored(row.get(1).map_err(sqlite_error)?)?)
            .ok_or_else(|| invalid("native journal chunk byte overflow"))?;
        ordinal += 1;
    }
    if ordinal != count {
        return Err(invalid("native journal chunk set is incomplete"));
    }
    Ok(bytes)
}

/// Exact payload bytes of the chunk set one stored join root commits to.
fn root_chunk_bytes(
    connection: &Connection,
    key: &str,
    payload: &[u8],
) -> Result<u64, AdmissionOperationStoreError> {
    match knowledge::encoding::journal_chunks(key, payload)? {
        None => Ok(0),
        Some((prefix, count)) => chunk_set_bytes(connection, &prefix, count),
    }
}

/// Exact payload bytes of the journal-owned chunks of the joins in
/// `(after, through]`, read from each root's own chunk set. One seek on the
/// partial authority index first decides whether the authority has any.
fn knowledge_chunk_bytes(
    connection: &Connection,
    authority: &str,
    after: u64,
    through: u64,
) -> Result<u64, AdmissionOperationStoreError> {
    let chunked: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records
             WHERE record_key GLOB 'knowledge-encoding-chunk:*'
               AND json_extract(payload,'$.owner.kind')='journal'
               AND json_extract(payload,'$.owner.authority')=?1)",
            [authority],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !chunked {
        return Ok(0);
    }
    let mut statement = connection
        .prepare(
            "SELECT record_key, payload FROM admission_operation_recovery_records
             WHERE record_key > ?1 AND record_key <= ?2 ORDER BY record_key",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement
        .query(params![
            join_key(authority, after),
            join_key(authority, through)
        ])
        .map_err(sqlite_error)?;
    let mut bytes = 0_u64;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let key: String = row.get(0).map_err(sqlite_error)?;
        let payload: Vec<u8> = row.get(1).map_err(sqlite_error)?;
        bytes = bytes
            .checked_add(root_chunk_bytes(connection, &key, &payload)?)
            .ok_or_else(|| invalid("native journal chunk byte overflow"))?;
    }
    Ok(bytes)
}

/// Contiguous knowledge joins in `(after, through]`, at most one segment's
/// worth, each root counted with the chunk set it commits to.
fn knowledge_range(
    connection: &Connection,
    authority: &str,
    after: u64,
    through: u64,
) -> Result<Range, AdmissionOperationStoreError> {
    let mut range = knowledge_rows(connection, authority, after, through)?;
    if range.count > MAX_SEGMENT_KNOWLEDGE {
        return Err(invalid("knowledge history exhausted"));
    }
    if range.count != 0 {
        range.bytes = range
            .bytes
            .checked_add(knowledge_chunk_bytes(
                connection, authority, after, range.last,
            )?)
            .ok_or_else(|| invalid("native journal chunk byte overflow"))?;
    }
    Ok(range)
}

/// Bytes of one knowledge join, its root plus its own chunk set, and whether
/// any later join exists.
fn knowledge_entry(
    connection: &Connection,
    authority: &str,
    sequence: u64,
) -> Result<(Option<u64>, bool), AdmissionOperationStoreError> {
    let key = join_key(authority, sequence);
    let payload: Option<Vec<u8>> = connection
        .query_row(
            "SELECT payload FROM admission_operation_recovery_records WHERE record_key = ?1",
            [&key],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    let later = knowledge_later(connection, authority, sequence)?;
    let Some(payload) = payload else {
        return Ok((None, later));
    };
    let bytes = u64::try_from(payload.len())
        .map_err(invalid)?
        .checked_add(root_chunk_bytes(connection, &key, &payload)?)
        .ok_or_else(|| invalid("native journal chunk byte overflow"))?;
    Ok((Some(bytes), later))
}

/// Whether any knowledge join follows `sequence`.
fn knowledge_later(
    connection: &Connection,
    authority: &str,
    sequence: u64,
) -> Result<bool, AdmissionOperationStoreError> {
    if !recovery_records(connection)? {
        return Ok(false);
    }
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records
             WHERE record_key > ?1 AND record_key < ?2)",
            params![
                join_key(authority, sequence),
                prefix_end(&knowledge::prefix(authority))?
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

/// Head of one relational family for a reader outside a writer append: the
/// absolute last sequence, with the live tail above the latest seal bounded
/// and contiguous.
pub(in crate::admission_operation_store::security_participant_state) fn family_head(
    connection: &Connection,
    family: Family,
    authority: &str,
) -> Result<u64, AdmissionOperationStoreError> {
    let floor = floor(connection, authority)?;
    let range = family_range(connection, family, authority, floor.sequence(family), OPEN)?;
    if range.count > MAX_SEGMENT_ENTRIES || range.bytes > MAX_SEGMENT_BYTES {
        return Err(invalid(family.exhausted()));
    }
    Ok(range.last)
}

/// Absolute last knowledge join sequence for a reader outside a writer
/// append, with at most 4096 live joins.
pub(in crate::admission_operation_store::security_participant_state) fn knowledge_head(
    connection: &Connection,
    authority: &str,
) -> Result<u64, AdmissionOperationStoreError> {
    if !recovery_records(connection)? {
        return Ok(0);
    }
    let floor = floor(connection, authority)?;
    let range = knowledge_rows(connection, authority, floor.knowledge(), OPEN)?;
    if range.count > MAX_SEGMENT_KNOWLEDGE {
        return Err(invalid("knowledge history exhausted"));
    }
    Ok(range.last)
}

/// Sequence of the last knowledge join key. A proof whose writer authenticated
/// the live segment in this same transaction requires only that its record is
/// the next key.
pub(in crate::admission_operation_store::security_participant_state) fn knowledge_last(
    connection: &Connection,
    authority: &str,
) -> Result<u64, AdmissionOperationStoreError> {
    if !recovery_records(connection)? {
        return Ok(0);
    }
    let prefix = knowledge::prefix(authority);
    let last: Option<String> = connection
        .query_row(
            "SELECT record_key FROM admission_operation_recovery_records
             WHERE record_key GLOB ?1 ORDER BY record_key DESC LIMIT 1",
            [format!("{prefix}*")],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some(key) = last else {
        return Ok(0);
    };
    key.strip_prefix(&prefix)
        .and_then(|ordinal| ordinal.parse::<u64>().ok())
        .filter(|sequence| join_key(authority, *sequence) == key)
        .ok_or_else(|| invalid("knowledge history exhausted"))
}

/// Exact entries and retained bytes of the live segment.
struct Live {
    families: [Range; 4],
    knowledge: Range,
    count: u64,
    bytes: u64,
}

impl Live {
    fn empty(floor: &Floor) -> Self {
        Self {
            families: FAMILIES.map(|family| Range::empty(floor.sequence(family))),
            knowledge: Range::empty(floor.knowledge()),
            count: 0,
            bytes: 0,
        }
    }
    fn last(&self, family: Option<Family>) -> u64 {
        family.map_or(self.knowledge.last, |family| {
            self.families[family.index()].last
        })
    }
    fn fits(&self, append: &Append) -> bool {
        self.count < MAX_SEGMENT_ENTRIES
            && self
                .bytes
                .checked_add(append.bytes)
                .is_some_and(|bytes| bytes <= MAX_SEGMENT_BYTES)
            && (append.family.is_some() || self.knowledge.count < MAX_SEGMENT_KNOWLEDGE)
    }
    fn advance(&mut self, append: &Append) -> Result<(), AdmissionOperationStoreError> {
        let range = match append.family {
            Some(family) => &mut self.families[family.index()],
            None => &mut self.knowledge,
        };
        range.count = range
            .count
            .checked_add(1)
            .ok_or_else(|| invalid("native journal count overflow"))?;
        range.bytes = range
            .bytes
            .checked_add(append.bytes)
            .ok_or_else(|| invalid("native journal byte overflow"))?;
        range.last = append.sequence;
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| invalid("native journal count overflow"))?;
        self.bytes = self
            .bytes
            .checked_add(append.bytes)
            .ok_or_else(|| invalid("native journal byte overflow"))?;
        Ok(())
    }
    fn require_bounds(&self) -> Result<(), AdmissionOperationStoreError> {
        if self.count > MAX_SEGMENT_ENTRIES
            || self.bytes > MAX_SEGMENT_BYTES
            || self.knowledge.count > MAX_SEGMENT_KNOWLEDGE
        {
            return Err(invalid("combined native journal exceeds bounds"));
        }
        Ok(())
    }
}

fn live(
    connection: &Connection,
    authority: &str,
    floor: &Floor,
) -> Result<Live, AdmissionOperationStoreError> {
    let mut live = Live::empty(floor);
    for family in FAMILIES {
        let range = family_range(connection, family, authority, floor.sequence(family), OPEN)?;
        live.count = live
            .count
            .checked_add(range.count)
            .ok_or_else(|| invalid("native journal count overflow"))?;
        live.bytes = live
            .bytes
            .checked_add(range.bytes)
            .ok_or_else(|| invalid("native journal byte overflow"))?;
        live.families[family.index()] = range;
    }
    if recovery_records(connection)? {
        let knowledge = knowledge_range(connection, authority, floor.knowledge(), OPEN)?;
        live.count = live
            .count
            .checked_add(knowledge.count)
            .ok_or_else(|| invalid("native journal count overflow"))?;
        live.bytes = live
            .bytes
            .checked_add(knowledge.bytes)
            .ok_or_else(|| invalid("native journal byte overflow"))?;
        live.knowledge = knowledge;
    }
    Ok(live)
}

/// Entries and retained bytes of the live segment for a reader outside a
/// writer append.
pub(in crate::admission_operation_store::security_participant_state) fn live_totals(
    connection: &Connection,
    authority: &str,
) -> Result<(u64, u64), AdmissionOperationStoreError> {
    let floor = floor(connection, authority)?;
    let live = live(connection, authority, &floor)?;
    live.require_bounds()?;
    Ok((live.count, live.bytes))
}

/// The writer and the global commit head a snapshot was read at.
#[derive(Eq, PartialEq)]
struct Cut {
    connection: usize,
    head: i64,
    digest: String,
}

/// The anchored global head, with no commit row beyond it.
fn cut(connection: &Connection) -> Result<Cut, AdmissionOperationStoreError> {
    let (head, digest, beyond): (i64, String, bool) = connection
        .query_row(
            "SELECT head_sequence, head_chain_digest,
                EXISTS(SELECT 1 FROM authority_global_commits WHERE commit_sequence > meta.head_sequence)
             FROM authority_global_commit_meta AS meta WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(sqlite_error)?;
    if beyond {
        return Err(invalid("global commit row follows its anchored head"));
    }
    Ok(Cut {
        connection: connection as *const Connection as usize,
        head,
        digest,
    })
}

/// Rows of the initialization catalog. A loaded authority bounds it at 16, so
/// the read stops at 17.
fn initializations(connection: &Connection) -> Result<i64, AdmissionOperationStoreError> {
    connection
        .query_row(
            "SELECT COUNT(*) FROM (SELECT 1 FROM security_participant_state_initializations LIMIT 17)",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

/// Highest row id of one present relational family table over every
/// authority, by one seek. Its rows are never updated or deleted, and each
/// insert takes the next.
fn family_rowid(
    connection: &Connection,
    family: Family,
) -> Result<i64, AdmissionOperationStoreError> {
    let rowid: Option<i64> = connection
        .query_row(family.rowid_sql(), [], |row| row.get(0))
        .map_err(sqlite_error)?;
    Ok(rowid.unwrap_or(0))
}

/// Bytes of one row of a present relational family and whether any later row
/// follows it.
fn family_row(
    connection: &Connection,
    family: Family,
    authority: &str,
    sequence: u64,
) -> Result<(Option<u64>, bool), AdmissionOperationStoreError> {
    let (bytes, later): (Option<i64>, bool) = connection
        .query_row(
            family.row_sql(),
            params![authority, param(sequence)?],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error)?;
    Ok((bytes.map(stored).transpose()?, later))
}

/// Projection of the commit at one global sequence.
fn commit_at(
    connection: &Connection,
    sequence: i64,
) -> Result<(String, String, i64), AdmissionOperationStoreError> {
    connection
        .query_row(
            "SELECT projection_kind, projection_key, projection_sequence
             FROM authority_global_commits WHERE commit_sequence = ?1",
            [sequence],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| invalid("native journal global commit is absent"))
}

/// The exact next journal entry, derived from its actual canonical record.
#[derive(Eq, PartialEq)]
pub(in crate::admission_operation_store::security_participant_state) struct Append {
    family: Option<Family>,
    authority: String,
    sequence: u64,
    bytes: u64,
}

/// An entry appended before the effect it journals. A seal it needs takes the
/// physical intake band.
pub(in crate::admission_operation_store::security_participant_state) struct PreEffectAppend(Append);

/// An entry owed after its effect. A seal it needs requires an allowance its
/// plan priced before the effect.
pub(in crate::admission_operation_store::security_participant_state) struct OwedAppend(Append);

impl PreEffectAppend {
    pub(in crate::admission_operation_store::security_participant_state) fn entry(
        &self,
    ) -> &Append {
        &self.0
    }
}

impl OwedAppend {
    pub(in crate::admission_operation_store::security_participant_state) fn entry(
        &self,
    ) -> &Append {
        &self.0
    }
}

impl Append {
    fn relational<T: Serialize>(
        family: Family,
        authority: &AdmissionIdentifier,
        sequence: u64,
        record: &T,
    ) -> Result<Self, AdmissionOperationStoreError> {
        Ok(Self {
            family: Some(family),
            authority: authority.as_str().to_owned(),
            sequence,
            bytes: u64::try_from(canonical_json_bytes(record).map_err(invalid)?.len())
                .map_err(invalid)?,
        })
    }
    pub(in crate::admission_operation_store::security_participant_state) fn mutation(
        record: &Record,
    ) -> Result<PreEffectAppend, AdmissionOperationStoreError> {
        Self::relational(
            Family::Mutations,
            &record.authority,
            record.sequence,
            record,
        )
        .map(PreEffectAppend)
    }
    pub(in crate::admission_operation_store::security_participant_state) fn egress(
        record: &egress::Record,
    ) -> Result<PreEffectAppend, AdmissionOperationStoreError> {
        Self::relational(Family::Egress, &record.authority, record.sequence, record)
            .map(PreEffectAppend)
    }
    pub(in crate::admission_operation_store::security_participant_state) fn nonce_preflight(
        record: &nonce_preflight::Record,
    ) -> Result<PreEffectAppend, AdmissionOperationStoreError> {
        Self::relational(
            Family::NoncePreflight,
            &record.authority,
            record.sequence,
            record,
        )
        .map(PreEffectAppend)
    }
    /// A knowledge join retains its encoded root plus every staged chunk.
    pub(in crate::admission_operation_store::security_participant_state) fn knowledge(
        record: &knowledge::Record,
        write: &VerifiedKnowledgeEncodingWrite<'_, '_>,
    ) -> Result<PreEffectAppend, AdmissionOperationStoreError> {
        let mut bytes = u64::try_from(write.root_payload().len()).map_err(invalid)?;
        for chunk in write.staged_chunks() {
            bytes = bytes
                .checked_add(u64::try_from(chunk.payload().len()).map_err(invalid)?)
                .ok_or_else(|| invalid("native journal chunk byte overflow"))?;
        }
        Ok(PreEffectAppend(Self {
            family: None,
            authority: record.authority.clone(),
            sequence: record.sequence,
            bytes,
        }))
    }
    pub(in crate::admission_operation_store::security_participant_state) fn output(
        record: &output::Record,
    ) -> Result<OwedAppend, AdmissionOperationStoreError> {
        Self::relational(Family::Output, &record.authority, record.sequence, record).map(OwedAppend)
    }
}

/// Whether the append continues the live segment or first sealed it.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::admission_operation_store::security_participant_state) enum Boundary {
    Live,
    Sealed,
}

enum Band<'a, 'plan> {
    Intake,
    Owed(Option<&'a VerifiedNativeSealAllowance<'plan>>),
}

/// One authenticated reading of an authority's native journal: its latest seal
/// and its live segment. A writer captures it once per append and reads heads
/// and totals from it. Every use re-verifies the same writer at the same global
/// commit head, so it is never staler than its own transaction.
pub(in crate::admission_operation_store::security_participant_state) struct SegmentSnapshot {
    authority: String,
    initialization: String,
    initializations: i64,
    rowids: [Option<i64>; 4],
    cut: Cut,
    floor: Floor,
    live: Live,
}

impl SegmentSnapshot {
    pub(in crate::admission_operation_store::security_participant_state) fn capture(
        connection: &Connection,
        initialization: &SecurityParticipantStateInitialization,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let authority = initialization.authority.as_str();
        let floor = floor(connection, authority)?;
        if floor
            .seal
            .as_ref()
            .is_some_and(|seal| seal.initialization != initialization.digest)
        {
            return Err(invalid(
                "native journal seal belongs to another initialization",
            ));
        }
        let live = live(connection, authority, &floor)?;
        live.require_bounds()?;
        let mut rowids = [None; 4];
        for family in FAMILIES {
            if family.present(connection)? {
                rowids[family.index()] = Some(family_rowid(connection, family)?);
            }
        }
        Ok(Self {
            authority: authority.to_owned(),
            initialization: initialization.digest.clone(),
            initializations: initializations(connection)?,
            rowids,
            cut: cut(connection)?,
            floor,
            live,
        })
    }

    pub(in crate::admission_operation_store::security_participant_state) fn authority(
        &self,
    ) -> &str {
        &self.authority
    }

    /// The same writer at the same global commit head.
    pub(in crate::admission_operation_store::security_participant_state) fn verify(
        &self,
        connection: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        if cut(connection)? != self.cut {
            return Err(invalid(
                "native journal snapshot changed its writer or global head",
            ));
        }
        Ok(())
    }

    /// Whether the writer's journal footprint is exactly the pinned one: the
    /// same global head with nothing beyond it, the same initializations, the
    /// same relational journal rows and no later knowledge join.
    pub(in crate::admission_operation_store::security_participant_state) fn unchanged(
        &self,
        connection: &Connection,
    ) -> Result<bool, AdmissionOperationStoreError> {
        Ok(cut(connection)? == self.cut && self.settled(connection)?)
    }

    /// No initialization, relational journal row of any authority or later
    /// knowledge join of this authority was added beyond the pinned ones.
    fn settled(&self, connection: &Connection) -> Result<bool, AdmissionOperationStoreError> {
        if initializations(connection)? != self.initializations {
            return Ok(false);
        }
        for family in FAMILIES {
            if let Some(rowid) = self.rowids[family.index()] {
                if family_rowid(connection, family)? != rowid {
                    return Ok(false);
                }
            }
        }
        Ok(!knowledge_later(
            connection,
            &self.authority,
            self.live.knowledge.last,
        )?)
    }

    /// The latest journal entry in global order: the family head with the
    /// highest global commit, since each family commits its rows in sequence.
    /// `None` names the knowledge family; no entry is the imported source.
    pub(in crate::admission_operation_store::security_participant_state) fn latest(
        &self,
        connection: &Connection,
    ) -> Result<Option<(Option<Family>, u64)>, AdmissionOperationStoreError> {
        self.verify(connection)?;
        let mut latest: Option<(u64, Option<Family>, u64)> = None;
        for family in FAMILIES {
            let last = self.live.families[family.index()].last;
            if last > family.initial() {
                let commit =
                    commit_of(connection, family.projection_kind(), &self.authority, last)?;
                if latest.is_none_or(|(highest, _, _)| commit > highest) {
                    latest = Some((commit, Some(family), last));
                }
            }
        }
        let last = self.live.knowledge.last;
        if last != 0 {
            let commit = commit_of(connection, "recovery", &join_key(&self.authority, last), 1)?;
            if latest.is_none_or(|(highest, _, _)| commit > highest) {
                latest = Some((commit, None, last));
            }
        }
        Ok(latest.map(|(_, family, sequence)| (family, sequence)))
    }

    /// Absolute last sequence of one relational family.
    pub(in crate::admission_operation_store::security_participant_state) fn head(
        &self,
        connection: &Connection,
        family: Family,
    ) -> Result<u64, AdmissionOperationStoreError> {
        self.verify(connection)?;
        Ok(self.live.families[family.index()].last)
    }

    /// Absolute last knowledge join sequence.
    pub(in crate::admission_operation_store::security_participant_state) fn knowledge_head(
        &self,
        connection: &Connection,
    ) -> Result<u64, AdmissionOperationStoreError> {
        self.verify(connection)?;
        Ok(self.live.knowledge.last)
    }

    /// Pristine protected key and scope the seal of this live segment would
    /// occupy. Every seal key of an authority has this exact width.
    pub(in crate::admission_operation_store::security_participant_state) fn next_seal_record(
        &self,
        connection: &Connection,
    ) -> Result<(String, String), AdmissionOperationStoreError> {
        self.verify(connection)?;
        Ok((
            seal_key(&self.authority, self.floor.segment()?),
            seal_scope(&self.authority),
        ))
    }

    /// Entries and retained bytes of the live segment.
    pub(in crate::admission_operation_store::security_participant_state) fn totals(
        &self,
        connection: &Connection,
    ) -> Result<(u64, u64), AdmissionOperationStoreError> {
        self.verify(connection)?;
        Ok((self.live.count, self.live.bytes))
    }

    /// Mutation or dispatch join, egress commit, nonce preflight, knowledge join.
    pub(in crate::admission_operation_store::security_participant_state) fn prepare_pre_effect_append(
        &mut self,
        tx: &Transaction<'_>,
        owner: &SqliteServingOwner,
        append: &PreEffectAppend,
    ) -> Result<Boundary, AdmissionOperationStoreError> {
        self.prepare(tx, owner, &append.0, Band::Intake)
    }

    /// Output join. A needed seal without a priced allowance refuses before any
    /// write.
    pub(in crate::admission_operation_store::security_participant_state) fn prepare_owed_append(
        &mut self,
        tx: &Transaction<'_>,
        owner: &SqliteServingOwner,
        append: &OwedAppend,
        allowance: Option<&VerifiedNativeSealAllowance<'_>>,
    ) -> Result<Boundary, AdmissionOperationStoreError> {
        self.prepare(tx, owner, &append.0, Band::Owed(allowance))
    }

    /// Called by every native writer in its own transaction, after its recovery
    /// lease check and immediately before its entry append. If the exact next
    /// entry would cross a live segment bound, the segment is sealed first from
    /// its actual rows; seal and entry commit or roll back together.
    fn prepare(
        &mut self,
        tx: &Transaction<'_>,
        owner: &SqliteServingOwner,
        append: &Append,
        band: Band<'_, '_>,
    ) -> Result<Boundary, AdmissionOperationStoreError> {
        self.verify(tx)?;
        if append.authority != self.authority {
            return Err(invalid("native journal entry belongs to another authority"));
        }
        if self.live.last(append.family).checked_add(1) != Some(append.sequence) {
            return Err(invalid("native journal entry is not the next actual row"));
        }
        if append.bytes > MAX_SEGMENT_BYTES {
            return Err(invalid("native journal entry exceeds a whole segment"));
        }
        if self.live.fits(append) {
            return Ok(Boundary::Live);
        }
        if self.live.count == 0 {
            return Err(invalid("native journal entry exceeds a whole segment"));
        }
        let band = match band {
            Band::Intake => SealBand::Intake,
            Band::Owed(Some(allowance)) => {
                SealBand::Owed(allowance.covers(tx, &self.authority)?.clone())
            }
            Band::Owed(None) => {
                return Err(invalid(
                    "owed native journal append has no priced seal allowance",
                ))
            }
        };
        let seal = derive(
            tx,
            &self.authority,
            &self.initialization,
            &self.floor,
            &self.live,
        )?;
        let proof = VerifiedNativeJournalSeal {
            transaction: tx,
            key: seal_key(&self.authority, seal.segment),
            scope: seal_scope(&self.authority),
            payload: protected::encode(&seal)?,
            band,
        };
        protected::persist_native_journal_seal(tx, owner, &proof)?;
        let sealed = cut(tx)?;
        if load_seal(tx, &self.authority, &proof.key)? != seal
            || self.cut.head.checked_add(1) != Some(sealed.head)
            || commit_of(tx, "recovery", &proof.key, 1)? != stored(sealed.head)?
        {
            return Err(invalid("native journal seal differs from its readback"));
        }
        if !self.settled(tx)? {
            return Err(invalid("native journal seal introduced other history"));
        }
        #[cfg(feature = "admission-test-support")]
        seal_fault::after_seal(owner, &self.authority)?;
        self.cut = sealed;
        self.floor = Floor { seal: Some(seal) };
        self.live = Live::empty(&self.floor);
        Ok(Boundary::Sealed)
    }

    /// The writer appended exactly its decided entry: the row holds the decided
    /// bytes and nothing follows it. The live segment advances by that entry,
    /// and nothing else changed. A relational row appends no global commit of
    /// its own; a knowledge root's encoding commits are bound by its liability.
    pub(in crate::admission_operation_store::security_participant_state) fn appended(
        &mut self,
        connection: &Connection,
        entry: &Append,
    ) -> Result<(), AdmissionOperationStoreError> {
        if connection as *const Connection as usize != self.cut.connection
            || entry.authority != self.authority
        {
            return Err(invalid("native journal snapshot changed its writer"));
        }
        let (bytes, later) = match entry.family {
            Some(family) => family_row(connection, family, &self.authority, entry.sequence)?,
            None => knowledge_entry(connection, &self.authority, entry.sequence)?,
        };
        if bytes != Some(entry.bytes)
            || later
            || self.live.last(entry.family).checked_add(1) != Some(entry.sequence)
        {
            return Err(invalid(
                "native journal append differs from its decided entry",
            ));
        }
        self.live.advance(entry)?;
        self.live.require_bounds()?;
        if let Some(family) = entry.family {
            let rowid = self.rowids[family.index()]
                .as_mut()
                .ok_or_else(|| invalid("native journal family table is absent"))?;
            *rowid = rowid
                .checked_add(1)
                .ok_or_else(|| invalid("native journal row id overflow"))?;
            if cut(connection)? != self.cut {
                return Err(invalid("native journal append introduced other history"));
            }
        }
        if !self.settled(connection)? {
            return Err(invalid("native journal append introduced other history"));
        }
        Ok(())
    }

    /// The writer appended exactly the global commit of its appended relational
    /// entry: the one commit after the pinned head names this family, authority
    /// and sequence, and nothing else changed. The snapshot moves to that head.
    pub(in crate::admission_operation_store::security_participant_state) fn committed(
        &mut self,
        connection: &Connection,
        entry: &Append,
    ) -> Result<(), AdmissionOperationStoreError> {
        let family = entry
            .family
            .ok_or_else(|| invalid("native journal commit has no relational family"))?;
        let next = cut(connection)?;
        if next.connection != self.cut.connection
            || entry.authority != self.authority
            || self.live.last(entry.family) != entry.sequence
            || self.cut.head.checked_add(1) != Some(next.head)
            || commit_at(connection, next.head)?
                != (
                    family.projection_kind().to_owned(),
                    self.authority.clone(),
                    param(entry.sequence)?,
                )
            || !self.settled(connection)?
        {
            return Err(invalid(
                "native journal global append introduced other history",
            ));
        }
        self.cut = next;
        Ok(())
    }
}

fn commit_of(
    connection: &Connection,
    kind: &str,
    key: &str,
    sequence: u64,
) -> Result<u64, AdmissionOperationStoreError> {
    let commit: i64 = connection
        .query_row(
            "SELECT commit_sequence FROM authority_global_commits
             WHERE projection_kind = ?1 AND projection_key = ?2 AND projection_sequence = ?3",
            params![kind, key, param(sequence)?],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| invalid("native journal row lacks its global commit"))?;
    stored(commit)
}

fn family_digest(
    connection: &Connection,
    family: Family,
    authority: &str,
    sequence: u64,
) -> Result<String, AdmissionOperationStoreError> {
    connection
        .query_row(
            family.digest_sql(),
            params![authority, param(sequence)?],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| invalid("native journal cut row is absent"))
}

fn knowledge_digest(
    connection: &Connection,
    authority: &str,
    sequence: u64,
) -> Result<String, AdmissionOperationStoreError> {
    let row = protected::raw_checked(connection, &join_key(authority, sequence))?
        .ok_or_else(|| invalid("knowledge journal cut root is absent"))?;
    Ok(sha256_hex(&row.payload))
}

/// Highest global commit of the authority's native journal at a cut: the
/// initialization, or the commit of any family's last row.
fn cut_commit(
    connection: &Connection,
    authority: &str,
    cuts: &[(Family, u64); 4],
    knowledge: u64,
) -> Result<u64, AdmissionOperationStoreError> {
    let mut highest = commit_of(
        connection,
        Family::Mutations.projection_kind(),
        authority,
        1,
    )?;
    for (family, last) in cuts {
        if *last > family.initial() {
            highest = highest.max(commit_of(
                connection,
                family.projection_kind(),
                authority,
                *last,
            )?);
        }
    }
    if knowledge != 0 {
        highest = highest.max(commit_of(
            connection,
            "recovery",
            &join_key(authority, knowledge),
            1,
        )?);
    }
    Ok(highest)
}

fn derive(
    connection: &Connection,
    authority: &str,
    initialization: &str,
    floor: &Floor,
    live: &Live,
) -> Result<NativeJournalSeal, AdmissionOperationStoreError> {
    let cut = |family: Family| -> Result<FamilyCut, AdmissionOperationStoreError> {
        let range = live.families[family.index()];
        Ok(FamilyCut {
            last_sequence: range.last,
            last_digest: if range.count == 0 {
                floor.digest(family, initialization)
            } else {
                family_digest(connection, family, authority, range.last)?
            },
            count: range.count,
            bytes: range.bytes,
        })
    };
    let knowledge = FamilyCut {
        last_sequence: live.knowledge.last,
        last_digest: if live.knowledge.count == 0 {
            floor.knowledge_digest(initialization)
        } else {
            knowledge_digest(connection, authority, live.knowledge.last)?
        },
        count: live.knowledge.count,
        bytes: live.knowledge.bytes,
    };
    let cuts = FAMILIES.map(|family| (family, live.families[family.index()].last));
    Ok(NativeJournalSeal {
        schema: SCHEMA.to_owned(),
        authority: authority.to_owned(),
        initialization: initialization.to_owned(),
        segment: floor.segment()?,
        previous: floor.previous(initialization)?,
        mutations: cut(Family::Mutations)?,
        egress: cut(Family::Egress)?,
        output: cut(Family::Output)?,
        nonce_preflight: cut(Family::NoncePreflight)?,
        last_global_commit: cut_commit(connection, authority, &cuts, knowledge.last_sequence)?,
        knowledge,
    })
}

/// Decide an Output entry one byte larger than the live segment's remaining
/// room, in the caller's writer and the chosen band, without appending it.
#[cfg(test)]
pub(in crate::admission_operation_store::security_participant_state) fn decide_unfitting_output(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    initialization: &SecurityParticipantStateInitialization,
    owed: bool,
) -> Result<Boundary, AdmissionOperationStoreError> {
    let mut snapshot = SegmentSnapshot::capture(tx, initialization)?;
    let entry = Append {
        family: Some(Family::Output),
        authority: snapshot.authority.clone(),
        sequence: snapshot
            .live
            .last(Some(Family::Output))
            .checked_add(1)
            .ok_or_else(|| invalid("native output sequence overflow"))?,
        bytes: MAX_SEGMENT_BYTES
            .checked_sub(snapshot.live.bytes)
            .and_then(|room| room.checked_add(1))
            .ok_or_else(|| invalid("native journal byte overflow"))?,
    };
    if owed {
        snapshot.prepare_owed_append(tx, owner, &OwedAppend(entry), None)
    } else {
        snapshot.prepare_pre_effect_append(tx, owner, &PreEffectAppend(entry))
    }
}

/// Every seal key must belong to an initialized authority. Streams the whole
/// seal namespace, so seals of unknown authorities fail closed.
pub(in crate::admission_operation_store::security_participant_state) fn verify_seal_owners(
    connection: &Connection,
    initialized: &[SecurityParticipantStateInitialization],
) -> Result<(), AdmissionOperationStoreError> {
    if !recovery_records(connection)? {
        return Ok(());
    }
    let owners = initialized
        .iter()
        .map(|initialization| seal_prefix(initialization.authority.as_str()))
        .collect::<BTreeSet<_>>();
    let mut statement = connection
        .prepare(
            "SELECT record_key FROM admission_operation_recovery_records WHERE record_key GLOB ?1
             UNION SELECT record_key FROM admission_operation_recovery_events WHERE record_key GLOB ?1
             UNION SELECT projection_key FROM authority_global_commits
               WHERE projection_kind = 'recovery' AND projection_key GLOB ?1",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement
        .query([format!("{SEAL_NAMESPACE}*")])
        .map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let key: String = row.get(0).map_err(sqlite_error)?;
        let owned = key.rsplit_once(':').is_some_and(|(prefix, ordinal)| {
            owners.contains(&format!("{prefix}:"))
                && ordinal.len() == 16
                && ordinal.bytes().all(|byte| byte.is_ascii_digit())
        });
        if !owned {
            return Err(invalid("native journal seal has no initialized authority"));
        }
    }
    Ok(())
}

/// Stream every seal of one authority and its live tail with bounded memory.
/// Refuses a gap, foreign or reordered seal, a broken previous link, a cut
/// that differs from its actual rows, an empty or oversized segment, a seal
/// committed outside its cut, and a live tail beyond the segment bounds.
pub(in crate::admission_operation_store::security_participant_state) fn verify_authority(
    connection: &Connection,
    initialization: &SecurityParticipantStateInitialization,
) -> Result<(), AdmissionOperationStoreError> {
    if !recovery_records(connection)? {
        return Ok(());
    }
    let authority = initialization.authority.as_str();
    let mut floor = Floor { seal: None };
    let mut statement = connection
        .prepare(
            "SELECT record_key FROM admission_operation_recovery_records
             WHERE record_key GLOB ?1 ORDER BY record_key",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement
        .query([format!("{}*", seal_prefix(authority))])
        .map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let key: String = row.get(0).map_err(sqlite_error)?;
        if key != seal_key(authority, floor.segment()?) {
            return Err(invalid("native journal seals have a gap or a foreign key"));
        }
        let seal = load_seal(connection, authority, &key)?;
        if seal.initialization != initialization.digest
            || seal.previous != floor.previous(&initialization.digest)?
        {
            return Err(invalid("native journal seal breaks its previous link"));
        }
        verify_cut(connection, initialization, &floor, &seal, &key)?;
        floor = Floor { seal: Some(seal) };
    }
    live(connection, authority, &floor)?.require_bounds()
}

fn verify_cut(
    connection: &Connection,
    initialization: &SecurityParticipantStateInitialization,
    floor: &Floor,
    seal: &NativeJournalSeal,
    key: &str,
) -> Result<(), AdmissionOperationStoreError> {
    let authority = initialization.authority.as_str();
    let digest_of_initialization = initialization.digest.as_str();
    for family in FAMILIES {
        let cut = seal.cut(family);
        let range = family_range(
            connection,
            family,
            authority,
            floor.sequence(family),
            cut.last_sequence,
        )?;
        let digest = if cut.count == 0 {
            floor.digest(family, digest_of_initialization)
        } else {
            family_digest(connection, family, authority, cut.last_sequence)?
        };
        if range.count != cut.count
            || range.bytes != cut.bytes
            || range.last != cut.last_sequence
            || digest != cut.last_digest
        {
            return Err(invalid("native journal seal differs from its family rows"));
        }
    }
    let range = knowledge_range(
        connection,
        authority,
        floor.knowledge(),
        seal.knowledge.last_sequence,
    )?;
    let digest = if seal.knowledge.count == 0 {
        floor.knowledge_digest(digest_of_initialization)
    } else {
        knowledge_digest(connection, authority, seal.knowledge.last_sequence)?
    };
    if range.count != seal.knowledge.count
        || range.bytes != seal.knowledge.bytes
        || range.last != seal.knowledge.last_sequence
        || digest != seal.knowledge.last_digest
    {
        return Err(invalid(
            "native journal seal differs from its knowledge rows",
        ));
    }
    let (count, bytes) = seal.totals()?;
    if count == 0
        || count > MAX_SEGMENT_ENTRIES
        || bytes > MAX_SEGMENT_BYTES
        || seal.knowledge.count > MAX_SEGMENT_KNOWLEDGE
    {
        return Err(invalid(
            "native journal seal closes an empty or oversized segment",
        ));
    }
    let cuts = FAMILIES.map(|family| (family, seal.cut(family).last_sequence));
    let committed = commit_of(connection, "recovery", key, 1)?;
    if seal.last_global_commit
        != cut_commit(connection, authority, &cuts, seal.knowledge.last_sequence)?
        || committed <= seal.last_global_commit
    {
        return Err(invalid("native journal seal is outside its global cut"));
    }
    // The first row of every family after the cut follows the seal itself.
    for (family, last) in cuts {
        let next = last
            .checked_add(1)
            .ok_or_else(|| invalid("native journal sequence overflow"))?;
        if family_range(connection, family, authority, last, next)?.count == 1
            && commit_of(connection, family.projection_kind(), authority, next)? <= committed
        {
            return Err(invalid("native journal row precedes its segment seal"));
        }
    }
    let next = seal
        .knowledge
        .last_sequence
        .checked_add(1)
        .ok_or_else(|| invalid("knowledge sequence overflow"))?;
    if protected::raw_checked(connection, &join_key(authority, next))?.is_some()
        && commit_of(connection, "recovery", &join_key(authority, next), 1)? <= committed
    {
        return Err(invalid("knowledge join precedes its segment seal"));
    }
    Ok(())
}
