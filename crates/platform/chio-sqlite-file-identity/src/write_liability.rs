//! Checked frame-cost DATA shared by independently authenticated writers.
//! These descriptors neither authenticate a source nor reserve disk or WAL.

const CURSOR_LEVELS: u64 = 20;
const BALANCE_PAGES_PER_LEVEL: u64 = 6;
const NEW_BALANCE_WALKS: u64 = 1;
const EXISTING_BALANCE_WALKS: u64 = 3;
const ALLOCATION_OR_FREE_FRAMES: u64 = 2;
const FRAME_HEADER_BYTES: u64 = 24;
const WAL_HEADER_BYTES: u64 = 32;
const MAX_WAL_SECTOR_BYTES: u64 = 65_536;
const DISK_OVERLAP_MULTIPLIER: u64 = 2;
/// An append that reaches SQLite's lock-byte page skips it, so the file grows
/// by one page more than the allocations of that transaction.
const LOCK_BYTE_PAGE_SKIP: u64 = 1;
/// The existing safe integer ceiling of a native generation. SQLite encodes
/// every generation up to 2^53-1 within its 8-byte signed serial type.
const GENERATION_SAFE_INTEGER_CEILING: u64 = 9_007_199_254_740_991;
/// Pages one `balance_nonroot` of the pinned bundled SQLite can dirty: up
/// to `NB + 2` (5) rewritten child pages, the parent page it inserts the
/// divider into, and the freelist trunk page its allocation or free writes.
const SPLIT_BALANCE_PAGES_PER_LEVEL: u64 = 7;
/// Pages one `balance_nonroot` can append to the file: `apNew` holds up to
/// `NB + 2` pages against up to `NB` (3) old pages, so at most 2 are fresh.
const SPLIT_NEW_PAGES_PER_LEVEL: u64 = 2;

/// Mathematical inputs for the pinned bundled SQLite frame calculation.
/// The owning adapter separately verifies its actual file, UTF-8 row codec,
/// FULL WAL, auto-vacuum policy, source cut, and complete writer catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqliteFramePriceProfileData {
    page_size: u64,
}

impl SqliteFramePriceProfileData {
    pub fn checked(page_size: u64, reserved_bytes: u64) -> Result<Self, String> {
        if !(512..=65_536).contains(&page_size)
            || !page_size.is_power_of_two()
            || reserved_bytes != 0
        {
            return Err("SQLite frame price geometry is unsupported".to_owned());
        }
        Ok(Self { page_size })
    }

    /// Price a complete transaction frame bound, including FULL commit padding
    /// and overlapping WAL/checkpoint storage. The caller must authenticate the
    /// profile and supply a conservative nonzero bound; this grants no funding.
    pub fn price_frames(
        &self,
        complete_frame_bound: u64,
    ) -> Result<SqliteTransactionWritePriceData, String> {
        if complete_frame_bound == 0 {
            return Err("SQLite transaction frame bound is empty".to_owned());
        }
        let frame_bytes = add(self.page_size, FRAME_HEADER_BYTES)?;
        let padding = ceil(MAX_WAL_SECTOR_BYTES, frame_bytes)?;
        let wal_frames = add(complete_frame_bound, padding)?;
        let wal_bytes = add(mul(wal_frames, frame_bytes)?, WAL_HEADER_BYTES)?;
        Ok(SqliteTransactionWritePriceData {
            wal_bytes,
            disk_bytes: mul(wal_bytes, DISK_OVERLAP_MULTIPLIER)?,
            wal_frames,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TreeKindData {
    Record,
    FreshInsertions,
    SingletonRoot,
    ObservedRootLeaf,
    SameKeyRewrites,
    /// Same-key rewrites split at preparation: `growing` of the rows change
    /// their encoded size, the rest overwrite in place.
    SplitSameKeyRewrites {
        growing: u64,
    },
}

/// One table or index tree, including every repeated actual producer mutation.
/// Each mutable index is a distinct descriptor. WITHOUT ROWID primary keys
/// belong to the table tree and must not be counted as an invented extra index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqliteTreeWriteShapeData {
    kind: TreeKindData,
    cursor_levels: u64,
    possible_before_bytes: Option<u64>,
    maximum_after_bytes: u64,
    mutations: u64,
}

impl SqliteTreeWriteShapeData {
    pub fn record(
        possible_before_bytes: Option<u64>,
        maximum_after_bytes: u64,
        mutations: u64,
    ) -> Result<Self, String> {
        if maximum_after_bytes == 0 || possible_before_bytes == Some(0) || mutations == 0 {
            return Err("SQLite tree shape lost its complete record bound".to_owned());
        }
        Ok(Self {
            kind: TreeKindData::Record,
            cursor_levels: CURSOR_LEVELS,
            possible_before_bytes,
            maximum_after_bytes,
            mutations,
        })
    }

    /// Only a source-proved append of distinct fresh records can use this
    /// insert-only pattern. Multiple mutations in `record` remain ambiguous
    /// and conservatively retain intermediate existing-row costs.
    pub fn fresh_insertions(maximum_record_bytes: u64, insertions: u64) -> Result<Self, String> {
        if maximum_record_bytes == 0 || insertions == 0 {
            return Err("SQLite insert-only shape lost its producing bound".to_owned());
        }
        Ok(Self {
            kind: TreeKindData::FreshInsertions,
            cursor_levels: CURSOR_LEVELS,
            possible_before_bytes: None,
            maximum_after_bytes: maximum_record_bytes,
            mutations: insertions,
        })
    }

    /// Only an authenticated, existing INTEGER PRIMARY KEY singleton table
    /// without secondary indexes can use this fixed-root descriptor.
    pub fn singleton_root(maximum_record_bytes: u64, mutations: u64) -> Result<Self, String> {
        if maximum_record_bytes == 0 || mutations == 0 {
            return Err("SQLite singleton shape lost its producing bound".to_owned());
        }
        Ok(Self {
            kind: TreeKindData::SingletonRoot,
            cursor_levels: CURSOR_LEVELS,
            possible_before_bytes: Some(maximum_record_bytes),
            maximum_after_bytes: maximum_record_bytes,
            mutations,
        })
    }

    /// One observed existing root leaf, with spilling and auto-vacuum disabled.
    /// The caller authenticates the actual root page and proves that every
    /// existing cell is local and its initial free space holds ALL possible
    /// new cells of this transaction, including replacements and rolled-back
    /// writes without credit for removals. The tree cannot split or allocate
    /// overflow pages, and its single root reaches the WAL at most once.
    /// This current-transaction DATA cannot reserve a future writer's space.
    pub fn observed_root_leaf() -> Self {
        Self {
            kind: TreeKindData::ObservedRootLeaf,
            cursor_levels: 1,
            possible_before_bytes: None,
            maximum_after_bytes: 0,
            mutations: 1,
        }
    }

    /// Encoded width class of one SQLite integer generation: the serial
    /// content width in bytes. Zero and one carry SQLite's special serial
    /// encodings with no content bytes, and every signed width transition up
    /// to the existing safe integer ceiling is a distinct class, so a stored
    /// generation grows its cell exactly at one of the six class boundaries.
    pub fn generation_width_class(generation: u64) -> Result<u64, String> {
        if generation > GENERATION_SAFE_INTEGER_CEILING {
            return Err("SQLite generation exceeds the safe integer ceiling".to_owned());
        }
        Ok(match generation {
            0 | 1 => 0,
            2..=127 => 1,
            128..=32_767 => 2,
            32_768..=8_388_607 => 3,
            8_388_608..=2_147_483_647 => 4,
            2_147_483_648..=140_737_488_355_327 => 6,
            _ => 8,
        })
    }

    /// Smallest generation of one `generation_width_class`. A stored
    /// generation below the floor of the class of a rewrite's new generation
    /// is the exact set of rows whose cell can grow in that rewrite: every
    /// generation at or above the class floor keeps its class, and the class
    /// of a generation never decreases while the counter is enforced to stay
    /// within the retained class.
    pub fn generation_width_class_floor(width_class: u64) -> Result<u64, String> {
        Ok(match width_class {
            0 => 0,
            1 => 2,
            2 => 128,
            3 => 32_768,
            4 => 8_388_608,
            6 => 2_147_483_648,
            8 => 140_737_488_355_328,
            _ => return Err("SQLite generation width class is unencoded".to_owned()),
        })
    }
}

impl SqliteTreeWriteShapeData {
    /// Existing records of one tree rewritten under their unchanged key, each
    /// to a record that may be larger or smaller. `total_record_bytes` bounds
    /// the summed encoded size of every rewritten record.
    ///
    /// SQLite performs no delete for an unchanged key: the UPDATE reaches
    /// `sqlite3BtreeInsert`, which overwrites in place when the encoded size is
    /// equal and otherwise replaces the cell and balances at most once. This
    /// shape therefore charges one balance walk per rewrite, not the three of
    /// an ambiguous existing record. The caller authenticates that the tree has
    /// no secondary index to maintain and that its writer leaves keys unchanged.
    pub fn same_key_rewrites(rows: u64, total_record_bytes: u64) -> Result<Self, String> {
        if rows == 0 || total_record_bytes == 0 {
            return Err("SQLite same-key rewrite shape lost its producing bound".to_owned());
        }
        Ok(Self {
            kind: TreeKindData::SameKeyRewrites,
            cursor_levels: CURSOR_LEVELS,
            possible_before_bytes: None,
            maximum_after_bytes: total_record_bytes,
            mutations: rows,
        })
    }

    /// A same-key rewrite fan-out measured at preparation. `growing` of the
    /// `rows` rewritten rows change their encoded size (SQLite drops and
    /// reinserts the cell, with at most one balance cascade per level), every
    /// other row keeps its size and SQLite overwrites it in place: an
    /// unchanged-size cell is rewritten through `btreeOverwriteCell`, which
    /// dirties no page at all when the compared bytes are equal and only the
    /// pages holding differing bytes otherwise, and it allocates nothing.
    ///
    /// Required proof from the pricing recipe: every rewritten record is
    /// byte-identical to its stored image except the `generation` column.
    /// SQLite takes the in-place overwrite path only when the whole encoded
    /// record size is unchanged, so generation width-class equality alone
    /// proves nothing about the other columns: an UPDATE that keeps the
    /// generation within its class but lengthens another column fails the
    /// equal-size check and falls through to the replace path, costing the
    /// full per-row drop, insert and balance cascade plus fresh overflow
    /// images. The recipe must prove the only mutated column is the
    /// generation: this implies every same-width row keeps its encoded size
    /// exactly (its `generation` stays inside its class), and every growing
    /// row strictly raises the width class of its generation column alone, so
    /// the old image is at most as long as the new one, which the doubled
    /// image term for growing rows also relies on. The native owner's
    /// retained width recipe and its scope gate on the generation allocator
    /// must retain this proof beside the class floor, before the rewrite
    /// runs.
    ///
    /// The caller measures the split in the same transaction with
    /// `generation_width_class` and `generation_width_class_floor`, retains
    /// the recipe until the owed rewrite runs, and enforces on the file's
    /// generation allocator that no row is introduced below the measured
    /// class; this descriptor prices the split only.
    pub fn same_key_rewrites_class_split(
        rows: u64,
        total_record_bytes: u64,
        growing: u64,
    ) -> Result<Self, String> {
        if rows == 0 || total_record_bytes == 0 || growing > rows {
            return Err("SQLite split same-key shape lost its producing bound".to_owned());
        }
        Ok(Self {
            kind: TreeKindData::SplitSameKeyRewrites { growing },
            cursor_levels: CURSOR_LEVELS,
            possible_before_bytes: None,
            maximum_after_bytes: total_record_bytes,
            mutations: rows,
        })
    }

    /// Bound the cursor by a retained ceiling on this tree's logical records.
    /// Every non-root interior page has at least two children and every leaf
    /// is nonempty. A rowid table therefore needs at least 2^(h-2) records for
    /// h levels, allowing the page-one virtual root. Index records on interior
    /// pages only increase that minimum. The additional level covers a root
    /// split during a mutation. This is DATA: the writer must enforce the row
    /// ceiling for this tree and its indexes until the transaction commits.
    pub fn within_retained_rows(mut self, rows: u64) -> Result<Self, String> {
        self.cursor_levels = Self::retained_row_cursor_levels(rows)?;
        Ok(self)
    }

    pub fn retained_row_cursor_levels(rows: u64) -> Result<u64, String> {
        if rows == 0 {
            return Err("SQLite retained tree row ceiling is empty".to_owned());
        }
        Ok(u64::from(rows.ilog2()).saturating_add(3).min(CURSOR_LEVELS))
    }
}

/// A whole independently committed transaction. The source adapter includes
/// its tables, mutable indexes, history, metadata and bank writes together.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqliteTransactionWriteShapeData {
    trees: Vec<SqliteTreeWriteShapeData>,
}

impl SqliteTransactionWriteShapeData {
    pub fn checked(trees: Vec<SqliteTreeWriteShapeData>) -> Result<Self, String> {
        if trees.is_empty() {
            return Err("SQLite transaction price has no producing trees".to_owned());
        }
        Ok(Self { trees })
    }

    /// Identity DATA of the page-bounded calculator. A source recipe that prices
    /// with `price_within_pages` or a same-key rewrite shape
    /// binds this beside the common descriptor; recipes that do not use them keep
    /// their common descriptor unchanged.
    pub fn page_bounded_descriptor() -> &'static str {
        "chio.sqlite.page-bounded-frame-price.v1; bundled3.51.3; same_key_rewrite_one_balance_walk; dirty_pages_at_most_file_pages_with_cache_spill_off; growth=balance_plus_overflow_allocations+lock_byte_page; independent_transactions"
    }

    /// Identity DATA of the split same-key rewrite price. A source recipe that
    /// prices a fan-out with `same_key_rewrites_class_split` binds this beside
    /// the common descriptor and the page-bounded descriptor.
    pub fn split_same_key_rewrites_descriptor() -> &'static str {
        "chio.sqlite.split-same-key-frame-price.v3; bundled3.51.3; recipe_proves_new_record_identical_except_generation_column; same_width_in_place_no_allocation_dirties_only_differing_pages; growing_drop_insert_cascade; balance_level7_children_nb_plus_2_parent_freelist_trunk; growth2_pages_per_level_plus_per_row_overflow_slack; same_width_one_image_set_plus_row_slack; growing_old_and_new_images; zero_and_one_special_encodings; class_floor_measured_at_preparation; independent_transactions"
    }

    /// A no-spill transaction with auto-vacuum disabled writes each dirty
    /// page to the WAL once. The pinned allocator consumes only the head
    /// freelist trunk: every passed trunk is itself an allocated page, while
    /// a newly created trunk is a page being freed. Those pages are already
    /// included in the balance and old/new overflow terms. Only page one and
    /// the final unconsumed original trunk need an additional allowance.
    /// Old overflow images remain charged, including with secure deletion on.
    /// The caller must authenticate and enforce both connection settings.
    pub fn price_without_spill(
        &self,
        profile: &SqliteFramePriceProfileData,
    ) -> Result<SqliteTransactionWritePriceData, String> {
        profile.price_frames(transaction_frame_bound_with_spill_policy(
            profile, self, true,
        )?)
    }

    pub fn no_spill_descriptor() -> &'static str {
        "chio.sqlite.no-spill-frame-price.v1; bundled3.51.3; cache_spill_off; auto_vacuum_none; balance_and_old_new_overflow_pages_once; secure_delete_supported; passed_freelist_trunk_is_allocated; new_trunk_is_freed; page_one_and_final_original_trunk_plus_one_slack; independent_transactions"
    }

    /// The same price when the whole file never exceeds `page_ceiling` pages while
    /// the transaction runs. With cache spill off each dirty page reaches the WAL
    /// once, and every dirty page is a page of the file, so the frame bound is the
    /// smaller of the generic bound and the ceiling. The caller must retain that
    /// ceiling and enforce it on every writer of the file; this grants no funding.
    pub fn price_within_pages(
        &self,
        profile: &SqliteFramePriceProfileData,
        page_ceiling: u64,
    ) -> Result<SqliteTransactionWritePriceData, String> {
        if page_ceiling == 0 {
            return Err("SQLite page ceiling is empty".to_owned());
        }
        let frames = transaction_frame_bound(profile, self)?.min(page_ceiling);
        profile.price_frames(frames)
    }

    /// Most pages the transaction can add to the file. Every page it allocates
    /// is among its record trees' balance-walk or overflow pages, so the count
    /// of allocations bounds the appended pages whatever the file's size when
    /// the transaction runs and whatever other writers do before it.
    pub fn maximum_page_growth(
        &self,
        profile: &SqliteFramePriceProfileData,
    ) -> Result<u64, String> {
        let payload = overflow_payload(profile)?;
        let mut growth = LOCK_BYTE_PAGE_SKIP;
        for tree in &self.trees {
            match tree.kind {
                TreeKindData::SingletonRoot | TreeKindData::ObservedRootLeaf => {}
                TreeKindData::SplitSameKeyRewrites { growing } => {
                    // A same-width row appends nothing: the overwrite path
                    // allocates no page, so a fully same-width fan-out grows
                    // nothing beyond the lock-byte page. A growing row's
                    // cascade appends at most `SPLIT_NEW_PAGES_PER_LEVEL`
                    // pages per level, and its new cell keeps at most one
                    // image set of the rewritten record's bound on new
                    // overflow pages. Each growing row's chain is bounded per
                    // row (each chain page holds `usableSize - 4` payload
                    // bytes), so the summed chains carry the same per-row
                    // rounding slack the frames side charges: ceil of the sum
                    // can shortchange the sum of per-row ceils by up to
                    // `growing - 1` pages.
                    if growing > 0 {
                        let new_pages =
                            mul(growing, mul(tree.cursor_levels, SPLIT_NEW_PAGES_PER_LEVEL)?)?;
                        let overflow = add(ceil(tree.maximum_after_bytes, payload)?, growing)?;
                        growth = add(growth, add(new_pages, overflow)?)?;
                    }
                }
                _ => {
                    let (balance, overflow) = record_tree_terms(tree, payload)?;
                    growth = add(growth, add(balance, overflow)?)?;
                }
            }
        }
        Ok(growth)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqliteTransactionWritePriceData {
    wal_bytes: u64,
    disk_bytes: u64,
    wal_frames: u64,
}

impl SqliteTransactionWritePriceData {
    pub fn wal_bytes(&self) -> u64 {
        self.wal_bytes
    }

    /// Appended WAL and possible later main-file allocation coexist. An owning
    /// adapter adds its independently authenticated anchor or side-file cost.
    pub fn disk_bytes(&self) -> u64 {
        self.disk_bytes
    }

    pub fn wal_frames(&self) -> u64 {
        self.wal_frames
    }
}

/// Stable calculator identity DATA to bind into the actual source profile.
/// It identifies the bound, not a supported producer or a funded loan.
pub fn write_price_algorithm_descriptor() -> &'static str {
    "chio.sqlite.transaction-frame-price.v2; bundled3.51.3; depth20; balance6; newwalk1; existingwalk3; allocation_or_free2; frame24; header32; FULL_sector65536; reserved0; before_or_intermediate_overflow; ambiguous_new_rewrites_existing_cost; explicit_fresh_insertions; independent_transactions"
}

fn overflow_payload(profile: &SqliteFramePriceProfileData) -> Result<u64, String> {
    profile
        .page_size
        .checked_sub(4)
        .filter(|bytes| *bytes > 0)
        .ok_or_else(|| "SQLite overflow divisor is invalid".to_owned())
}

/// Balance-walk pages and overflow pages of one record tree. Every page one
/// of its writes allocates is among these.
fn record_tree_terms(tree: &SqliteTreeWriteShapeData, payload: u64) -> Result<(u64, u64), String> {
    if tree.kind == TreeKindData::SameKeyRewrites {
        let balance = mul(
            mul(tree.mutations, tree.cursor_levels)?,
            BALANCE_PAGES_PER_LEVEL,
        )?;
        let images = add(ceil(tree.maximum_after_bytes, payload)?, tree.mutations)?;
        // The old and the new image of every rewrite.
        return Ok((balance, mul(images, 2)?));
    }
    let intermediate_existing = tree.kind == TreeKindData::Record
        && tree.possible_before_bytes.is_none()
        && tree.mutations > 1;
    let walks = if tree.possible_before_bytes.is_some() || intermediate_existing {
        EXISTING_BALANCE_WALKS
    } else {
        NEW_BALANCE_WALKS
    };
    let balance = mul(
        mul(mul(tree.mutations, walks)?, tree.cursor_levels)?,
        BALANCE_PAGES_PER_LEVEL,
    )?;
    let after = ceil(tree.maximum_after_bytes, payload)?;
    let previous = match tree.possible_before_bytes {
        Some(bytes) => ceil(bytes.max(tree.maximum_after_bytes), payload)?,
        None if intermediate_existing => ceil(tree.maximum_after_bytes, payload)?,
        None => 0,
    };
    let overflow = mul(add(after, previous)?, tree.mutations)?;
    Ok((balance, overflow))
}

/// Raw frame bound of a split same-key rewrite fan-out under the pinned
/// bundled SQLite. A same-width row reaches `btreeOverwriteCell`, which
/// requires an entirely local cell (`nLocal == nPayload`) and overwrites it
/// in place, dirtying only its leaf page, or `btreeOverwriteOverflowCell`
/// for a spilled cell, which overwrites the local window and then each
/// overflow page and dirties only the pages whose compared bytes differ:
/// it allocates no page, frees no page and touches no freelist trunk. Its
/// dirtied image pages are at most one set of the rewritten bytes, so the
/// same-width rows together dirty at most `ceil(total, payload)` pages of
/// images plus one slack page per row, beside one leaf page per row.
///
/// A growing row's cell is dropped and its fresh cell reinserted: the leaf
/// page plus at most one cascade of `balance_nonroot`, each level dirtying
/// at most `SPLIT_BALANCE_PAGES_PER_LEVEL` pages (up to `NB + 2` rewritten
/// children, the parent and the freelist trunk its allocation or free
/// writes), and the drop and reinsert each keep an image of the rewritten
/// bytes on overflow pages: one old and one new set, at most
/// `ceil(total, payload)` pages each plus one slack page per growing row.
fn split_same_key_rewrite_frames(
    tree: &SqliteTreeWriteShapeData,
    growing: u64,
    payload: u64,
) -> Result<u64, String> {
    let same = tree
        .mutations
        .checked_sub(growing)
        .ok_or_else(|| "SQLite split same-key rows are negative".to_owned())?;
    let images = ceil(tree.maximum_after_bytes, payload)?;
    let same_frames = add(add(same, images)?, tree.mutations)?;
    let cascade = mul(
        growing,
        add(1, mul(tree.cursor_levels, SPLIT_BALANCE_PAGES_PER_LEVEL)?)?,
    )?;
    // Old and new image sets are charged only for rows that actually grow:
    // at `growing == 0` no record is replaced, no growing image exists, and
    // the same-width rows keep their own single image set inside
    // `same_frames` above. The doubled image term is deliberately kept for
    // growing rows: by default the freed old chain pages are not WAL frames
    // (`freePage2` frees them), but `secure_delete` writes them, and the
    // overcount also absorbs the freelist-trunk frames dirtied by each
    // growing row's overflow allocation and free (`fillInCell`,
    // `freePage2`), which this formula never counts explicitly. Do not
    // narrow it.
    let growing_images = if growing == 0 {
        0
    } else {
        add(mul(images, 2)?, add(growing, growing)?)?
    };
    add(add(same_frames, cascade)?, growing_images)
}

/// Raw frame bound of a transaction, before FULL commit padding.
fn transaction_frame_bound(
    profile: &SqliteFramePriceProfileData,
    transaction: &SqliteTransactionWriteShapeData,
) -> Result<u64, String> {
    transaction_frame_bound_with_spill_policy(profile, transaction, false)
}

fn transaction_frame_bound_with_spill_policy(
    profile: &SqliteFramePriceProfileData,
    transaction: &SqliteTransactionWriteShapeData,
    no_spill: bool,
) -> Result<u64, String> {
    let payload = overflow_payload(profile)?;
    // Page1 can be dirtied by allocation, even when the source tables are small.
    let mut frames = if no_spill { 3 } else { 1 };
    for tree in &transaction.trees {
        match tree.kind {
            TreeKindData::ObservedRootLeaf => {
                if !no_spill {
                    return Err("SQLite observed root leaf requires spilling disabled".into());
                }
                frames = add(frames, 1)?;
            }
            TreeKindData::SingletonRoot => {
                if tree.maximum_after_bytes > profile.page_size - 100 {
                    return Err("SQLite singleton record exceeds its fixed root".to_owned());
                }
                frames = add(frames, tree.mutations)?;
            }
            TreeKindData::SplitSameKeyRewrites { growing } => {
                frames = add(
                    frames,
                    split_same_key_rewrite_frames(tree, growing, payload)?,
                )?;
            }
            TreeKindData::Record
            | TreeKindData::FreshInsertions
            | TreeKindData::SameKeyRewrites => {
                let (balance, overflow) = record_tree_terms(tree, payload)?;
                frames = add(
                    frames,
                    mul(
                        add(balance, overflow)?,
                        if no_spill {
                            1
                        } else {
                            ALLOCATION_OR_FREE_FRAMES
                        },
                    )?,
                )?;
            }
        }
    }
    Ok(frames)
}

pub fn price_transaction_write_shape(
    profile: &SqliteFramePriceProfileData,
    transaction: &SqliteTransactionWriteShapeData,
) -> Result<SqliteTransactionWritePriceData, String> {
    profile.price_frames(transaction_frame_bound(profile, transaction)?)
}

fn add(left: u64, right: u64) -> Result<u64, String> {
    left.checked_add(right)
        .ok_or_else(|| "SQLite physical price sum exhausted".to_owned())
}

fn mul(left: u64, right: u64) -> Result<u64, String> {
    left.checked_mul(right)
        .ok_or_else(|| "SQLite physical price product exhausted".to_owned())
}

fn ceil(value: u64, divisor: u64) -> Result<u64, String> {
    if divisor == 0 {
        return Err("SQLite physical price divisor is zero".to_owned());
    }
    value
        .checked_div(divisor)
        .and_then(|quotient| quotient.checked_add(u64::from(!value.is_multiple_of(divisor))))
        .ok_or_else(|| "SQLite physical price ceiling exhausted".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_spill_price_preserves_overflow_and_freelist_writes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        for page_size in [512_u64, 4096] {
            for secure_delete in [0, 1] {
                let directory = tempfile::tempdir()?;
                let path = directory.path().join("freelist.sqlite3");
                let mut connection = rusqlite::Connection::open(&path)?;
                connection.execute_batch(&format!(
                    "PRAGMA page_size={page_size}; PRAGMA journal_mode=WAL;
                     PRAGMA synchronous=FULL; PRAGMA cache_spill=0;
                     PRAGMA auto_vacuum=NONE; PRAGMA wal_autocheckpoint=0;
                     PRAGMA secure_delete={secure_delete};
                     CREATE TABLE payloads (id INTEGER PRIMARY KEY, body BLOB NOT NULL);"
                ))?;
                // Retain several original freelist trunks. Allocation must
                // consume their leaves and cross trunks, not just append.
                let tx = connection.transaction()?;
                for id in 0..128 {
                    tx.execute("INSERT INTO payloads VALUES (?1, zeroblob(65536))", [id])?;
                }
                tx.commit()?;
                connection.execute("DELETE FROM payloads", [])?;
                connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
                let free_before: i64 =
                    connection.query_row("PRAGMA freelist_count", [], |row| row.get(0))?;
                assert!(free_before > i64::try_from(2 * (page_size / 4))?);
                let tx = connection.transaction()?;
                for id in 0..32 {
                    tx.execute("INSERT INTO payloads VALUES (?1, zeroblob(131072))", [id])?;
                }
                for id in 0..16 {
                    tx.execute(
                        "UPDATE payloads SET body=zeroblob(262144) WHERE id=?1",
                        [id],
                    )?;
                }
                tx.commit()?;
                let profile = SqliteFramePriceProfileData::checked(page_size, 0)?;
                let shape = SqliteTransactionWriteShapeData::checked(vec![
                    SqliteTreeWriteShapeData::fresh_insertions(131072 + 32, 32)?
                        .within_retained_rows(64)?,
                    SqliteTreeWriteShapeData::same_key_rewrites(16, 16 * (262144 + 32))?
                        .within_retained_rows(64)?,
                ])?;
                let price = shape.price_without_spill(&profile)?;
                let wal = std::fs::metadata(path.with_extension("sqlite3-wal"))?.len();
                assert!(wal > 0);
                assert!(
                    wal <= price.wal_bytes(),
                    "page_size={page_size} secure_delete={secure_delete}: {wal} > {}",
                    price.wal_bytes()
                );
                assert!(
                    price.wal_bytes()
                        < price_transaction_write_shape(&profile, &shape)?.wal_bytes()
                );
            }
        }
        Ok(())
    }

    #[test]
    fn independent_transactions_retain_separate_commit_costs() -> Result<(), String> {
        let profile = SqliteFramePriceProfileData::checked(4096, 0)?;
        let first = SqliteTreeWriteShapeData::record(None, 16_384, 1)?;
        let second = SqliteTreeWriteShapeData::record(Some(16_384), 16_384, 1)?;
        let first_price = price_transaction_write_shape(
            &profile,
            &SqliteTransactionWriteShapeData::checked(vec![first.clone()])?,
        )?;
        let second_price = price_transaction_write_shape(
            &profile,
            &SqliteTransactionWriteShapeData::checked(vec![second.clone()])?,
        )?;
        let merged = price_transaction_write_shape(
            &profile,
            &SqliteTransactionWriteShapeData::checked(vec![first, second])?,
        )?;
        assert!(first_price.wal_bytes() + second_price.wal_bytes() > merged.wal_bytes());
        assert!(first_price.disk_bytes() + second_price.disk_bytes() > merged.disk_bytes());
        Ok(())
    }

    #[test]
    fn same_size_rewrites_retain_old_images_and_every_history_write() -> Result<(), String> {
        let profile = SqliteFramePriceProfileData::checked(512, 0)?;
        let price = |mutations| -> Result<SqliteTransactionWritePriceData, String> {
            price_transaction_write_shape(
                &profile,
                &SqliteTransactionWriteShapeData::checked(vec![
                    SqliteTreeWriteShapeData::record(Some(32_768), 32_768, mutations)?,
                    SqliteTreeWriteShapeData::record(None, 1024, mutations)?,
                    SqliteTreeWriteShapeData::singleton_root(256, mutations)?,
                ])?,
            )
        };
        assert!(price(3)?.wal_bytes() > 2 * price(1)?.wal_bytes());
        assert!(price(3)?.wal_frames() > price(1)?.wal_frames());
        Ok(())
    }

    #[test]
    fn an_initially_absent_repeated_row_keeps_its_intermediate_existing_image() -> Result<(), String>
    {
        let profile = SqliteFramePriceProfileData::checked(4096, 0)?;
        let price = |tree| {
            price_transaction_write_shape(
                &profile,
                &SqliteTransactionWriteShapeData::checked(vec![tree])?,
            )
        };
        let inserted_then_rewritten = price(SqliteTreeWriteShapeData::record(None, 1_048_576, 2)?)?;
        let already_existing = price(SqliteTreeWriteShapeData::record(
            Some(1_048_576),
            1_048_576,
            2,
        )?)?;
        let distinct_fresh_records =
            price(SqliteTreeWriteShapeData::fresh_insertions(1_048_576, 2)?)?;
        assert_eq!(inserted_then_rewritten, already_existing);
        assert!(inserted_then_rewritten.wal_bytes() > distinct_fresh_records.wal_bytes());
        assert!(inserted_then_rewritten.disk_bytes() > distinct_fresh_records.disk_bytes());
        Ok(())
    }

    #[test]
    fn page_bounded_rewrites_price_the_file_not_every_balance_walk() -> Result<(), String> {
        let profile = SqliteFramePriceProfileData::checked(4096, 0)?;
        let rows = 4096;
        let bytes = 8 * 1024 * 1024;
        let shape = SqliteTransactionWriteShapeData::checked(vec![
            SqliteTreeWriteShapeData::same_key_rewrites(rows, bytes)?,
        ])?;
        let walked = price_transaction_write_shape(&profile, &shape)?;
        let ceiling = 1 << 15;
        let bounded = shape.price_within_pages(&profile, ceiling)?;
        assert_eq!(
            bounded.wal_frames(),
            profile.price_frames(ceiling)?.wal_frames()
        );
        assert!(bounded.wal_bytes() * 10 < walked.wal_bytes());
        // One balance walk per rewrite is a third of the ambiguous existing record.
        let ambiguous = price_transaction_write_shape(
            &profile,
            &SqliteTransactionWriteShapeData::checked(vec![SqliteTreeWriteShapeData::record(
                Some(2048),
                2048,
                rows,
            )?])?,
        )?;
        assert!(walked.wal_bytes() < ambiguous.wal_bytes());
        // Growth counts every allocation of the one balance walk per rewrite
        // and both overflow images; it never reads the file's size.
        assert_eq!(
            shape.maximum_page_growth(&profile)?,
            rows * 20 * 6 + 2 * (bytes.div_ceil(4092) + rows) + 1
        );
        assert!(SqliteTreeWriteShapeData::same_key_rewrites(0, bytes).is_err());
        assert!(SqliteTreeWriteShapeData::same_key_rewrites(rows, 0).is_err());
        assert!(shape.price_within_pages(&profile, 0).is_err());
        Ok(())
    }

    /// Real WAL frames of a width-growing UPDATE of a WITHOUT ROWID table stay
    /// within the page-bounded price, at the transitions an integer's encoded
    /// width changes (0 to 1 byte at 1 to 2, 1 to 2 bytes at 127 to 128).
    #[test]
    fn real_width_growing_rewrites_stay_within_the_page_bounded_price(
    ) -> Result<(), Box<dyn std::error::Error>> {
        const ROWS: u64 = 4096;
        for (page_size, before, after) in [(4096_u64, 1_i64, 2_i64), (512, 127, 128)] {
            let directory = tempfile::tempdir()?;
            let connection = rusqlite::Connection::open(directory.path().join("rewrite.sqlite3"))?;
            connection.execute_batch(&format!(
                "PRAGMA page_size = {page_size}; PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL; PRAGMA cache_spill = 0;
                 PRAGMA wal_autocheckpoint = 0; PRAGMA auto_vacuum = NONE;
                 CREATE TABLE flow_contexts (
                    authority TEXT NOT NULL, tenant TEXT NOT NULL, principal TEXT NOT NULL,
                    lineage TEXT NOT NULL, session TEXT NOT NULL, epoch TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    PRIMARY KEY (authority, tenant, principal, lineage, session, epoch)
                 ) STRICT, WITHOUT ROWID;"
            ))?;
            let mut insert = connection.prepare(
                "INSERT INTO flow_contexts VALUES ('authority', 'tenant', ?1, ?2, ?3, 'epoch', ?4)",
            )?;
            for index in 0..ROWS {
                insert.execute(rusqlite::params![
                    format!("principal-{}", index % 7),
                    format!("lineage-{index:05}"),
                    format!(
                        "session-{index:05}-{}",
                        "x".repeat(usize::try_from(index % 64)?)
                    ),
                    before,
                ])?;
            }
            drop(insert);
            connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
            let page_count =
                u64::try_from(
                    connection.query_row("PRAGMA page_count", [], |row| row.get::<_, i64>(0))?,
                )?;
            connection.execute("UPDATE flow_contexts SET generation = ?1", [after])?;
            let wal = std::fs::metadata(directory.path().join("rewrite.sqlite3-wal"))?.len();
            let frames = (wal - WAL_HEADER_BYTES) / (page_size + FRAME_HEADER_BYTES);
            let profile = SqliteFramePriceProfileData::checked(page_size, 0)?;
            let shape = SqliteTransactionWriteShapeData::checked(vec![
                SqliteTreeWriteShapeData::same_key_rewrites(ROWS, ROWS * 160)?,
            ])?;
            let growth = shape.maximum_page_growth(&profile)?;
            let ceiling = (page_count + growth).next_power_of_two();
            let price = shape.price_within_pages(&profile, ceiling)?;
            assert!(frames > 1, "the update wrote no frames");
            assert!(
                frames <= price.wal_frames(),
                "page size {page_size}: {frames} frames exceed the price {}",
                price.wal_frames()
            );
            let after_pages =
                u64::try_from(
                    connection.query_row("PRAGMA page_count", [], |row| row.get::<_, i64>(0))?,
                )?;
            assert!(after_pages <= page_count + growth);
        }
        Ok(())
    }

    #[test]
    fn split_same_key_rewrites_price_measured_growing_rows_exactly() -> Result<(), String> {
        let profile = SqliteFramePriceProfileData::checked(4096, 0)?;
        let rows = 4096;
        let bytes = 8 * 1024 * 1024;
        let price = |growing: u64| {
            price_transaction_write_shape(
                &profile,
                &SqliteTransactionWriteShapeData::checked(vec![
                    SqliteTreeWriteShapeData::same_key_rewrites_class_split(rows, bytes, growing)?,
                ])?,
            )
        };
        let padding = 65_536u64.div_ceil(4096 + FRAME_HEADER_BYTES);
        let images = bytes.div_ceil(4092);
        for growing in [0, 8, rows] {
            let priced = price(growing)?;
            let same_frames = (rows - growing) + images + rows;
            let cascade = growing * (1 + CURSOR_LEVELS * SPLIT_BALANCE_PAGES_PER_LEVEL);
            // Growing image sets exist only for growing rows: at zero
            // growing rows no record is replaced, while the same-width
            // rows keep their single image set inside `same_frames`.
            let growing_images = if growing == 0 {
                0
            } else {
                2 * images + 2 * growing
            };
            assert_eq!(
                1 + same_frames + cascade + growing_images + padding,
                priced.wal_frames(),
                "growing {growing}"
            );
        }
        let shape = SqliteTransactionWriteShapeData::checked(vec![
            SqliteTreeWriteShapeData::same_key_rewrites_class_split(rows, bytes, 128)?,
        ])?;
        // The growth carries the per-row overflow rounding slack beside the
        // balance fresh pages: ceil of the summed bytes shortchanges the sum
        // of the per-row ceils.
        assert_eq!(
            shape.maximum_page_growth(&profile)?,
            LOCK_BYTE_PAGE_SKIP
                + 128 * CURSOR_LEVELS * SPLIT_NEW_PAGES_PER_LEVEL
                + bytes.div_ceil(4092)
                + 128
        );
        // A fully same-width fan-out grows only the lock-byte page.
        let same_width = SqliteTransactionWriteShapeData::checked(vec![
            SqliteTreeWriteShapeData::same_key_rewrites_class_split(rows, bytes, 0)?,
        ])?;
        assert_eq!(
            same_width.maximum_page_growth(&profile)?,
            LOCK_BYTE_PAGE_SKIP
        );
        // The split is a tighter specialization of the generic existing-record
        // walk, so it stays below it at every measured split. The meaningful
        // invariant is monotonicity: more growing rows means strictly more
        // liability, at every measured step up to the whole fan-out.
        let ambiguous = price_transaction_write_shape(
            &profile,
            &SqliteTransactionWriteShapeData::checked(vec![SqliteTreeWriteShapeData::record(
                Some(8_388_608),
                8_388_608,
                rows,
            )?])?,
        )?;
        let zero = price(0)?;
        let few = price(8)?;
        let all = price(rows)?;
        assert!(zero.wal_frames() < ambiguous.wal_frames());
        assert!(few.wal_frames() < ambiguous.wal_frames());
        assert!(all.wal_frames() < ambiguous.wal_frames());
        assert!(zero.wal_frames() < few.wal_frames());
        assert!(few.wal_frames() < all.wal_frames());
        assert!(zero.disk_bytes() < all.disk_bytes());
        assert!(
            SqliteTreeWriteShapeData::same_key_rewrites_class_split(rows, bytes, rows + 1).is_err()
        );
        assert!(SqliteTreeWriteShapeData::same_key_rewrites_class_split(0, bytes, 0).is_err());
        assert!(SqliteTreeWriteShapeData::same_key_rewrites_class_split(rows, 0, 0).is_err());
        Ok(())
    }

    /// Real WAL frames of a same-width UPDATE of the WITHOUT ROWID contexts
    /// table stay within the split price at `growing == 0`: the pinned
    /// SQLite overwrites equal-size cells in place and dirties only the
    /// pages holding differing bytes, and the measured count is far below
    /// the priced bound, at both the ordinary width and the 127 to 128
    /// serial-width boundary driven through the growing split instead.
    #[test]
    fn real_same_width_rewrites_stay_within_the_split_price(
    ) -> Result<(), Box<dyn std::error::Error>> {
        const ROWS: u64 = 512;
        let directory = tempfile::tempdir()?;
        let connection = rusqlite::Connection::open(directory.path().join("split.sqlite3"))?;
        connection.execute_batch(&format!(
            "PRAGMA page_size = 4096; PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL; PRAGMA cache_spill = 0;
             PRAGMA wal_autocheckpoint = 0; PRAGMA auto_vacuum = NONE;
             CREATE TABLE flow_contexts (
                authority TEXT NOT NULL, tenant TEXT NOT NULL, principal TEXT NOT NULL,
                lineage TEXT NOT NULL, session TEXT NOT NULL, epoch TEXT NOT NULL,
                generation INTEGER NOT NULL,
                PRIMARY KEY (authority, tenant, principal, lineage, session, epoch)
             ) STRICT, WITHOUT ROWID;"
        ))?;
        let mut insert = connection.prepare(
            "INSERT INTO flow_contexts VALUES ('authority', 'tenant', ?1, ?2, ?3, 'epoch', 2)",
        )?;
        for index in 0..ROWS {
            insert.execute(rusqlite::params![
                format!("principal-{}", index % 7),
                format!("lineage-{index:05}"),
                "x".repeat(usize::try_from(1200)?),
            ])?;
        }
        drop(insert);
        connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        let page_count = u64::try_from(
            connection.query_row("PRAGMA page_count", [], |row| row.get::<_, i64>(0))?,
        )?;
        let profile = SqliteFramePriceProfileData::checked(4096, 0)?;
        let row_bytes = ROWS * 1600;
        let growing_shape = |growing: u64| {
            SqliteTransactionWriteShapeData::checked(vec![
                SqliteTreeWriteShapeData::same_key_rewrites_class_split(ROWS, row_bytes, growing)?,
            ])
        };
        let measure = |generation: i64| -> Result<u64, Box<dyn std::error::Error>> {
            connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
            connection.execute("UPDATE flow_contexts SET generation = ?1", [generation])?;
            let wal = std::fs::metadata(directory.path().join("split.sqlite3-wal"))?.len();
            Ok((wal - WAL_HEADER_BYTES) / (4096 + FRAME_HEADER_BYTES))
        };
        // The same-width rewrite keeps the one-byte serial class of 2.
        let same_width = measure(3)?;
        // The boundary rewrite grows every cell from the one-byte serial
        // class of 3 to the two-byte class of 128.
        let boundary = measure(128)?;
        let price = |growing: u64| -> Result<u64, String> {
            let shape = growing_shape(growing)?;
            let growth = shape.maximum_page_growth(&profile)?;
            let ceiling = (page_count + growth).next_power_of_two();
            Ok(shape.price_within_pages(&profile, ceiling)?.wal_frames())
        };
        assert!(same_width > 1, "the same-width update wrote no frames");
        assert!(
            same_width <= price(0)?,
            "{same_width} same-width frames exceed the priced {}",
            price(0)?
        );
        assert!(
            boundary <= price(ROWS)?,
            "{boundary} growing frames exceed the priced {}",
            price(ROWS)?
        );
        let after_pages = u64::try_from(
            connection.query_row("PRAGMA page_count", [], |row| row.get::<_, i64>(0))?,
        )?;
        let growth = growing_shape(ROWS)?.maximum_page_growth(&profile)?;
        assert!(after_pages <= page_count + growth);
        Ok(())
    }

    /// Real WAL frames and real page growth of a per-row overflow-rounding
    /// fan-out stay inside the split price: 64 spilled rows on 512-byte
    /// pages each keep their own overflow chain, so the summed chains cost
    /// more pages than the ceil of the summed bytes, and the priced per-row
    /// slack covers that difference. The same-width rewrite of the same
    /// spilled rows allocates nothing, proving the `growing == 0`
    /// conditional charges no growing image while the same-width rows keep
    /// their real coverage.
    #[test]
    fn real_per_row_overflow_rounding_stays_within_the_split_growth(
    ) -> Result<(), Box<dyn std::error::Error>> {
        const ROWS: u64 = 64;
        const PAGE: u64 = 512;
        let directory = tempfile::tempdir()?;
        let connection = rusqlite::Connection::open(directory.path().join("rounding.sqlite3"))?;
        connection.execute_batch(&format!(
            "PRAGMA page_size = {PAGE}; PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL; PRAGMA cache_spill = 0;
             PRAGMA wal_autocheckpoint = 0; PRAGMA auto_vacuum = NONE;
             CREATE TABLE flow_contexts (
                authority TEXT NOT NULL, tenant TEXT NOT NULL, principal TEXT NOT NULL,
                lineage TEXT NOT NULL, session TEXT NOT NULL, epoch TEXT NOT NULL,
                generation INTEGER NOT NULL,
                PRIMARY KEY (authority, tenant, principal, lineage, session, epoch)
             ) STRICT, WITHOUT ROWID;"
        ))?;
        let mut insert = connection.prepare(
            "INSERT INTO flow_contexts VALUES ('authority', 'tenant', ?1, ?2, ?3, 'epoch', 2)",
        )?;
        for index in 0..ROWS {
            insert.execute(rusqlite::params![
                format!("principal-{}", index % 7),
                format!("lineage-{index:05}"),
                "x".repeat(1000),
            ])?;
        }
        drop(insert);
        connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        let pages = |connection: &rusqlite::Connection| -> Result<u64, Box<dyn std::error::Error>> {
            Ok(u64::try_from(connection.query_row(
                "PRAGMA page_count",
                [],
                |row| row.get::<_, i64>(0),
            )?)?)
        };
        let before = pages(&connection)?;
        let profile = SqliteFramePriceProfileData::checked(PAGE, 0)?;
        // Every row's session alone spills past one 508-byte chain page.
        let row_bytes = ROWS * 1100;
        let shape = |growing: u64| {
            SqliteTransactionWriteShapeData::checked(vec![
                SqliteTreeWriteShapeData::same_key_rewrites_class_split(ROWS, row_bytes, growing)?,
            ])
        };
        let measure = |generation: i64| -> Result<u64, Box<dyn std::error::Error>> {
            connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
            connection.execute("UPDATE flow_contexts SET generation = ?1", [generation])?;
            let wal = std::fs::metadata(directory.path().join("rounding.sqlite3-wal"))?.len();
            Ok((wal - WAL_HEADER_BYTES) / (PAGE + FRAME_HEADER_BYTES))
        };
        // The boundary rewrite grows every cell from the one-byte serial
        // class of 2 to the two-byte class of 128, replacing every spilled row.
        let growth = shape(ROWS)?.maximum_page_growth(&profile)?;
        let ceiling = (before + growth).next_power_of_two();
        let priced_frames = shape(ROWS)?
            .price_within_pages(&profile, ceiling)?
            .wal_frames();
        let boundary_frames = measure(128)?;
        let after = pages(&connection)?;
        assert!(boundary_frames > 1, "the growing update wrote no frames");
        assert!(
            boundary_frames <= priced_frames,
            "{boundary_frames} growing frames exceed the priced {priced_frames}"
        );
        assert!(
            after <= before + growth,
            "{after} pages exceed {before} plus the priced growth {growth}"
        );
        // The same-width rewrite of the same spilled rows allocates nothing.
        let same_width_frames = measure(3)?;
        let same_after = pages(&connection)?;
        assert_eq!(same_after, after, "the same-width update grew the file");
        let same_growth = shape(0)?.maximum_page_growth(&profile)?;
        assert_eq!(same_growth, LOCK_BYTE_PAGE_SKIP);
        let same_ceiling = (before + same_growth).next_power_of_two();
        let same_priced = shape(0)?
            .price_within_pages(&profile, same_ceiling)?
            .wal_frames();
        assert!(
            same_width_frames <= same_priced,
            "{same_width_frames} same-width frames exceed the priced {same_priced}"
        );
        Ok(())
    }

    #[test]
    fn generation_width_classes_cover_the_special_encodings_and_every_transition(
    ) -> Result<(), String> {
        let class = SqliteTreeWriteShapeData::generation_width_class;
        let floor = SqliteTreeWriteShapeData::generation_width_class_floor;
        for (generation, width) in [
            (0, 0),
            (1, 0),
            (2, 1),
            (127, 1),
            (128, 2),
            (32_767, 2),
            (32_768, 3),
            (8_388_607, 3),
            (8_388_608, 4),
            (2_147_483_647, 4),
            (2_147_483_648, 6),
            (140_737_488_355_327, 6),
            (140_737_488_355_328, 8),
            (GENERATION_SAFE_INTEGER_CEILING, 8),
        ] {
            assert_eq!(class(generation)?, width, "generation {generation}");
            let floor_value = floor(width)?;
            if width > 0 {
                assert_eq!(class(floor_value)?, width);
                assert!(class(floor_value - 1)? < width);
            }
        }
        assert!(class(GENERATION_SAFE_INTEGER_CEILING + 1).is_err());
        assert_eq!(floor(0)?, 0);
        assert!(floor(5).is_err());
        Ok(())
    }

    #[test]
    fn malformed_geometry_and_exhausted_record_counts_refuse() -> Result<(), String> {
        assert!(SqliteFramePriceProfileData::checked(512, 32).is_err());
        assert!(SqliteFramePriceProfileData::checked(1000, 0).is_err());
        assert!(SqliteTreeWriteShapeData::record(Some(0), 1024, 1).is_err());
        assert!(SqliteTreeWriteShapeData::record(None, 1024, 0).is_err());
        let profile = SqliteFramePriceProfileData::checked(4096, 0)?;
        assert!(profile.price_frames(0).is_err());
        assert!(profile.price_frames(u64::MAX).is_err());
        let exhausted =
            SqliteTransactionWriteShapeData::checked(vec![SqliteTreeWriteShapeData::record(
                Some(u64::MAX),
                u64::MAX,
                u64::MAX,
            )?])?;
        assert!(price_transaction_write_shape(&profile, &exhausted).is_err());
        Ok(())
    }
}
