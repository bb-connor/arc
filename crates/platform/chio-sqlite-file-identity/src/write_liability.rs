//! Checked frame-cost data for independently authenticated SQLite writers.
//! These descriptors neither authenticate a source nor reserve disk or WAL.

/// `BTCURSOR_MAX_DEPTH` of the pinned bundled SQLite.
const CURSOR_LEVELS: u64 = 20;
const BALANCE_PAGES_PER_LEVEL: u64 = 6;
const NEW_BALANCE_WALKS: u64 = 1;
const EXISTING_BALANCE_WALKS: u64 = 3;
const ALLOCATION_OR_FREE_FRAMES: u64 = 2;
/// `WAL_FRAME_HDRSIZE` of the pinned bundled SQLite.
const FRAME_HEADER_BYTES: u64 = 24;
/// `WAL_HDRSIZE` of the pinned bundled SQLite.
const WAL_HEADER_BYTES: u64 = 32;
/// `MAX_SECTOR_SIZE`: a FULL commit pads the WAL to at most this boundary.
const MAX_WAL_SECTOR_BYTES: u64 = 65_536;
const DISK_OVERLAP_MULTIPLIER: u64 = 2;
/// An append that reaches SQLite's lock-byte page skips it, so the file grows
/// by one page more than the allocations of that transaction.
const LOCK_BYTE_PAGE_SKIP: u64 = 1;
/// The safe integer ceiling of a native generation. SQLite encodes every
/// generation up to 2^53-1 within its 8-byte signed serial type.
const GENERATION_SAFE_INTEGER_CEILING: u64 = 9_007_199_254_740_991;
/// Pages one `balance_nonroot` of the pinned bundled SQLite can dirty: up
/// to `NB + 2` (5) rewritten child pages, the parent page it inserts the
/// divider into, and the freelist trunk page its allocation or free writes.
const SPLIT_BALANCE_PAGES_PER_LEVEL: u64 = 7;
/// Pages one `balance_nonroot` can append to the file: `apNew` holds up to
/// `NB + 2` pages against up to `NB` (3) old pages, so at most 2 are fresh.
const SPLIT_NEW_PAGES_PER_LEVEL: u64 = 2;
/// A singleton record must fit its fixed root after the largest page
/// header, page one's 100-byte database header.
const PAGE_ONE_HEADER_BYTES: u64 = 100;
/// `PRAGMA auto_vacuum` value of NONE.
const AUTO_VACUUM_NONE: u64 = 0;

/// Mathematical inputs for the pinned bundled SQLite frame calculation: page
/// geometry and the observed `auto_vacuum` mode, which must be NONE (0).
/// Every price and page-growth bound holds only for that mode; pointer-map
/// pages, commit-time page relocation and incremental vacuum are outside
/// every term. These inputs are unauthenticated data. The owning adapter
/// reads them from its verified actual file before selecting any price, and
/// separately verifies FULL WAL, the source cut, the complete writer catalog
/// and stored-row byte bounds in the file's authenticated text encoding. The
/// calculator takes byte counts and is encoding agnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqliteFramePriceProfileData {
    page_size: u64,
}

impl SqliteFramePriceProfileData {
    /// Refuses every page size other than a power of two from 512 to 65536
    /// bytes and every nonzero reserved region, then every `auto_vacuum`
    /// mode other than NONE (0), including FULL (1) and INCREMENTAL (2).
    pub fn checked(page_size: u64, reserved_bytes: u64, auto_vacuum: u64) -> Result<Self, String> {
        if !(512..=65_536).contains(&page_size)
            || !page_size.is_power_of_two()
            || reserved_bytes != 0
        {
            return Err("SQLite frame price geometry is unsupported".to_owned());
        }
        if auto_vacuum != AUTO_VACUUM_NONE {
            return Err("SQLite frame price requires auto-vacuum NONE".to_owned());
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
/// Every attempted producer mutation counts, including writes a statement or
/// savepoint rollback later discards; discarded writes earn no credit.
/// Each mutable index is a distinct descriptor. WITHOUT ROWID primary keys
/// belong to the table tree and must not be counted as an extra index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqliteTreeWriteShapeData {
    kind: TreeKindData,
    cursor_levels: u64,
    possible_before_bytes: Option<u64>,
    maximum_after_bytes: u64,
    mutations: u64,
}

impl SqliteTreeWriteShapeData {
    /// A record written `mutations` times. `possible_before_bytes` is the
    /// largest stored image the first write may replace, or `None` when the
    /// key may be absent. Repeated mutations without a before image retain the
    /// intermediate existing-row cost of every later write.
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

    /// One observed existing root leaf, priced only with spilling and
    /// auto-vacuum disabled. The caller authenticates the actual root page and
    /// proves that every existing cell is local and its initial free space
    /// holds ALL possible new cells of this transaction, including
    /// replacements and rolled-back writes without credit for removals. The
    /// tree cannot split or allocate overflow pages, and its single root
    /// reaches the WAL at most once. This current-transaction data cannot
    /// reserve a future writer's space.
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
    /// to the safe integer ceiling is a distinct class, so a stored
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
    /// to a record that may be larger, equal or smaller. `total_record_bytes`
    /// bounds the sum, over every rewritten row, of the larger of its stored
    /// image and its new image, so it bounds both the old and the new image
    /// sets, including rows that shrink.
    ///
    /// This shape charges one balance walk per rewrite, not the three of an
    /// ambiguous existing record, so it is valid only for a real unchanged-key
    /// overwrite: the UPDATE reaches `sqlite3BtreeInsert` with no prior
    /// delete, which overwrites in place when the encoded size is equal and
    /// otherwise replaces the cell and balances at most once.
    ///
    /// Required proof from the owning native recipe, against the actual
    /// catalog and the exact changed columns, before it chooses this price:
    /// - every key of the tree is unchanged by the writer;
    /// - no secondary or partial index covers a rewritten column or has a
    ///   `WHERE` clause over one, so no index entry is deleted or reinserted;
    /// - no foreign key turns the UPDATE into a delete and reinsert. With
    ///   foreign keys enabled, `sqlite3FkRequired` selects that path when a
    ///   rewritten column is a child key of a foreign key into the same
    ///   table, or a parent key whose ON UPDATE action is not NO ACTION.
    ///   Foreign keys may stay enabled when the catalog and the changed
    ///   columns prove neither case.
    ///
    /// This shape is data and cannot inspect a connection. A recipe that
    /// cannot prove every premise prices a valid conservative shape such as
    /// `record`. Trigger effects belong to the complete writer catalog.
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
    /// Required proof from the owning recipe: every premise of
    /// `same_key_rewrites` (unchanged keys, no secondary or partial index over
    /// a rewritten column, and no foreign-key delete and reinsert path), and
    /// that every rewritten record is byte-identical to its stored image
    /// except the `generation` column. A foreign-key delete and reinsert
    /// replaces even an equal-size row, so it would void the in-place charge
    /// of every same-width row. `total_record_bytes` bounds the sum of every
    /// rewritten row's new image, the larger of its two images here.
    ///
    /// SQLite takes the in-place overwrite path only when the whole encoded
    /// record size is unchanged, so generation width-class equality alone
    /// proves nothing about the other columns: an
    /// UPDATE that keeps the generation within its class but lengthens
    /// another column fails the equal-size check and falls through to the
    /// replace path, costing the full per-row drop, insert and balance
    /// cascade plus fresh overflow images. Because only the generation
    /// changes, every same-width row keeps its encoded size exactly (its
    /// `generation` stays inside its class), and every growing row strictly
    /// raises the width class of its generation column alone, so the old
    /// image is at most as long as the new one, which the doubled image term
    /// for growing rows relies on. A shrinking row is outside this shape and
    /// is priced by `same_key_rewrites`. The native owner's retained width
    /// recipe and its scope gate on the generation allocator must retain this
    /// proof beside the class floor, before the rewrite runs.
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
    /// split during a mutation. This is data: the writer must enforce the row
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

    /// Identity of the page-bounded calculator. A source recipe that prices
    /// with `price_within_pages` or a same-key rewrite shape binds this beside
    /// `write_price_algorithm_descriptor`.
    pub fn page_bounded_descriptor() -> &'static str {
        "chio.sqlite.page-bounded-frame-price.v1; bundled3.51.3; auto_vacuum_none; same_key_rewrite_one_balance_walk; recipe_proves_unchanged_key_no_rewritten_column_index_no_fk_delete_reinsert; dirty_pages_at_most_file_pages_with_cache_spill_off; growth=balance_plus_overflow_allocations+lock_byte_page; independent_transactions"
    }

    /// Identity of the split same-key rewrite price. A source recipe that
    /// prices a fan-out with `same_key_rewrites_class_split` binds this beside
    /// `write_price_algorithm_descriptor` and the page-bounded descriptor.
    pub fn split_same_key_rewrites_descriptor() -> &'static str {
        "chio.sqlite.split-same-key-frame-price.v1; bundled3.51.3; auto_vacuum_none; recipe_proves_new_record_identical_except_generation_column; recipe_proves_unchanged_key_no_rewritten_column_index_no_fk_delete_reinsert; same_width_in_place_no_allocation_dirties_only_differing_pages; growing_drop_insert_cascade; balance_level7_children_nb_plus_2_parent_freelist_trunk; growth2_pages_per_level_plus_per_row_overflow_slack; same_width_one_image_set_plus_row_slack; growing_old_and_new_images; zero_and_one_special_encodings; class_floor_measured_at_preparation; independent_transactions"
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

    /// The same price when the whole file never exceeds `page_ceiling` pages
    /// while the transaction runs. With cache spill off each dirty page
    /// reaches the WAL once, and every dirty page is a page of the file, so
    /// the frame bound is the smaller of the generic bound and the ceiling.
    /// The caller must retain that ceiling and enforce it on every writer of
    /// the file; this grants no funding.
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
                TreeKindData::SingletonRoot => require_singleton_fit(profile, tree)?,
                TreeKindData::ObservedRootLeaf => {}
                TreeKindData::SplitSameKeyRewrites { growing } => {
                    // A same-width row appends nothing: the overwrite path
                    // allocates no page. A growing row's cascade appends at
                    // most `SPLIT_NEW_PAGES_PER_LEVEL` pages per level, and
                    // its new cell keeps at most one image set of the
                    // rewritten record's bound on new overflow pages. Each
                    // chain is bounded per row (a chain page holds
                    // `usableSize - 4` payload bytes), so the ceil of the
                    // summed bytes can fall short of the sum of the per-row
                    // ceils by up to `growing - 1` pages; one page per
                    // growing row covers that rounding.
                    if growing > 0 {
                        let new_pages =
                            mul(growing, mul(tree.cursor_levels, SPLIT_NEW_PAGES_PER_LEVEL)?)?;
                        let overflow = add(ceil(tree.maximum_after_bytes, payload)?, growing)?;
                        growth = add(growth, add(new_pages, overflow)?)?;
                    }
                }
                TreeKindData::Record
                | TreeKindData::FreshInsertions
                | TreeKindData::SameKeyRewrites => {
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

/// Calculator identity to bind into the actual source profile. It identifies
/// the bound, not a supported producer or a funded loan.
pub fn write_price_algorithm_descriptor() -> &'static str {
    "chio.sqlite.transaction-frame-price.v1; bundled3.51.3; depth20; balance6; newwalk1; existingwalk3; allocation_or_free2; frame24; header32; FULL_sector65536; reserved0; auto_vacuum_none; before_or_intermediate_overflow; ambiguous_new_rewrites_existing_cost; explicit_fresh_insertions; independent_transactions"
}

/// Payload bytes one overflow page carries: `usableSize - 4`.
fn overflow_payload(profile: &SqliteFramePriceProfileData) -> Result<u64, String> {
    profile
        .page_size
        .checked_sub(4)
        .filter(|bytes| *bytes > 0)
        .ok_or_else(|| "SQLite overflow divisor is invalid".to_owned())
}

/// A singleton record stays local in its fixed root, so it neither spills to
/// overflow pages nor splits the root. Frame pricing and page growth share
/// this refusal.
fn require_singleton_fit(
    profile: &SqliteFramePriceProfileData,
    tree: &SqliteTreeWriteShapeData,
) -> Result<(), String> {
    if tree.maximum_after_bytes > profile.page_size - PAGE_ONE_HEADER_BYTES {
        return Err("SQLite singleton record exceeds its fixed root".to_owned());
    }
    Ok(())
}

/// Balance-walk pages and overflow pages of one record tree. Every page one
/// of its writes allocates is among these.
fn record_tree_terms(tree: &SqliteTreeWriteShapeData, payload: u64) -> Result<(u64, u64), String> {
    if tree.kind == TreeKindData::SameKeyRewrites {
        let balance = mul(
            mul(tree.mutations, tree.cursor_levels)?,
            BALANCE_PAGES_PER_LEVEL,
        )?;
        // One image set of the bound plus one rounding page per row, charged
        // once for the old images and once for the new ones.
        let images = add(ceil(tree.maximum_after_bytes, payload)?, tree.mutations)?;
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
/// overwrites an entirely local cell (`nLocal == nPayload`) in place,
/// dirtying only its leaf page, or calls `btreeOverwriteOverflowCell` for a
/// spilled cell, which overwrites the local window and then each overflow
/// page and dirties only the pages whose compared bytes differ: it allocates
/// no page, frees no page and touches no freelist trunk. Its dirtied image
/// pages are at most one set of the rewritten bytes, so the same-width rows
/// together dirty at most `ceil(total, payload)` pages of images plus one
/// slack page per row, beside one leaf page per row.
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
    // with no growing row nothing is replaced, and the same-width rows keep
    // their single image set inside `same_frames`. For growing rows the
    // doubled image term is required: `freePage2` does not write freed old
    // chain pages by default, but `secure_delete` does, and the term also
    // covers the freelist-trunk frames each growing row's overflow
    // allocation (`fillInCell`) and free (`freePage2`) dirties, which no
    // other term counts.
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
    // Allocation can dirty page one even when the source tables are small.
    let mut frames = if no_spill { 3 } else { 1 };
    for tree in &transaction.trees {
        match tree.kind {
            TreeKindData::ObservedRootLeaf => {
                if !no_spill {
                    return Err("SQLite observed root leaf requires spilling disabled".to_owned());
                }
                frames = add(frames, 1)?;
            }
            TreeKindData::SingletonRoot => {
                require_singleton_fit(profile, tree)?;
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
mod tests;
