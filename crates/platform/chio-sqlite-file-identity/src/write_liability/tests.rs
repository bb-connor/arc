use super::*;

mod real_sqlite;

const UNSUPPORTED_GEOMETRY: &str = "SQLite frame price geometry is unsupported";
const LOST_RECORD_BOUND: &str = "SQLite tree shape lost its complete record bound";
const LOST_SAME_KEY_BOUND: &str = "SQLite same-key rewrite shape lost its producing bound";
const LOST_SPLIT_BOUND: &str = "SQLite split same-key shape lost its producing bound";
const SUM_EXHAUSTED: &str = "SQLite physical price sum exhausted";
const PRODUCT_EXHAUSTED: &str = "SQLite physical price product exhausted";

fn refused<T: std::fmt::Debug>(result: Result<T, String>, expected: &str) {
    match result {
        Err(actual) => assert_eq!(actual, expected),
        Ok(value) => panic!("expected refusal {expected:?}, got {value:?}"),
    }
}

fn transaction(
    trees: Vec<SqliteTreeWriteShapeData>,
) -> Result<SqliteTransactionWriteShapeData, String> {
    SqliteTransactionWriteShapeData::checked(trees)
}

#[test]
fn independent_transactions_retain_separate_commit_costs() -> Result<(), String> {
    let profile = SqliteFramePriceProfileData::checked(4096, 0, 0)?;
    let first = SqliteTreeWriteShapeData::record(None, 16_384, 1)?;
    let second = SqliteTreeWriteShapeData::record(Some(16_384), 16_384, 1)?;
    let first_price = price_transaction_write_shape(&profile, &transaction(vec![first.clone()])?)?;
    let second_price =
        price_transaction_write_shape(&profile, &transaction(vec![second.clone()])?)?;
    let merged = price_transaction_write_shape(&profile, &transaction(vec![first, second])?)?;
    assert!(first_price.wal_bytes() + second_price.wal_bytes() > merged.wal_bytes());
    assert!(first_price.disk_bytes() + second_price.disk_bytes() > merged.disk_bytes());
    Ok(())
}

#[test]
fn same_size_rewrites_retain_old_images_and_every_history_write() -> Result<(), String> {
    let profile = SqliteFramePriceProfileData::checked(512, 0, 0)?;
    let price = |mutations| -> Result<SqliteTransactionWritePriceData, String> {
        price_transaction_write_shape(
            &profile,
            &transaction(vec![
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
fn an_initially_absent_repeated_row_keeps_its_intermediate_existing_image() -> Result<(), String> {
    let profile = SqliteFramePriceProfileData::checked(4096, 0, 0)?;
    let price = |tree| price_transaction_write_shape(&profile, &transaction(vec![tree])?);
    let inserted_then_rewritten = price(SqliteTreeWriteShapeData::record(None, 1_048_576, 2)?)?;
    let already_existing = price(SqliteTreeWriteShapeData::record(
        Some(1_048_576),
        1_048_576,
        2,
    )?)?;
    let distinct_fresh_records = price(SqliteTreeWriteShapeData::fresh_insertions(1_048_576, 2)?)?;
    assert_eq!(inserted_then_rewritten, already_existing);
    assert!(inserted_then_rewritten.wal_bytes() > distinct_fresh_records.wal_bytes());
    assert!(inserted_then_rewritten.disk_bytes() > distinct_fresh_records.disk_bytes());
    // A single write of an absent key is a fresh insertion, not an existing row.
    assert_eq!(
        price(SqliteTreeWriteShapeData::record(None, 1_048_576, 1)?)?,
        price(SqliteTreeWriteShapeData::fresh_insertions(1_048_576, 1)?)?
    );
    Ok(())
}

#[test]
fn page_bounded_rewrites_price_the_file_not_every_balance_walk() -> Result<(), String> {
    let profile = SqliteFramePriceProfileData::checked(4096, 0, 0)?;
    let rows = 4096;
    let bytes = 8 * 1024 * 1024;
    let shape = transaction(vec![SqliteTreeWriteShapeData::same_key_rewrites(
        rows, bytes,
    )?])?;
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
        &transaction(vec![SqliteTreeWriteShapeData::record(
            Some(2048),
            2048,
            rows,
        )?])?,
    )?;
    assert!(walked.wal_bytes() < ambiguous.wal_bytes());
    // Growth counts every allocation of the one balance walk per rewrite and
    // both overflow images; it never reads the file's size.
    assert_eq!(
        shape.maximum_page_growth(&profile)?,
        rows * 20 * 6 + 2 * (bytes.div_ceil(4092) + rows) + 1
    );
    // A ceiling above the generic bound leaves the generic bound in force.
    assert_eq!(shape.price_within_pages(&profile, u64::MAX)?, walked);
    refused(
        SqliteTreeWriteShapeData::same_key_rewrites(0, bytes),
        LOST_SAME_KEY_BOUND,
    );
    refused(
        SqliteTreeWriteShapeData::same_key_rewrites(rows, 0),
        LOST_SAME_KEY_BOUND,
    );
    refused(
        shape.price_within_pages(&profile, 0),
        "SQLite page ceiling is empty",
    );
    Ok(())
}

#[test]
fn split_same_key_rewrites_price_measured_growing_rows_exactly() -> Result<(), String> {
    let profile = SqliteFramePriceProfileData::checked(4096, 0, 0)?;
    let rows = 4096;
    let bytes = 8 * 1024 * 1024;
    let price = |growing: u64| {
        price_transaction_write_shape(
            &profile,
            &transaction(vec![
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
        // Growing image sets exist only for growing rows; with none, the
        // same-width rows keep their single image set inside `same_frames`.
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
    let shape = transaction(vec![
        SqliteTreeWriteShapeData::same_key_rewrites_class_split(rows, bytes, 128)?,
    ])?;
    // The growth carries the per-row overflow rounding slack beside the
    // balance fresh pages: ceil of the summed bytes falls short of the sum of
    // the per-row ceils.
    assert_eq!(
        shape.maximum_page_growth(&profile)?,
        LOCK_BYTE_PAGE_SKIP
            + 128 * CURSOR_LEVELS * SPLIT_NEW_PAGES_PER_LEVEL
            + bytes.div_ceil(4092)
            + 128
    );
    // A fully same-width fan-out grows only the lock-byte page.
    let same_width = transaction(vec![
        SqliteTreeWriteShapeData::same_key_rewrites_class_split(rows, bytes, 0)?,
    ])?;
    assert_eq!(
        same_width.maximum_page_growth(&profile)?,
        LOCK_BYTE_PAGE_SKIP
    );
    // The split stays below the generic existing-record walk at every
    // measured split, and more growing rows always cost strictly more.
    let ambiguous = price_transaction_write_shape(
        &profile,
        &transaction(vec![SqliteTreeWriteShapeData::record(
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
    refused(
        SqliteTreeWriteShapeData::same_key_rewrites_class_split(rows, bytes, rows + 1),
        LOST_SPLIT_BOUND,
    );
    refused(
        SqliteTreeWriteShapeData::same_key_rewrites_class_split(0, bytes, 0),
        LOST_SPLIT_BOUND,
    );
    refused(
        SqliteTreeWriteShapeData::same_key_rewrites_class_split(rows, 0, 0),
        LOST_SPLIT_BOUND,
    );
    Ok(())
}

#[test]
fn generation_width_classes_cover_the_special_encodings_and_every_transition() -> Result<(), String>
{
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
    for generation in [GENERATION_SAFE_INTEGER_CEILING + 1, u64::MAX] {
        refused(
            class(generation),
            "SQLite generation exceeds the safe integer ceiling",
        );
    }
    assert_eq!(floor(0)?, 0);
    for width in [5, 7, 9, u64::MAX] {
        refused(floor(width), "SQLite generation width class is unencoded");
    }
    Ok(())
}

#[test]
fn malformed_geometry_and_exhausted_record_counts_refuse() -> Result<(), String> {
    for (page_size, reserved) in [
        (512, 32),
        (512, 1),
        (1000, 0),
        (256, 0),
        (131_072, 0),
        (0, 0),
    ] {
        refused(
            SqliteFramePriceProfileData::checked(page_size, reserved, 0),
            UNSUPPORTED_GEOMETRY,
        );
    }
    for page_size in [512, 1024, 4096, 65_536] {
        SqliteFramePriceProfileData::checked(page_size, 0, 0)?;
    }
    refused(
        SqliteTreeWriteShapeData::record(Some(0), 1024, 1),
        LOST_RECORD_BOUND,
    );
    refused(
        SqliteTreeWriteShapeData::record(None, 1024, 0),
        LOST_RECORD_BOUND,
    );
    refused(
        SqliteTreeWriteShapeData::record(None, 0, 1),
        LOST_RECORD_BOUND,
    );
    let profile = SqliteFramePriceProfileData::checked(4096, 0, 0)?;
    refused(
        profile.price_frames(0),
        "SQLite transaction frame bound is empty",
    );
    refused(profile.price_frames(u64::MAX), SUM_EXHAUSTED);
    let exhausted = transaction(vec![SqliteTreeWriteShapeData::record(
        Some(u64::MAX),
        u64::MAX,
        u64::MAX,
    )?])?;
    refused(
        price_transaction_write_shape(&profile, &exhausted),
        PRODUCT_EXHAUSTED,
    );
    refused(exhausted.price_without_spill(&profile), PRODUCT_EXHAUSTED);
    refused(exhausted.maximum_page_growth(&profile), PRODUCT_EXHAUSTED);
    Ok(())
}

#[test]
fn every_calculator_descriptor_is_its_exact_v1_identity() {
    assert_eq!(
        write_price_algorithm_descriptor(),
        "chio.sqlite.transaction-frame-price.v1; bundled3.51.3; depth20; balance6; newwalk1; existingwalk3; allocation_or_free2; frame24; header32; FULL_sector65536; reserved0; auto_vacuum_none; before_or_intermediate_overflow; ambiguous_new_rewrites_existing_cost; explicit_fresh_insertions; independent_transactions"
    );
    assert_eq!(
        SqliteTransactionWriteShapeData::page_bounded_descriptor(),
        "chio.sqlite.page-bounded-frame-price.v1; bundled3.51.3; auto_vacuum_none; same_key_rewrite_one_balance_walk; recipe_proves_unchanged_key_no_rewritten_column_index_no_fk_delete_reinsert; dirty_pages_at_most_file_pages_with_cache_spill_off; growth=balance_plus_overflow_allocations+lock_byte_page; independent_transactions"
    );
    assert_eq!(
        SqliteTransactionWriteShapeData::split_same_key_rewrites_descriptor(),
        "chio.sqlite.split-same-key-frame-price.v1; bundled3.51.3; auto_vacuum_none; recipe_proves_new_record_identical_except_generation_column; recipe_proves_unchanged_key_no_rewritten_column_index_no_fk_delete_reinsert; same_width_in_place_no_allocation_dirties_only_differing_pages; growing_drop_insert_cascade; balance_level7_children_nb_plus_2_parent_freelist_trunk; growth2_pages_per_level_plus_per_row_overflow_slack; same_width_one_image_set_plus_row_slack; growing_old_and_new_images; zero_and_one_special_encodings; class_floor_measured_at_preparation; independent_transactions"
    );
    assert_eq!(
        SqliteTransactionWriteShapeData::no_spill_descriptor(),
        "chio.sqlite.no-spill-frame-price.v1; bundled3.51.3; cache_spill_off; auto_vacuum_none; balance_and_old_new_overflow_pages_once; secure_delete_supported; passed_freelist_trunk_is_allocated; new_trunk_is_freed; page_one_and_final_original_trunk_plus_one_slack; independent_transactions"
    );
}

#[test]
fn an_observed_root_leaf_is_priced_only_without_spilling() -> Result<(), String> {
    let profile = SqliteFramePriceProfileData::checked(4096, 0, 0)?;
    let shape = transaction(vec![SqliteTreeWriteShapeData::observed_root_leaf()])?;
    // Page one, the final original freelist trunk, one slack frame and the
    // single root page.
    assert_eq!(
        shape.price_without_spill(&profile)?,
        profile.price_frames(4)?
    );
    assert_eq!(shape.maximum_page_growth(&profile)?, LOCK_BYTE_PAGE_SKIP);
    let spill = "SQLite observed root leaf requires spilling disabled";
    refused(price_transaction_write_shape(&profile, &shape), spill);
    refused(shape.price_within_pages(&profile, 1 << 20), spill);
    let mixed = transaction(vec![
        SqliteTreeWriteShapeData::fresh_insertions(64, 1)?,
        SqliteTreeWriteShapeData::observed_root_leaf(),
    ])?;
    refused(price_transaction_write_shape(&profile, &mixed), spill);
    mixed.price_without_spill(&profile)?;
    Ok(())
}

#[test]
fn empty_shapes_and_zero_bounds_refuse() -> Result<(), String> {
    refused(
        SqliteTransactionWriteShapeData::checked(Vec::new()),
        "SQLite transaction price has no producing trees",
    );
    let insert_only = "SQLite insert-only shape lost its producing bound";
    refused(
        SqliteTreeWriteShapeData::fresh_insertions(0, 1),
        insert_only,
    );
    refused(
        SqliteTreeWriteShapeData::fresh_insertions(1, 0),
        insert_only,
    );
    let singleton = "SQLite singleton shape lost its producing bound";
    refused(SqliteTreeWriteShapeData::singleton_root(0, 1), singleton);
    refused(SqliteTreeWriteShapeData::singleton_root(1, 0), singleton);
    let empty_ceiling = "SQLite retained tree row ceiling is empty";
    refused(
        SqliteTreeWriteShapeData::retained_row_cursor_levels(0),
        empty_ceiling,
    );
    refused(
        SqliteTreeWriteShapeData::fresh_insertions(1, 1)?.within_retained_rows(0),
        empty_ceiling,
    );
    Ok(())
}

#[test]
fn retained_rows_bound_the_cursor_up_to_the_maximum_depth() -> Result<(), String> {
    let levels = SqliteTreeWriteShapeData::retained_row_cursor_levels;
    for (rows, expected) in [
        (1, 3),
        (2, 4),
        (3, 4),
        (4, 5),
        (64, 9),
        (1 << 16, 19),
        (1 << 17, CURSOR_LEVELS),
        (u64::MAX, CURSOR_LEVELS),
    ] {
        assert_eq!(levels(rows)?, expected, "rows {rows}");
    }
    let profile = SqliteFramePriceProfileData::checked(4096, 0, 0)?;
    let price = |tree| price_transaction_write_shape(&profile, &transaction(vec![tree])?);
    let unbounded = price(SqliteTreeWriteShapeData::fresh_insertions(64, 1)?)?;
    let bounded =
        price(SqliteTreeWriteShapeData::fresh_insertions(64, 1)?.within_retained_rows(64)?)?;
    assert!(bounded.wal_frames() < unbounded.wal_frames());
    assert_eq!(
        price(SqliteTreeWriteShapeData::fresh_insertions(64, 1)?.within_retained_rows(u64::MAX)?)?,
        unbounded
    );
    Ok(())
}

#[test]
fn a_singleton_record_must_fit_its_fixed_root() -> Result<(), String> {
    let profile = SqliteFramePriceProfileData::checked(512, 0, 0)?;
    let fits = transaction(vec![SqliteTreeWriteShapeData::singleton_root(412, 3)?])?;
    assert_eq!(
        price_transaction_write_shape(&profile, &fits)?,
        profile.price_frames(1 + 3)?
    );
    assert_eq!(
        fits.price_without_spill(&profile)?,
        profile.price_frames(3 + 3)?
    );
    assert_eq!(fits.maximum_page_growth(&profile)?, LOCK_BYTE_PAGE_SKIP);
    let oversized = transaction(vec![SqliteTreeWriteShapeData::singleton_root(413, 1)?])?;
    let exceeded = "SQLite singleton record exceeds its fixed root";
    refused(
        price_transaction_write_shape(&profile, &oversized),
        exceeded,
    );
    refused(oversized.price_without_spill(&profile), exceeded);
    refused(oversized.maximum_page_growth(&profile), exceeded);
    Ok(())
}

#[test]
fn every_price_and_growth_sum_refuses_exhaustion() -> Result<(), String> {
    let profile = SqliteFramePriceProfileData::checked(4096, 0, 0)?;
    let walks = transaction(vec![SqliteTreeWriteShapeData::same_key_rewrites(
        u64::MAX,
        1,
    )?])?;
    refused(
        price_transaction_write_shape(&profile, &walks),
        PRODUCT_EXHAUSTED,
    );
    refused(walks.maximum_page_growth(&profile), PRODUCT_EXHAUSTED);
    let rows = u64::MAX / 2;
    let cascade = transaction(vec![
        SqliteTreeWriteShapeData::same_key_rewrites_class_split(rows, 1, rows)?,
    ])?;
    refused(
        price_transaction_write_shape(&profile, &cascade),
        PRODUCT_EXHAUSTED,
    );
    refused(cascade.maximum_page_growth(&profile), PRODUCT_EXHAUSTED);
    let singletons = transaction(vec![
        SqliteTreeWriteShapeData::singleton_root(1, u64::MAX)?,
        SqliteTreeWriteShapeData::singleton_root(1, 1)?,
    ])?;
    refused(
        price_transaction_write_shape(&profile, &singletons),
        SUM_EXHAUSTED,
    );
    refused(singletons.price_without_spill(&profile), SUM_EXHAUSTED);
    let rows_overflow = transaction(vec![
        SqliteTreeWriteShapeData::same_key_rewrites_class_split(u64::MAX, 1, u64::MAX)?,
    ])?;
    refused(
        price_transaction_write_shape(&profile, &rows_overflow),
        SUM_EXHAUSTED,
    );
    // The frame count fits, but its byte product does not.
    refused(profile.price_frames(u64::MAX / 4120), PRODUCT_EXHAUSTED);
    Ok(())
}

#[test]
fn frame_profiles_require_auto_vacuum_none_after_geometry() -> Result<(), String> {
    let refusal = "SQLite frame price requires auto-vacuum NONE";
    for page_size in [512, 4096, 65_536] {
        SqliteFramePriceProfileData::checked(page_size, 0, 0)?;
    }
    for mode in [1, 2, 3, u64::MAX] {
        refused(SqliteFramePriceProfileData::checked(4096, 0, mode), refusal);
        refused(
            SqliteFramePriceProfileData::checked(1000, 0, mode),
            UNSUPPORTED_GEOMETRY,
        );
        refused(
            SqliteFramePriceProfileData::checked(4096, 32, mode),
            UNSUPPORTED_GEOMETRY,
        );
    }
    Ok(())
}
