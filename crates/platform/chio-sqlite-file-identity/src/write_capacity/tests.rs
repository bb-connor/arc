use super::*;

fn amount(wal_mib: u64, disk_mib: u64) -> Result<SqlitePhysicalDebtAmountData, String> {
    SqlitePhysicalDebtAmountData::checked(wal_mib * MIB, disk_mib * MIB)
}

fn capacity_refusal() -> Result<(), String> {
    Err("SQLite write would consume an owed finishing reserve".to_owned())
}

#[test]
fn same_volume_debts_preserve_the_complete_disk_floor() -> Result<(), String> {
    let owed = amount(16, 32)?;
    let current = amount(8, 16)?;
    let other = amount(20, 40)?;
    require_physical_write_capacity(
        SqliteWriteCapacityStageData::Intake,
        8 * MIB,
        190 * MIB,
        &owed,
        &[],
        &current,
    )?;
    assert_eq!(
        require_physical_write_capacity(
            SqliteWriteCapacityStageData::Intake,
            8 * MIB,
            190 * MIB,
            &owed,
            &[other],
            &current,
        ),
        capacity_refusal()
    );
    require_physical_write_capacity(
        SqliteWriteCapacityStageData::Intake,
        8 * MIB,
        216 * MIB,
        &owed,
        &[other],
        &current,
    )?;
    assert_eq!(
        require_physical_write_capacity(
            SqliteWriteCapacityStageData::Intake,
            8 * MIB,
            216 * MIB - 1,
            &owed,
            &[other],
            &current,
        ),
        capacity_refusal()
    );
    Ok(())
}

#[test]
fn every_file_keeps_its_own_wal_limit() -> Result<(), String> {
    require_physical_write_capacity(
        SqliteWriteCapacityStageData::Intake,
        44 * MIB,
        1024 * MIB,
        &amount(16, 32)?,
        &[amount(120, 240)?],
        &amount(8, 16)?,
    )
}

#[test]
fn intake_preserves_the_complete_progress_gap() -> Result<(), String> {
    let current = amount(1, 2)?;
    require_physical_write_capacity(
        SqliteWriteCapacityStageData::Intake,
        62 * MIB,
        1024 * MIB,
        &amount(64, 128)?,
        &[],
        &current,
    )?;
    assert_eq!(
        require_physical_write_capacity(
            SqliteWriteCapacityStageData::Intake,
            62 * MIB,
            1024 * MIB,
            &amount(65, 130)?,
            &[],
            &current,
        ),
        capacity_refusal()
    );
    assert_eq!(
        require_physical_write_capacity(
            SqliteWriteCapacityStageData::Intake,
            63 * MIB,
            1024 * MIB,
            &amount(0, 0)?,
            &[],
            &current,
        ),
        capacity_refusal()
    );
    Ok(())
}

#[test]
fn owed_progress_retains_other_purposes_and_its_disk_floor() -> Result<(), String> {
    let current = amount(8, 16)?;
    require_physical_write_capacity(
        SqliteWriteCapacityStageData::OwedProgress,
        103 * MIB,
        64 * MIB,
        &amount(16, 32)?,
        &[],
        &current,
    )?;
    for (pending, disk) in [(104 * MIB, 64 * MIB), (103 * MIB, 63 * MIB)] {
        assert_eq!(
            require_physical_write_capacity(
                SqliteWriteCapacityStageData::OwedProgress,
                pending,
                disk,
                &amount(16, 32)?,
                &[],
                &current,
            ),
            capacity_refusal()
        );
    }
    Ok(())
}

#[test]
fn stages_apply_distinct_intake_limits_and_disk_floors() -> Result<(), String> {
    let zero = amount(0, 0)?;
    let current = amount(1, 2)?;
    require_physical_write_capacity(
        SqliteWriteCapacityStageData::OwedProgress,
        63 * MIB,
        18 * MIB,
        &zero,
        &[],
        &current,
    )?;
    assert_eq!(
        require_physical_write_capacity(
            SqliteWriteCapacityStageData::Intake,
            63 * MIB,
            130 * MIB,
            &zero,
            &[],
            &current,
        ),
        capacity_refusal()
    );
    for (stage, floor) in [
        (SqliteWriteCapacityStageData::Intake, 128 * MIB),
        (SqliteWriteCapacityStageData::OwedProgress, 16 * MIB),
    ] {
        require_physical_write_capacity(stage, 0, floor, &zero, &[], &zero)?;
        assert_eq!(
            require_physical_write_capacity(stage, 0, floor - 1, &zero, &[], &zero),
            capacity_refusal()
        );
    }
    Ok(())
}

#[test]
fn wal_thresholds_refuse_at_the_exact_byte() -> Result<(), String> {
    let zero = amount(0, 0)?;
    for (stage, limit) in [
        (SqliteWriteCapacityStageData::Intake, 64 * MIB),
        (SqliteWriteCapacityStageData::OwedProgress, 128 * MIB),
    ] {
        require_physical_write_capacity(stage, limit - 1, 1024 * MIB, &zero, &[], &zero)?;
        for pending in [limit, limit + 1] {
            assert_eq!(
                require_physical_write_capacity(stage, pending, 1024 * MIB, &zero, &[], &zero),
                capacity_refusal()
            );
        }
    }
    let owed = SqlitePhysicalDebtAmountData::checked(128 * MIB - 1, 128 * MIB - 1)?;
    require_physical_write_capacity(
        SqliteWriteCapacityStageData::Intake,
        0,
        1024 * MIB,
        &owed,
        &[],
        &zero,
    )?;
    assert_eq!(
        require_physical_write_capacity(
            SqliteWriteCapacityStageData::Intake,
            1,
            1024 * MIB,
            &owed,
            &[],
            &zero,
        ),
        capacity_refusal()
    );
    Ok(())
}

#[test]
fn debt_amounts_require_disk_to_cover_wal() -> Result<(), String> {
    assert_eq!(
        SqlitePhysicalDebtAmountData::checked(1, 0),
        Err("SQLite debt disk amount is smaller than its WAL amount".to_owned())
    );
    for bytes in [0, 1, u64::MAX] {
        let actual = SqlitePhysicalDebtAmountData::checked(bytes, bytes)?;
        assert_eq!((actual.wal_bytes(), actual.disk_bytes()), (bytes, bytes));
    }
    Ok(())
}

#[test]
fn debt_addition_and_subtraction_preserve_exact_amounts() -> Result<(), String> {
    let left = SqlitePhysicalDebtAmountData::checked(3, 5)?;
    let right = SqlitePhysicalDebtAmountData::checked(2, 3)?;
    let sum = left.checked_add(&right)?;
    assert_eq!(sum, SqlitePhysicalDebtAmountData::checked(5, 8)?);
    assert_eq!(sum.checked_sub(&right)?, left);
    assert_eq!(sum.checked_sub(&left)?, right);
    assert_eq!(
        sum.checked_sub(&sum)?,
        SqlitePhysicalDebtAmountData::checked(0, 0)?
    );
    assert_eq!(
        SqlitePhysicalDebtAmountData::checked(4, 4)?
            .checked_sub(&SqlitePhysicalDebtAmountData::checked(1, 3)?),
        Err("SQLite debt disk amount is smaller than its WAL amount".to_owned())
    );
    Ok(())
}

#[test]
fn amount_arithmetic_refuses_wal_and_disk_exhaustion() -> Result<(), String> {
    let one = SqlitePhysicalDebtAmountData::checked(1, 1)?;
    let zero = SqlitePhysicalDebtAmountData::checked(0, 0)?;
    let largest = SqlitePhysicalDebtAmountData::checked(u64::MAX, u64::MAX)?;
    assert_eq!(
        largest.checked_add(&one),
        Err("SQLite WAL amount arithmetic exhausted".to_owned())
    );
    assert_eq!(
        zero.checked_sub(&one),
        Err("SQLite WAL amount arithmetic exhausted".to_owned())
    );
    let disk_only = SqlitePhysicalDebtAmountData::checked(0, 1)?;
    assert_eq!(
        SqlitePhysicalDebtAmountData::checked(0, u64::MAX)?.checked_add(&disk_only),
        Err("SQLite disk amount arithmetic exhausted".to_owned())
    );
    assert_eq!(
        zero.checked_sub(&disk_only),
        Err("SQLite disk amount arithmetic exhausted".to_owned())
    );
    Ok(())
}

#[test]
fn malformed_operands_refuse_in_each_position() -> Result<(), String> {
    let invalid = SqlitePhysicalDebtAmountData {
        wal_bytes: 2,
        disk_bytes: 1,
    };
    let valid = SqlitePhysicalDebtAmountData::checked(0, 2)?;
    let error = "SQLite debt disk amount is smaller than its WAL amount".to_owned();
    assert_eq!(invalid.checked_add(&valid), Err(error.clone()));
    assert_eq!(valid.checked_add(&invalid), Err(error.clone()));
    assert_eq!(invalid.checked_sub(&valid), Err(error.clone()));
    assert_eq!(valid.checked_sub(&invalid), Err(error.clone()));
    for (owed, others, current) in [
        (invalid, vec![], valid),
        (valid, vec![invalid], valid),
        (valid, vec![], invalid),
    ] {
        assert_eq!(
            require_physical_write_capacity(
                SqliteWriteCapacityStageData::Intake,
                0,
                u64::MAX,
                &owed,
                &others,
                &current,
            ),
            Err(error.clone())
        );
    }
    Ok(())
}

#[test]
fn every_capacity_sum_refuses_overflow() -> Result<(), String> {
    let zero = SqlitePhysicalDebtAmountData::checked(0, 0)?;
    let one = SqlitePhysicalDebtAmountData::checked(1, 1)?;
    let two = SqlitePhysicalDebtAmountData::checked(2, 2)?;
    let disk_max = SqlitePhysicalDebtAmountData::checked(0, u64::MAX)?;
    let disk_one = SqlitePhysicalDebtAmountData::checked(0, 1)?;
    for (pending, owed, others, current) in [
        (u64::MAX, zero, vec![], one),
        (u64::MAX - 1, two, vec![], zero),
        (0, zero, vec![disk_max, disk_one], zero),
        (0, disk_max, vec![], zero),
        (0, zero, vec![disk_max], zero),
    ] {
        assert_eq!(
            require_physical_write_capacity(
                SqliteWriteCapacityStageData::OwedProgress,
                pending,
                u64::MAX,
                &owed,
                &others,
                &current,
            ),
            Err("SQLite capacity sum exhausted".to_owned())
        );
    }
    assert_eq!(
        require_physical_write_capacity(
            SqliteWriteCapacityStageData::OwedProgress,
            0,
            u64::MAX,
            &SqlitePhysicalDebtAmountData::checked(u64::MAX, u64::MAX)?,
            &[],
            &one,
        ),
        Err("SQLite WAL amount arithmetic exhausted".to_owned())
    );
    assert_eq!(
        require_physical_write_capacity(
            SqliteWriteCapacityStageData::OwedProgress,
            0,
            u64::MAX,
            &disk_max,
            &[],
            &disk_one,
        ),
        Err("SQLite disk amount arithmetic exhausted".to_owned())
    );
    Ok(())
}

#[test]
fn the_policy_descriptor_binds_the_exact_capacity_contract() {
    assert_eq!(
        write_capacity_policy_descriptor(),
        "chio.sqlite.managed-write-capacity.v1; per_file_intake_WAL64MiB; per_file_owed_WAL128MiB; same_filesystem_intake_disk_floor128MiB; same_filesystem_progress_disk_floor16MiB; checked_current_and_all_remaining_debt"
    );
}
