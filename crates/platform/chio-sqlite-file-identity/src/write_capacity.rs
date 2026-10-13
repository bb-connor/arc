//! Checked capacity amounts are DATA and never authenticate a funded writer.
//! The owner verifies its complete bank, file, namespace and producer catalog.

const MIB: u64 = 1_024 * 1_024;
const INTAKE_WAL_BYTES: u64 = 64 * MIB;
const PROGRESS_WAL_BYTES: u64 = 128 * MIB;
const INTAKE_DISK_FLOOR_BYTES: u64 = 128 * MIB;
const PROGRESS_DISK_FLOOR_BYTES: u64 = 16 * MIB;

/// A new managed policy must be bound into each actual financing profile.
/// This descriptor does not assert that an earlier Process file had this policy.
pub fn write_capacity_policy_descriptor() -> &'static str {
    "chio.sqlite.managed-write-capacity.v1; per_file_intake_WAL64MiB; per_file_owed_WAL128MiB; same_filesystem_intake_disk_floor128MiB; same_filesystem_progress_disk_floor16MiB; checked_current_and_all_remaining_debt"
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqlitePhysicalDebtAmountData {
    wal_bytes: u64,
    disk_bytes: u64,
}

impl SqlitePhysicalDebtAmountData {
    pub fn checked(wal_bytes: u64, disk_bytes: u64) -> Result<Self, String> {
        let amount = Self {
            wal_bytes,
            disk_bytes,
        };
        amount.validate()?;
        Ok(amount)
    }

    pub fn wal_bytes(&self) -> u64 {
        self.wal_bytes
    }
    pub fn disk_bytes(&self) -> u64 {
        self.disk_bytes
    }

    pub fn checked_add(&self, other: &Self) -> Result<Self, String> {
        self.combine(other, u64::checked_add)
    }

    pub fn checked_sub(&self, other: &Self) -> Result<Self, String> {
        self.combine(other, u64::checked_sub)
    }

    fn combine(
        &self,
        other: &Self,
        operation: fn(u64, u64) -> Option<u64>,
    ) -> Result<Self, String> {
        self.validate()?;
        other.validate()?;
        Self::checked(
            operation(self.wal_bytes, other.wal_bytes)
                .ok_or_else(|| "SQLite WAL amount arithmetic exhausted".to_owned())?,
            operation(self.disk_bytes, other.disk_bytes)
                .ok_or_else(|| "SQLite disk amount arithmetic exhausted".to_owned())?,
        )
    }

    fn validate(&self) -> Result<(), String> {
        if self.disk_bytes < self.wal_bytes {
            return Err("SQLite debt disk amount is smaller than its WAL amount".to_owned());
        }
        Ok(())
    }
}

/// The owning source decides whether a current mutation is ordinary intake or
/// a real prepaid purpose. Choosing this DATA value creates no progress permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqliteWriteCapacityStageData {
    Intake,
    OwedProgress,
}

/// Amount preservation is separate from actual inventory and borrowing proof.
/// Other-file debt belongs to independently verified files on the same volume;
/// its WAL must never be charged against this file's WAL limit.
pub fn require_physical_write_capacity(
    stage: SqliteWriteCapacityStageData,
    pending_wal_bytes: u64,
    available_disk_bytes: u64,
    owed_this_file: &SqlitePhysicalDebtAmountData,
    owed_other_files: &[SqlitePhysicalDebtAmountData],
    current_write: &SqlitePhysicalDebtAmountData,
) -> Result<(), String> {
    let total = owed_this_file.checked_add(current_write)?;
    let other_disk = owed_other_files.iter().try_fold(0_u64, |sum, amount| {
        amount.validate()?;
        add(sum, amount.disk_bytes())
    })?;
    let current_wal = add(pending_wal_bytes, current_write.wal_bytes())?;
    let remaining_wal = add(pending_wal_bytes, total.wal_bytes())?;
    let disk_floor = match stage {
        SqliteWriteCapacityStageData::Intake => INTAKE_DISK_FLOOR_BYTES,
        SqliteWriteCapacityStageData::OwedProgress => PROGRESS_DISK_FLOOR_BYTES,
    };
    let required_disk = add(add(disk_floor, total.disk_bytes())?, other_disk)?;
    if (stage == SqliteWriteCapacityStageData::Intake && current_wal >= INTAKE_WAL_BYTES)
        || remaining_wal >= PROGRESS_WAL_BYTES
        || available_disk_bytes < required_disk
    {
        return Err("SQLite write would consume an owed finishing reserve".to_owned());
    }
    Ok(())
}

fn add(left: u64, right: u64) -> Result<u64, String> {
    left.checked_add(right)
        .ok_or_else(|| "SQLite capacity sum exhausted".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn amount(wal_mib: u64, disk_mib: u64) -> Result<SqlitePhysicalDebtAmountData, String> {
        SqlitePhysicalDebtAmountData::checked(wal_mib * MIB, disk_mib * MIB)
    }

    #[test]
    fn a_write_preserves_debt_in_every_file_on_the_same_volume() -> Result<(), String> {
        let owed = amount(16, 32)?;
        let current = amount(8, 16)?;
        let other = amount(20, 40)?;
        // Genuine existing one-file equation is the positive control.
        require_physical_write_capacity(
            SqliteWriteCapacityStageData::Intake,
            8 * MIB,
            190 * MIB,
            &owed,
            &[],
            &current,
        )?;
        assert!(
            require_physical_write_capacity(
                SqliteWriteCapacityStageData::Intake,
                8 * MIB,
                190 * MIB,
                &owed,
                &[other],
                &current,
            )
            .is_err(),
            "a write borrowed disk already owed to another same-volume journal"
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
        )?;
        Ok(())
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
        assert!(require_physical_write_capacity(
            SqliteWriteCapacityStageData::Intake,
            62 * MIB,
            1024 * MIB,
            &amount(65, 130)?,
            &[],
            &current,
        )
        .is_err());
        assert!(require_physical_write_capacity(
            SqliteWriteCapacityStageData::Intake,
            63 * MIB,
            1024 * MIB,
            &amount(0, 0)?,
            &[],
            &current,
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn owed_progress_retains_the_other_purposes() -> Result<(), String> {
        let current = amount(8, 16)?;
        require_physical_write_capacity(
            SqliteWriteCapacityStageData::OwedProgress,
            103 * MIB,
            64 * MIB,
            &amount(16, 32)?,
            &[],
            &current,
        )?;
        assert!(require_physical_write_capacity(
            SqliteWriteCapacityStageData::OwedProgress,
            104 * MIB,
            64 * MIB,
            &amount(16, 32)?,
            &[],
            &current,
        )
        .is_err());
        assert!(require_physical_write_capacity(
            SqliteWriteCapacityStageData::OwedProgress,
            103 * MIB,
            63 * MIB,
            &amount(16, 32)?,
            &[],
            &current,
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn invalid_operands_and_capacity_overflow_refuse() -> Result<(), String> {
        let invalid = SqlitePhysicalDebtAmountData {
            wal_bytes: 2,
            disk_bytes: 1,
        };
        let valid = SqlitePhysicalDebtAmountData::checked(0, 2)?;
        assert!(invalid.checked_add(&valid).is_err());
        assert!(valid.checked_sub(&invalid).is_err());
        assert!(require_physical_write_capacity(
            SqliteWriteCapacityStageData::Intake,
            0,
            u64::MAX,
            &valid,
            &[invalid],
            &valid,
        )
        .is_err());
        let largest = SqlitePhysicalDebtAmountData::checked(u64::MAX, u64::MAX)?;
        assert!(largest
            .checked_add(&SqlitePhysicalDebtAmountData::checked(1, 1)?)
            .is_err());
        assert!(require_physical_write_capacity(
            SqliteWriteCapacityStageData::Intake,
            0,
            u64::MAX,
            &largest,
            &[],
            &valid,
        )
        .is_err());
        Ok(())
    }
}
