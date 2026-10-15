//! Checked capacity amounts for one SQLite file and its same-volume debts.
//! The owner authenticates the files, outstanding purposes and write authority.

const MIB: u64 = 1_024 * 1_024;
const INTAKE_WAL_BYTES: u64 = 64 * MIB;
const PROGRESS_WAL_BYTES: u64 = 128 * MIB;
const INTAKE_DISK_FLOOR_BYTES: u64 = 128 * MIB;
const PROGRESS_DISK_FLOOR_BYTES: u64 = 16 * MIB;

/// Bind this policy descriptor into the owning store's financing profile.
pub fn write_capacity_policy_descriptor() -> &'static str {
    "chio.sqlite.managed-write-capacity.v1; per_file_intake_WAL64MiB; per_file_owed_WAL128MiB; same_filesystem_intake_disk_floor128MiB; same_filesystem_progress_disk_floor16MiB; checked_current_and_all_remaining_debt"
}

/// Physical byte amounts. Constructing an amount does not reserve capacity.
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

/// The owner selects the stage from authenticated intake or prepaid purpose.
/// Selecting a stage supplies no authority to consume a finishing reserve.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqliteWriteCapacityStageData {
    Intake,
    OwedProgress,
}

/// Check the current write together with all remaining physical debt.
///
/// WAL limits apply only to this file. Other files must be independently
/// authenticated and reside on the same volume; their disk debts are summed.
/// The current write must be priced separately from the remaining debt.
/// Available disk must cover the complete sum plus the selected stage's floor.
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
mod tests;
