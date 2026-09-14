//! Lifecycle transitions are scoped data mutations, not serving activation.

use super::*;

pub(super) fn verify(connection: ScopedReader<'_>) -> PortResult<()> {
    let lifecycle: (i64, String, i64, i64, i64) = connection
        .query_row(sql::LIFECYCLE_SCHEMA, &[], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .map_err(sqlite_error)?;
    if lifecycle.0 != 2
        || lifecycle.1 != DECLASSIFICATION_READINESS_CURSOR
        || !matches!(lifecycle.2, 0 | 1)
        || !matches!(lifecycle.3, 0 | 1)
        || lifecycle.4 != 0
        || (lifecycle.2 == 1 && lifecycle.3 == 1)
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

impl ScopedMutation<'_> {
    pub(super) fn begin_declassification_reconciliation(&self) -> PortResult<()> {
        let connection = self;
        let updated = connection
            .execute(sql::BEGIN_RECONCILIATION, &[])
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        Ok(())
    }

    pub(super) fn end_declassification_reconciliation(&self) -> PortResult<()> {
        let connection = self;
        let updated = connection
            .execute(sql::END_RECONCILIATION, &[])
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        Ok(())
    }

    pub(super) fn seal_declassification_live_dispatch(&self) -> PortResult<()> {
        let connection = self;
        let lifecycle: (i64, i64, i64) = connection
            .query_row(sql::STATUS, &[], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(sqlite_error)?;
        if lifecycle == (0, 1, 0) {
            return Ok(());
        }
        if lifecycle != (0, 0, 0) {
            return Err(PortError::conflict());
        }
        let updated = connection
            .execute(sql::SEAL_DISPATCH, &[])
            .map_err(sqlite_error)?;
        if updated != 1 {
            return Err(PortError::conflict());
        }
        Ok(())
    }

    pub(super) fn reset_declassification_lifecycle(&self) -> PortResult<()> {
        if self
            .execute(sql::RESET_LIFECYCLE, &[])
            .map_err(sqlite_error)?
            != 1
        {
            return Err(PortError::integrity_failure());
        }
        Ok(())
    }
}
