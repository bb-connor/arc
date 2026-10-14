//! Free space and uncheckpointed WAL bound physical recovery pressure.
//! Retained native history and checkpointed WAL capacity are not intake quotas.
//! Logical participants independently bound their owned records and transitions.
use super::*;

const MIB: u64 = 1024 * 1024;

mod physical_liability;
#[cfg(test)]
pub(in crate::admission_operation_store) use physical_liability::price_protected_command_liability;
#[cfg(test)]
pub(in crate::admission_operation_store) use physical_liability::price_raw_custody_liability;
pub(in crate::admission_operation_store) use physical_liability::{
    physical_command_write_profile, price_native_tool_outcome_phases,
    price_protected_command_with_row_limits, raw_custody_price_algorithm_fingerprint,
    tool_outcome_price_algorithm_fingerprint, PhysicalLiabilityData, ProtectedCommandLiabilityPlan,
};

#[cfg(test)]
mod pressure_tests;

#[derive(Clone, Copy)]
struct PhysicalUsage {
    wal: u64,
    available: u64,
}
fn admits(usage: PhysicalUsage, intake: bool) -> bool {
    let (wal, reserve) = if intake {
        (64 * MIB, 128 * MIB)
    } else {
        (128 * MIB, 16 * MIB)
    };
    usage.wal < wal && usage.available >= reserve
}

pub(super) fn check(
    connection: &Connection,
    intake: bool,
) -> Result<(), AdmissionOperationStoreError> {
    check_usage(connection, intake, true, None)
}

/// Native capture observes pressure inside its writer without checkpointing.
pub(in crate::admission_operation_store) fn check_committing(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    check_usage(connection, false, false, None)
}

/// New participant records preserve physical capacity owed to existing work.
pub(in crate::admission_operation_store) fn check_intake_committing(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    check_usage(connection, true, false, None)
}

/// One prepaid native finishing purpose spends its own priced amount after
/// its account transition already removed it from the bank. Every other
/// outstanding reserve on this file and its volume stays untouched.
pub(in crate::admission_operation_store) fn check_funded_committing(
    connection: &Connection,
    spent: &PhysicalLiabilityData,
) -> Result<(), AdmissionOperationStoreError> {
    check_usage(connection, false, false, Some(spent))
}

fn check_usage(
    connection: &Connection,
    intake: bool,
    checkpoint: bool,
    spent: Option<&PhysicalLiabilityData>,
) -> Result<(), AdmissionOperationStoreError> {
    let usage = physical_usage(connection, checkpoint)?;
    if !admits(usage, intake) {
        return Err(invariant("recovery disk headroom exhausted"));
    }
    preserve_native_finishing_debt(connection, usage, intake, spent)
}

/// Apply the managed write-capacity policy with every outstanding native
/// finishing debt: this file's own debt and other registered files on the
/// same volume. An unopened bank owes nothing and leaves the floors above.
fn preserve_native_finishing_debt(
    connection: &Connection,
    usage: PhysicalUsage,
    intake: bool,
    spent: Option<&PhysicalLiabilityData>,
) -> Result<(), AdmissionOperationStoreError> {
    use chio_sqlite_file_identity::{
        require_physical_write_capacity, SqlitePhysicalDebtAmountData, SqliteWriteCapacityStageData,
    };
    let Some(debt) = super::storage::native_finishing_debt_for_file(connection)? else {
        return Ok(());
    };
    let amount = |liability: &PhysicalLiabilityData| {
        SqlitePhysicalDebtAmountData::checked(liability.wal_bytes(), liability.disk_bytes())
            .map_err(invariant)
    };
    let others = debt
        .other_files
        .iter()
        .map(amount)
        .collect::<Result<Vec<_>, _>>()?;
    let current = match spent {
        Some(liability) => amount(liability)?,
        None => SqlitePhysicalDebtAmountData::checked(0, 0).map_err(invariant)?,
    };
    require_physical_write_capacity(
        if intake {
            SqliteWriteCapacityStageData::Intake
        } else {
            SqliteWriteCapacityStageData::OwedProgress
        },
        usage.wal,
        usage.available,
        &amount(&debt.this_file)?,
        &others,
        &current,
    )
    .map_err(|error| {
        #[cfg(feature = "admission-test-support")]
        eprintln!(
            "native capacity refusal intake={intake} pending_wal={} owed_wal={} current_wal={} available_disk={} owed_disk={} current_disk={} other_disk={:?}",
            usage.wal,
            debt.this_file.wal_bytes(),
            current.wal_bytes(),
            usage.available,
            debt.this_file.disk_bytes(),
            current.disk_bytes(),
            others.iter().map(|amount| amount.disk_bytes()).collect::<Vec<_>>(),
        );
        invariant(error)
    })
}

fn physical_usage(
    connection: &Connection,
    checkpoint: bool,
) -> Result<PhysicalUsage, AdmissionOperationStoreError> {
    connection
        .path()
        .ok_or_else(|| invariant("recovery requires a persistent authority"))?;
    let wal = wal_pressure(connection, checkpoint)?;
    // Capacity of the filesystem holding SQLite's actual open main file, not
    // whatever a path names after a rename.
    let available = chio_sqlite_file_identity::main_database_available_bytes(connection)
        .map_err(|_| invariant("recovery disk capacity is unavailable"))?;
    Ok(PhysicalUsage { wal, available })
}

/// Committed WAL frame pressure of `connection`'s main file. The observer is
/// read-only and never checkpoints, so another file's writer may call it at
/// its COMMIT boundary.
pub(crate) fn observed_wal_pressure(
    connection: &Connection,
) -> Result<u64, AdmissionOperationStoreError> {
    wal_pressure(connection, false)
}

fn wal_pressure(
    connection: &Connection,
    checkpoint: bool,
) -> Result<u64, AdmissionOperationStoreError> {
    // SQLite refuses even NOOP checkpoints on a connection in a transaction.
    // A separate read-only observer reports committed frame pressure without
    // touching the writer, checkpointing pages or waiting on a busy owner.
    let may_checkpoint = checkpoint && connection.is_autocommit();
    let observer;
    let connection = if connection.is_autocommit() {
        connection
    } else {
        observer = Connection::open_with_flags(
            connection
                .path()
                .ok_or_else(|| invariant("recovery requires a persistent authority"))?,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(sqlite_error)?;
        observer
            .busy_timeout(std::time::Duration::ZERO)
            .map_err(sqlite_error)?;
        &observer
    };
    let mode: String = connection
        .query_row("PRAGMA main.journal_mode", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    if mode != "wal" {
        return Err(invariant("recovery WAL profile is unsupported"));
    }
    let mut bytes = wal_backlog(connection, "PRAGMA main.wal_checkpoint(NOOP)")?;
    if may_checkpoint && bytes >= 32 * MIB {
        // PASSIVE does not invoke the busy handler or wait for pinned readers.
        // Admission uses the remaining frame count after this attempt, rather
        // than the WAL allocation's historical high-water length.
        bytes = wal_backlog(connection, "PRAGMA main.wal_checkpoint(PASSIVE)")?;
    }
    Ok(bytes)
}

fn wal_backlog(
    connection: &Connection,
    statement: &str,
) -> Result<u64, AdmissionOperationStoreError> {
    let (busy, log, checkpointed): (i64, i64, i64) = connection
        .query_row(statement, [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(sqlite_error)?;
    if !matches!(busy, 0 | 1) {
        return Err(invariant("recovery WAL observation refused"));
    }
    if (log, checkpointed) == (-1, -1) {
        if busy != 0 {
            return Err(invariant("recovery WAL observation is unavailable"));
        }
        // An unused WAL has no frames. wal_pressure independently requires WAL
        // mode; actual observation errors cannot take this branch.
        return Ok(0);
    }
    let frames = log
        .checked_sub(checkpointed)
        .filter(|_| log >= 0 && checkpointed >= 0)
        .and_then(|frames| u64::try_from(frames).ok())
        .ok_or_else(|| invariant("recovery WAL observation refused"))?;
    if frames == 0 {
        return Ok(0);
    }
    let page_size: u32 = connection
        .query_row("PRAGMA main.page_size", [], |row| row.get(0))
        .map_err(sqlite_error)?;
    if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
        return Err(invariant("recovery WAL page size refused"));
    }
    // WAL frames have a 24-byte header; the WAL itself has a 32-byte header.
    frames
        .checked_mul(u64::from(page_size) + 24)
        .and_then(|bytes| bytes.checked_add(32))
        .ok_or_else(|| invariant("recovery WAL capacity refused"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_progress_keeps_physical_settlement_headroom() -> Result<(), Box<dyn std::error::Error>>
    {
        let usage = PhysicalUsage {
            wal: 0,
            available: 256 * MIB,
        };
        let reserved_usage = [
            (
                "WAL",
                PhysicalUsage {
                    wal: 64 * MIB,
                    ..usage
                },
            ),
            (
                "free space",
                PhysicalUsage {
                    available: 128 * MIB - 1,
                    ..usage
                },
            ),
        ];
        let workflow = WorkflowId::new("workflow:physical-headroom")?;
        let revision = SafeInteger::new(1)?;
        for permission in [
            RecoveryPermission::Resume,
            RecoveryPermission::Inspect,
            RecoveryPermission::Settle,
        ] {
            let intake = super::super::requires_intake_headroom(permission);
            assert!(!intake);
            for (resource, usage) in reserved_usage {
                assert!(
                    admits(usage, intake),
                    "native {permission:?} progress exhausted its physical {resource} reserve"
                );
            }
            assert!(!admits(
                PhysicalUsage {
                    wal: 128 * MIB,
                    ..usage
                },
                intake
            ));
            assert!(!admits(
                PhysicalUsage {
                    available: 16 * MIB - 1,
                    ..usage
                },
                intake
            ));
        }
        for permission in [
            RecoveryPermission::Create,
            RecoveryPermission::Select,
            RecoveryPermission::Approve,
            RecoveryPermission::Report,
            RecoveryPermission::Maintain,
        ] {
            for (_, usage) in reserved_usage {
                assert!(!admits(
                    usage,
                    super::super::requires_intake_headroom(permission)
                ));
            }
        }
        assert!(!super::super::requires_command_intake_headroom(
            &RecoveryCommandBodyV1::InspectWorkflow {
                workflow_id: workflow.clone(),
            }
        ));
        for body in [
            RecoveryCommandBodyV1::CreateWorkflow {
                creation_key: CreationKey::new("physical-intake")?,
                template: RecoveryTemplateV1::SupportTicketPublicIssue,
                request_seed: ProtectedText::new("{}")?,
            },
            RecoveryCommandBodyV1::SelectOffer {
                workflow_id: workflow.clone(),
                expected_revision: revision,
                offer_id: OfferId::new("physical-intake")?,
            },
            RecoveryCommandBodyV1::SubmitApproval {
                workflow_id: workflow.clone(),
                expected_revision: revision,
                approval: ProtectedText::new("{}")?,
            },
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: workflow.clone(),
                expected_revision: revision,
            },
            RecoveryCommandBodyV1::CancelWorkflow {
                workflow_id: workflow.clone(),
                expected_revision: revision,
            },
            RecoveryCommandBodyV1::ReportDecision {
                workflow_id: workflow,
                expected_revision: revision,
                decision: RecoveryReportedDecision::Accepted,
            },
        ] {
            assert!(super::super::requires_command_intake_headroom(&body));
            for (_, usage) in reserved_usage {
                assert!(!admits(
                    usage,
                    super::super::requires_command_intake_headroom(&body)
                ));
            }
        }
        Ok(())
    }

    #[test]
    fn product_reports_keep_physical_intake_headroom() -> Result<(), Box<dyn std::error::Error>> {
        let report = RecoveryCommandBodyV1::ReportDecision {
            workflow_id: WorkflowId::new("workflow:physical-report-headroom")?,
            expected_revision: SafeInteger::new(1)?,
            decision: RecoveryReportedDecision::Accepted,
        };
        let usage = PhysicalUsage {
            wal: 0,
            available: 256 * MIB,
        };
        for usage in [
            PhysicalUsage {
                wal: 64 * MIB,
                ..usage
            },
            PhysicalUsage {
                available: 128 * MIB - 1,
                ..usage
            },
        ] {
            assert!(!admits(
                usage,
                super::super::requires_intake_headroom(RecoveryPermission::Report)
            ));
            assert!(!admits(
                usage,
                super::super::requires_command_intake_headroom(&report)
            ));
        }
        Ok(())
    }

    #[test]
    fn intake_stops_before_settlement_and_disk_exhaustion() {
        let usage = PhysicalUsage {
            wal: 64 * MIB,
            available: 127 * MIB,
        };
        assert!(!admits(usage, true));
        assert!(admits(usage, false));
        assert!(!admits(
            PhysicalUsage {
                available: 16 * MIB - 1,
                ..usage
            },
            false
        ));
        assert!(!admits(
            PhysicalUsage {
                wal: 128 * MIB,
                ..usage
            },
            false
        ));
    }

    #[cfg(unix)]
    #[test]
    fn recovery_pinned_reader_wal_headroom_refuses_intake_and_preserves_committed_data(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("wal.db");
        let writer = Connection::open(&path)?;
        writer.pragma_update(None, "journal_mode", "WAL")?;
        writer.pragma_update(None, "wal_autocheckpoint", 0)?;
        writer.execute_batch("CREATE TABLE retained(id INTEGER PRIMARY KEY, payload BLOB NOT NULL); INSERT INTO retained VALUES(1,X'010203'); PRAGMA wal_checkpoint(TRUNCATE);")?;
        let reader = Connection::open(&path)?;
        reader.execute_batch("BEGIN;")?;
        assert_eq!(
            reader.query_row("SELECT payload FROM retained WHERE id=1", [], |row| row
                .get::<_, Vec<u8>>(0))?,
            [1, 2, 3]
        );
        for _ in 0..17 {
            writer.execute(
                "INSERT INTO retained(payload) VALUES(zeroblob(4194304))",
                [],
            )?;
        }
        assert!(std::fs::metadata(format!("{}-wal", path.display()))?.len() >= 64 * MIB);
        assert!(check(&writer, true).is_err());
        check(&writer, false)?;
        assert_eq!(
            writer.query_row("SELECT count(*) FROM retained", [], |row| row
                .get::<_, i64>(0))?,
            18
        );
        assert_eq!(
            reader.query_row("SELECT count(*) FROM retained", [], |row| row
                .get::<_, i64>(0))?,
            1
        );
        reader.execute_batch("ROLLBACK;")?;
        check(&writer, true)?;
        assert_eq!(
            writer.query_row("SELECT payload FROM retained WHERE id=1", [], |row| row
                .get::<_, Vec<u8>>(0))?,
            [1, 2, 3]
        );
        Ok(())
    }
}
