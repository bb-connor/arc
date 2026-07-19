fn entry_from_raw(raw: EntryRaw) -> Result<AdmissionLogEntry, AdmissionConsensusError> {
    Ok(AdmissionLogEntry {
        index: nonnegative_u64(raw.0, "log index")?,
        leader_epoch: nonnegative_u64(raw.1, "leader epoch")?,
        operation_id: raw.2,
        command_kind: command_kind_from_label(&raw.3)?,
        canonical_command: raw.4,
        command_digest: raw.5,
    })
}

fn load_all_entries(
    connection: &Connection,
) -> Result<Vec<AdmissionLogEntry>, AdmissionConsensusError> {
    let mut statement = connection.prepare(
        r#"
        SELECT log_index, leader_epoch, operation_id, command_kind,
               canonical_command, command_digest
        FROM admission_consensus_log
        ORDER BY log_index ASC
        "#,
    )?;
    let rows = statement.query_map([], read_entry_raw)?;
    let mut entries = Vec::new();
    for row in rows {
        entries.push(entry_from_raw(row?)?);
    }
    Ok(entries)
}

fn insert_commit_proof(
    transaction: &Transaction<'_>,
    proof: &AdmissionCommitProof,
) -> Result<(), AdmissionConsensusError> {
    let witnesses = canonical_json_bytes(&proof.witness_urls).map_err(|error| {
        AdmissionConsensusError::Protocol(format!(
            "admission witness canonicalization failed: {error}"
        ))
    })?;
    let witnesses = String::from_utf8(witnesses).map_err(|_| {
        AdmissionConsensusError::Protocol("admission witness JSON was not UTF-8".to_string())
    })?;
    if let Some(existing) = load_commit_proof(transaction, proof.index)? {
        if existing != *proof {
            return Err(AdmissionConsensusError::Protocol(
                "admission commit proof conflicts with persisted evidence".to_string(),
            ));
        }
        return Ok(());
    }
    transaction.execute(
        r#"
        INSERT INTO admission_consensus_commits (
            log_index, leader_epoch, current_term_commit_index, leader_id,
            membership_digest, quorum_size, witness_urls_json, protocol_version
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
        params![
            sqlite_u64(proof.index)?,
            sqlite_u64(proof.leader_epoch)?,
            sqlite_u64(proof.current_term_commit_index)?,
            proof.leader_id,
            proof.membership_digest,
            sqlite_usize(proof.quorum_size)?,
            witnesses,
            proof.protocol_version,
        ],
    )?;
    Ok(())
}

fn load_commit_proof(
    connection: &Connection,
    index: u64,
) -> Result<Option<AdmissionCommitProof>, AdmissionConsensusError> {
    let raw = connection
        .query_row(
            r#"
            SELECT log_index, leader_epoch, current_term_commit_index, leader_id,
                   membership_digest, quorum_size, witness_urls_json, protocol_version
            FROM admission_consensus_commits
            WHERE log_index = ?1
            "#,
            params![sqlite_u64(index)?],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        )
        .optional()?;
    raw.map(|raw| {
        let witness_urls = serde_json::from_str(&raw.6).map_err(|error| {
            AdmissionConsensusError::Protocol(format!(
                "persisted admission witnesses are invalid: {error}"
            ))
        })?;
        Ok(AdmissionCommitProof {
            protocol_version: raw.7,
            membership_digest: raw.4,
            index: nonnegative_u64(raw.0, "commit index")?,
            leader_epoch: nonnegative_u64(raw.1, "commit leader epoch")?,
            current_term_commit_index: nonnegative_u64(raw.2, "current-term commit index")?,
            leader_id: raw.3,
            quorum_size: nonnegative_usize(raw.5, "quorum size")?,
            witness_urls,
        })
    })
    .transpose()
}

fn load_commit_proofs(
    connection: &Connection,
) -> Result<Vec<AdmissionCommitProof>, AdmissionConsensusError> {
    let meta = load_meta(connection)?;
    (1..=meta.commit_index)
        .map(|index| {
            load_commit_proof(connection, index)?.ok_or_else(|| {
                AdmissionConsensusError::Protocol(format!(
                    "admission commit proof {index} is missing"
                ))
            })
        })
        .collect()
}

fn load_result(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<AdmissionConsensusResult>, AdmissionConsensusError> {
    let raw = connection
        .query_row(
            r#"
            SELECT operation_id, log_index, response_json, response_digest,
                   security_projection_digest
            FROM admission_consensus_results
            WHERE operation_id = ?1
            "#,
            params![operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    raw.map(|raw| {
        Ok(AdmissionConsensusResult {
            operation_id: raw.0,
            log_index: nonnegative_u64(raw.1, "result log index")?,
            response_json: raw.2,
            response_digest: raw.3,
            security_projection_digest: raw.4,
        })
    })
    .transpose()
}

fn load_results(
    connection: &Connection,
) -> Result<Vec<AdmissionConsensusResult>, AdmissionConsensusError> {
    let mut statement = connection.prepare(
        r#"
        SELECT operation_id, log_index, response_json, response_digest,
               security_projection_digest
        FROM admission_consensus_results
        ORDER BY log_index ASC
        "#,
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    })?;
    let mut results = Vec::new();
    for row in rows {
        let raw = row?;
        results.push(AdmissionConsensusResult {
            operation_id: raw.0,
            log_index: nonnegative_u64(raw.1, "result log index")?,
            response_json: raw.2,
            response_digest: raw.3,
            security_projection_digest: raw.4,
        });
    }
    Ok(results)
}

fn command_kind_label(kind: AdmissionCommandKind) -> &'static str {
    match kind {
        AdmissionCommandKind::LeadershipBarrier => "leadership_barrier",
        AdmissionCommandKind::IncrementInvocation => "increment_invocation",
        AdmissionCommandKind::CompositeAuthorize => "composite_authorize",
        AdmissionCommandKind::CaptureInvocations => "capture_invocations",
        AdmissionCommandKind::ReverseExposure => "reverse_exposure",
        AdmissionCommandKind::ReleaseExposure => "release_exposure",
        AdmissionCommandKind::ReconcileSpend => "reconcile_spend",
        AdmissionCommandKind::CaptureExposure => "capture_exposure",
        AdmissionCommandKind::Revoke => "revoke",
        AdmissionCommandKind::CombinedCapture => "combined_capture",
    }
}

fn command_kind_from_label(value: &str) -> Result<AdmissionCommandKind, AdmissionConsensusError> {
    match value {
        "leadership_barrier" => Ok(AdmissionCommandKind::LeadershipBarrier),
        "increment_invocation" => Ok(AdmissionCommandKind::IncrementInvocation),
        "composite_authorize" => Ok(AdmissionCommandKind::CompositeAuthorize),
        "capture_invocations" => Ok(AdmissionCommandKind::CaptureInvocations),
        "reverse_exposure" => Ok(AdmissionCommandKind::ReverseExposure),
        "release_exposure" => Ok(AdmissionCommandKind::ReleaseExposure),
        "reconcile_spend" => Ok(AdmissionCommandKind::ReconcileSpend),
        "capture_exposure" => Ok(AdmissionCommandKind::CaptureExposure),
        "revoke" => Ok(AdmissionCommandKind::Revoke),
        "combined_capture" => Ok(AdmissionCommandKind::CombinedCapture),
        _ => Err(AdmissionConsensusError::Protocol(format!(
            "unknown admission command kind `{value}`"
        ))),
    }
}

fn quota_profile_from_label(value: &str) -> Result<BudgetQuotaProfileView, String> {
    match value {
        "chio.grant-invocation.v1" => Ok(BudgetQuotaProfileView::GrantInvocation),
        "chio.aggregate-capability-invocation.v1" => {
            Ok(BudgetQuotaProfileView::AggregateCapabilityInvocation)
        }
        "chio.aggregate-family-invocation.v1" => {
            Ok(BudgetQuotaProfileView::AggregateFamilyInvocation)
        }
        "chio.broker-capability-execution.v1" => {
            Ok(BudgetQuotaProfileView::SupplementalBrokerExecution)
        }
        _ => Err(format!(
            "unknown persisted invocation quota profile `{value}`"
        )),
    }
}

fn sqlite_u64(value: u64) -> Result<i64, AdmissionConsensusError> {
    i64::try_from(value).map_err(|_| {
        AdmissionConsensusError::Protocol("admission integer exceeds SQLite range".to_string())
    })
}

fn sqlite_usize(value: usize) -> Result<i64, AdmissionConsensusError> {
    i64::try_from(value).map_err(|_| {
        AdmissionConsensusError::Protocol("admission count exceeds SQLite range".to_string())
    })
}

fn nonnegative_u64(value: i64, label: &str) -> Result<u64, AdmissionConsensusError> {
    u64::try_from(value)
        .map_err(|_| AdmissionConsensusError::Protocol(format!("persisted {label} is negative")))
}

fn nonnegative_usize(value: i64, label: &str) -> Result<usize, AdmissionConsensusError> {
    usize::try_from(value).map_err(|_| {
        AdmissionConsensusError::Protocol(format!("persisted {label} is negative or too large"))
    })
}

fn checked_successor(value: u64, label: &str) -> Result<u64, AdmissionConsensusError> {
    value
        .checked_add(1)
        .ok_or_else(|| AdmissionConsensusError::Protocol(format!("{label} overflow")))
}

fn checked_predecessor(value: u64, label: &str) -> Result<u64, AdmissionConsensusError> {
    value
        .checked_sub(1)
        .ok_or_else(|| AdmissionConsensusError::Protocol(format!("{label} underflow")))
}

fn one_based_offset(offset: usize, label: &str) -> Result<u64, AdmissionConsensusError> {
    let offset = u64::try_from(offset)
        .map_err(|_| AdmissionConsensusError::Protocol(format!("{label} exceeds u64")))?;
    checked_successor(offset, label)
}

fn usize_index(value: u64, label: &str) -> Result<usize, AdmissionConsensusError> {
    usize::try_from(value)
        .map_err(|_| AdmissionConsensusError::Protocol(format!("{label} exceeds usize")))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/trust_control/cluster/admission_consensus_parts/nested_01.inc"));
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/trust_control/cluster/admission_consensus_parts/nested_02.inc"));
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/trust_control/cluster/admission_consensus_parts/nested_03.inc"));
}
