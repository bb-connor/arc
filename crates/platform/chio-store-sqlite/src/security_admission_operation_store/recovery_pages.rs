//! Legacy-family recovery inventory bodies with bounded page ownership.
use super::*;

impl SqliteAdmissionOperationStore {
    pub(super) fn recovery_candidates_legacy(
        &self,
        kind: AdmissionOperationKind,
        limit: usize,
    ) -> Result<Vec<AdmissionOperation>, AdmissionOperationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).map_err(|_| {
            AdmissionOperationError::Overflow(
                "prioritized admission recovery limit exceeds i64".to_string(),
            )
        })?;
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                r#"
                SELECT operation.operation_id
                FROM admission_operations AS operation
                LEFT JOIN admission_cleanup_actions AS handoff
                  ON handoff.operation_id = operation.operation_id
                 AND handoff.kind = 'caller_reservation_handoff'
                WHERE operation.kind = ?1
                  AND operation.state NOT IN (
                    'completed',
                    'compensated_before_dispatch',
                    'outcome_unknown_after_dispatch'
                  )
                ORDER BY CASE
                    WHEN operation.state != 'caller_reserved' THEN 0
                    WHEN handoff.state IS NULL OR handoff.state != 'completed' THEN 1
                    ELSE 2
                  END ASC,
                  operation.updated_at ASC,
                  operation.operation_id ASC
                LIMIT ?2
                "#,
            )
            .map_err(sqlite_error)?;
        let operation_ids = statement
            .query_map(params![kind.as_str(), limit], |row| row.get::<_, String>(0))
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        operation_ids
            .into_iter()
            .map(|operation_id| {
                load_operation(&connection, &operation_id)?.ok_or_else(|| {
                    AdmissionOperationError::Unavailable(
                        "admission operation disappeared during prioritized recovery inventory"
                            .to_string(),
                    )
                })
            })
            .collect()
    }

    pub(super) fn recovery_candidates_page(
        &self,
        kind: AdmissionOperationKind,
        after_operation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AdmissionOperation>, AdmissionOperationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).map_err(|_| {
            AdmissionOperationError::Overflow("recovery page limit exceeds i64".into())
        })?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT operation_id FROM admission_operations WHERE kind = ?1
             AND (?2 IS NULL OR operation_id > ?2)
             AND state NOT IN ('completed', 'compensated_before_dispatch', 'outcome_unknown_after_dispatch')
             ORDER BY operation_id ASC LIMIT ?3",
        ).map_err(sqlite_error)?;
        let ids = statement
            .query_map(params![kind.as_str(), after_operation_id, limit], |row| {
                row.get::<_, String>(0)
            })
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        ids.into_iter()
            .map(|id| {
                load_operation(&connection, &id)?.ok_or_else(|| {
                    AdmissionOperationError::Unavailable(
                        "recovery page operation disappeared".into(),
                    )
                })
            })
            .collect()
    }

    pub(super) fn compensation_cleanup_page(
        &self,
        kind: Option<AdmissionOperationKind>,
        after_operation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>, AdmissionOperationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).map_err(|_| {
            AdmissionOperationError::Overflow("cleanup page limit exceeds i64".into())
        })?;
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT operation.operation_id FROM admission_operations AS operation
             WHERE operation.state IN ('compensation_pending', 'compensated_before_dispatch')
               AND (?1 IS NULL OR operation.kind = ?1)
               AND (?2 IS NULL OR operation.operation_id > ?2)
               AND EXISTS(SELECT 1 FROM admission_cleanup_actions AS cleanup
                 WHERE cleanup.operation_id = operation.operation_id AND cleanup.state != 'completed'
                   AND cleanup.kind NOT IN ('caller_reservation_handoff_intent', 'caller_reservation_handoff'))
             ORDER BY operation.operation_id ASC LIMIT ?3",
        ).map_err(sqlite_error)?;
        let rows = statement
            .query_map(
                params![
                    kind.map(AdmissionOperationKind::as_str),
                    after_operation_id,
                    limit
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
    }

    pub(super) fn pending_cleanup_action_page(
        &self,
        operation_kind: AdmissionOperationKind,
        action_kind: AdmissionCleanupActionKind,
        after_operation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>, AdmissionOperationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).map_err(|_| {
            AdmissionOperationError::Overflow("pending journal page limit exceeds i64".into())
        })?;
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                r#"
                SELECT operation.operation_id
                FROM admission_operations AS operation
                WHERE operation.kind = ?1
                  AND (?3 IS NULL OR operation.operation_id > ?3)
                  AND NOT (?2 = 'terminal_receipt' AND operation.state = 'compensation_pending')
                  AND EXISTS (
                      SELECT 1
                      FROM admission_cleanup_actions AS cleanup
                      WHERE cleanup.operation_id = operation.operation_id
                        AND cleanup.kind = ?2
                        AND cleanup.state != 'completed'
                  )
                ORDER BY operation.operation_id ASC
                LIMIT ?4
                "#,
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(
                params![
                    operation_kind.as_str(),
                    action_kind.as_str(),
                    after_operation_id,
                    limit
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(sqlite_error)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(sqlite_error)
    }
}
