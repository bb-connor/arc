use super::*;

const PAGE_KEYS: u32 = 128;
const KINDS: [ResponseEffectKind; 5] = [
    ResponseEffectKind::SuspendSession,
    ResponseEffectKind::RestrictEgress,
    ResponseEffectKind::ThrottleSession,
    ResponseEffectKind::SuspendCapabilitySet,
    ResponseEffectKind::FreezeIssuance,
];

fn visit_commands(
    connection: &Connection,
    kind: ResponseEffectKind,
    mut visit: impl FnMut(VerifiedCommand) -> PortResult<()>,
) -> PortResult<()> {
    let table = commands::journal_table(kind)?;
    let mut after = (String::new(), String::new());
    loop {
        let mut statement = connection.prepare(&format!(
            "SELECT tenant_id, idempotency_key FROM {table} WHERE (tenant_id, idempotency_key) > (?1, ?2) \
             ORDER BY tenant_id, idempotency_key LIMIT ?3",
        )).map_err(sqlite_error)?;
        let keys = statement
            .query_map(params![after.0, after.1, PAGE_KEYS], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        drop(statement);
        if keys.is_empty() {
            return Ok(());
        }
        for (tenant, key) in &keys {
            TenantId::new(tenant).map_err(|_| PortError::integrity_failure())?;
            RecordId::new(key).map_err(|_| PortError::integrity_failure())?;
            match commands::load(connection, kind, tenant, key)? {
                Some(command) => visit(command)?,
                None if kind == ResponseEffectKind::FreezeIssuance => {}
                None => return Err(PortError::integrity_failure()),
            }
        }
        after = keys
            .last()
            .cloned()
            .ok_or_else(PortError::integrity_failure)?;
    }
}

fn no_active_contribution(connection: &Connection, marker: &Marker) -> PortResult<()> {
    let table = match marker.effect_kind {
        ResponseEffectKind::SuspendSession => "security_effect_contributions",
        ResponseEffectKind::RestrictEgress => "security_egress_restriction_effects",
        ResponseEffectKind::ThrottleSession => "security_session_throttle_effects",
        ResponseEffectKind::SuspendCapabilitySet => "security_capability_set_suspension_effects",
        ResponseEffectKind::FreezeIssuance => "security_issuance_freeze_effects",
        ResponseEffectKind::EscalateAlert => return Err(PortError::integrity_failure()),
    };
    let active: bool = connection
        .query_row(
            &format!(
                "SELECT EXISTS(SELECT 1 FROM {table} WHERE tenant_id = ?1 AND effect_id = ?2)"
            ),
            params![marker.tenant_id.as_str(), marker.effect_id.as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if active {
        Err(PortError::integrity_failure())
    } else {
        Ok(())
    }
}

pub(super) fn backfill(connection: &Connection) -> PortResult<()> {
    for kind in KINDS {
        visit_commands(connection, kind, |command| {
            if command.request.operation == EffectOperation::Remove {
                let marker = Marker::from_command(&command)?;
                no_active_contribution(connection, &marker)?;
                persist_first(connection, &marker)?;
            }
            Ok(())
        })?;
    }
    verify_coverage(connection)
}

pub(super) fn verify_kind_coverage(
    connection: &Connection,
    kind: ResponseEffectKind,
) -> PortResult<()> {
    visit_commands(connection, kind, |command| {
        if command.request.operation == EffectOperation::Remove {
            let original = Marker::from_command(&command)?;
            let marker =
                verified_marker(connection, &original.tenant_id, kind, &original.effect_id)?
                    .ok_or_else(PortError::integrity_failure)?;
            if !marker.same_identity(&original) {
                return Err(PortError::integrity_failure());
            }
            no_active_contribution(connection, &marker)?;
        }
        Ok(())
    })?;
    let mut after = (String::new(), String::new());
    loop {
        let mut statement = connection.prepare(
            "SELECT tenant_id, effect_id FROM security_response_effect_finality \
             WHERE effect_kind = ?1 AND (tenant_id, effect_id) > (?2, ?3) ORDER BY tenant_id, effect_id LIMIT ?4",
        ).map_err(sqlite_error)?;
        let keys = statement
            .query_map(
                params![kind_name(kind)?, after.0, after.1, PAGE_KEYS],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        drop(statement);
        if keys.is_empty() {
            return Ok(());
        }
        for (tenant, effect) in &keys {
            let tenant = TenantId::new(tenant).map_err(|_| PortError::integrity_failure())?;
            let effect = EffectId::new(effect).map_err(|_| PortError::integrity_failure())?;
            let marker = verified_marker(connection, &tenant, kind, &effect)?
                .ok_or_else(PortError::integrity_failure)?;
            no_active_contribution(connection, &marker)?;
        }
        after = keys
            .last()
            .cloned()
            .ok_or_else(PortError::integrity_failure)?;
    }
}

pub(super) fn verify_coverage(connection: &Connection) -> PortResult<()> {
    for kind in KINDS {
        verify_kind_coverage(connection, kind)?;
    }
    let unknown: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM security_response_effect_finality \
         WHERE effect_kind NOT IN ('suspend_session', 'restrict_egress', 'throttle_session', 'suspend_capability_set', 'freeze_issuance'))",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if unknown {
        Err(PortError::integrity_failure())
    } else {
        Ok(())
    }
}
