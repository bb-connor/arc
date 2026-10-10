use chio_kernel::{
    ActiveResponseCommittedDispatch, ActiveResponseExecutorAuthorityIdentity,
    ActiveResponseExecutorError,
};
use chio_quarantine::{decode_response_record, validate_response_dispatch_authorization};
use chio_security_types::ports::{
    RecordId, ResponseDispatchKey, ResponseDispatchLoadOutcome, ResponseDispatchStore, TenantId,
};

pub(super) fn load_committed_active_response_dispatch<S: ResponseDispatchStore + ?Sized>(
    store: &S,
    identity: &ActiveResponseExecutorAuthorityIdentity,
    tenant_id: &TenantId,
    dispatch_id: &RecordId,
) -> Result<Option<ActiveResponseCommittedDispatch>, ActiveResponseExecutorError> {
    let key = ResponseDispatchKey {
        tenant_id: tenant_id.clone(),
        dispatch_id: dispatch_id.clone(),
    };
    let record = match store.load_dispatch(&key) {
        Ok(ResponseDispatchLoadOutcome::Found(record)) => *record,
        Ok(ResponseDispatchLoadOutcome::Missing) => return Ok(None),
        Err(error) => {
            return Err(ActiveResponseExecutorError::NotReady(format!(
                "committed active-response dispatch readback failed: {error}"
            )))
        }
    };
    let snapshot = decode_response_record(&record.response_plan).map_err(|error| {
        ActiveResponseExecutorError::OutcomeUnknown(format!(
            "committed active-response response record is invalid: {error}"
        ))
    })?;
    validate_response_dispatch_authorization(&record.response_plan, &record.authorization)
        .map_err(|error| {
            ActiveResponseExecutorError::OutcomeUnknown(format!(
                "committed active-response dispatch authorization is invalid: {error}"
            ))
        })?;
    if record.authorization.body.key != key
        || record.authorization.body.action_id != snapshot.plan.action_id
        || record.authorization.body.executor_authority_id.as_str() != identity.authority_id()
        || record.authorization.body.executor_authority_generation != identity.generation()
        || record.response_plan.tenant_id != *tenant_id
        || record.response_plan.action_id != snapshot.plan.action_id
        || record.initial_work.tenant_id != *tenant_id
        || record.initial_work.action_id != snapshot.plan.action_id
        || snapshot.plan.tenant_id != *tenant_id
        || snapshot.execution_dispatch.as_ref().is_none_or(|binding| {
            binding.tenant_id != *tenant_id
                || binding.dispatch_id != *dispatch_id
                || binding.action_id != snapshot.plan.action_id
        })
    {
        return Err(ActiveResponseExecutorError::OutcomeUnknown(
            "committed active-response dispatch readback is not exactly tenant-bound".to_string(),
        ));
    }
    Ok(Some(ActiveResponseCommittedDispatch::new(
        snapshot.plan,
        record.authorization,
        record.response_plan,
    )))
}

#[cfg(test)]
mod tests {
    use super::super::tests::{require_success, Harness};
    use super::super::{ActiveResponseExecutorAuthority, ActiveResponseExecutorError};
    use chio_security_types::ports::TenantId;
    use rusqlite::{params, Connection};

    #[test]
    fn production_readback_is_exact_tenant_scoped_and_tamper_evident() {
        let harness = Harness::new();
        let request = harness.automatic_request();
        require_success(
            harness.executor.execute_source(&request),
            "commit production readback fixture",
        );

        let committed = require_success(
            harness.executor.load_committed_active_response_dispatch(
                &request.response_plan.tenant_id,
                &request.dispatch_id,
            ),
            "load exact committed production dispatch",
        )
        .unwrap_or_else(|| panic!("exact committed production dispatch is missing"));
        assert_eq!(committed.response_plan(), &request.response_plan);
        assert_eq!(
            committed.authorization().body.key.dispatch_id,
            request.dispatch_id
        );

        let other_tenant = TenantId::new("tenant-readback-other")
            .unwrap_or_else(|error| panic!("other readback tenant: {error}"));
        assert!(require_success(
            harness
                .executor
                .load_committed_active_response_dispatch(&other_tenant, &request.dispatch_id,),
            "tenant-scoped committed dispatch miss",
        )
        .is_none());

        let connection = Connection::open(&harness.database_path)
            .unwrap_or_else(|error| panic!("open readback tamper connection: {error}"));
        let changed = connection
            .execute(
                r#"
                UPDATE security_response_dispatches
                SET authorization_body_hash = zeroblob(32)
                WHERE tenant_id = ?1 AND dispatch_id = ?2
                "#,
                params![
                    request.response_plan.tenant_id.as_str(),
                    request.dispatch_id.as_str()
                ],
            )
            .unwrap_or_else(|error| panic!("tamper committed readback hash: {error}"));
        assert_eq!(changed, 1);
        assert!(matches!(
            harness.executor.load_committed_active_response_dispatch(
                &request.response_plan.tenant_id,
                &request.dispatch_id,
            ),
            Err(ActiveResponseExecutorError::NotReady(_)
                | ActiveResponseExecutorError::OutcomeUnknown(_))
        ));
    }
}
