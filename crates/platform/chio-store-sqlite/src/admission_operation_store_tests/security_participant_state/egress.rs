//! Actual SQLite custody transitions. These do not activate native dispatch.
use super::*;
use chio_kernel::{SecurityInvocationContext, ToolCallRequest};
use chio_security_types::ports::{
    CommittedEgressFence, Digest32, EgressFence, EgressFenceCommit, EgressFenceRequest, RecordId,
    RequestId,
};

#[path = "egress/authority.rs"]
mod authority;
#[path = "egress/compensation.rs"]
mod compensation;
#[path = "egress/crash.rs"]
mod crash;
#[path = "egress/faults.rs"]
mod faults;
#[path = "egress/integrity.rs"]
mod integrity;
#[path = "egress/lifecycle.rs"]
mod lifecycle;
#[path = "egress/migration.rs"]
mod migration;
#[path = "egress/portable.rs"]
mod portable;

struct Pending {
    operation: AdmissionOperationV1,
    lease: AdmissionRecoveryLease,
    initialized: SecurityParticipantStateInitialization,
    context: SecurityInvocationContext,
    request: ToolCallRequest,
    plan: EgressFenceRequest,
}

impl Pending {
    fn acquire(&self, fixture: &Fixture) -> AnchoredTestResult<EgressFence> {
        Ok(fixture.store.acquire_security_participant_egress(
            &self.operation,
            &self.lease,
            &self.initialized,
            &self.context,
            &self.request,
            &self.plan,
            now_ms(),
        )?)
    }

    fn commit(
        &self,
        fixture: &Fixture,
        commitment: &EgressFenceCommit,
    ) -> AnchoredTestResult<CommittedEgressFence> {
        Ok(fixture.store.commit_security_participant_egress(
            &self.operation,
            &self.lease,
            &self.initialized,
            &self.context,
            &self.request,
            commitment,
            now_ms(),
        )?)
    }
}

fn renew(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    lease: &AdmissionRecoveryLease,
) -> AnchoredTestResult<AdmissionRecoveryLease> {
    let now = now_ms();
    Ok(fixture.store.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        lease.untrusted_claim().claimant_id(),
        now,
        now + 120_000,
        &fixture.fence,
    )?)
}

fn pending(fixture: &Fixture, name: &str, generation: Option<u64>) -> AnchoredTestResult<Pending> {
    let initialized = fixture
        .store
        .load_security_participant_state(
            &identifier("authority", "source"),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("native initialization absent")?;
    let (mut context, join) = mutations::request(&format!("{name}-join"))?;
    if let Some(generation) = generation {
        context = SecurityInvocationContext::v1(
            context
                .as_v1()
                .clone()
                .with_flow_state_generation(generation),
        );
    }
    let (mut operation, mut lease) = mutations::setup(fixture, name, &context)?;
    lease = renew(fixture, &operation, &lease)?;
    let joined = fixture.store.join_security_participant_flow(
        &operation,
        &lease,
        &initialized,
        &context,
        &join,
        now_ms(),
    )?;
    context = SecurityInvocationContext::v1(
        context
            .as_v1()
            .clone()
            .with_flow_state_generation(joined.context_generation),
    );
    // State-machine custody fixture, not evidence of physical budget settlement.
    // Budget tests separately exercise joint authorization and capture ports.
    for (state, attachments) in [
        (
            AdmissionOperationState::BudgetAuthorized,
            vec![AdmissionAttachment::BudgetHoldId(identifier(
                "hold",
                &format!("{name}-hold"),
            ))],
        ),
        (AdmissionOperationState::ReadyToDispatch, vec![]),
        (AdmissionOperationState::CapturePending, vec![]),
    ] {
        operation = fixture
            .store
            .compare_and_swap(
                &command(&operation, lease, attachments, state, None),
                now_ms(),
            )?
            .into_operation();
        lease = fixture.store.claim_recovery(
            operation.binding().operation_id(),
            operation.version(),
            &identifier("claimant", name),
            now_ms(),
            now_ms() + 120_000,
            &fixture.fence,
        )?;
    }
    let (_, retained) = fixture
        .store
        .load_retained_tool_request(operation.binding().operation_id(), &fixture.fence, now_ms())?
        .ok_or("retained request absent")?;
    let request = retained.request_for_revalidation().clone();
    let hash: [u8; 32] = hex::decode(operation.binding().action_parameter_hash().as_str())?
        .try_into()
        .map_err(|_| "action digest width")?;
    let plan = EgressFenceRequest {
        key: join.key,
        request_id: RequestId::new(name)?,
        request_hash: Digest32::new(hash),
        expected_context_generation: joined.context_generation,
        expires_at_unix_ms: now_ms() + 90_000,
    };
    Ok(Pending {
        operation,
        lease,
        initialized,
        context,
        request,
        plan,
    })
}

fn commitment(fence: &EgressFence) -> AnchoredTestResult<EgressFenceCommit> {
    Ok(EgressFenceCommit {
        fence: fence.clone(),
        dispatch_commitment_id: RecordId::new("native-egress-dispatch")?,
        committed_at_unix_ms: now_ms(),
    })
}

fn counts(fixture: &Fixture) -> AnchoredTestResult<(i64, i64, i64)> {
    Ok(fixture.store.connection()?.query_row(
        "SELECT (SELECT COUNT(*) FROM security_participant_egress_events),
            (SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = 'security_participant_egress'),
            (SELECT COUNT(*) FROM security_participant_state_egress_fences)",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?)
}

fn joins(fixture: &Fixture) -> AnchoredTestResult<Vec<Vec<u8>>> {
    let connection = fixture.store.connection()?;
    let mut statement = connection.prepare(
        "SELECT canonical_record FROM security_participant_state_mutations ORDER BY security_authority_id, sequence",
    )?;
    let rows = statement
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn reopen(fixture: Fixture) -> AnchoredTestResult<Fixture> {
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    Ok(Fixture {
        _temp,
        database,
        lock_root,
        store: authority.admission_operation_store(),
        fence: authority.mutation_fence(),
        authority,
    })
}
