//! Declassified egress commit through the same test backend. The writer
//! authenticates the live signed grant against the fence and stamps both the
//! commitment and its use evidence at its own clock.
use super::*;
use crate::admission_operation::NativeSecurityDispatchLedgerRecordV1;
use chio_core::receipt::security::{
    ActiveDefensePolicyBinding, ActiveDefenseReceiptBody, ActiveDefenseReceiptHeader,
    DeclassificationConsumptionReceiptBody,
};
use chio_security_types::flow::DeclassificationPurpose;
use chio_security_types::ports::{
    derive_declassification_event_id, derive_declassification_transition_id, CanonicalBody,
    DeclassificationConsumeRequest, DeclassificationConsumptionEvidenceCommit,
    DeclassificationTransitionBinding, DeclassificationUseState, DestinationId, Digest32, GrantId,
    ReceiptAppendRequest, RecordId, RequestId,
};
use chio_security_types::{DeclassificationGrantBody, DeclassificationGrantClaims};
use std::time::Duration;

const POLICY: &[u8] = br#"{"schema":"chio.native-flow-dispatch-policy.v2"}"#;

type Retained = Result<
    (
        Option<NativeSecurityEgressHistoryV1>,
        NativeSecurityDispatchLedgerRecordV1,
    ),
    KernelError,
>;

fn refused<E>(_: E) -> Box<dyn std::error::Error> {
    "declassification fixture refused".into()
}

fn digest32(bytes: &[u8]) -> Digest32 {
    Digest32::new(*chio_core::sha256(bytes).as_bytes())
}

/// The original admission keeps no grant; only the live request carries one.
fn declassified_fixture(
    name: &str,
    grant_lifetime_secs: u64,
) -> TestResult<(
    ChioKernel,
    ToolCallRequest,
    SecurityInvocationContext,
    Arc<TestAdmissionOperationStore>,
)> {
    let (kernel, request, context, store) = fixture(name)?;
    let trusted = context.as_v1();
    let now_secs = current_unix_timestamp_ms() / 1000;
    let body = DeclassificationGrantBody::new(DeclassificationGrantClaims {
        grant_id: GrantId::new("kernel-egress-grant")?,
        capability_id: RecordId::new(&request.capability.id)?,
        tenant_id: trusted.tenant_id().clone(),
        subject_id: trusted.principal_id().clone(),
        agent_id: RecordId::new(&request.agent_id)?,
        session_id: trusted.session_id().clone(),
        source_label_hash: digest32(b"kernel-egress-source"),
        target_label: InformationLabel::bottom(),
        destination_id: DestinationId::new(&request.server_id)?,
        tool_name: RecordId::new(&request.tool_name)?,
        purpose: DeclassificationPurpose::new("kernel-egress-purpose")?,
        request_hash: digest32(&canonical_json_bytes(&request.arguments)?),
        issued_at_unix_seconds: now_secs - 1,
        expires_at_unix_seconds: now_secs + grant_lifetime_secs,
        authority_key_id: RecordId::new("kernel-egress-authority")?,
    })?;
    let grant = chio_core_types::SignedDeclassificationGrant::sign(
        body,
        &chio_core::Keypair::generate(),
    )?;
    let mut live = request;
    live.declassification_grant = Some(grant.into());
    Ok((kernel, live, context, store))
}

fn consumption_evidence(
    request: &ToolCallRequest,
    consumed_at: u64,
) -> TestResult<DeclassificationConsumptionEvidenceCommit> {
    let grant = request
        .declassification_grant
        .as_ref()
        .ok_or("live request carries no grant")?;
    let claims = grant.body();
    let binding = DeclassificationTransitionBinding::Consumption {
        tenant_id: claims.tenant_id().clone(),
        grant_id: claims.grant_id().clone(),
        request_hash: claims.request_hash(),
        request_id: RequestId::new(&request.request_id)?,
    };
    let body = ActiveDefenseReceiptBody::DeclassificationConsumption(
        DeclassificationConsumptionReceiptBody {
            header: ActiveDefenseReceiptHeader::new(
                consumed_at,
                claims.tenant_id().clone(),
                derive_declassification_transition_id(&binding).map_err(refused)?,
                Vec::new(),
            )
            .map_err(refused)?,
            policy: ActiveDefensePolicyBinding {
                policy_version: RecordId::new("native-flow-dispatch-policy-v2")?,
                policy_hash: digest32(POLICY),
            },
            grant_id: claims.grant_id().clone(),
            grant_hash: digest32(&canonical_json_bytes(grant)?),
            request_hash: claims.request_hash(),
            event_id: derive_declassification_event_id(&binding).map_err(refused)?,
            state: DeclassificationUseState::ConsumedPendingDispatch,
        },
    );
    body.validate().map_err(refused)?;
    Ok(DeclassificationConsumptionEvidenceCommit {
        consumption: DeclassificationConsumeRequest {
            tenant_id: claims.tenant_id().clone(),
            grant_id: claims.grant_id().clone(),
            request_hash: claims.request_hash(),
            consumed_at_unix_ms: consumed_at,
            grant_expires_at_unix_ms: claims.expires_at_unix_seconds() * 1000,
        },
        transition_binding: binding,
        receipt: ReceiptAppendRequest {
            tenant_id: claims.tenant_id().clone(),
            evidence_type: RecordId::new(body.kind().as_str())?,
            evidence_id: body.evidence_id().map_err(refused)?,
            canonical_body: CanonicalBody::new(canonical_json_bytes(&body)?).map_err(refused)?,
            body_hash: body.body_digest().map_err(refused)?,
            transition_id: body.header().transition_id.clone(),
            occurred_at_unix_ms: consumed_at,
        },
    })
}

struct Timing {
    fence_lifetime_ms: u64,
    delay_ms: u64,
    fault: Fault,
}

/// Prepare the event, build its use evidence at the prepared clock, wait, then
/// hand both to the physical writer. Returns the prepared clock and outcome.
fn retain_after_delay(
    kernel: &ChioKernel,
    request: &ToolCallRequest,
    context: &SecurityInvocationContext,
    store: &TestAdmissionOperationStore,
    timing: Timing,
) -> TestResult<(u64, Retained)> {
    let operation = store.operation();
    let commit = kernel
        .prepare_native_security_egress(operation.binding().operation_id(), request, context)?
        .acquire(current_unix_timestamp_ms() + timing.fence_lifetime_ms)?
        .prepare_commit()?;
    let prepared_at = commit.trusted_now_unix_ms();
    let consumption = consumption_evidence(commit.request(), prepared_at)?;
    store.native_egress.arm_commit(timing.fault)?;
    std::thread::sleep(Duration::from_millis(timing.delay_ms));
    let result = commit
        .retain_for_declassified_capture(0, POLICY, &consumption)
        .map(|(_, history, ledger)| (history, ledger));
    Ok((prepared_at, result))
}

#[test]
fn declassified_commit_after_a_five_second_delay_keeps_the_original_authority() -> TestResult {
    let (kernel, request, context, store) = declassified_fixture("declassified-delay", 300)?;
    let operation = store.operation();
    let (prepared_at, result) = retain_after_delay(
        &kernel,
        &request,
        &context,
        &store,
        Timing {
            fence_lifetime_ms: 60_000,
            delay_ms: 5_100,
            fault: Fault::PhysicalEventClock,
        },
    )?;
    let (history, ledger) = result?;
    let commitment = history
        .ok_or("egress history")?
        .commitment
        .ok_or("egress commitment")?;
    let used = commitment.declassification.ok_or("use evidence")?;
    let event_at = commitment.commitment.committed_at_unix_ms;
    assert!(event_at > prepared_at + 5_000);
    assert_eq!(used.consumption.consumed_at_unix_ms, event_at);
    assert_eq!(used.receipt.occurred_at_unix_ms, event_at);
    assert!(!ledger.canonical_record.is_empty());
    assert_eq!(store.operation(), operation);
    Ok(())
}

#[test]
fn declassified_commit_refuses_expired_authority_before_any_physical_write() -> TestResult {
    // The grant has second resolution, so it expires 1 to 2 seconds from now.
    for (name, grant_lifetime_secs, fence_lifetime_ms, delay_ms, reason) in [
        ("grant", 2_u64, 60_000_u64, 2_300_u64, "not currently valid"),
        ("fence", 300, 1_000, 1_200, "expired or invalid"),
    ] {
        let (kernel, request, context, store) =
            declassified_fixture(&format!("declassified-expired-{name}"), grant_lifetime_secs)?;
        let operation = store.operation();
        let (_, result) = retain_after_delay(
            &kernel,
            &request,
            &context,
            &store,
            Timing {
                fence_lifetime_ms,
                delay_ms,
                fault: Fault::PhysicalEventClock,
            },
        )?;
        let error = result.err().ok_or("expired authority accepted")?;
        assert!(error.to_string().contains(reason), "{name}: {error}");
        assert!(!store.native_egress.committed()?, "{name}");
        assert_eq!(store.operation(), operation);
    }
    Ok(())
}

#[test]
fn declassified_commit_refuses_an_expired_original_lease_without_renewal() -> TestResult {
    let (kernel, request, context, store) = declassified_fixture("declassified-lease", 300)?;
    let operation = store.operation();
    let acquired = kernel
        .prepare_native_security_egress(operation.binding().operation_id(), &request, &context)?
        .acquire(current_unix_timestamp_ms() + 60_000)?;
    // Only the commit lease is shortened; the fence and grant stay valid, so
    // the test store's own lease validation is the sole refusing authority.
    store.native_egress.cap_lease(1_000)?;
    let commit = acquired.prepare_commit()?;
    let consumption = consumption_evidence(commit.request(), commit.trusted_now_unix_ms())?;
    let original_claim = store
        .state
        .lock()
        .map_err(|_| "test admission state poisoned")?
        .claim
        .clone();
    assert!(original_claim.is_some());
    store.native_egress.arm_commit(Fault::PhysicalEventClock)?;
    std::thread::sleep(Duration::from_millis(1_200));
    let error = commit
        .retain_for_declassified_capture(0, POLICY, &consumption)
        .err()
        .ok_or("expired lease accepted")?;
    assert!(error.to_string().contains("fenced"), "{error}");
    assert!(
        store
            .state
            .lock()
            .map_err(|_| "test admission state poisoned")?
            .claim
            == original_claim,
        "the expired lease was renewed or replaced"
    );
    assert!(!store.native_egress.committed()?);
    assert_eq!(store.operation(), operation);
    Ok(())
}

#[test]
fn declassified_commit_refuses_use_evidence_left_at_the_prepared_clock() -> TestResult {
    let (kernel, request, context, store) = declassified_fixture("declassified-stale-use", 300)?;
    let (_, result) = retain_after_delay(
        &kernel,
        &request,
        &context,
        &store,
        Timing {
            fence_lifetime_ms: 60_000,
            delay_ms: 0,
            fault: Fault::StaleConsumptionClock,
        },
    )?;
    let error = result.err().ok_or("unstamped use evidence accepted")?;
    assert!(error.to_string().contains("commitment differs"), "{error}");
    Ok(())
}

#[test]
fn ordinary_retention_refuses_declassification_before_any_acquisition() -> TestResult {
    let (kernel, request, context, store) = declassified_fixture("ordinary-retention-grant", 300)?;
    let operation = store.operation();
    for deadline in [None, Some(current_unix_timestamp_ms() + 60_000)] {
        let prepared = kernel.prepare_native_security_egress(
            operation.binding().operation_id(),
            &request,
            &context,
        )?;
        let error = prepared
            .retain_for_capture(deadline, 0, POLICY)
            .err()
            .ok_or("ordinary retention accepted a declassification grant")?;
        assert!(
            error
                .to_string()
                .contains("declassification selection differs"),
            "{error}"
        );
        assert!(store.native_egress.acquisition().is_err());
        assert!(!store.native_egress.committed()?);
        assert_eq!(store.operation(), operation);
    }
    Ok(())
}

#[test]
fn declassified_retention_requires_a_live_grant_and_evidence_for_the_prepared_event() -> TestResult
{
    let (kernel, request, context, store) = declassified_fixture("declassified-binding", 300)?;
    let operation = store.operation();
    let mut plain = request.clone();
    plain.declassification_grant = None;
    for (live, offset) in [(&plain, 0_u64), (&request, 1)] {
        let commit = kernel
            .prepare_native_security_egress(operation.binding().operation_id(), live, &context)?
            .acquire(current_unix_timestamp_ms() + 60_000)?
            .prepare_commit()?;
        let consumption = consumption_evidence(&request, commit.trusted_now_unix_ms() - offset)?;
        let error = commit
            .retain_for_declassified_capture(0, POLICY, &consumption)
            .err()
            .ok_or("unbound declassification accepted")?;
        assert!(
            error.to_string().contains("prepared event clock"),
            "{error}"
        );
        assert!(!store.native_egress.committed()?);
    }
    Ok(())
}
