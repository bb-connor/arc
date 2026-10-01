use super::*;
use std::future::Future;

impl CombinedFixture {
    pub(super) fn competing_request(&self, label: &str) -> TestResult<ToolCallRequest> {
        let mut request = self.inner.request.clone();
        request.request_id = format!("req-combined-{label}");
        let mut admission = bundle();
        admission.admission_id = format!("adm-combined-{label}");
        admission.binding.request_id = request.request_id.clone();
        admission.binding.tool_args_sha256 = tool_args_sha256(&request.arguments)?;
        request
            .governed_intent
            .as_mut()
            .and_then(|intent| intent.context.as_mut())
            .ok_or("competing governed context")?["chioAdmission"] = serde_json::json!({
            "admissionId": admission.admission_id,
            "bundleSha256": runtime_admission_bundle_sha256(&admission)?,
        });
        self.inner.source.insert_bundle(admission)?;
        Ok(request)
    }
}

#[test]
fn combined_owned_competitor_cannot_steal_a_parked_claim_and_release_allows_a_fresh_owner(
) -> TestResult {
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(NOW / 1000, []);
    let fixture = CombinedFixture::new()?;
    let competitor = fixture.competing_request("competing")?;
    let after_release = fixture.competing_request("after-release")?;
    let polls = Arc::new(AtomicU64::new(0));
    let mut kernel = fixture.kernel(faults::FaultHook::new(
        fixture.hook()?,
        fixture.inner._directory.path().join("runtime.sqlite3"),
        faults::Fault::Park(polls.clone()),
    ))?;
    let first = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut admitted = Box::pin(kernel.evaluate_tool_call_with_metadata(
                &fixture.inner.request,
                Some(swarm_route_metadata()),
            ));
            std::future::poll_fn(|cx| {
                let result = admitted.as_mut().poll(cx);
                assert!(result.is_pending(), "parked owner finished: {result:?}");
                if polls.load(Ordering::SeqCst) > 0 {
                    std::task::Poll::Ready(())
                } else {
                    std::task::Poll::Pending
                }
            })
            .await;
            let history = faults::history(&fixture.inner)?;
            assert_eq!(history.len(), 1);
            assert_eq!(history[0].intent.resources().len(), 3);
            assert_eq!(
                history[0].disposition,
                RuntimeParticipantDisposition::ReservedBeforeDispatch
            );
            let denied = kernel
                .evaluate_tool_call_with_metadata(&competitor, Some(swarm_route_metadata()))
                .await?;
            assert_eq!(denied.verdict, Verdict::Deny, "{denied:#?}");
            assert!(
                denied
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains(
                        "runtime participant resource is already reserved or historically spent"
                    )),
                "competitor must reach the physical replay conflict: {denied:#?}"
            );
            assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 0);
            assert_eq!(
                fixture.history(&history[0].reference)?.1,
                history,
                "a competing denial must not release the admitted owner's resources"
            );
            let raw = rusqlite::Connection::open(
                fixture.inner._directory.path().join("authority.sqlite3"),
            )?;
            let claims: i64 = raw.query_row(
                "SELECT count(*) FROM runtime_replay_claim_episodes",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(claims, 1, "competitor cannot leave a partial claim");
            let state: String = raw.query_row(
                "SELECT state FROM admission_operations WHERE request_id = ?1",
                [&competitor.request_id],
                |row| row.get(0),
            )?;
            assert_eq!(state, "compensated_before_dispatch");
            drop(admitted);
            Ok::<_, Box<dyn std::error::Error>>(history[0].reference.clone())
        })?;
    assert_eq!(
        fixture.history(&first)?.1[0].disposition,
        RuntimeParticipantDisposition::ReleasedBeforeDispatch
    );
    kernel.set_runtime_admission_hook(Arc::new(fixture.hook()?));
    let allowed = kernel
        .evaluate_tool_call_blocking_with_metadata(&after_release, Some(swarm_route_metadata()))?;
    assert_eq!(allowed.verdict, Verdict::Allow, "{allowed:#?}");
    assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 1);
    let metadata = allowed
        .receipt
        .metadata
        .as_ref()
        .ok_or("fresh owner receipt metadata")?;
    let reference: RuntimeParticipantClaimReferenceV1 = serde_json::from_value(
        metadata["chio_runtime"]["operation_owned_replay"]["reference"].clone(),
    )?;
    assert_ne!(reference.operation_id(), first.operation_id());
    let (_, history) = fixture.history(&reference)?;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].intent.resources().len(), 3);
    assert_eq!(
        history[0].disposition,
        RuntimeParticipantDisposition::RetainedAfterDispatchCommit
    );
    assert_eq!(
        fixture.history(&first)?.1[0].disposition,
        RuntimeParticipantDisposition::ReleasedBeforeDispatch
    );
    Ok(())
}
