use super::*;
use crate::kernel::verified_treaty::TreatyVerificationEvidence;
use crate::post_invocation::{
    PostInvocationContext, PostInvocationHook, PostInvocationHookIdentity, PostInvocationVerdict,
};
use std::sync::{Condvar, Mutex, Weak};

#[derive(Default)]
struct Rendezvous {
    arrivals: Mutex<usize>,
    ready: Condvar,
}

impl Rendezvous {
    fn meet(&self) -> Result<(), String> {
        let mut arrivals = self.arrivals.lock().map_err(|_| "rendezvous lock")?;
        *arrivals += 1;
        self.ready.notify_all();
        let (arrivals, _) = self
            .ready
            .wait_timeout_while(arrivals, Duration::from_secs(10), |arrivals| *arrivals < 2)
            .map_err(|_| "rendezvous wait")?;
        (*arrivals == 2)
            .then_some(())
            .ok_or_else(|| "concurrent recovery did not reach the rendezvous".into())
    }
}

#[derive(Default)]
struct RecoveryOverlap {
    installed: Rendezvous,
    observed: Rendezvous,
}

struct RecoveryProbe {
    kernel: Mutex<Weak<ChioKernel>>,
    overlap: Arc<RecoveryOverlap>,
    reports: Mutex<Vec<String>>,
}

struct ProbeHook(Arc<RecoveryProbe>);

impl PostInvocationHook for ProbeHook {
    fn name(&self) -> &str {
        "retained-federation-recovery-probe"
    }

    fn inspect(
        &self,
        context: &PostInvocationContext<'_>,
        _: &serde_json::Value,
    ) -> PostInvocationVerdict {
        let kernel = self
            .0
            .kernel
            .lock()
            .ok()
            .and_then(|kernel| kernel.upgrade());
        let Some(kernel) = kernel else {
            // Initial dispatch uses the same frozen, identity output plan.
            return PostInvocationVerdict::Allow;
        };
        let observation = (|| -> Result<(), String> {
            self.0.overlap.installed.meet()?;
            let request = context.request.ok_or("recovery request")?;
            let outer_key = current_receipt_evaluation_scope_key();
            let nested =
                RECEIPT_EVALUATION_SCOPE_KEY.sync_scope(uuid::Uuid::now_v7().to_string(), || {
                    let _nested = kernel.scope_receipt_federation_admission_for_request(
                        &request.request_id,
                        ReceiptFederationAdmission {
                            remote_kernel_id: None,
                            peer: None,
                            verified_treaty_material: None,
                        },
                    );
                    kernel
                        .receipt_federation_admission_for_request(&request.request_id, None)
                        .is_some()
                });
            if !nested || current_receipt_evaluation_scope_key() != outer_key {
                return Err("nested scope did not restore recovery scope".into());
            }
            let snapshot = kernel
                .receipt_federation_admission_for_request(
                    &request.request_id,
                    request.federated_origin_kernel_id.as_deref(),
                )
                .ok_or("retained recovery snapshot")?;
            let material = snapshot.verified_treaty_material.ok_or("verified treaty")?;
            let metadata = material.receipt_metadata();
            let report = metadata["chio_runtime"]["federation_treaty_dsse"]["treaty_binding_ref"]
                ["admission_report_sha256"]
                .as_str()
                .ok_or("local report binding")?;
            self.0
                .reports
                .lock()
                .map_err(|_| "report lock")?
                .push(report.into());
            Ok(())
        })();
        // Neither recovery may drop its retained scope before both inspect it.
        let finished = self.0.overlap.observed.meet();
        match observation.and(finished) {
            Ok(()) => PostInvocationVerdict::Allow,
            Err(reason) => PostInvocationVerdict::Escalate(reason),
        }
    }

    fn durable_identity(&self) -> Result<Option<PostInvocationHookIdentity>, String> {
        PostInvocationHookIdentity::from_canonical_config(
            self.name(),
            "1",
            "chio-kernel.tests.retained-federation-recovery-probe.v1",
            &(),
        )
        .map(Some)
    }
}

struct ReportAdmission {
    treaty: TreatyDsseAdmissionHook,
    report: String,
}

impl RuntimeAdmissionHook for ReportAdmission {
    fn name(&self) -> &str {
        "distinct-local-federation-report"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        let material = self.treaty.verified_material(context)?;
        let mut evidence = serde_json::to_value(&material.verification_evidence)
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        // The signed peer report remains unchanged. Local admission accepts a
        // different report binding, as the real runtime admission hook may do.
        evidence["admission"]["admission_report_sha256"] = serde_json::json!(self.report);
        let evidence: TreatyVerificationEvidence = serde_json::from_value(evidence)
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        let material = evidence.reverify(
            context.request,
            ["kernel.org-a", "kernel.org-b"],
            [
                &self.treaty.origin_keypair.public_key(),
                &self.treaty.local_keypair.public_key(),
            ],
            context.now_unix_ms,
        )?;
        Ok(RuntimeAdmissionDecision::allow_with_verified_treaty_material(None, material))
    }
}

fn pending_fixture(
    local: &Keypair,
    origin: &Keypair,
    report: &str,
    probe: &Arc<RecoveryProbe>,
) -> Result<Fixture, Box<dyn std::error::Error>> {
    let mut config = make_config();
    config.keypair = local.clone();
    config.policy_hash = sha256_hex(b"durable-admission-test-policy");
    let kernel = make_kernel(config);
    kernel.set_federation_local_kernel_id("kernel.org-b");
    let trust = KernelTrustExchange::new("kernel.org-b", local.clone())
        .with_trusted_peer("kernel.org-a", origin.public_key());
    let peer = handshake_and_pin(&trust, "kernel.org-a", origin, current_unix_timestamp());
    let mut kernel = kernel.with_federation_peers(vec![peer]);
    kernel.set_receipt_store(Box::new(AdmissionReceiptProjectionStore::default()))?;
    let store = Arc::new(TestAdmissionOperationStore::new(admission_test_fence()));
    kernel.set_durable_admission_store(store.clone(), store.clone(), admission_test_fence())?;
    kernel.set_budget_store_handle(store.budget_store());
    kernel.set_runtime_admission_hook(Arc::new(ReportAdmission {
        treaty: TreatyDsseAdmissionHook::new(origin.clone(), local.clone()),
        report: report.into(),
    }));
    kernel.set_federation_cosigner(Arc::new(InProcessCoSigner::new(
        "kernel.org-a",
        origin.clone(),
        local.public_key(),
    )));
    kernel.add_post_invocation_hook(Box::new(ProbeHook(probe.clone())));
    let invocations = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(DurableAdmissionCheckingServer {
        id: "durable-server".into(),
        tools: vec!["mutate".into()],
        invocations: invocations.clone(),
        store: store.clone(),
    }));
    let capability = kernel.issue_capability(
        &Keypair::generate().public_key(),
        make_scope(vec![make_grant("durable-server", "mutate")]),
        300,
    )?;
    let mut request = make_request_with_arguments(
        "shared-recovery-request",
        &capability,
        "mutate",
        "durable-server",
        serde_json::json!({"record": "ledger-7", "value": "settled"}),
    );
    request.federated_origin_kernel_id = Some("kernel.org-a".into());
    store.fail_next_evaluation_begin();
    assert!(kernel.evaluate_tool_call_blocking(&request).is_err());
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    Ok(Fixture {
        kernel,
        request,
        store,
        invocations,
        origin_keypair: origin.clone(),
    })
}

fn restart(fixture: &Fixture, probe: &Arc<RecoveryProbe>) -> Result<ChioKernel, KernelError> {
    let fence = StoreMutationFence {
        owner_epoch: 2,
        lease_id: "recovery-isolation-owner-2".into(),
        ..admission_test_fence()
    };
    fixture.store.rotate_fence(fence.clone());
    let mut config = make_config();
    config.keypair = fixture.kernel.config.keypair.clone();
    config.policy_hash = fixture.kernel.config.policy_hash.clone();
    let mut kernel = make_kernel(config);
    kernel.set_federation_local_kernel_id("kernel.org-b");
    kernel.set_receipt_store(Box::new(AdmissionReceiptProjectionStore::default()))?;
    kernel.set_durable_admission_store(fixture.store.clone(), fixture.store.clone(), fence)?;
    kernel.set_budget_store_handle(fixture.store.budget_store());
    kernel.set_runtime_admission_hook(Arc::new(RejectNewRuntimeAdmission(Arc::new(
        AtomicU64::new(0),
    ))));
    kernel.set_federation_cosigner(Arc::new(InProcessCoSigner::new(
        "kernel.org-a",
        fixture.origin_keypair.clone(),
        kernel.config.keypair.public_key(),
    )));
    kernel.add_post_invocation_hook(Box::new(ProbeHook(probe.clone())));
    Ok(kernel)
}

#[test]
fn concurrent_recovery_keeps_distinct_treaty_reports_for_the_same_request_id() -> TestResult {
    let local = Keypair::generate();
    let origin = Keypair::generate();
    let overlap = Arc::new(RecoveryOverlap::default());
    let probes = [0, 1].map(|_| {
        Arc::new(RecoveryProbe {
            kernel: Mutex::new(Weak::new()),
            overlap: overlap.clone(),
            reports: Mutex::new(Vec::new()),
        })
    });
    let reports = ["a".repeat(64), "b".repeat(64)];
    let fixtures = [
        pending_fixture(&local, &origin, &reports[0], &probes[0])?,
        pending_fixture(&local, &origin, &reports[1], &probes[1])?,
    ];
    assert_eq!(
        fixtures[0].request.request_id,
        fixtures[1].request.request_id
    );
    assert_ne!(
        fixtures[0].request.capability.id,
        fixtures[1].request.capability.id
    );
    assert_ne!(
        fixtures[0].store.operation().binding().operation_id(),
        fixtures[1].store.operation().binding().operation_id()
    );
    let first = restart(&fixtures[0], &probes[0])?;
    let mut second = restart(&fixtures[1], &probes[1])?;
    // The existing fixture store holds one operation. Share the production map
    // to exercise the same collision as two sweeps on a single kernel, while
    // retaining independent real admission and outcome records for both rows.
    second.receipt_federation_admissions = first.receipt_federation_admissions.clone();
    let kernels = [Arc::new(first), Arc::new(second)];
    for (probe, kernel) in probes.iter().zip(&kernels) {
        *probe.kernel.lock().map_err(|_| "probe lock")? = Arc::downgrade(kernel);
    }
    let results = std::thread::scope(|threads| {
        let first = threads.spawn(|| kernels[0].reconcile_recoverable_admissions());
        let second = threads.spawn(|| kernels[1].reconcile_recoverable_admissions());
        [first.join(), second.join()]
    });
    for (index, result) in results.into_iter().enumerate() {
        assert_eq!(result.map_err(|_| "recovery worker panicked")??, 1);
        assert_eq!(
            *probes[index].reports.lock().map_err(|_| "report lock")?,
            vec![reports[index].clone()]
        );
        assert_eq!(fixtures[index].invocations.load(Ordering::SeqCst), 1);
        assert_eq!(
            fixtures[index].store.operation().state(),
            AdmissionOperationState::Completed
        );
        let state = fixtures[index]
            .store
            .state
            .lock()
            .map_err(|_| "state lock")?;
        let receipt = state.receipt.as_ref().ok_or("terminal receipt")?;
        let envelope = kernels[index]
            .federation_dsse_envelope(&receipt.id)
            .ok_or("bilateral DSSE")?;
        let statement = chio_federation::bilateral_dsse::verify_chio_bilateral_dsse_envelope(
            &envelope,
            &origin.public_key(),
            &local.public_key(),
        )?;
        assert_eq!(
            statement
                .predicate
                .treaty_binding_ref
                .ok_or("treaty binding")?
                .admission_report_sha256,
            reports[index]
        );
        assert!(receipt.verify_signature()?);
    }
    assert!(kernels[0].receipt_federation_admissions.is_empty());
    assert!(current_receipt_evaluation_scope_key().is_none());
    Ok(())
}
