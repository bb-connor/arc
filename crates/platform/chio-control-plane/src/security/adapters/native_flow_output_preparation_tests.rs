// Real captured SQLite operations and resolved payloads exercise preparation
// only. No historical artifact is promoted to a live release or tool permit.
use super::*;
use crate::security::adapters::digest;
use chio_kernel::admission_operation::AdmissionMutationSequencer;
use chio_kernel::{
    CapabilityAuthority, CapabilityAuthorityWorkloadBinding, LocalCapabilityAuthority,
    ToolCallChunk, ToolCallOutput, ToolCallStream,
};

fn assert_unlocked(sequencer: &AdmissionMutationSequencer) {
    // A bounded reentry probe detects a callback under the mutation lock
    // without leaving the test permanently blocked on a recursive lock.
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let sequencer = sequencer.clone();
    std::thread::spawn(move || {
        let result = sequencer.lock().map(drop).is_ok();
        let _ = sender.send(result);
    });
    assert_eq!(
        receiver.recv_timeout(std::time::Duration::from_secs(2)),
        Ok(true)
    );
}

struct ReentrantWorkloadAuthority {
    inner: LocalCapabilityAuthority,
    sequencer: AdmissionMutationSequencer,
    calls: Arc<AtomicUsize>,
}

impl CapabilityAuthority for ReentrantWorkloadAuthority {
    fn authority_public_key(&self) -> chio_core::PublicKey {
        self.inner.authority_public_key()
    }

    fn workload_binding(&self) -> Option<CapabilityAuthorityWorkloadBinding> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_unlocked(&self.sequencer);
        self.inner.workload_binding()
    }

    fn issue_capability(
        &self,
        subject: &chio_core::PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<chio_core::capability::token::CapabilityToken, KernelError> {
        self.inner.issue_capability(subject, scope, ttl_seconds)
    }
}

struct Classifier {
    calls: AtomicUsize,
    expired: std::sync::atomic::AtomicBool,
    output_error: std::sync::Mutex<Option<String>>,
    expected: Vec<u8>,
    sequencer: AdmissionMutationSequencer,
    expire_at: Option<u64>,
}

impl ClassificationPort for Classifier {
    fn classify(&self, request: &ClassificationRequest) -> PortResult<ClassificationResult> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request.payload.as_bytes(), self.expected);
        assert_eq!(request.payload_digest, digest(&self.expected));
        assert_eq!(request.tenant_id.as_str(), "native-tenant");
        assert_unlocked(&self.sequencer);
        if let Some(expiry) = self.expire_at {
            let remaining = expiry
                .checked_sub(now_ms()?)
                .filter(|ms| (1..60_000).contains(ms))
                .ok_or_else(PortError::unavailable)?;
            std::thread::sleep(std::time::Duration::from_millis(remaining));
            assert!(
                now_ms()? >= expiry,
                "real clock did not reach original lease expiry"
            );
            self.expired.store(true, Ordering::SeqCst);
        }
        let mut result = CountingEmptyClassifier::new().classify(request)?;
        result.findings = chio_security_types::ports::BoundedVec::new(vec![
            chio_security_types::ports::ClassificationFinding {
                category: RecordId::new("restricted").map_err(PortError::from)?,
                confidence_basis_points: 10_000,
                byte_range: Some(chio_security_types::ports::ByteRange {
                    start: 0,
                    end: request
                        .payload
                        .as_bytes()
                        .len()
                        .try_into()
                        .map_err(|_| PortError::invalid_data())?,
                }),
                field_path: None,
            },
        ])
        .map_err(|_| PortError::invalid_data())?;
        Ok(result)
    }
}

fn prepare(
    fixture: &Fixture,
    finalizing: &Finalizing,
    lease: &AdmissionRecoveryLease,
    output: &ToolCallOutput,
) -> TestResult<Result<(), KernelError>> {
    let raw = fixture
        .authority
        .tool_outcome_store()
        .load_raw_invocation_by_operation(finalizing.operation.binding().operation_id())?
        .ok_or("raw native output")?;
    Ok(test_support::with_security_release_output(
        &finalizing.operation,
        &raw,
        &finalizing.outcome,
        &finalizing.evaluation,
        output,
        |context| {
            fixture
                .kernel
                .prepare_native_output_for_test(context, lease)
        },
    )?)
}

fn install_classifier(
    fixture: &mut Fixture,
    expected: &serde_json::Value,
    expire_at: Option<u64>,
) -> TestResult<Arc<Classifier>> {
    let classifier = Arc::new(Classifier {
        calls: AtomicUsize::new(0),
        expired: std::sync::atomic::AtomicBool::new(false),
        output_error: std::sync::Mutex::new(None),
        expected: chio_core::canonical_json_bytes(expected)?,
        sequencer: AdmissionMutationSequencer::for_fence(&fixture.authority.mutation_fence())?,
        expire_at,
    });
    let mut config = flow_config();
    config.category_labels = CategoryLabelMap::new(
        ClassifierId::new("classifier.empty")?,
        ClassifierVersion::new("1")?,
        BTreeMap::from([(
            RecordId::new("restricted")?,
            super::super::super::super::restricted_label(),
        )]),
    )?;
    let resolver = NativeFlowResolver::new(
        fixture.binding.clone(),
        super::super::super::super::registry(false, InformationLabel::bottom())?,
        classifier.clone(),
        Arc::new(Clock::default()),
        config,
    )?;
    fixture
        .kernel
        .set_security_pre_dispatch_hook(Arc::new(ObservedOutputHook {
            resolver,
            classifier: classifier.clone(),
        }));
    Ok(classifier)
}

#[test]
fn native_output_preparation_classifies_actual_value_and_ordered_stream_chunks() -> TestResult {
    for stream in [false, true] {
        let mut fixture = super::super::super::super::public_fixture()?;
        let delivered = serde_json::json!({"delivered": "redacted-value"});
        let (output, expected) = if stream {
            let chunks = vec![delivered.clone(), serde_json::json!({"last": "visible"})];
            (
                ToolCallOutput::Stream(ToolCallStream {
                    chunks: chunks
                        .iter()
                        .cloned()
                        .map(|data| ToolCallChunk { data })
                        .collect(),
                }),
                serde_json::Value::Array(chunks),
            )
        } else {
            (ToolCallOutput::Value(delivered.clone()), delivered)
        };
        let finalizing =
            finalizing_with_output(&mut fixture, false, InformationLabel::bottom(), &output)?;
        let classifier = install_classifier(&mut fixture, &expected, None)?;
        let workload_calls = Arc::new(AtomicUsize::new(0));
        fixture
            .kernel
            .set_capability_authority(Box::new(ReentrantWorkloadAuthority {
                inner: LocalCapabilityAuthority::new(fixture.signer.clone()),
                sequencer: classifier.sequencer.clone(),
                calls: workload_calls.clone(),
            }));
        prepare(&fixture, &finalizing, &finalizing.lease, &output)??;
        assert_eq!(workload_calls.load(Ordering::SeqCst), 1);
        assert_eq!(classifier.calls.load(Ordering::SeqCst), 1);
        assert_eq!(counts(&fixture)?, (1, 1, 0));
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        let record = fixture
            .authority
            .admission_operation_store()
            .load_security_participant_output(
                finalizing.operation.binding().operation_id(),
                &fixture.authority.mutation_fence(),
                now_ms()?,
            )?
            .ok_or("classified output taint")?;
        assert_eq!(
            record.output.output_label(),
            &super::super::super::super::restricted_label()
        );
        reopen(fixture, &record)?;
    }
    Ok(())
}

#[test]
fn native_output_preparation_cannot_renew_a_lease_that_expires_during_classification() -> TestResult
{
    let mut fixture = super::super::super::super::public_fixture()?;
    let output = ToolCallOutput::Value(serde_json::json!({"allowed": true}));
    let finalizing = finalizing(&mut fixture, false)?;
    let classifier = install_classifier(
        &mut fixture,
        &serde_json::json!({"allowed": true}),
        Some(finalizing.lease.untrusted_claim().expires_at_unix_ms()),
    )?;
    assert!(prepare(&fixture, &finalizing, &finalizing.lease, &output)?.is_err());
    assert_eq!(classifier.calls.load(Ordering::SeqCst), 1);
    assert!(
        classifier.expired.load(Ordering::SeqCst),
        "classification did not reach original lease expiry"
    );
    assert!(
        classifier
            .output_error
            .lock()
            .map_err(|_| "output observation lock")?
            .as_deref()
            .is_some_and(|error| error.contains("native output original lease expired")),
        "denial did not come from the original lease check"
    );
    assert_eq!(counts(&fixture)?, (0, 0, 0));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

// Observe the resolver's real rejection before outer callback containment
// redacts it. This wrapper preserves success and never manufactures an error.
struct ObservedOutputHook {
    resolver: NativeFlowResolver,
    classifier: Arc<Classifier>,
}
impl SecurityPreDispatchHook for ObservedOutputHook {
    fn name(&self) -> &str {
        "observed-native-output"
    }
    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        self.resolver.native_authority_binding()
    }
    fn commit(
        &self,
        context: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        self.resolver.commit(context)
    }
    fn prepare_native_output(
        &self,
        context: &chio_kernel::tool_outcome::DurableSecurityReleaseContext<'_>,
        authority: &chio_kernel::NativeSecurityOutputJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        let result = self.resolver.prepare_native_output(context, authority);
        *self
            .classifier
            .output_error
            .lock()
            .map_err(|_| KernelError::Internal("output observation lock".into()))? =
            result.as_ref().err().map(ToString::to_string);
        result
    }
}

struct FaultyHook {
    binding: NativeSecurityAuthorityBindingV1,
    mode: u8,
}
impl SecurityPreDispatchHook for FaultyHook {
    fn name(&self) -> &str {
        "native-output-fault"
    }
    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        Ok(Some(self.binding.clone()))
    }
    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Err(KernelError::GuardDenied(
            "test output hook cannot dispatch".into(),
        ))
    }
    fn prepare_native_output(
        &self,
        _: &chio_kernel::tool_outcome::DurableSecurityReleaseContext<'_>,
        authority: &chio_kernel::NativeSecurityOutputJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        if self.mode == 0 {
            return Ok(());
        }
        let _ = authority.join_output(InformationLabel::bottom());
        if self.mode == 2 {
            let _ = authority.join_output(InformationLabel::bottom());
        }
        assert!(self.mode != 3, "injected output hook panic after join");
        Ok(())
    }
}

#[test]
fn native_output_preparation_rejects_missing_double_suppressed_and_panicking_joins() -> TestResult {
    use chio_store_sqlite::admission_operation_store::NativeOutputJoinTestFault;
    for mode in 0..4 {
        let mut fixture = super::super::super::super::public_fixture()?;
        let finalizing = finalizing(&mut fixture, false)?;
        fixture
            .kernel
            .set_security_pre_dispatch_hook(Arc::new(FaultyHook {
                binding: fixture.binding.clone(),
                mode,
            }));
        let store = fixture.authority.admission_operation_store();
        if mode == 1 {
            store.inject_native_output_join_failure_for_test(
                NativeOutputJoinTestFault::BeforeCommit,
            )?;
        }
        let result = prepare(
            &fixture,
            &finalizing,
            &finalizing.lease,
            &ToolCallOutput::Value(serde_json::json!({"allowed": true})),
        )?;
        if mode == 1 {
            store.clear_native_output_join_failure_for_test()?;
        }
        assert!(result.is_err(), "mode {mode} suppressed its output failure");
        let committed = i64::from(mode >= 2);
        assert_eq!(counts(&fixture)?, (committed, committed, 0));
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
