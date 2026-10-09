//! Finishing eligibility follows the Kernel's actual Native authority selection.
use super::*;
use crate::admission_operation::{AdmissionDigest, NativeSecurityAuthorityBindingV1};

#[test]
fn ordinary_durable_call_without_retained_original_dispatches_and_replays_once(
) -> Result<(), Box<dyn std::error::Error>> {
    let (kernel, request, store, calls) =
        durable_admission_fixture("ordinary-durable-without-retained-original");
    assert!(kernel.native_security_authority_binding()?.is_none());
    let first = kernel.evaluate_tool_call_blocking(&request)?;
    assert!(store
        .state
        .lock()
        .expect("store state")
        .retained_request
        .is_none());
    assert_eq!(first.verdict, Verdict::Allow, "reason: {:?}", first.reason);
    assert_eq!(
        first.output,
        Some(ToolCallOutput::Value(serde_json::json!({
            "tool": request.tool_name,
            "echo": request.arguments,
        })))
    );
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert!(store
        .state
        .lock()
        .expect("store state")
        .retained_request
        .is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let replay = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(replay.verdict, Verdict::Allow, "reason: {:?}", replay.reason);
    assert_eq!(replay.output, first.output);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    Ok(())
}

struct SelectedNativeHook(NativeSecurityAuthorityBindingV1);

impl SecurityPreDispatchHook for SelectedNativeHook {
    fn name(&self) -> &str {
        "selected-native-finishing-eligibility"
    }

    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        Ok(Some(self.0.clone()))
    }

    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        panic!("missing original must refuse before Native dispatch")
    }
}

#[test]
fn selected_native_finishing_refuses_missing_retained_original_at_eligibility_guard(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut kernel, request, store, calls) =
        durable_admission_fixture("selected-native-missing-retained-original");
    let now = current_unix_timestamp_ms();
    let admission = kernel
        .begin_durable_tool_admission(&request, &security_binding::matching(&request)?, now)?
        .ok_or("durable admission")?;
    assert!(admission.original_retained_request().is_none());
    let original_operation = store.operation();

    // Select through the actual host hook after preparing an ordinary original.
    // The missing original cannot demote current Native authority to ordinary.
    let binding = NativeSecurityAuthorityBindingV1::new(
        AdmissionIdentifier::try_new("store", "native-finishing-store")?,
        AdmissionIdentifier::try_new("authority", "native-finishing-authority")?,
        AdmissionDigest::try_new("initialization", sha256_hex(b"native-finishing-selection"))?,
    );
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(Arc::new(SelectedNativeHook(binding.clone())));
    assert_eq!(kernel.native_security_authority_binding()?, Some(binding));
    let context = security_binding::context(&request, 1)?;

    let error = kernel
        .prepare_original_native_finishing_before_first_purpose(
            &request,
            Some(&context),
            Some(&admission),
            None,
            now,
        )
        .expect_err("selected Native authority requires its retained original");
    assert!(
        matches!(error, KernelError::DurableAdmission(ref detail)
            if detail == "native finishing lost its retained original"),
        "the owning eligibility guard must refuse: {error:?}"
    );
    assert_eq!(store.operation(), original_operation);
    assert!(store
        .state
        .lock()
        .expect("store state")
        .budget_authorization
        .is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}
