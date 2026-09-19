//! Hook configuration is not authority to replace or hide retained custody.
//! These coordinator doubles do not qualify a physical replay store.

use super::*;
use crate::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1;
use std::panic::{catch_unwind, AssertUnwindSafe};

#[derive(Default)]
struct Calls {
    selection: AtomicU64,
    legacy: AtomicU64,
    diagnostics: AtomicU64,
}

struct SelectionProbe {
    calls: Arc<Calls>,
    panic: bool,
}

impl RuntimeAdmissionHook for SelectionProbe {
    fn name(&self) -> &str {
        self.calls.diagnostics.fetch_add(1, Ordering::SeqCst);
        "runtime-selection-probe"
    }

    fn runtime_participant_binding(&self) -> Option<&RuntimeParticipantAuthorityBindingV1> {
        self.calls.selection.fetch_add(1, Ordering::SeqCst);
        assert!(!self.panic, "injected runtime authority selection panic");
        None
    }

    fn evaluate(
        &self,
        _: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.calls.legacy.fetch_add(1, Ordering::SeqCst);
        panic!("failed authority selection must not enter legacy evaluation");
    }

    fn release_reserved(&self, _: &serde_json::Value) -> Result<(), KernelError> {
        self.calls.legacy.fetch_add(1, Ordering::SeqCst);
        panic!("retained operation custody must not enter legacy release");
    }
}

#[test]
fn runtime_selection_panic_is_denied_before_original_admission() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("runtime-selection-begin");
    let calls = Arc::new(Calls::default());
    kernel.set_runtime_admission_hook(Arc::new(SelectionProbe {
        calls: calls.clone(),
        panic: true,
    }));
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )
    .expect("matching grants");
    let result = catch_unwind(AssertUnwindSafe(|| {
        kernel.begin_durable_tool_admission(&request, &matching, current_unix_timestamp_ms())
    }));
    assert!(result.is_ok(), "runtime authority selection escaped admission");
    assert!(result.expect("contained callback").is_err());
    assert!(store.state.lock().expect("fixture").operation.is_none());
    assert_eq!(calls.selection.load(Ordering::SeqCst), 1);
    assert_eq!(calls.legacy.load(Ordering::SeqCst), 0);
    assert_eq!(calls.diagnostics.load(Ordering::SeqCst), 0);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn runtime_selection_panic_cannot_fall_back_to_legacy_evaluation() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("runtime-selection-evaluate");
    let calls = Arc::new(Calls::default());
    kernel.set_runtime_admission_hook(Arc::new(SelectionProbe {
        calls: calls.clone(),
        panic: true,
    }));
    let now = current_unix_timestamp_ms();
    let result = catch_unwind(AssertUnwindSafe(|| {
        kernel.run_runtime_admission_hook(&request, None, now / 1000, now, Some(0), None)
    }));
    assert!(result.is_ok(), "runtime authority selection escaped evaluation");
    assert!(!result.expect("contained callback").allowed);
    assert!(store.state.lock().expect("fixture").operation.is_none());
    assert_eq!(calls.selection.load(Ordering::SeqCst), 1);
    assert_eq!(calls.legacy.load(Ordering::SeqCst), 0);
    assert_eq!(calls.diagnostics.load(Ordering::SeqCst), 0);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn retained_runtime_release_does_not_depend_on_current_hook_selection() {
    for hook in [None, Some(false), Some(true)] {
        let (mut kernel, store, invocations) = fixture();
        let original = store.operation();
        let calls = Arc::new(Calls::default());
        if let Some(panic) = hook {
            kernel.set_runtime_admission_hook(Arc::new(SelectionProbe {
                calls: calls.clone(),
                panic,
            }));
        }
        let result = catch_unwind(AssertUnwindSafe(|| {
            kernel.release_runtime_admission_reservations(Some(&original), None)
        }));
        assert!(result.is_ok(), "hook {hook:?} escaped retained release");
        result.expect("contained release").expect("release retained owner");
        assert_eq!(calls.selection.load(Ordering::SeqCst), 0, "hook {hook:?}");
        assert_eq!(calls.legacy.load(Ordering::SeqCst), 0, "hook {hook:?}");
        assert_eq!(calls.diagnostics.load(Ordering::SeqCst), 0, "hook {hook:?}");
        let state = store.runtime_recovery.0.lock().expect("fixture");
        assert_eq!(state.release_calls, 1, "hook {hook:?}");
        assert_eq!(
            state.history.as_ref().expect("history")[0].disposition,
            RuntimeParticipantDisposition::ReleasedBeforeDispatch,
            "hook {hook:?}",
        );
        assert_eq!(store.operation(), original);
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        drop(state);
        kernel
            .release_runtime_admission_reservations(Some(&original), None)
            .expect("exact cleanup retry");
        assert_eq!(
            store.runtime_recovery.0.lock().expect("fixture").release_calls,
            1,
            "retry must not release twice for hook {hook:?}",
        );
        assert_eq!(calls.selection.load(Ordering::SeqCst), 0, "hook {hook:?}");
        assert_eq!(calls.legacy.load(Ordering::SeqCst), 0, "hook {hook:?}");
        assert_eq!(calls.diagnostics.load(Ordering::SeqCst), 0, "hook {hook:?}");
    }
}

#[test]
fn absent_runtime_ledger_does_not_turn_selection_failure_into_successful_release() {
    let (mut kernel, _, _, invocations) =
        durable_admission_fixture("runtime-selection-release");
    let calls = Arc::new(Calls::default());
    kernel.set_runtime_admission_hook(Arc::new(SelectionProbe {
        calls: calls.clone(),
        panic: true,
    }));
    let result = catch_unwind(AssertUnwindSafe(|| {
        kernel.release_runtime_admission_reservations(None, None)
    }));
    assert!(result.is_ok(), "runtime authority selection escaped release");
    assert!(result.expect("contained callback").is_err());
    assert_eq!(calls.selection.load(Ordering::SeqCst), 1);
    assert_eq!(calls.legacy.load(Ordering::SeqCst), 0);
    assert_eq!(calls.diagnostics.load(Ordering::SeqCst), 0);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}
