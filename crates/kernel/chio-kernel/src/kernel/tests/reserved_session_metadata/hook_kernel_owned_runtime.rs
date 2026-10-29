//! A runtime-admission hook writes `chio_runtime`, but some of its fields are
//! written only by the kernel: reservation retention, identity disposition,
//! cleanup and post-effect faults, payment credential disposition and verified
//! treaty evidence. A hook decision, allow or deny, that names one of them is
//! refused: the tool never runs, the hook releases with the metadata it
//! returned, and the forged field is absent from the signed denial.
use super::*;
use std::sync::{Mutex, PoisonError};

const KERNEL_OWNED_FIELD_REFUSAL: &str =
    "runtime admission hook metadata names a kernel-owned chio_runtime field";

const KERNEL_OWNED_FIELDS: [&str; 17] = [
    "retained_destructive_lease_id",
    "retained_treaty_continuation_id",
    "retained_swarm_continuation_id",
    "reservations_retained_fail_closed",
    "reservation_retained",
    "identity_disposition",
    "retryable_after_resume",
    "pre_dispatch_cleanup_failed",
    "pre_dispatch_cleanup_faults",
    "pre_dispatch_cleanup_reason",
    "post_effect_fault",
    "evaluation_started_at",
    "payment_credential_disposition",
    "dispatch_credential_disposition",
    "dispatch_credential_retention_outcome_unknown",
    "pre_dispatch_payment_unwind",
    "federation_treaty_dsse",
];

struct RuntimeFieldHook {
    runtime: serde_json::Value,
    allow: bool,
    unknown_top_level_key: bool,
    released: Mutex<Vec<serde_json::Value>>,
}

impl RuntimeFieldHook {
    fn new(runtime: serde_json::Value, allow: bool) -> StdArc<Self> {
        StdArc::new(Self {
            runtime,
            allow,
            unknown_top_level_key: false,
            released: Mutex::new(Vec::new()),
        })
    }

    fn metadata(&self) -> serde_json::Value {
        let mut metadata = serde_json::json!({ "chio_runtime": self.runtime });
        if self.unknown_top_level_key {
            metadata["not_a_hook_key"] = serde_json::json!(true);
        }
        metadata
    }

    fn released(&self) -> Vec<serde_json::Value> {
        self.released
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl RuntimeAdmissionHook for RuntimeFieldHook {
    fn name(&self) -> &str {
        "runtime-field-hook"
    }

    fn evaluate_operation_owned(
        &self,
        _context: &RuntimeAdmissionContext<'_>,
        _authority: &RuntimeParticipantClaimAuthority<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        Err(KernelError::DurableAdmission(
            "runtime field hook has no operation-owned plan".into(),
        ))
    }

    fn evaluate(
        &self,
        _context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        let metadata = Some(self.metadata());
        Ok(if self.allow {
            RuntimeAdmissionDecision::allow(metadata)
        } else {
            RuntimeAdmissionDecision::deny("hook policy denies", metadata)
        })
    }

    fn release_reserved(&self, metadata: &serde_json::Value) -> Result<(), KernelError> {
        self.released
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(metadata.clone());
        Ok(())
    }
}

fn forging(field: &str, allow: bool) -> StdArc<RuntimeFieldHook> {
    forging_runtime(field, allow, false)
}

fn forging_runtime(
    field: &str,
    allow: bool,
    unknown_top_level_key: bool,
) -> StdArc<RuntimeFieldHook> {
    let mut runtime = serde_json::Map::new();
    runtime.insert("admission_id".into(), serde_json::json!("hook-admission"));
    runtime.insert(field.into(), serde_json::json!("forged"));
    StdArc::new(RuntimeFieldHook {
        runtime: serde_json::Value::Object(runtime),
        allow,
        unknown_top_level_key,
        released: Mutex::new(Vec::new()),
    })
}

fn assert_kernel_owned_field_refused(
    response: ToolCallResponse,
    hook: &RuntimeFieldHook,
    invocations: &AtomicU64,
    field: &str,
) {
    assert_eq!(response.verdict, Verdict::Deny, "{field}");
    assert_eq!(
        response.reason.as_deref(),
        Some(KERNEL_OWNED_FIELD_REFUSAL),
        "{field}"
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0, "{field}");
    let signed = response.receipt.metadata.as_ref().expect("denial metadata");
    assert_ne!(
        signed.pointer(&format!("/chio_runtime/{field}")),
        Some(&serde_json::json!("forged")),
        "{field}"
    );
    assert_eq!(
        signed.pointer("/runtime_admission/failure_code"),
        Some(&serde_json::json!(
            "runtime_admission_hook_metadata_kernel_owned_field"
        )),
        "{field}"
    );
    assert_eq!(
        signed.pointer("/runtime_admission/field"),
        Some(&serde_json::json!(field)),
        "{field}"
    );
    assert_eq!(hook.released(), vec![hook.metadata()], "{field}");
}

#[test]
fn hook_allow_naming_a_kernel_owned_runtime_field_is_refused() {
    for field in KERNEL_OWNED_FIELDS {
        let (mut kernel, request, _context, invocations) = fixture();
        let hook = forging(field, true);
        kernel.set_runtime_admission_hook(hook.clone());
        let response = kernel
            .evaluate_tool_call_blocking(&request)
            .expect("runtime admission denial");
        assert_kernel_owned_field_refused(response, &hook, &invocations, field);
    }
}

#[test]
fn hook_deny_naming_a_kernel_owned_runtime_field_is_refused() {
    for field in KERNEL_OWNED_FIELDS {
        let (mut kernel, request, _context, invocations) = fixture();
        let hook = forging(field, false);
        kernel.set_runtime_admission_hook(hook.clone());
        let response = kernel
            .evaluate_tool_call_blocking(&request)
            .expect("runtime admission denial");
        assert_kernel_owned_field_refused(response, &hook, &invocations, field);
    }
}

#[test]
fn unknown_top_level_key_does_not_carry_a_kernel_owned_runtime_field_into_the_denial() {
    for allow in [true, false] {
        for field in KERNEL_OWNED_FIELDS {
            let (mut kernel, request, _context, invocations) = fixture();
            let hook = forging_runtime(field, allow, true);
            kernel.set_runtime_admission_hook(hook.clone());
            let response = kernel
                .evaluate_tool_call_blocking(&request)
                .expect("runtime admission denial");
            assert_kernel_owned_field_refused(response, &hook, &invocations, field);
        }
    }
}

#[test]
fn hook_forging_a_retained_reservation_is_refused_on_the_async_path() {
    let (mut kernel, request, _context, invocations) = fixture();
    let hook = RuntimeFieldHook::new(
        serde_json::json!({
            "admission_id": "hook-admission",
            "retained_destructive_lease_id": "lease-never-reserved",
            "reservations_retained_fail_closed": true
        }),
        false,
    );
    kernel.set_runtime_admission_hook(hook.clone());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime");
    let response = runtime
        .block_on(kernel.evaluate_tool_call_with_metadata(&request, None))
        .expect("runtime admission denial");
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(response.reason.as_deref(), Some(KERNEL_OWNED_FIELD_REFUSAL));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let signed = response.receipt.metadata.as_ref().expect("denial metadata");
    assert!(signed
        .pointer("/chio_runtime/retained_destructive_lease_id")
        .is_none());
    assert!(signed
        .pointer("/chio_runtime/reservations_retained_fail_closed")
        .is_none());
    assert_eq!(
        signed.pointer("/runtime_admission/field"),
        Some(&serde_json::json!("retained_destructive_lease_id"))
    );
    assert_eq!(hook.released(), vec![hook.metadata()]);
}

#[test]
fn hook_writing_only_shared_runtime_fields_is_admitted() {
    let (mut kernel, request, _context, invocations) = fixture();
    let hook = RuntimeFieldHook::new(
        serde_json::json!({
            "admission_id": "hook-admission",
            "accepted": true,
            "reservation_release_failed": false
        }),
        true,
    );
    kernel.set_runtime_admission_hook(hook.clone());
    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("runtime admission allow");
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let signed = response.receipt.metadata.as_ref().expect("allow metadata");
    assert_eq!(
        signed.pointer("/chio_runtime/admission_id"),
        Some(&serde_json::json!("hook-admission"))
    );
}
