//! Classified input is resolved by the physical writer under its actual lease.
use super::*;
use crate::admission_operation::NativeSecurityInputJoinRequestV1;

impl NativeSecurityFlowJoinAuthority<'_> {
    /// Join classified input plus all inherited native labels into each of the
    /// principal, lineage and session rows. The hook supplies only an input
    /// label. Identity, operation, transition, selected authority and the actual
    /// lease remain kernel-owned. Shares the single-attempt rule with raw joins.
    pub fn join_input(
        &self,
        input_label: InformationLabel,
    ) -> Result<FlowStateSnapshot, KernelError> {
        self.attempt(|| {
            let input = NativeSecurityInputJoinRequestV1::new(
                self.admission.operation.binding().operation_id().clone(),
                self.key(),
                input_label,
            )
            .map_err(durable_store_error)?;
            self.with_join_custody(|runtime, lease, now| {
                let operation = &self.admission.operation;
                let acknowledged = store_call(|| {
                    runtime.store.join_native_security_input(
                        operation,
                        lease,
                        &self.binding,
                        self.context,
                        &input,
                        now,
                    )
                });
                // Inspect independently even after failure or panic. A durable
                // write does not turn a lost acknowledgement into success.
                let history = store_call(|| {
                    runtime.store.load_native_security_input_join(
                        operation.binding().operation_id(),
                        &runtime.fence,
                        now,
                    )
                });
                let acknowledged = acknowledged?;
                let (current, history) =
                    history?.ok_or_else(|| invalid("native input operation readback is absent"))?;
                let history = history
                    .ok_or_else(|| invalid("native input preparation has no recorded join"))?;
                if current != *operation
                    || history != acknowledged
                    || history.input != input
                    || history.join.binding != self.binding
                    || history.join.operation_id != *operation.binding().operation_id()
                {
                    return Err(invalid(
                        "native input acknowledgement differs from original intent history",
                    ));
                }
                history.validate().map_err(durable_store_error)?;
                let snapshot = history.join.snapshot.clone();
                self.confirm(history.join)?;
                Ok(snapshot)
            })
        })
    }
}
