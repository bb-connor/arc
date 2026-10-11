use super::*;

#[test]
fn caller_wait_transitions_require_nonce_owned_tool_dispatch_and_never_reopen_a_terminal() {
    for kind in AdmissionOperationKind::ALL {
        for execution_nonce in [false, true] {
            let mut requirements = binding(kind).participant_requirements();
            requirements.execution_nonce = execution_nonce;
            let permitted = kind == AdmissionOperationKind::ToolDispatch
                && execution_nonce
                && requirements.budget_capture;
            for (from, to) in [
                (
                    AdmissionOperationState::DispatchCommitted,
                    AdmissionOperationState::AwaitingCallerReport,
                ),
                (
                    AdmissionOperationState::AwaitingCallerReport,
                    AdmissionOperationState::Finalizing,
                ),
            ] {
                assert_eq!(is_legal_transition(kind, requirements, from, to), permitted);
            }
            for from in AdmissionOperationState::ALL
                .into_iter()
                .filter(|state| state.is_terminal())
            {
                assert!(!is_legal_transition(
                    kind,
                    requirements,
                    from,
                    AdmissionOperationState::AwaitingCallerReport
                ));
            }
        }
    }
}
