include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/security/broker_parts/part_01.inc"
));
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/security/broker_parts/part_02.inc"
));
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/security/broker_parts/part_03.inc"
));

impl AuthoritativeBrokerExecutionAdapter {
    pub fn release_admission(&self, operation_id: &str) -> Result<bool, BrokerIntegrationError> {
        validate_identifier(operation_id, "broker operation id")?;
        let admission = self.registry.load_by_operation(operation_id)?;
        if let Some(admission) = admission.as_ref() {
            let operation = self
                .admission_operations
                .load(operation_id)?
                .ok_or_else(|| {
                    BrokerIntegrationError::Conflict(
                        "broker release outbox lost its durable kernel operation".to_string(),
                    )
                })?;
            if !matches!(
                operation.state(),
                AdmissionOperationState::CompensationPending
                    | AdmissionOperationState::CompensatedBeforeDispatch
            ) || operation.dispatch_state() != AdmissionDispatchState::NotStarted
                || operation.broker_attempt_id()
                    != Some(admission.registration.ids.attempt_id.as_str())
            {
                return Err(BrokerIntegrationError::Conflict(
                    "broker release requires the exact durable compensation-fenced operation"
                        .to_string(),
                ));
            }
            let acknowledgement = self
                .attempt_registration
                .release_attempt(&admission.registration, &admission.request)?;
            acknowledgement.validate_for(&admission.registration)?;
            let _ = self.registry.remove(operation_id)?;
        }
        Ok(admission.is_some())
    }
}
