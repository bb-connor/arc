//! Finalize already claimed preparation without touching legacy replay state.

use super::*;

impl PreparedRuntimeAdmission {
    pub(crate) fn destructive_resource(&self) -> Option<(&str, &str)> {
        self.bundle.destructive.then_some(()).and_then(|()| {
            self.bundle
                .lease_id
                .as_deref()
                .map(|id| (id, self.bundle_digest.as_str()))
        })
    }

    /// Called only after the kernel confirms the exact operation-owned claim.
    /// Trust-floor CAS is real mutable authority, never replaced by a successful
    /// replay adapter. On failure, the kernel retains and releases claim custody.
    pub(crate) fn commit_operation_owned(
        mut self,
        store: &dyn RuntimeAdmissionStore,
    ) -> Result<RuntimeAdmissionReport, ChioRuntimeError> {
        if let Some((entry, previous_hash)) = self.trust_floor_update.take() {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                store.validate_and_record_runtime_trust_floor(entry, previous_hash.as_deref())
            })) {
                Ok(Ok(())) => self.checks.push(passed("runtime_trust.floor")),
                Ok(Err(ChioRuntimeError::Rejected { code, .. })) => {
                    return Ok(rejected_report(
                        self.report_schema,
                        &self.admission_id,
                        code,
                        self.checks,
                    ))
                }
                Ok(Err(error)) => return Err(error),
                Err(_) => {
                    return Ok(rejected_report(
                        self.report_schema,
                        &self.admission_id,
                        "runtime_trust_floor_error",
                        self.checks,
                    ))
                }
            }
        }
        self.operation_owned_report()
    }

    /// Reuse a committed trust floor without another CAS or replay mutation.
    /// The hook separately verifies the kernel-loaded original claim intent.
    pub(crate) fn resume_operation_owned(
        mut self,
        store: &dyn RuntimeAdmissionStore,
    ) -> Result<RuntimeAdmissionReport, ChioRuntimeError> {
        if let Some((entry, previous_hash)) = self.trust_floor_update.take() {
            let retained = store.runtime_trust_floor(&entry.verifier_id, &entry.key_id)?;
            validate_runtime_trust_floor_transition(
                retained.clone(),
                &entry,
                previous_hash.as_deref(),
            )?;
            if retained.as_ref() != Some(&entry) {
                return Err(ChioRuntimeError::Rejected {
                    code: "runtime_trust_floor_changed",
                    detail: "reserved operation lost its original trust floor".into(),
                });
            }
            self.checks.push(passed("runtime_trust.floor"));
        }
        self.operation_owned_report()
    }

    fn operation_owned_report(mut self) -> Result<RuntimeAdmissionReport, ChioRuntimeError> {
        self.checks.push(passed("runtime.operation_owned_replay"));
        if self.bundle.destructive {
            self.checks.push(passed("destructive.lease_reserved"));
        }
        let mut metadata = receipt_metadata(
            self.report_schema,
            &self.bundle,
            true,
            None,
            None,
            self.pheromone_advisory.as_ref(),
            self.policy_decision.as_ref(),
        );
        if let Some(runtime) = metadata
            .get_mut("chio_runtime")
            .and_then(serde_json::Value::as_object_mut)
        {
            runtime.remove("reserved_destructive_lease_id");
        }
        Ok(RuntimeAdmissionReport {
            schema: self.report_schema.to_owned(),
            admission_id: self.admission_id,
            accepted: true,
            failure_code: None,
            checks: self.checks,
            pheromone_advisory: self.pheromone_advisory,
            pheromone_policy_decision: self.policy_decision,
            receipt_metadata: metadata,
        })
    }
}
