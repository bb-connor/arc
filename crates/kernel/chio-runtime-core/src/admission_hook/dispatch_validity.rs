//! Earliest exclusive deadline of the exact artifacts already verified by the
//! runtime hook. This module neither verifies signatures nor issues authority.

use super::*;
use chio_kernel::admission_operation::runtime_participant::RuntimeDispatchValidity;

impl<S: RuntimeAdmissionStore + Send + Sync> ChioRuntimeAdmissionHook<S> {
    pub(super) fn native_dispatch_validity(
        &self,
        now_unix_ms: u64,
        artifact_valid_until_unix_ms: u64,
    ) -> Result<RuntimeDispatchValidity, KernelError> {
        let mut until = self
            .profile
            .expires_at_unix_ms
            .min(artifact_valid_until_unix_ms);
        if let Some(trust) = &self.runtime_trust_input {
            until = until
                .min(trust.body.expires_at_unix_ms)
                .min(self.selected_key_deadline(
                    &trust.body.verifier_id,
                    &trust.body.key_id,
                    &trust.signer_key,
                )?);
        }
        if let Some(policy) = &self.runtime_pheromone_policy {
            let weights = self
                .runtime_peer_weights
                .as_ref()
                .ok_or_else(|| invalid("missing verified runtime weights"))?;
            let report = self
                .pheromone_query_report
                .as_ref()
                .ok_or_else(|| invalid("missing verified runtime query report"))?;
            let advisory =
                crate::serde_io::runtime_pheromone_advisory_from_query_report_value(&report.body)
                    .map_err(|_| invalid("invalid verified runtime query report"))?;
            // Policy permits age == max_age. Convert that inclusive boundary to
            // an exclusive millisecond deadline with checked arithmetic.
            let report_until = advisory
                .evaluated_at_unix_ms
                .checked_add(policy.body.max_query_report_age_ms)
                .and_then(|last_valid| last_valid.checked_add(1))
                .ok_or_else(|| invalid("runtime query report deadline overflow"))?;
            until = until
                .min(policy.body.expires_at_unix_ms)
                .min(weights.body.expires_at_unix_ms)
                .min(report_until)
                .min(self.selected_key_deadline(
                    &policy.body.verifier_id,
                    &policy.body.key_id,
                    &policy.signer_key,
                )?)
                .min(self.selected_key_deadline(
                    &weights.body.verifier_id,
                    &weights.body.key_id,
                    &weights.signer_key,
                )?);
        }
        RuntimeDispatchValidity::new(now_unix_ms, until)
            .map_err(|error| invalid(&error.to_string()))
    }

    fn selected_key_deadline(
        &self,
        verifier_id: &str,
        key_id: &str,
        signer: &PublicKey,
    ) -> Result<u64, KernelError> {
        // Match exactly the key selected by the signature verifier. Unrelated
        // expired keys neither extend nor shorten the admitted artifact's life.
        self.trusted_verifier_keys
            .iter()
            .find(|key| {
                key.verifier_id == verifier_id && key.key_id == key_id && key.public_key == *signer
            })
            .map(|key| key.valid_until_unix_ms)
            .ok_or_else(|| invalid("runtime dispatch lost its verified signing key"))
    }
}

fn invalid(message: &str) -> KernelError {
    KernelError::DurableAdmission(message.into())
}
