//! Read-only native flow observations, never activation or mutation authority.

use super::{
    AdmissionOperationStoreError, NativeSecurityAuthorityBindingV1, I_JSON_MAX_SAFE_INTEGER,
};
use chio_security_types::ports::{FlowStateKey, FlowStateSnapshot};

/// Data observed in one fenced store snapshot. It can become stale immediately;
/// every native mutation must independently recheck its operation, lease,
/// original selection and current rows. Constructing this value authenticates
/// nothing and grants no right to read, mutate, consume, release or dispatch.
///
/// An unjoined session may inherit effective labels from its principal and
/// lineage without having an exact flow-context row. Its effective snapshot
/// generation must not be mistaken for a stored context generation at admission.
#[derive(Clone, Eq, PartialEq)]
pub struct NativeSecurityFlowObservationV1 {
    binding: NativeSecurityAuthorityBindingV1,
    key: FlowStateKey,
    snapshot: Option<FlowStateSnapshot>,
    stored_context_generation: Option<u64>,
    observed_at_unix_ms: u64,
}

impl NativeSecurityFlowObservationV1 {
    pub fn new(
        binding: NativeSecurityAuthorityBindingV1,
        key: FlowStateKey,
        snapshot: Option<FlowStateSnapshot>,
        stored_context_generation: Option<u64>,
        observed_at_unix_ms: u64,
    ) -> Result<Self, AdmissionOperationStoreError> {
        if observed_at_unix_ms == 0
            || observed_at_unix_ms > I_JSON_MAX_SAFE_INTEGER
            || snapshot.as_ref().is_some_and(|snapshot| {
                snapshot.key != key
                    || snapshot.context_generation == 0
                    || snapshot.context_generation > I_JSON_MAX_SAFE_INTEGER
            })
            || stored_context_generation.is_some_and(|generation| {
                snapshot
                    .as_ref()
                    .map(|snapshot| snapshot.context_generation)
                    != Some(generation)
            })
        {
            return Err(AdmissionOperationStoreError::Invariant(
                "native flow observation is inconsistent".into(),
            ));
        }
        Ok(Self {
            binding,
            key,
            snapshot,
            stored_context_generation,
            observed_at_unix_ms,
        })
    }

    pub fn binding(&self) -> &NativeSecurityAuthorityBindingV1 {
        &self.binding
    }

    pub fn key(&self) -> &FlowStateKey {
        &self.key
    }

    /// Effective labels and generation, if the requested isolation epoch exists.
    /// Absence is not evidence that future inherited labels will be public.
    pub fn snapshot(&self) -> Option<&FlowStateSnapshot> {
        self.snapshot.as_ref()
    }

    /// Generation of the exact persisted context row, or absence before its
    /// first join. This is the observation native admission compares in SQL.
    pub fn stored_context_generation(&self) -> Option<u64> {
        self.stored_context_generation
    }

    pub fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }
}

impl std::fmt::Debug for NativeSecurityFlowObservationV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSecurityFlowObservationV1")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission_operation::{AdmissionDigest, AdmissionIdentifier};
    use chio_security_types::ports::{IsolationEpochId, LineageId, SessionId, TenantId};
    use chio_security_types::{InformationLabel, PrincipalId};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn sample(
    ) -> Result<(NativeSecurityAuthorityBindingV1, FlowStateSnapshot), Box<dyn std::error::Error>>
    {
        Ok((
            NativeSecurityAuthorityBindingV1::new(
                AdmissionIdentifier::try_new("store", "private-store")?,
                AdmissionIdentifier::try_new("authority", "private-authority")?,
                AdmissionDigest::try_new("initialization", "a".repeat(64))?,
            ),
            FlowStateSnapshot {
                key: FlowStateKey {
                    tenant_id: TenantId::new("private-tenant")?,
                    principal_id: PrincipalId::new("private-principal")?,
                    lineage_id: LineageId::new("private-lineage")?,
                    session_id: SessionId::new("private-session")?,
                    isolation_epoch_id: IsolationEpochId::new("private-epoch")?,
                },
                principal_label: InformationLabel::bottom(),
                lineage_label: InformationLabel::bottom(),
                session_label: InformationLabel::bottom(),
                context_generation: 3,
            },
        ))
    }

    #[test]
    fn effective_inherited_state_does_not_claim_a_persisted_context() -> TestResult {
        let (binding, snapshot) = sample()?;
        let inherited = NativeSecurityFlowObservationV1::new(
            binding.clone(),
            snapshot.key.clone(),
            Some(snapshot.clone()),
            None,
            1000,
        )?;
        assert_eq!(inherited.snapshot(), Some(&snapshot));
        assert_eq!(inherited.stored_context_generation(), None);
        let stored = NativeSecurityFlowObservationV1::new(
            binding.clone(),
            snapshot.key.clone(),
            Some(snapshot.clone()),
            Some(3),
            1000,
        )?;
        assert_eq!(stored.stored_context_generation(), Some(3));
        let absent = NativeSecurityFlowObservationV1::new(binding, snapshot.key, None, None, 1000)?;
        assert!(absent.snapshot().is_none());
        assert_eq!(absent.observed_at_unix_ms(), 1000);
        Ok(())
    }

    #[test]
    fn inconsistent_key_generation_or_time_cannot_construct_an_observation() -> TestResult {
        let (binding, snapshot) = sample()?;
        for generation in [0, 2, 4, I_JSON_MAX_SAFE_INTEGER + 1] {
            assert!(NativeSecurityFlowObservationV1::new(
                binding.clone(),
                snapshot.key.clone(),
                Some(snapshot.clone()),
                Some(generation),
                1000
            )
            .is_err());
        }
        for time in [0, I_JSON_MAX_SAFE_INTEGER + 1] {
            assert!(NativeSecurityFlowObservationV1::new(
                binding.clone(),
                snapshot.key.clone(),
                Some(snapshot.clone()),
                Some(3),
                time
            )
            .is_err());
        }
        for generation in [0, I_JSON_MAX_SAFE_INTEGER + 1] {
            let mut invalid = snapshot.clone();
            invalid.context_generation = generation;
            assert!(NativeSecurityFlowObservationV1::new(
                binding.clone(),
                snapshot.key.clone(),
                Some(invalid),
                None,
                1000
            )
            .is_err());
        }
        assert!(NativeSecurityFlowObservationV1::new(
            binding.clone(),
            snapshot.key.clone(),
            None,
            Some(3),
            1000
        )
        .is_err());
        let mut other = snapshot.key.clone();
        other.session_id = SessionId::new("different")?;
        assert!(
            NativeSecurityFlowObservationV1::new(binding, other, Some(snapshot), None, 1000)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn observation_debug_does_not_expose_scope_or_labels() -> TestResult {
        let (binding, snapshot) = sample()?;
        let observation = NativeSecurityFlowObservationV1::new(
            binding.clone(),
            snapshot.key.clone(),
            Some(snapshot),
            Some(3),
            1000,
        )?;
        assert_eq!(observation.binding(), &binding);
        assert!(!format!("{observation:?}").contains("private"));
        Ok(())
    }
}
