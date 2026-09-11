//! Retain policy and physical participants without converting history to authority.
use super::*;
use crate::admission_operation::{
    NativeSecurityDispatchLedgerContext, NativeSecurityDispatchLedgerRecordV1,
};

impl<'a> PreparedNativeSecurityEgress<'a> {
    /// Retain preparation without discarding its affine live handle. Dedicated
    /// capture must still verify credentials and physical freshness atomically.
    pub fn retain_for_capture(
        self,
        egress_expires_at_unix_ms: Option<u64>,
        grant_index: usize,
        policy_json: &[u8],
    ) -> Result<
        (
            Self,
            Option<NativeSecurityEgressHistoryV1>,
            NativeSecurityDispatchLedgerRecordV1,
        ),
        KernelError,
    > {
        self.validate_ledger_input(grant_index, policy_json)?;
        let (prepared, history) = if let Some(expires) = egress_expires_at_unix_ms {
            let acquired = self.acquire(expires)?;
            let history = acquired.commit_current()?;
            (acquired.prepared, Some(history))
        } else {
            (self, None)
        };
        let ledger = prepared.retain_dispatch_ledger_current(grant_index, policy_json)?;
        Ok((prepared, history, ledger))
    }

    /// Validate immutable journal inputs before acquiring any egress custody.
    /// Acquisition, commitment and journal retention remain separate durable
    /// writes. A later failure does not erase an earlier successful phase.
    pub fn acquire_and_commit_with_dispatch_ledger(
        self,
        expires_at_unix_ms: u64,
        grant_index: usize,
        policy_json: &[u8],
    ) -> Result<
        (
            NativeSecurityEgressHistoryV1,
            NativeSecurityDispatchLedgerRecordV1,
        ),
        KernelError,
    > {
        self.validate_ledger_input(grant_index, policy_json)?;
        self.acquire(expires_at_unix_ms)?
            .commit_with_dispatch_ledger(grant_index, policy_json)
    }

    /// Retain a non-egress preparation. The writer requires the exact original
    /// operation, current policy observation and physical grant/participant set.
    /// This consumes the handle without capturing quota or invoking a connector.
    pub fn retain_dispatch_ledger(
        self,
        grant_index: usize,
        policy_json: &[u8],
    ) -> Result<NativeSecurityDispatchLedgerRecordV1, KernelError> {
        self.retain_dispatch_ledger_current(grant_index, policy_json)
    }

    fn validate_ledger_input(
        &self,
        grant_index: usize,
        policy_json: &[u8],
    ) -> Result<serde_json::Value, KernelError> {
        if u32::try_from(grant_index).is_err()
            || self.original.retained_matching_grant(grant_index).is_none()
        {
            return Err(invalid(
                "native dispatch ledger selected an unmatched grant",
            ));
        }
        if policy_json.is_empty() || policy_json.len() > 256 * 1024 {
            return Err(invalid("native dispatch policy exceeds its bound"));
        }
        let policy: serde_json::Value = serde_json::from_slice(policy_json)
            .map_err(|_| invalid("native dispatch policy is not JSON"))?;
        if canonical_json_bytes(&policy)
            .map_err(|_| invalid("native dispatch policy is not canonical"))?
            != policy_json
        {
            return Err(invalid("native dispatch policy is not canonical"));
        }
        Ok(policy)
    }

    fn retain_dispatch_ledger_current(
        &self,
        grant_index: usize,
        policy_json: &[u8],
    ) -> Result<NativeSecurityDispatchLedgerRecordV1, KernelError> {
        let policy = self.validate_ledger_input(grant_index, policy_json)?;
        let runtime = self.kernel.durable_runtime()?;
        let _guard = runtime.lock_mutations()?;
        let now = runtime.refresh_trusted_time(self.observation.observed_at_unix_ms());
        self.revalidate(runtime, now)?;
        let lease = self.kernel.claim_admission_recovery(&self.operation, now)?;
        let acknowledged = store_call(|| {
            runtime
                .store
                .retain_native_dispatch_ledger(NativeSecurityDispatchLedgerContext {
                    custody: self.command_context(&lease, now),
                    grant_index,
                    policy_json,
                })
        });
        // Always read after attempting a write, including a lost acknowledgement.
        // Historical presence cannot turn an unconfirmed call into success.
        let loaded = store_call(|| {
            runtime
                .store
                .load_native_dispatch_ledger(self.operation_id(), &runtime.fence, now)
        });
        let acknowledged = acknowledged?;
        let loaded = loaded?.ok_or_else(|| invalid("native dispatch ledger readback is absent"))?;
        if loaded != acknowledged {
            return Err(invalid(
                "native dispatch ledger acknowledgement differs from readback",
            ));
        }
        self.validate_ledger(&loaded, grant_index, &policy)?;
        let after = runtime.refresh_trusted_time(now);
        self.revalidate(runtime, after)?;
        if store_call(|| {
            runtime
                .store
                .load_native_dispatch_ledger(self.operation_id(), &runtime.fence, after)
        })?
        .as_ref()
            != Some(&loaded)
        {
            return Err(invalid(
                "native dispatch ledger changed during confirmation",
            ));
        }
        Ok(loaded)
    }

    fn validate_ledger(
        &self,
        record: &NativeSecurityDispatchLedgerRecordV1,
        grant_index: usize,
        policy: &serde_json::Value,
    ) -> Result<(), KernelError> {
        if record.operation_id != *self.operation_id()
            || record.canonical_record.is_empty()
            || record.canonical_record.len() > 1024 * 1024
            || record.record_digest.as_str() != sha256_hex(&record.canonical_record)
        {
            return Err(invalid(
                "native dispatch ledger returned invalid bounded evidence",
            ));
        }
        let value: serde_json::Value = serde_json::from_slice(&record.canonical_record)
            .map_err(|_| invalid("native dispatch ledger is not JSON"))?;
        let operation = serde_json::to_value(self.operation.to_persisted())
            .map_err(|_| invalid("native dispatch operation cannot encode"))?;
        let context = serde_json::to_value(&self.context)
            .map_err(|_| invalid("native dispatch context cannot encode"))?;
        if canonical_json_bytes(&value)
            .map_err(|_| invalid("native dispatch ledger is not canonical"))?
            != record.canonical_record
            || value.get("schema").and_then(serde_json::Value::as_str)
                != Some("chio.native-dispatch-preparation-ledger.v1")
            || value.get("operation") != Some(&operation)
            || value.get("context") != Some(&context)
            || value.get("policy") != Some(policy)
            || value.get("grant_index").and_then(serde_json::Value::as_u64)
                != u64::try_from(grant_index).ok()
            || value
                .get("live_request_digest")
                .and_then(serde_json::Value::as_str)
                != Some(self.live_request_hash.as_str())
        {
            return Err(invalid(
                "native dispatch ledger changed the prepared command",
            ));
        }
        Ok(())
    }
}

impl AcquiredNativeSecurityEgress<'_> {
    /// Confirm egress, then retain its exact policy and participant ledger. A
    /// failure keeps historical custody visible to recovery and grants no permit.
    pub fn commit_with_dispatch_ledger(
        self,
        grant_index: usize,
        policy_json: &[u8],
    ) -> Result<
        (
            NativeSecurityEgressHistoryV1,
            NativeSecurityDispatchLedgerRecordV1,
        ),
        KernelError,
    > {
        // The caller may already own acquisition. Reject malformed immutable
        // inputs before adding a commitment, without undoing that acquisition.
        self.prepared
            .validate_ledger_input(grant_index, policy_json)?;
        let history = self.commit_current()?;
        let record = self
            .prepared
            .retain_dispatch_ledger_current(grant_index, policy_json)?;
        Ok((history, record))
    }
}
