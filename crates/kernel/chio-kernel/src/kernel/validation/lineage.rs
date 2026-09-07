//! Signed capability lineage resolution and parent registration.

use super::*;

impl ChioKernel {
    /// Resolve original signed intermediate scopes. Legacy scalar snapshots
    /// cannot serve as evidence for a narrowed recursive chain.
    pub(super) fn signed_capability_ancestors(
        &self,
        cap: &CapabilityToken,
    ) -> Result<Vec<CapabilityToken>, String> {
        if cap.delegation_chain.len() <= 1 || !cap.requires_chain_binding() {
            return Ok(Vec::new());
        }
        if cap.delegation_chain.len() > self.config.max_delegation_depth as usize {
            return Err("delegation chain exceeds configured maximum depth".to_string());
        }
        cap.delegation_chain
            .iter()
            .map(|link| {
                let snapshot = self
                    .with_receipt_store(|store| {
                        Ok(store.get_capability_snapshot(&link.capability_id)?)
                    })
                    .map_err(|error| format!("signed ancestor lookup failed: {error}"))?
                    .flatten()
                    .ok_or_else(|| format!("missing signed ancestor {}", link.capability_id))?;
                snapshot.signed_capability.ok_or_else(|| {
                    format!(
                        "ancestor {} has no signed token evidence",
                        link.capability_id
                    )
                })
            })
            .collect()
    }

    /// Resolve the signed root token that the negotiated family-budget verifiers
    /// require for a delegated capability.
    ///
    /// Migration prerequisite: once a peer negotiates either family budget feature,
    /// every delegated capability from that peer needs a receipt-store snapshot
    /// carrying `signed_capability` for its root. Snapshots written before signed
    /// token retention carry no signed token, so enabling a feature against a store
    /// that still holds them denies those capabilities with "has no signed token
    /// evidence", which is distinct from the missing-row and tamper reasons.
    /// Backfill signed root snapshots before turning either feature on.
    pub(crate) fn negotiated_capability_root(
        &self,
        cap: &CapabilityToken,
        peer: &chio_core::capability::features::CapabilityNegotiation,
    ) -> Result<Option<CapabilityToken>, String> {
        let features = &peer.features;
        let lineage_required = features
            .get(chio_core::capability::features::AGGREGATE_INVOCATION_BUDGET)
            .copied()
            .unwrap_or(false)
            || features
                .get(chio_core::capability::features::CUMULATIVE_APPROVAL_BUDGET)
                .copied()
                .unwrap_or(false);
        if !lineage_required || cap.delegation_chain.is_empty() {
            return Ok(None);
        }

        let root_id = cap
            .delegation_chain
            .first()
            .map(|link| link.capability_id.as_str())
            .ok_or_else(|| "delegated capability has no root delegation link".to_string())?;
        let snapshot = self
            .with_receipt_store(|store| Ok(store.get_capability_snapshot(root_id)?))
            .map_err(|error| format!("failed to resolve signed capability root: {error}"))?
            .flatten()
            .ok_or_else(|| format!("missing signed capability root snapshot for {root_id}"))?;
        let signed_root = snapshot.signed_capability.ok_or_else(|| {
            format!("capability root snapshot {root_id} has no signed token evidence")
        })?;
        if signed_root.id != root_id {
            return Err(format!(
                "signed capability root {} does not match requested root {root_id}",
                signed_root.id
            ));
        }
        Ok(Some(signed_root))
    }

    /// Validate and retain a capability that will parent delegated work.
    /// Hosts may restore a process tree root-first before invoking its leaves.
    /// This performs the existing non-tool admission checks and records the
    /// verified ancestor snapshot without consuming an invocation budget.
    pub fn register_delegation_parent(
        &self,
        capability: &CapabilityToken,
    ) -> Result<(), KernelError> {
        self.validate_non_tool_capability(capability, &capability.subject.to_hex())?;
        self.record_observed_capability_snapshot(capability)?;
        self.register_budget_parent(
            capability.id.clone(),
            capability.budget_share_bps.unwrap_or(10_000),
        )
        .map_err(|error| KernelError::DelegationInvalid(error.to_string()))
    }
}
