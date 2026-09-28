//! Portable evaluation wiring and trusted-time refusal boundary.
use super::*;

impl ChioKernel {
    /// Run the portable pure-compute verdict path provided by
    /// `chio-kernel-core`.
    ///
    /// This exposes the same synchronous checks the core kernel performs
    /// (capability signature, issuer trust, time bounds, subject binding,
    /// scope match, sync guard pipeline) in isolation from the
    /// `chio-kernel`-only concerns (budget mutation, revocation lookup,
    /// governed-transaction evaluation, tool dispatch, receipt
    /// persistence).
    ///
    /// Adapters that run the kernel on constrained platforms (wasm32,
    /// edge workers, mobile via FFI) should prefer this entry point --
    /// it does not require a tokio runtime, a sqlite database, or any
    /// IO adapter. The full `evaluate_tool_call_*` API remains the
    /// authoritative path for the desktop sidecar.
    ///
    /// Verified-core boundary note:
    /// `formal/proof-manifest.toml` treats this shell method as the one
    /// `chio-kernel` entrypoint inside the current bounded verified core,
    /// because it delegates directly to `chio_kernel_core::evaluate` after
    /// supplying trusted issuers and portable guard/context wiring.
    pub fn evaluate_portable_verdict<'a>(
        &self,
        capability: &'a CapabilityToken,
        request: &chio_kernel_core::PortableToolCallRequest,
        guards: &'a [&'a dyn chio_kernel_core::Guard],
        clock: &'a dyn chio_kernel_core::Clock,
        session_filesystem_roots: Option<&'a [String]>,
    ) -> chio_kernel_core::EvaluationVerdict {
        let trusted = self.trusted_issuer_keys();
        let now = match clock.unix_millis() {
            Ok(now) => now.as_secs(),
            Err(error) => {
                return chio_kernel_core::EvaluationVerdict {
                    verdict: chio_kernel_core::Verdict::Deny,
                    reason: Some(format!("trusted clock refused: {error}")),
                    matched_grant_index: None,
                    verified: None,
                };
            }
        };
        let peer_profile = match self.capability_negotiation_for_remote(None, now) {
            Ok(profile) => profile,
            // Fail closed: a negotiation error denies rather than falling back
            // to the permissive default profile.
            Err(reason) => {
                return chio_kernel_core::EvaluationVerdict {
                    verdict: chio_kernel_core::Verdict::Deny,
                    reason: Some(format!(
                        "capability negotiation failed; denying fail-closed: {reason}"
                    )),
                    matched_grant_index: None,
                    verified: None,
                };
            }
        };
        let trust_resolver = self.capability_trust_root_resolver_snapshot();
        let direct_root = match self.negotiated_capability_root(capability, &peer_profile) {
            Ok(root) => root,
            Err(reason) => {
                return chio_kernel_core::EvaluationVerdict {
                    verdict: chio_kernel_core::Verdict::Deny,
                    reason: Some(reason),
                    matched_grant_index: None,
                    verified: None,
                };
            }
        };
        let ancestors = match self.signed_capability_ancestors(capability) {
            Ok(ancestors) => ancestors,
            Err(reason) => {
                return chio_kernel_core::EvaluationVerdict {
                    verdict: chio_kernel_core::Verdict::Deny,
                    reason: Some(reason),
                    matched_grant_index: None,
                    verified: None,
                };
            }
        };
        let mut budgets = match self.budget_registry.lock() {
            Ok(guard) => guard,
            Err(_poisoned) => {
                // The monetary lock is poisoned: a panic left the registry in an
                // unknown state. Deny fail-closed and trip the degraded flag so
                // later evaluations are denied at the pre-dispatch gate too.
                self.record_tcb_lock_poison("budget_registry");
                return chio_kernel_core::EvaluationVerdict {
                    verdict: chio_kernel_core::Verdict::Deny,
                    reason: Some("budget registry lock poisoned; denying fail-closed".to_string()),
                    matched_grant_index: None,
                    verified: None,
                };
            }
        };
        chio_kernel_core::evaluate_with_full_floor_and_evidence(
            chio_kernel_core::EvaluateInput {
                request,
                capability,
                trusted_issuers: &trusted,
                clock,
                guards,
                session_filesystem_roots,
            },
            capability_crypto_floor(self.capability_crypto_floor),
            chio_kernel_core::CapabilityEvidenceContext {
                features: chio_kernel_core::CapabilityFeatureContext {
                    peer: &peer_profile,
                    direct_root: direct_root.as_ref(),
                },
                ancestors: &ancestors,
            },
            &trust_resolver,
            &mut *budgets,
        )
    }
}
