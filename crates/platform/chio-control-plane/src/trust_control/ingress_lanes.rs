//! Non-queued blocking lanes for the JSON ingress middleware, which runs on
//! every contract route before its handler. Each check family owns one lane,
//! so load on one family can exhaust only its own permits. A lane's refusal is
//! the request's response: a refused request never reaches the next layer.

use super::*;

pub(super) const WALLET_ENTITLEMENT_AT_CAPACITY: &str =
    "passport issuance credential authentication is at capacity";
pub(super) const WALLET_ENTITLEMENT_INCOMPLETE: &str =
    "passport issuance credential authentication did not complete";

/// Wallet entitlement checks this node runs at once. Any caller that presents
/// a bearer token starts one, and each reads, decodes and verifies the whole
/// offers file, so four bound the blocking-pool threads and the offers-file
/// buffers, each at most `MAX_SIGNED_FILE_BYTES`, that such callers can hold.
/// Public redemption and operator registry writes use separate service lanes.
const WALLET_ENTITLEMENT_PERMITS: usize = 4;

/// One ingress check family's lane and the fixed refusals it answers with
/// when its check produces no decision.
#[derive(Clone, Debug)]
pub(crate) struct IngressLane {
    lane: BlockingLane,
    at_capacity: &'static str,
    incomplete: &'static str,
}

impl IngressLane {
    /// The wallet credential entitlement check: the offers file read, its
    /// decode and per-offer verification, and the access token lookup.
    pub(super) fn wallet_entitlement(capacity: usize) -> Self {
        Self {
            lane: BlockingLane::new("ingress_wallet_entitlement", capacity),
            at_capacity: WALLET_ENTITLEMENT_AT_CAPACITY,
            incomplete: WALLET_ENTITLEMENT_INCOMPLETE,
        }
    }

    /// Runs `check` on the blocking pool under a permit from this lane and
    /// returns its value, or this lane's refusal when it produced none.
    ///
    /// Admission never waits: without a free permit the refusal is a 503 and
    /// `check` never runs. The permit is released only after `check` has
    /// returned, so a check whose request was dropped keeps its permit until
    /// that check has ended.
    pub(super) async fn run<T: Send + 'static>(
        &self,
        check: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, Response> {
        match run_bounded_blocking(&self.lane, check).await {
            Ok(value) => Ok(value),
            Err(refusal @ BlockingLaneError::Saturated(_)) => {
                Err(plain_http_error(refusal.status(), self.at_capacity))
            }
            Err(refusal @ BlockingLaneError::Join(_)) => {
                Err(plain_http_error(refusal.status(), self.incomplete))
            }
        }
    }

    #[cfg(test)]
    pub(super) fn blocking_lane(&self) -> &BlockingLane {
        &self.lane
    }
}

/// A fresh service-owned lane for wallet credential entitlement checks.
pub(super) fn wallet_entitlement_lane() -> IngressLane {
    IngressLane::wallet_entitlement(WALLET_ENTITLEMENT_PERMITS)
}
