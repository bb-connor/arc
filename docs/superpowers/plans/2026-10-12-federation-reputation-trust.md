# Federation reputation trust selection

Reconcile FEDERATION-RAW-SIGNER against main `66f976ab27` before changing code.
The existing issuance contract excludes keys outside the admitted authority
view. Federation reputation evaluation must use that same trust boundary
without loading private signing custody just to verify receipts.

1. Add expected-safe controls for receipts signed by a recovered authority and
   by its displaced local key. Exercise the real policy evaluator and receipt
   store, with a fixed trusted clock. Preserve the Original result.
2. If confirmed, obtain receipt-verification keys from the admitted service
   authority. Fail closed when reputation is required and authority is
   unavailable. Preserve policies that do not require reputation.
3. Run the focused federation and authority controls, strict control-plane
   Clippy, and affected static inventories. Ask Claude to review, then publish
   a separate PR on main.

No changes to unrelated reputation consumers, receipt scoring, authority
activation, signing custody or repository settings are included.
