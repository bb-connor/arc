# chio-open-market Architecture

`chio-open-market` owns Chio open bidding plus market fee schedules, bond requirements, and penalty state machines. It depends on listing and governance artifacts, then adds economic constraints around publication fees, participation fees, collateral classes, holds, slashes, and reverse slashes.

Bidding verifies signed listings and pricing hints before minting scoped capability offers. The bid path must reject stale pricing, inactive listings, scope widening, token issuer mismatches, and total-cost overflow before an ask can be accepted.

Penalty evaluation verifies fee-schedule, governance, activation, listing, and penalty signatures before applying market rules. Evidence references are part of that authorization trail, so optional digests must be syntactically valid SHA-256 hex when present.
