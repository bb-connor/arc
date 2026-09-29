# Fresh final review

Reviewer: one gpt-6-astra agent at high reasoning, fresh context, read-only.
Range: 7177be5092..0daaf44a59. No second review requested.

Two P2 findings blocked approval of the declared durable-linkage checker:

1. Native commands could substitute fencing token, lease owner, expiry or effect
   kind without changing signed receipts. Fabricated idempotency keys passed if
   copied into their events. Bind the complete request to plan and signed
   mutation; derive its expected command identity.
2. Intermediate response-commit body hashes were unchecked. Replacing the first
   atomic commit hash with zeroes passed. Include canonical committed snapshots
   and validate every hash and mutation prefix.

The author reproduced all six reported acceptance failures before the fix pass.
The initial 16-mutation suite and retention checker tests passed in review.
No further blocking issue was found in sync observation lifetime or the stated
revocation projection/fairness argument.

The reviewer declined to judge historical retention root cause/scale completion;
process/power-loss recovery, concurrency and other effect families; trusted
operator capture with a public fixture key; mechanized refinement/Rust equivalence
or the old temporal query; hosted/release/operator acceptance. The author retained
these explicit scope limits and recorded each ruling and its cost in the ledger.
