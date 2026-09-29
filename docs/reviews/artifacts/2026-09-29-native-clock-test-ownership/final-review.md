# Fresh final review

Reviewer: gpt-6-astra, high reasoning, read-only, no reviewer subagents.
Range: 8c8677470b6ff40491c0f66ac6aba31093be30bf..a8b5f11d3e.
Verdict: changes required. Two Important findings; no Critical or Minor findings.

1. Emergency stop reads fenced time before latching the kill switch. Clock
   rollback/unavailability can leave the flag false and permit execution after
   clock recovery without explicit resume. Latch independently of timestamp
   acquisition, represent absent time honestly, and cover recovery/resume.
2. The default-off runtime expiry cutpoint requires remaining lifetime below
   60000ms. The fixture's inclusive report age becomes an exclusive 60001ms
   deadline. Its setup guard rejects before the production expiry boundary.
   Correct the callback-only bound without changing authority windows.

Inspected clock paths retain skew checks, durable high-water checks, historical
report replay and final capture resampling. Clock locks are released before
inspected downstream store/effect calls. Fixture privacy and declaration
ownership follow the intended boundaries.

Qualification was incomplete at review: native campaign still running, with
runtime-expiry and broker peer timeout failures. Existing kernel inventory
preserved1491 tests.

Declined to judge, requiring executor rulings:
- Root cause and adequacy of broker transport timeout repair: executor diagnosing;
  the frozen review establishes failure, not the proposed repair.
- PQ-only execution, hosted qualification, publication compatibility and measured
  cost of added broker read transactions: outside supplied local qualification.

No merge, release or operational readiness assertion. No checkout mutations.
