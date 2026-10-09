# #1160 lands with KANI-PROOF-QUAL as an explicit residual

Decided by Connor on 2026-10-09. The full-domain Kani proof of attestation-encoding non-collision (KANI-PROOF-QUAL, P1 in #1160's landing ledger) cannot complete with available resources: Z3 exhausts memory at a 26 GiB cap, CVC5 is OOM-killed at a kernel-enforced 10 GiB, and a partial-domain probe timed out; partitioning is not shown feasible. The other proofs pass (both final typed receipt-hash proofs).

Ruling: amend the landing ledger to record KANI-PROOF-QUAL as an open residual, not a passed obligation. No release claim (including D8 previews under ADR-0011) may state or rely on that property as formally proven. Existing tests and any bounded-domain evidence stand meanwhile. Follow-up item KANI-ATTEST-DECOMP (P1) owns a feasible decomposition. #1160 then proceeds to landing candidate, the planner's delta review, the gate and merge.
