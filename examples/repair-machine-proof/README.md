# Paused machine-proof experiment

This independent workspace is an unfinished experiment in verifying Cartesi
machine transitions with RISC Zero. It is outside the Chio workspace and is
not an implemented repair verification or settlement service.

The release build was stopped before completion when work shifted to
interoperability between separately operated organizations. No proof was
generated or verified. The guest repair checker has not executed successfully.
Minimal Python ran in the experimental Linux image; the larger import probe
reached its cycle limit without completing. A cycle-limit exit is not a pass.

The adapter intends to reject development-mode and fake receipts. Even a valid
machine-transition proof would still need a verified application binding from
the agreed checker and input through to the complete execution and output.
The source here does not establish that binding. See the retained repair
exchange's trusted-operator boundary in
[report 26](../../docs/papers/review-2026-09/26-checked-repair-exchange.md).
