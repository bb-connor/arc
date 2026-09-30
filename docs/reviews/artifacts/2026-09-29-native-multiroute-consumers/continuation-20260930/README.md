# September 30 consumer continuation evidence

The [execution record](../../../2026-09-29-native-multiroute-consumers-execution.md)
contains the task states, changed contracts and remaining roadmap boundary.
The preceding partial evidence remains archived; its root README now links here.

`verification-index.json` records terminal acceptance and limitations. Local and
native logs are separate gzip streams. Reports are copied from successfully
completed campaign exports. A nonempty log is not evidence of a pass; earlier
failures and the optional interrupted control-plane rerun remain explicit.

`local-source.json`, `native-source.json` and `source-differences.json` bind the
current local checkout and final native build sources over their common base.
Production differences are import ordering and an EOF whitespace cleanup; other
differences are CI, docs,
fixtures and test assertions. `source-native-final.json` is the earlier build
snapshot, retained for the static helper/adapter and preceding CLI evidence.
`binaries-and-wheels.json` identifies immutable CLI generations 1 through 9,
static cage/MCP helpers, privileged adapters, the broker test helper and final
wheels. Image records name distinct earlier and final installed wheel generations.
Use the campaign's own binary/image fields; do not attribute old runs to CLI9.
This is bounded dirty-source qualification, not exact-final-commit hosted CI.

`review.md` records the independent review findings and repairs.
`attempt-dispositions.json` identifies the retained failed operations. Worker lifecycle
is recorded in `worker.json`. Private signing material, credential files and
original authority/recovery databases remain on the retained worker. They are
not included here. `SHA256SUMS` hashes all archived files except itself.

Failed native attempts are retained for: missing interpreter/syscall closure,
read/write ownership, installed-venv protection, missing package prerequisites,
Unix socket path limits, the MCP natural-exit race, and both classification
bounds. Public-repository attempt 4 passed the first large response and restart
replay, then refused capture of the next command when repeated decoding of the
retained output exhausted its existing fence. Attempt 5 exposed the enclosing projection/release verifier still loading
and decoding the payload repeatedly. The consolidated projection reader shares
one decoded payload for those checks while retaining every canonical, binding
and custody check. None of the failed operations was redispatched. The comparison run made while compilation consumed the worker reached
five completed operations, then retained the sixth as dispatch-committed after
handoff refusal. A fresh campaign under an idle build environment supplies the
comparison acceptance; it never reuses that uncertain operation.

The public fixture directory on the worker is named `itsdangerous-native`, but
its contents are the public `psf/requests` v2.32.3 checkout. Its report records the
actual commit and source archive hash. No real provider account was called;
provider decisions are controlled HTTPS fixtures with the production broker and
host-owned adapters.
