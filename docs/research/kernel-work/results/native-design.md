# Native correspondence experiment design

Recorded before new test code, 2026-10-02. Source baseline:
`188031256600903676eb69bda3144b9e8a1660da`. Recovery specification remains the
shipped-assumed PR #1172 revision `de84fc306efbb4c8dd6de748d0ad2a8d695fd30e`.

The smallest available seam is `ProcessRuntime::invoke` through durable SQLite
admission to a `ToolServerConnection`. Add an owning integration test, with no
production API changes. Each owner has a distinct signing key, authority store,
process journal and caller process. A separate endpoint process records and
fsyncs physical effects. The driver can inspect that log; the recovering kernel
cannot. Transport is a loopback test protocol, without a claim of authenticated
federation or independent administration.

Run two-owner and three-owner schedules. Kill the first owner before admission,
at tool entry before send, after the endpoint effect but before return, after
persisted outcome but before application release, and after application release.
Resume from identical retained requests twice. Other owners must complete their
authorized operations while the first remains unknown. Compare native process
charges, signed receipt identities and physical counts. Rebinding source bytes,
source version, recipient, request identity or capability must not redispatch.
Output from an unknown effect must remain absent.

The tool-entry cut is after native dispatch capture. There is no new hook at
every internal intent/capture transaction instruction. Existing durable-admission
tests cover those logical cuts separately; do not label them real process death.
Application receipt release is not the PR's universal artifact-release mediator.
No cross-owner money or approval theorem follows from separate durable owners.

Include a deliberately nonqualifying connector that submits twice during one
native invocation. The endpoint should count two effects. This tests whether
the model's one-send premise needs explicit connector qualification: a kernel
cannot count calls hidden below its `ToolServerConnection` boundary. Keep this
counterexample in results, and reject any unconditional one-external-effect
claim. Do not weaken the matched B1 comparison or silently repair production
connectors outside their ownership.

Design review: the planned observation channel is outside the caller process;
all crash points are named by their actual API boundary. Surviving replay must
use the original request and nonce. Successful sibling operations prevent a
deny-all result from passing. Counterexample and unavailable boundaries remain
visible in the Task 5 disposition. This is the implementer's design review;
a fresh reviewer assesses the final experiment and interpretation.
