# JVM Flink Integration Review: Correctness + Parity

## Summary

The Kotlin port is tight and faithful overall: the 14 parity invariants
are implemented with the same shapes and wire constants as the Python
reference, the test suite genuinely exercises each one, and the sync /
async split-path topology matches. Four concerns rise above nitpicks:
one semantic widening in the evaluator's exception catch that could
mask bugs as sidecar errors (P2), one byte-drift in `BodyCoercion` for
`null` elements (P2, unreachable in Flink today but lives in the DLQ
hot path), one metric-namespace divergence from the Python reference
(P2), and the `ChioClient.close()` no-op carries a behavior note rather
than a defect (P3). Tallies: 0 P1, 3 P2, 2 P3.

## Parity invariant checklist

| # | Invariant | Code location | Test | Status |
|---|---|---|---|---|
| 1 | Canonical JSON byte-equality | `CanonicalJson.kt:25-113` | `CanonicalJsonTest.kt:7-76` | OK |
| 2 | Deny emits only DLQ, no receipt | `ChioFlinkEvaluator.kt:151-175`, `ChioEvaluateFunction.kt:51-69`, `ChioVerdictSplitFunction.kt:28-44` | `ChioFlinkEvaluatorTest.kt:65-78`, `ChioEvaluateFunctionTest.kt:92-105`, `ChioVerdictSplitFunctionTest.kt:40-51`, `MiniClusterSyncJobIT.kt:61-66` | OK |
| 3 | `SYNTHETIC_RECEIPT_MARKER` in metadata (structural) | `SyntheticDenyReceipt.kt:22,63-67` | `SyntheticDenyReceiptTest.kt:9-11,53-70`, `ChioFlinkEvaluatorTest.kt:93-111` | OK |
| 4 | `[unsigned]` prefix idempotent | `SyntheticDenyReceipt.kt:47` | `SyntheticDenyReceiptTest.kt:13-36` | OK |
| 5 | Synthetic `kernelKey` / `signature` empty strings | `SyntheticDenyReceipt.kt:68-69` | `SyntheticDenyReceiptTest.kt:38-51` | OK |
| 6 | `subjectExtractor` required | `ChioFlinkConfig.kt:85-90` | `ChioFlinkConfigTest.kt:60-69` | OK |
| 7 | Tag names `chio-receipt` / `chio-dlq` | `ChioOutputTags.kt:17-18` | `ChioVerdictSplitFunctionTest.kt:13-16` | OK |
| 8 | Default prefix `chio-flink` | `ChioFlinkConfig.kt:48` | `ChioFlinkConfigTest.kt:26-33`, `ChioFlinkEvaluatorTest.kt:160-168` | OK |
| 9 | Fail-closed on sidecar error | `ChioFlinkEvaluator.kt:119-149` | `ChioFlinkEvaluatorTest.kt:80-111`, `ChioEvaluateFunctionTest.kt:107-141` | OK (see F1) |
| 10 | Narrow exception scoping | `ChioFlinkEvaluator.kt:97-149` | covered by evaluator deny/allow tests | Partial (see F1) |
| 11 | `maxInFlight` semaphore | `Slots.kt:14-75`, `ChioFlinkEvaluator.kt:76-81` | `ChioFlinkEvaluatorTest.kt:170-206` | OK |
| 12 | Factory pattern for client / DLQ router | `ChioFlinkConfig.kt:26-27,85-100`, `ChioFlinkEvaluator.kt:37-41` | `ChioFlinkConfigTest.kt:96-112` | OK |
| 13 | Counters + in-flight gauge | `ChioFlinkEvaluator.kt:42-53,95,120,152,188` | `ChioFlinkEvaluatorTest.kt:113-157` | OK (see F3) |
| 14 | OutputTag cached once, not per element | `ChioEvaluateFunction.kt:27-43`, `ChioVerdictSplitFunction.kt:16-26` | same operator tests | OK |

Extra checks requested:

- `ChioClientLike` shape matches Python's single-method Protocol:
  `ChioClientLike.kt:8-15` has exactly `evaluateToolCall(capability_id,
  tool_server, tool_name, parameters) -> ChioReceipt`. `ChioClient`
  implements it at `ChioClient.kt:34-35,85-103`. OK.
- Flink 2.2 `RuntimeContext` moves: `ChioFlinkEvaluator.kt:40-41` reads
  `runtimeContext.taskInfo.indexOfThisSubtask` / `taskInfo.attemptNumber`
  and the fake at `FakeRuntimeContext.kt:53-68` implements `TaskInfo`.
  OK.
- `SerializableFunction` / `SerializableSupplier` are `fun interface`s
  that extend `java.io.Serializable` (`SerializableFunction.kt:11-13`,
  `SerializableSupplier.kt:13-15`); `ChioFlinkConfig` implements
  `Serializable` and `ChioFlinkConfigTest.kt:96-112` exercises a Java
  serialization round-trip including the factory. OK.
- Async single-element emission: `ChioAsyncEvaluateFunction.kt:74-84`
  emits exactly one `EvaluationResult` via
  `resultFuture.complete(listOf(result))`, matching Python's
  `[EvaluationResult(...)]` shape.
  `ChioAsyncEvaluateFunctionTest.kt:42-52` asserts size == 1.
- Verdict splitter semantics: `ChioVerdictSplitFunction.kt:28-44`
  emits main only on allow; receipt side only when `receiptBytes` is
  non-null; DLQ side only when `dlqBytes` is non-null. Matches Python
  line-for-line. `ChioVerdictSplitFunctionTest.kt:18-51` covers each
  branch.

## Findings

### [P2] F1: `catch (RuntimeException)` in evaluator widens fail-closed beyond Python

`ChioFlinkEvaluator.kt:133-149` adds a third catch branch after
`ChioDeniedError` and `ChioError` that treats any `RuntimeException`
as a sidecar error: it bumps `sidecar_errors_total` and (under
`DENY`) synthesises a deny receipt. The inline comment claims "Match
Python parity" but Python's `evaluate_with_chio`
(`core.py:87-111`) catches only `ChioDeniedError` and `ChioError`;
any other exception (`TypeError`, `ValueError`, an ill-formed
response triggering a Jackson crash, a bug in `parametersExtractor`
that leaks out of a user-supplied extractor-but-executed-in-client-code,
etc.) propagates. In Python those bubble up, Flink restarts the task,
and the source rewinds.

In the Kotlin port they are silently laundered into "sidecar
unavailable" synthetic denies when `DENY` mode is selected, which
would mask genuine bugs behind what looks like a sidecar outage and
move legitimate events into the DLQ without a restart.

Impact: fail-closed is strictly stronger than necessary, but also less
observable. A panic-looking stream of "sidecar unavailable" denies
with no actual sidecar outage is the exact symptom this code would
produce, and debugging it means staring at the wrong service.

Confidence: high. The comment itself gives away the drift.

Proposed fix: delete the `catch (err: RuntimeException)` block. Let
runtime exceptions escape so Flink handles them. If the author really
wanted parity with Python's unwritten "sidecar error becomes
`ChioStreamingError`" behaviour, that wrap should happen inside
`ChioClient` (or a thin adapter), not in the operator's catch tower.

### [P2] F2: `BodyCoercion.canonicalBodyBytes(null)` disagrees with Python

`BodyCoercion.kt:22` returns `"null".toByteArray(UTF_8)` for a null
element. Python's `_canonical_body_bytes` (`flink.py:327-343`) never
special-cases `None`; it falls through to `str(element).encode("utf-8")`
which yields `b"None"`. Different four-byte payloads for the same
input.

This feeds `DlqRouter.buildRecord(originalValue=...)`, which embeds
the bytes as the DLQ record's `original_value` field after
`encodeOriginalValue` roundtrip-checks them through UTF-8. Neither
"null" nor "None" round-trip-break, so they land as
`{"utf8": "null"}` vs `{"utf8": "None"}`. That is a live byte-drift
in the DLQ wire layout whenever a null element reaches the operator.

Flink's `DataStream` does not officially support null records, so
this is unlikely in production today, but `BodyCoercion` is also the
`DefaultParametersExtractor` body source - the parameter_hash would
diverge too if a null element were ever processed.

Impact: DLQ byte-equality with Python consumers breaks if the null
path is hit.

Confidence: high (direct source comparison).

Proposed fix: replace the null branch with
`"None".toByteArray(StandardCharsets.UTF_8)`, or drop the null branch
entirely and let the `else` fallback produce `element.toString()`
which is already "null" in Kotlin but... actually `null.toString()`
throws a `NullPointerException`. Either hard-code `"None"` to match
Python, or short-circuit null at the call site and treat null elements
as a config error. The first is the minimum for parity.

### [P2] F3: Metrics live under a `chio.` subgroup vs Python's flat namespace

`ChioFlinkEvaluator.kt:44` calls
`runtimeContext.metricGroup.addGroup("chio")` before registering the
four counters and the gauge. Python (`flink.py:369-379`) registers
them flat on the operator's metric group. The resulting metric
identifiers diverge: Kotlin operators expose `...chio.allow_total`
while the PyFlink operators expose `...allow_total`.

This affects anyone reusing dashboards or alerts between the two
implementations. It is a divergence from the reference rather than a
fail-closed issue, and arguably the Kotlin behaviour is cleaner
(namespaced), but the two operators are no longer observationally
interchangeable.

Impact: monitoring parity, not runtime correctness.

Confidence: high.

Proposed fix: either register flat on `runtimeContext.metricGroup` to
match Python, or document the divergence prominently in the module
Javadoc and the operator-design doc. The cheapest compliance path is
a one-line change (drop the `addGroup("chio")` call and rename the
counters to `chio_allow_total` etc. if a prefix is still wanted).

### [P3] F4: `ChioClient.close()` is a no-op but the `AutoCloseable` contract is documented via comment

`ChioClient.kt:56-60` notes JDK 17's `HttpClient` has no `close()` and
leaves the method empty. `ChioFlinkEvaluator.kt:56-63` invokes
`close()` on any `AutoCloseable` client during `shutdown()`. This is
safe today (the method does nothing) but tomorrow's JDK 21+ runtime
picks up the `HttpClient.close()` method for free via Jackson's
`HttpClient` if someone bumps the toolchain; the shim will stop being
a no-op without any code change here.

Low risk now. Worth a Javadoc `@implNote` saying "future JDKs may turn
this into a real close" so the next maintainer does not assume it is
always cheap.

Confidence: medium (forward-compat note, not a current bug).

Proposed fix: add a one-line doc comment on `ChioClient.close()`
mentioning the forward-compat behaviour, or (preferred) add an
explicit `if (Runtime.version().feature() >= 21) httpClient.close()`
so the behaviour is deterministic when the shim disappears.

### [P3] F5: Async operator loses `failure_context` that Python passes to `evaluate_with_chio`

Python `flink.py:523-527` passes
`failure_context={"topic": subject, "request_id": request_id}` to
`evaluate_with_chio`, which uses it to decorate the wrapping
`ChioStreamingError`. Kotlin has no `ChioStreamingError` wrapper: the
`ChioError` raised by `ChioClient` is caught directly, and the
context (subject + request id) is dropped from the thrown exception
chain. Only the log message inside the synthetic deny reason survives
("sidecar unavailable; failing closed" - identical string to Python).

Impact: slightly worse forensics on sidecar-error restarts because the
top-level exception does not carry the failing subject/request_id.
Not a correctness issue.

Proposed fix: optional - add a small wrapping `ChioStreamingError`
subclass under `sdk/errors` that the operator uses to rethrow with
context. Or document the divergence. Low priority.

## Non-findings (verified correct)

- `CanonicalJson.kt` mirrors the Python knobs exactly: sorted map keys,
  alphabetized POJO props, `ensure_ascii=True` via
  `ESCAPE_NON_ASCII` + the lowercase-hex post-processor
  (`CanonicalJson.kt:77-112`), null content inclusion `ALWAYS`
  preserved, no whitespace separators. Three hand-computed Python
  vectors are asserted byte-for-byte in
  `CanonicalJsonTest.kt:7-49`.
- Deny path correctly skips receipt emission (`ChioFlinkEvaluator.kt:151-175`
  sets `receiptBytes = null`; both `ChioEvaluateFunction.kt:51-69` and
  `ChioVerdictSplitFunction.kt:28-44` gate side outputs on non-null).
  Verified end-to-end at `MiniClusterSyncJobIT.kt:30-70` (allow=1 main,
  deny=1 DLQ, receipts=1 allow only).
- `SYNTHETIC_RECEIPT_MARKER = "chio-streaming/synthetic-deny/v1"` is a
  constant string stored structurally in `receipt.metadata` under
  `chio_streaming_synthetic_marker` with a sibling boolean
  `chio_streaming_synthetic=true`. Signature remains empty string.
  Matches Python byte-for-byte.
- `[unsigned]` prefix is applied iff not already prefixed
  (`SyntheticDenyReceipt.kt:47`), so cascading synthesises stay stable.
  Verified in `SyntheticDenyReceiptTest.kt:13-36`.
- `ChioFlinkConfig` validates all six shapes Python validates (empty
  cap id, empty tool server, `maxInFlight < 1`, empty request id
  prefix, missing subject extractor, missing client / DLQ factories).
  Tested in `ChioFlinkConfigTest.kt:26-93`.
- `ChioFlinkConfig`, `Slots`, `DlqRouter`, `ChioReceipt`,
  `ReceiptEnvelope`, `EvaluationResult`, `FlinkProcessingOutcome`,
  `SerializableFunction`, `SerializableSupplier` all declare
  `Serializable` with an explicit `serialVersionUID`, and the config
  Java-serialization round-trip is exercised in
  `ChioFlinkConfigTest.kt:96-112`.
- `ChioClient` factory lives in `ChioFlinkConfig.clientFactory`; the
  operator constructs it inside `open()` via `bind()`
  (`ChioFlinkEvaluator.kt:37-39`), not the constructor - safe across
  JobManager to TaskManager serialization.
- Flink 2.2 `TaskInfo` migration is correctly applied: the production
  code reads `runtimeContext.taskInfo.indexOfThisSubtask` and
  `...attemptNumber`; the test fake implements the new `TaskInfo`
  interface (`FakeRuntimeContext.kt:53-68`).
- `RichAsyncFunction.asyncInvoke` emits exactly one
  `EvaluationResult` via `resultFuture.complete(listOf(result))`.
  Asserted in `ChioAsyncEvaluateFunctionTest.kt:42-52`.
- Metrics: counters `evaluations_total`, `allow_total`, `deny_total`,
  `sidecar_errors_total` and a gauge `in_flight` are registered under
  the (subgroup) metric group; all are exercised in
  `ChioFlinkEvaluatorTest.kt:113-157`. See F3 for the subgroup note.
- OutputTag objects are cached per operator in `open()` and reused per
  element (`ChioEvaluateFunction.kt:41-42`,
  `ChioVerdictSplitFunction.kt:23-25`); no per-element allocation.
- `Slots` acquire/release symmetry is exercised under contention in
  `ChioFlinkEvaluatorTest.kt:170-206`, which confirms `maxInFlight=2`
  admits at most 2 concurrent evaluations.
- `DlqRouter.buildRecord` refuses non-deny receipts, pins header
  order, canonicalises payload keys, and preserves source partition /
  offset as explicit nulls (`DlqRouter.kt:67-115` and the Python-parity
  asserts in `DlqRouterTest.kt`).
- `ChioDeniedError` thrown from `ChioClient` is caught narrowly and
  converted to a deny receipt with the denied reason / guard
  preserved, matching Python's `evaluate_with_chio`.
- `evaluateLocked` performs `ReceiptEnvelope.build` and
  `DlqRouter.buildRecord` OUTSIDE the sidecar try/catch, so envelope
  construction errors propagate (the bug the Python reference keeps
  fixing in the other brokers). Good.
