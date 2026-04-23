/**
 * Apache Flink operators that gate a DataStream through a Chio
 * capability. Mirrors `chio_streaming.flink` in Python.
 *
 * Public entry points:
 *
 * - [io.backbay.chio.flink.ChioAsyncEvaluateFunction] - primary async
 *   operator. Driven by `AsyncDataStream.unorderedWait(capacity=...)`.
 * - [io.backbay.chio.flink.ChioEvaluateFunction] - synchronous
 *   `ProcessFunction` variant for side-output-on-same-operator use.
 * - [io.backbay.chio.flink.ChioVerdictSplitFunction] - fans
 *   `EvaluationResult` into main + `chio-receipt` + `chio-dlq` side
 *   outputs. Tag names are the wire-stable
 *   [io.backbay.chio.flink.ChioOutputTags] constants.
 * - [io.backbay.chio.flink.ChioFlinkConfig] - serializable,
 *   builder-based configuration. Client and DLQ router are supplied
 *   as [io.backbay.chio.flink.SerializableSupplier] factories.
 * - [io.backbay.chio.flink.SidecarErrorBehaviour] - RAISE (let Flink
 *   restart on sidecar error) vs DENY (synthesise a deny receipt and
 *   keep flowing).
 *
 * This module does not drive transactions; pair with Flink's 2PC sinks
 * downstream. Flink version requirement: 2.2+.
 */
package io.backbay.chio.flink

/** Package summary marker; see KDoc on the [io.backbay.chio.flink] package for details. */
@Suppress("unused")
internal const val PACKAGE_DOC_ANCHOR: String = "io.backbay.chio.flink"
