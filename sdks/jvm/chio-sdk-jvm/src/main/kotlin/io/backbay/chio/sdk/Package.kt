/**
 * Transport-agnostic Chio client SDK for the JVM.
 *
 * Mirrors the Python `chio-sdk` package: typed HTTP client, canonical
 * JSON, signed-receipt primitives, DLQ envelope builders, and the
 * pure-Kotlin error hierarchy used by every JVM middleware.
 *
 * Public entry points:
 *
 * - [io.backbay.chio.sdk.ChioClient] - blocking sidecar client
 *   implementing [io.backbay.chio.sdk.ChioClientLike] and
 *   [java.lang.AutoCloseable].
 * - [io.backbay.chio.sdk.CanonicalJson] - Jackson canonicalizer
 *   byte-compatible with Python's `json.dumps(sort_keys=True,
 *   separators=(",", ":"), ensure_ascii=True)`.
 * - [io.backbay.chio.sdk.ChioReceipt] / [io.backbay.chio.sdk.Decision] -
 *   the signed-receipt object graph.
 * - [io.backbay.chio.sdk.SyntheticDenyReceipt] - fail-closed synthetic
 *   receipt carrying the `chio-streaming/synthetic-deny/v1` marker.
 * - [io.backbay.chio.sdk.DlqRouter] /
 *   [io.backbay.chio.sdk.ReceiptEnvelope] - canonical wire envelopes.
 * - [io.backbay.chio.sdk.errors] - the structured error hierarchy.
 *
 * Wire-level parity with the Python reference is non-negotiable and is
 * asserted by tests tagged `parity`.
 */
package io.backbay.chio.sdk

/** Package summary marker; see KDoc on the [io.backbay.chio.sdk] package for details. */
@Suppress("unused")
internal const val PACKAGE_DOC_ANCHOR: String = "io.backbay.chio.sdk"
