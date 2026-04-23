/**
 * The sidecar surface the Flink operator calls. ChioClient implements
 * this; test doubles can too without spinning up an HttpServer.
 * Mirrors chio_streaming.core.ChioClientLike Protocol (core.py:28-39).
 */
package io.backbay.chio.sdk

interface ChioClientLike {
    fun evaluateToolCall(
        capabilityId: String,
        toolServer: String,
        toolName: String,
        parameters: Map<String, Any?>,
    ): ChioReceipt
}
