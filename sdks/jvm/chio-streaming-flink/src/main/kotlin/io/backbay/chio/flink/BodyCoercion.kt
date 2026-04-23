/**
 * Canonical body bytes helper used by the default parameters extractor.
 * Mirrors _canonical_body_bytes in chio_streaming/flink.py:327-343.
 */
package io.backbay.chio.flink

import io.backbay.chio.sdk.CanonicalJson
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

internal object BodyCoercion {
    /**
     * Encoding rules (match flink.py:329-343):
     * 1. ByteArray / ByteBuffer passthrough.
     * 2. String encodes as UTF-8.
     * 3. Map canonical JSON via CanonicalJson.writeBytes.
     * 4. Fallback: element.toString().toByteArray(UTF_8).
     *
     * Null matches Python's fallthrough via ``str(None).encode("utf-8")``
     * which produces the four-byte payload "None". Kotlin's
     * ``null.toString()`` would NPE, so null is short-circuited to the
     * same payload explicitly.
     */
    @JvmStatic
    fun canonicalBodyBytes(element: Any?): ByteArray =
        when (element) {
            null -> "None".toByteArray(StandardCharsets.UTF_8)
            is ByteArray -> element
            is ByteBuffer -> {
                val buf = element.duplicate()
                val out = ByteArray(buf.remaining())
                buf.get(out)
                out
            }
            is String -> element.toByteArray(StandardCharsets.UTF_8)
            is Map<*, *> ->
                try {
                    CanonicalJson.writeBytes(element)
                } catch (_: Exception) {
                    element.toString().toByteArray(StandardCharsets.UTF_8)
                }
            else -> element.toString().toByteArray(StandardCharsets.UTF_8)
        }
}
