package io.backbay.chio.flink

import io.backbay.chio.sdk.errors.ChioValidationError
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals

class ScopeResolverTest {
    @Test
    fun explicitMapHit() {
        val out =
            ScopeResolver.resolve(
                mapOf("orders" to "tools:orders:deliver"),
                "orders",
            )
        assertEquals("tools:orders:deliver", out)
    }

    @Test
    fun defaultPrefixFallback() {
        val out = ScopeResolver.resolve(emptyMap(), "orders")
        assertEquals("events:consume:orders", out)
    }

    @Test
    fun customDefaultPrefix() {
        val out = ScopeResolver.resolve(emptyMap(), "x", "stream:read")
        assertEquals("stream:read:x", out)
    }

    @Test
    fun emptySubjectThrows() {
        assertThrows<ChioValidationError> {
            ScopeResolver.resolve(emptyMap(), "")
        }
    }
}
