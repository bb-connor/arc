package io.backbay.chio

import com.sun.net.httpserver.HttpServer
import jakarta.servlet.FilterChain
import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ChioFilterCapabilityTransportTest {

    @Test
    fun `query capability token is forwarded to sidecar`() {
        val observedCapability = AtomicReference<String?>()
        val sidecar = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        sidecar.createContext("/arc/evaluate") { exchange ->
            observedCapability.set(exchange.requestHeaders.getFirst("X-Chio-Capability"))
            val body = """
                {
                  "verdict": {"verdict":"allow"},
                  "receipt": {
                    "id": "receipt-query-capability",
                    "request_id": "req-1",
                    "route_pattern": "/echo",
                    "method": "POST",
                    "caller_identity_hash": "hash",
                    "verdict": {"verdict":"allow"},
                    "evidence": [],
                    "response_status": 200,
                    "timestamp": 1700000000,
                    "content_hash": "content",
                    "policy_hash": "policy",
                    "kernel_key": "kernel",
                    "signature": "signature"
                  },
                  "evidence": []
                }
            """.trimIndent().toByteArray()
            exchange.responseHeaders.add("Content-Type", "application/json")
            exchange.sendResponseHeaders(200, body.size.toLong())
            exchange.responseBody.use { it.write(body) }
        }
        sidecar.start()

        try {
            val filter = ChioFilter(
                ChioFilterConfig(sidecarUrl = "http://127.0.0.1:${sidecar.address.port}"),
            )
            val request = MockHttpServletRequest().apply {
                method = "POST"
                requestURI = "/echo"
                contentType = "application/json"
                addParameter("chio_capability", "query-token")
                setContent("""{"hello":"world"}""".toByteArray())
            }
            val response = MockHttpServletResponse()
            val chainCalled = AtomicBoolean(false)
            val chain = FilterChain { _, _ -> chainCalled.set(true) }

            filter.doFilter(request, response, chain)

            assertTrue(chainCalled.get())
            assertEquals("query-token", observedCapability.get())
            assertEquals("receipt-query-capability", response.getHeader("X-Chio-Receipt-Id"))
        } finally {
            sidecar.stop(0)
        }
    }

    @Test
    fun `fail-open passthrough does not attach a synthetic receipt header`() {
        val observedPassthrough = AtomicReference<ChioPassthrough?>()
        val filter = ChioFilter(
            ChioFilterConfig(
                sidecarUrl = "http://127.0.0.1:1",
                timeoutSeconds = 1,
                onSidecarError = "allow",
            ),
        )
        val request = MockHttpServletRequest().apply {
            method = "GET"
            requestURI = "/echo"
        }
        val response = MockHttpServletResponse()
        val chainCalled = AtomicBoolean(false)
        val chain = FilterChain { servletRequest, _ ->
            chainCalled.set(true)
            observedPassthrough.set(
                servletRequest.getAttribute(CHIO_PASSTHROUGH_ATTRIBUTE) as ChioPassthrough?,
            )
        }

        filter.doFilter(request, response, chain)

        assertTrue(chainCalled.get())
        assertEquals(null, response.getHeader("X-Chio-Receipt-Id"))
        assertEquals("allow_without_receipt", observedPassthrough.get()?.mode)
        assertEquals(ChioErrorCodes.SIDECAR_UNREACHABLE, observedPassthrough.get()?.error)
    }
}
