/**
 * Servlet filter that protects HTTP endpoints with ARC evaluation.
 *
 * Intercepts all requests, extracts caller identity, sends evaluation
 * requests to the ARC sidecar kernel, and either allows the request to
 * proceed with a signed receipt or returns a structured deny response.
 *
 * Fails closed by default: if the sidecar is unreachable, the request
 * is denied.
 */
package io.backbay.arc

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import jakarta.servlet.Filter
import jakarta.servlet.FilterChain
import jakarta.servlet.FilterConfig
import jakarta.servlet.ServletRequest
import jakarta.servlet.ServletResponse
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import java.util.UUID

/**
 * Configuration for the ARC servlet filter.
 *
 * @param sidecarUrl Base URL of the ARC sidecar kernel.
 * @param timeoutSeconds HTTP timeout for sidecar calls.
 * @param onSidecarError Behavior when sidecar is unreachable: "deny" (default) or "allow".
 * @param identityExtractor Custom identity extraction function.
 * @param routeResolver Custom route pattern resolver.
 */
data class ArcFilterConfig(
    val sidecarUrl: String = System.getenv("ARC_SIDECAR_URL") ?: "http://127.0.0.1:9090",
    val timeoutSeconds: Long = 5,
    val onSidecarError: String = "deny",
    val identityExtractor: IdentityExtractorFn = ::defaultIdentityExtractor,
    val routeResolver: (String, String) -> String = { _, path -> path },
)

/** ARC servlet filter for protecting HTTP APIs. */
class ArcFilter(
    private val config: ArcFilterConfig = ArcFilterConfig(),
) : Filter {

    private val client = ArcSidecarClient(config.sidecarUrl, config.timeoutSeconds)
    private val objectMapper = jacksonObjectMapper()

    override fun init(filterConfig: FilterConfig?) {
        // No initialization needed.
    }

    override fun doFilter(
        request: ServletRequest,
        response: ServletResponse,
        chain: FilterChain,
    ) {
        val httpRequest = request as HttpServletRequest
        val httpResponse = response as HttpServletResponse

        val method = httpRequest.method.uppercase()
        val validMethods = setOf("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
        if (method !in validMethods) {
            writeJsonError(httpResponse, 405, ArcErrorResponse(
                error = ArcErrorCodes.EVALUATION_FAILED,
                message = "unsupported HTTP method: $method",
            ))
            return
        }

        // Extract caller identity.
        val caller = config.identityExtractor(httpRequest)

        // Resolve route pattern.
        val routePattern = config.routeResolver(method, httpRequest.requestURI)

        // Build body hash.
        val bodyHash: String? = if (httpRequest.contentLength > 0) {
            val bodyBytes = httpRequest.inputStream.readAllBytes()
            sha256Hex(String(bodyBytes, Charsets.UTF_8))
        } else {
            null
        }

        // Extract selected headers.
        val headers = mutableMapOf<String, String>()
        for (header in listOf("content-type", "content-length", "x-arc-capability")) {
            val value = httpRequest.getHeader(header)
            if (value != null) {
                headers[header] = value
            }
        }

        // Build ARC HTTP request.
        val arcRequest = ArcHttpRequest(
            requestId = UUID.randomUUID().toString(),
            method = method,
            routePattern = routePattern,
            path = httpRequest.requestURI,
            query = httpRequest.parameterMap.mapValues { it.value.firstOrNull() ?: "" },
            headers = headers,
            caller = caller,
            bodyHash = bodyHash,
            bodyLength = httpRequest.contentLengthLong.coerceAtLeast(0),
            capabilityId = httpRequest.getHeader("X-Arc-Capability"),
            timestamp = System.currentTimeMillis() / 1000,
        )

        // Evaluate against sidecar.
        val result: EvaluateResponse
        try {
            result = client.evaluate(arcRequest)
        } catch (e: ArcSidecarException) {
            if (config.onSidecarError == "allow") {
                chain.doFilter(request, response)
                return
            }
            writeJsonError(httpResponse, 502, ArcErrorResponse(
                error = ArcErrorCodes.SIDECAR_UNREACHABLE,
                message = "ARC sidecar error: ${e.message}",
            ))
            return
        } catch (e: Exception) {
            if (config.onSidecarError == "allow") {
                chain.doFilter(request, response)
                return
            }
            writeJsonError(httpResponse, 502, ArcErrorResponse(
                error = ArcErrorCodes.SIDECAR_UNREACHABLE,
                message = "ARC sidecar error: ${e.message}",
            ))
            return
        }

        // Attach receipt ID.
        httpResponse.setHeader("X-Arc-Receipt-Id", result.receipt.id)

        // Check verdict.
        if (result.verdict.isDenied()) {
            val status = result.verdict.httpStatus ?: 403
            writeJsonError(httpResponse, status, ArcErrorResponse(
                error = ArcErrorCodes.ACCESS_DENIED,
                message = result.verdict.reason ?: "denied",
                receiptId = result.receipt.id,
                suggestion = "provide a valid capability token in the X-Arc-Capability header",
            ))
            return
        }

        // Request allowed -- forward to next filter/servlet.
        chain.doFilter(request, response)
    }

    override fun destroy() {
        // No cleanup needed.
    }

    private fun writeJsonError(response: HttpServletResponse, status: Int, body: ArcErrorResponse) {
        response.status = status
        response.contentType = "application/json"
        response.writer.write(objectMapper.writeValueAsString(body))
        response.writer.flush()
    }
}
