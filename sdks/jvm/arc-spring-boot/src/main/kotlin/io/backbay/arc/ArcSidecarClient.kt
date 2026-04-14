/**
 * ARC sidecar HTTP client for JVM.
 *
 * Communicates with the ARC Rust kernel running as a localhost sidecar.
 * Sends evaluation requests over HTTP and returns signed receipts.
 */
package io.backbay.arc

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/** Exception thrown when the ARC sidecar is unreachable or returns an error. */
class ArcSidecarException(
    val code: String,
    override val message: String,
    val statusCode: Int? = null,
) : RuntimeException(message)

/** ARC sidecar client. Sends evaluation requests to the Rust kernel. */
class ArcSidecarClient(
    private val baseUrl: String = DEFAULT_SIDECAR_URL,
    private val timeoutSeconds: Long = 5,
) {
    companion object {
        const val DEFAULT_SIDECAR_URL = "http://127.0.0.1:9090"
    }

    private val httpClient: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(timeoutSeconds))
        .build()

    private val objectMapper: ObjectMapper = jacksonObjectMapper()
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)

    /** Evaluate an HTTP request against the ARC kernel. */
    fun evaluate(request: ArcHttpRequest): EvaluateResponse {
        val body = objectMapper.writeValueAsString(request)
        val httpRequest = HttpRequest.newBuilder()
            .uri(URI.create("$baseUrl/arc/evaluate"))
            .header("Content-Type", "application/json")
            .timeout(Duration.ofSeconds(timeoutSeconds))
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build()

        val response = try {
            httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString())
        } catch (e: Exception) {
            throw ArcSidecarException(
                code = ArcErrorCodes.SIDECAR_UNREACHABLE,
                message = "failed to reach ARC sidecar at $baseUrl: ${e.message}",
            )
        }

        if (response.statusCode() >= 400) {
            throw ArcSidecarException(
                code = ArcErrorCodes.EVALUATION_FAILED,
                message = "sidecar returned ${response.statusCode()}: ${response.body()}",
                statusCode = response.statusCode(),
            )
        }

        return objectMapper.readValue(response.body())
    }

    /** Verify a receipt signature against the sidecar. */
    fun verifyReceipt(receipt: HttpReceipt): Boolean {
        val body = objectMapper.writeValueAsString(receipt)
        val httpRequest = HttpRequest.newBuilder()
            .uri(URI.create("$baseUrl/arc/verify"))
            .header("Content-Type", "application/json")
            .timeout(Duration.ofSeconds(timeoutSeconds))
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build()

        return try {
            val response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString())
            if (response.statusCode() != 200) return false
            val result: Map<String, Any> = objectMapper.readValue(response.body())
            result["valid"] == true
        } catch (_: Exception) {
            false
        }
    }

    /** Health check for the sidecar. */
    fun healthCheck(): Boolean {
        val httpRequest = HttpRequest.newBuilder()
            .uri(URI.create("$baseUrl/arc/health"))
            .timeout(Duration.ofSeconds(timeoutSeconds))
            .GET()
            .build()

        return try {
            val response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString())
            response.statusCode() == 200
        } catch (_: Exception) {
            false
        }
    }
}
