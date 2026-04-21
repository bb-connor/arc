/**
 * Chio sidecar HTTP client for JVM.
 *
 * Communicates with the Chio Rust kernel running as a localhost sidecar.
 * Sends evaluation requests over HTTP and returns signed receipts.
 */
package io.backbay.chio

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/** Exception thrown when the Chio sidecar is unreachable or returns an error. */
class ChioSidecarException(
    val code: String,
    override val message: String,
    val statusCode: Int? = null,
) : RuntimeException(message)

/** Chio sidecar client. Sends evaluation requests to the Rust kernel. */
class ChioSidecarClient(
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

    /** Evaluate an HTTP request against the Chio kernel. */
    fun evaluate(request: ChioHttpRequest, capabilityToken: String? = null): EvaluateResponse {
        val body = objectMapper.writeValueAsString(request)
        val requestBuilder = HttpRequest.newBuilder()
            .uri(URI.create("$baseUrl/chio/evaluate"))
            .header("Content-Type", "application/json")
            .timeout(Duration.ofSeconds(timeoutSeconds))
            .POST(HttpRequest.BodyPublishers.ofString(body))
        if (!capabilityToken.isNullOrBlank()) {
            requestBuilder.header("X-Chio-Capability", capabilityToken)
        }
        val httpRequest = requestBuilder.build()

        val response = try {
            httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString())
        } catch (e: Exception) {
            throw ChioSidecarException(
                code = ChioErrorCodes.SIDECAR_UNREACHABLE,
                message = "failed to reach Chio sidecar at $baseUrl: ${e.message}",
            )
        }

        if (response.statusCode() >= 400) {
            throw ChioSidecarException(
                code = ChioErrorCodes.EVALUATION_FAILED,
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
            .uri(URI.create("$baseUrl/chio/verify"))
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
            .uri(URI.create("$baseUrl/chio/health"))
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
