/**
 * Core types for the Chio HTTP substrate.
 *
 * These types mirror the Rust chio-http-core crate and define the contract
 * between JVM middleware and the Chio sidecar kernel.
 */
package io.backbay.chio

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty

/** How the caller authenticated to the upstream API. */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class AuthMethod(
    @JsonProperty("method") val method: String,
    @JsonProperty("token_hash") val tokenHash: String? = null,
    @JsonProperty("key_name") val keyName: String? = null,
    @JsonProperty("key_hash") val keyHash: String? = null,
    @JsonProperty("cookie_name") val cookieName: String? = null,
    @JsonProperty("cookie_hash") val cookieHash: String? = null,
    @JsonProperty("subject_dn") val subjectDn: String? = null,
    @JsonProperty("fingerprint") val fingerprint: String? = null,
) {
    companion object {
        fun anonymous(): AuthMethod = AuthMethod(method = "anonymous")
        fun bearer(tokenHash: String): AuthMethod = AuthMethod(method = "bearer", tokenHash = tokenHash)
        fun apiKey(keyName: String, keyHash: String): AuthMethod =
            AuthMethod(method = "api_key", keyName = keyName, keyHash = keyHash)
    }
}

/** The identity of the caller as extracted from the HTTP request. */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class CallerIdentity(
    @JsonProperty("subject") val subject: String,
    @JsonProperty("auth_method") val authMethod: AuthMethod,
    @JsonProperty("verified") val verified: Boolean = false,
    @JsonProperty("tenant") val tenant: String? = null,
    @JsonProperty("agent_id") val agentId: String? = null,
) {
    companion object {
        fun anonymous(): CallerIdentity =
            CallerIdentity(subject = "anonymous", authMethod = AuthMethod.anonymous())
    }
}

/** The kernel's evaluation verdict. */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class Verdict(
    @JsonProperty("verdict") val verdict: String,
    @JsonProperty("reason") val reason: String? = null,
    @JsonProperty("guard") val guard: String? = null,
    @JsonProperty("http_status") val httpStatus: Int? = null,
) {
    @JsonIgnore
    fun isAllowed(): Boolean = verdict == "allow"

    @JsonIgnore
    fun isDenied(): Boolean = verdict == "deny"

    companion object {
        fun allow(): Verdict = Verdict(verdict = "allow")
        fun deny(reason: String, guard: String, httpStatus: Int = 403): Verdict =
            Verdict(verdict = "deny", reason = reason, guard = guard, httpStatus = httpStatus)
    }
}

/** Per-guard evaluation evidence. */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class GuardEvidence(
    @JsonProperty("guard_name") val guardName: String,
    @JsonProperty("verdict") val verdict: Boolean,
    @JsonProperty("details") val details: String? = null,
)

/** Signed receipt for an HTTP request evaluation. */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class HttpReceipt(
    @JsonProperty("id") val id: String,
    @JsonProperty("request_id") val requestId: String,
    @JsonProperty("route_pattern") val routePattern: String,
    @JsonProperty("method") val method: String,
    @JsonProperty("caller_identity_hash") val callerIdentityHash: String,
    @JsonProperty("session_id") val sessionId: String? = null,
    @JsonProperty("verdict") val verdict: Verdict,
    @JsonProperty("evidence") val evidence: List<GuardEvidence> = emptyList(),
    @JsonProperty("response_status") val responseStatus: Int,
    @JsonProperty("timestamp") val timestamp: Long,
    @JsonProperty("content_hash") val contentHash: String,
    @JsonProperty("policy_hash") val policyHash: String,
    @JsonProperty("capability_id") val capabilityId: String? = null,
    @JsonProperty("metadata") val metadata: Any? = null,
    @JsonProperty("kernel_key") val kernelKey: String,
    @JsonProperty("signature") val signature: String,
)

/** HTTP request sent to the Chio sidecar for evaluation. */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class ChioHttpRequest(
    @JsonProperty("request_id") val requestId: String,
    @JsonProperty("method") val method: String,
    @JsonProperty("route_pattern") val routePattern: String,
    @JsonProperty("path") val path: String,
    @JsonProperty("query") val query: Map<String, String> = emptyMap(),
    @JsonProperty("headers") val headers: Map<String, String> = emptyMap(),
    @JsonProperty("caller") val caller: CallerIdentity,
    @JsonProperty("body_hash") val bodyHash: String? = null,
    @JsonProperty("body_length") val bodyLength: Long = 0,
    @JsonProperty("session_id") val sessionId: String? = null,
    @JsonProperty("capability_id") val capabilityId: String? = null,
    @JsonProperty("timestamp") val timestamp: Long,
)

/** Sidecar evaluation response. */
data class EvaluateResponse(
    @JsonProperty("verdict") val verdict: Verdict,
    @JsonProperty("receipt") val receipt: HttpReceipt,
    @JsonProperty("evidence") val evidence: List<GuardEvidence> = emptyList(),
)

/** Explicit fail-open degraded state where no Chio receipt exists. */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class ChioPassthrough(
    @JsonProperty("mode") val mode: String = "allow_without_receipt",
    @JsonProperty("error") val error: String = ChioErrorCodes.SIDECAR_UNREACHABLE,
    @JsonProperty("message") val message: String,
)

/** Structured error response body. */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class ChioErrorResponse(
    @JsonProperty("error") val error: String,
    @JsonProperty("message") val message: String,
    @JsonProperty("receipt_id") val receiptId: String? = null,
    @JsonProperty("suggestion") val suggestion: String? = null,
)

/** Chio error codes. */
object ChioErrorCodes {
    const val ACCESS_DENIED = "chio_access_denied"
    const val SIDECAR_UNREACHABLE = "chio_sidecar_unreachable"
    const val EVALUATION_FAILED = "chio_evaluation_failed"
    const val INVALID_RECEIPT = "chio_invalid_receipt"
    const val TIMEOUT = "chio_timeout"
}
