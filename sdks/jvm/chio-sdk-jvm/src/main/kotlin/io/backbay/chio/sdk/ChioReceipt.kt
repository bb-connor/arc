/**
 * Signed tool-call receipt. Mirrors chio_sdk.models.ChioReceipt
 * (models.py:419-442). Implements Serializable because it travels
 * inside EvaluationResult / FlinkProcessingOutcome which Flink
 * serialises across operator boundaries.
 */
package io.backbay.chio.sdk

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty
import java.io.Serializable

@JsonInclude(JsonInclude.Include.NON_NULL)
data class ChioReceipt(
    @JsonProperty("id") val id: String,
    @JsonProperty("timestamp") val timestamp: Long,
    @JsonProperty("capability_id") val capabilityId: String,
    @JsonProperty("tool_server") val toolServer: String,
    @JsonProperty("tool_name") val toolName: String,
    @JsonProperty("action") val action: ToolCallAction,
    @JsonProperty("decision") val decision: Decision,
    @JsonProperty("content_hash") val contentHash: String,
    @JsonProperty("policy_hash") val policyHash: String,
    @JsonProperty("evidence") val evidence: List<GuardEvidence> = emptyList(),
    @JsonProperty("metadata") val metadata: Map<String, Any?>? = null,
    @JsonProperty("kernel_key") val kernelKey: String,
    @JsonProperty("signature") val signature: String,
) : Serializable {
    @JsonIgnore
    fun isAllowed(): Boolean = decision.isAllowed()

    @JsonIgnore
    fun isDenied(): Boolean = decision.isDenied()

    companion object {
        private const val serialVersionUID: Long = 1L
    }
}
