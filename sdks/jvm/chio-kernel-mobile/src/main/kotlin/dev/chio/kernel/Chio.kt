package dev.chio.kernel

data class ChioMobileReceiptEvidence(
    val schema: String,
    val platform: String,
    val token: String,
    val nonce: String,
    val trustLevel: TrustLevel,
)

enum class TrustLevel {
    HARDWARE,
    SOFTWARE,
}

class ChioKernel {
    fun evaluate(requestJson: String): String = uniffi.chio_kernel_mobile.evaluate(requestJson)

    fun signReceipt(bodyJson: String, canonicalContentHex: String, signingSeedHex: String): String =
        uniffi.chio_kernel_mobile.signReceipt(bodyJson, canonicalContentHex, signingSeedHex)

    /** Inspect shape only; this does not verify device integrity or authorize a call. */
    fun inspectMobileReceiptEnvelopes(receiptJson: String, evidenceJson: String): String =
        uniffi.chio_kernel_mobile.inspectMobileReceiptEnvelopes(receiptJson, evidenceJson)
}
