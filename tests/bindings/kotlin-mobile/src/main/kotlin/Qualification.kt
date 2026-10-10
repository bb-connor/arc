import dev.chio.kernel.ChioKernel
import uniffi.chio_kernel_mobile.ChioMobileException

fun main() {
    val kernel = ChioKernel()
    val result = kernel.inspectMobileReceiptEnvelopes(
        """{"schema":"chio.mobile.receipt.v1","receipt_id":"kotlin-test"}""",
        """{"schema":"chio.mobile.attestation-evidence.v1","platform":"play_integrity"}"""
    )
    check(result.contains("\"status\":\"shape_only\"")) { result }
    check(result.contains("\"authoritative\":false")) { result }
    check(result.contains("\"authorized\":false")) { result }
    println("PASS native receipt inspection preserves non-authoritative status")
    try {
        kernel.inspectMobileReceiptEnvelopes("{}", "{}")
        error("malformed receipt was accepted")
    } catch (expected: ChioMobileException.AttestationRejected) {
        check(expected.detail.contains("urn:chio:error:attest:signed-json-invalid-shape"))
        println("PASS malformed receipt raises the Rust typed error")
    }
    try {
        kernel.evaluate("{}")
        error("missing capability was accepted")
    } catch (expected: ChioMobileException.InvalidJson) {
        println("PASS evaluation invokes Rust and rejects a missing capability")
    }
    try {
        kernel.signReceipt("{}", "", "00".repeat(32))
        error("malformed receipt body was signed")
    } catch (expected: ChioMobileException.InvalidJson) {
        println("PASS three-argument signer invokes Rust and rejects a malformed receipt")
    }
    println("Kotlin native consumer: 4 passed; Android AAR and device matrix not exercised")
}
