import { canonicalizeJson, canonicalizeJsonString } from "./json.js";
import { sha256Hex, verifyEd25519Signature } from "./crypto.js";
import { parseJsonText } from "./errors.js";
export function parseReceiptJson(input) {
    return parseJsonText(input);
}
export function receiptBody(receipt) {
    const { signature: _signature, ...body } = receipt;
    return body;
}
export function receiptBodyCanonicalJson(receipt) {
    return canonicalizeJson(receiptBody(receipt));
}
export function verifyReceipt(receipt) {
    const bodyCanonicalJson = receiptBodyCanonicalJson(receipt);
    const parameterCanonicalJson = canonicalizeJson(receipt.action.parameters);
    return {
        signature_valid: verifyEd25519Signature(bodyCanonicalJson, receipt.kernel_key, receipt.signature),
        parameter_hash_valid: receipt.action.parameter_hash === sha256Hex(parameterCanonicalJson),
        decision: receipt.decision.verdict,
    };
}
export function verifyReceiptJson(input) {
    return verifyReceipt(parseReceiptJson(input));
}
export { canonicalizeJsonString };
//# sourceMappingURL=receipt.js.map