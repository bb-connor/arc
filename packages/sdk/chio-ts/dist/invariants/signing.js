import { isValidEd25519PublicKeyHex, isValidEd25519SignatureHex, publicKeyHexMatches, signEd25519Message, verifyEd25519Signature, } from "./crypto.js";
import { canonicalizeJsonString } from "./json.js";
export function isValidPublicKeyHex(value) {
    return isValidEd25519PublicKeyHex(value);
}
export function isValidSignatureHex(value) {
    return isValidEd25519SignatureHex(value);
}
export function signUtf8MessageEd25519(input, seedHex) {
    return signEd25519Message(input, seedHex);
}
export function verifyUtf8MessageEd25519(input, publicKeyHex, signatureHex) {
    return verifyEd25519Signature(input, publicKeyHex, signatureHex);
}
export function signJsonStringEd25519(input, seedHex) {
    const canonical_json = canonicalizeJsonString(input);
    const signed = signEd25519Message(canonical_json, seedHex);
    return {
        canonical_json,
        public_key_hex: signed.public_key_hex,
        signature_hex: signed.signature_hex,
    };
}
export function verifyJsonStringSignatureEd25519(input, publicKeyHex, signatureHex) {
    return verifyEd25519Signature(canonicalizeJsonString(input), publicKeyHex, signatureHex);
}
export { publicKeyHexMatches };
//# sourceMappingURL=signing.js.map