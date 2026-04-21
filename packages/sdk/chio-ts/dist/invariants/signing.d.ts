import { publicKeyHexMatches } from "./crypto.js";
export interface Utf8MessageSignature {
    public_key_hex: string;
    signature_hex: string;
}
export interface CanonicalJsonSignature extends Utf8MessageSignature {
    canonical_json: string;
}
export declare function isValidPublicKeyHex(value: string): boolean;
export declare function isValidSignatureHex(value: string): boolean;
export declare function signUtf8MessageEd25519(input: string, seedHex: string): Utf8MessageSignature;
export declare function verifyUtf8MessageEd25519(input: string, publicKeyHex: string, signatureHex: string): boolean;
export declare function signJsonStringEd25519(input: string, seedHex: string): CanonicalJsonSignature;
export declare function verifyJsonStringSignatureEd25519(input: string, publicKeyHex: string, signatureHex: string): boolean;
export { publicKeyHexMatches };
//# sourceMappingURL=signing.d.ts.map