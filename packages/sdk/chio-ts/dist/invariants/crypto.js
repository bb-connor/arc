import { createHash, createPrivateKey, createPublicKey, sign as signMessage, verify as verifySignature, } from "node:crypto";
import { ChioInvariantError } from "./errors.js";
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
function normalizeHex(hex) {
    return hex.startsWith("0x") ? hex.slice(2).toLowerCase() : hex.toLowerCase();
}
function hexToBuffer(hex, expectedBytes, code) {
    const normalized = normalizeHex(hex);
    if (!/^[0-9a-f]+$/i.test(normalized)) {
        throw new ChioInvariantError(code, "value is not valid hexadecimal");
    }
    if (normalized.length !== expectedBytes * 2) {
        throw new ChioInvariantError(code, `expected ${expectedBytes} bytes of hex, got ${normalized.length / 2}`);
    }
    return Buffer.from(normalized, "hex");
}
function createEd25519PrivateKey(seedHex) {
    try {
        return createPrivateKey({
            key: Buffer.concat([ED25519_PKCS8_PREFIX, hexToBuffer(seedHex, 32, "invalid_hex")]),
            format: "der",
            type: "pkcs8",
        });
    }
    catch (cause) {
        if (cause instanceof ChioInvariantError) {
            throw cause;
        }
        throw new ChioInvariantError("invalid_hex", "value is not a valid Ed25519 seed", { cause });
    }
}
function createEd25519PublicKey(publicKeyHex) {
    try {
        return createPublicKey({
            key: Buffer.concat([ED25519_SPKI_PREFIX, hexToBuffer(publicKeyHex, 32, "invalid_public_key")]),
            format: "der",
            type: "spki",
        });
    }
    catch (cause) {
        if (cause instanceof ChioInvariantError) {
            throw cause;
        }
        throw new ChioInvariantError("invalid_public_key", "value is not a valid Ed25519 public key", { cause });
    }
}
export function sha256Hex(input) {
    return createHash("sha256").update(input).digest("hex");
}
export function isValidEd25519PublicKeyHex(publicKeyHex) {
    try {
        hexToBuffer(publicKeyHex, 32, "invalid_public_key");
        return true;
    }
    catch {
        return false;
    }
}
export function isValidEd25519SignatureHex(signatureHex) {
    try {
        hexToBuffer(signatureHex, 64, "invalid_signature");
        return true;
    }
    catch {
        return false;
    }
}
export function publicKeyHexMatches(left, right) {
    return normalizeHex(left) === normalizeHex(right);
}
function publicKeyHexFromSeedHex(seedHex) {
    const privateKey = createEd25519PrivateKey(seedHex);
    const publicKeyDer = createPublicKey(privateKey).export({
        format: "der",
        type: "spki",
    });
    return Buffer.from(publicKeyDer).subarray(ED25519_SPKI_PREFIX.length).toString("hex");
}
export function signEd25519Message(message, seedHex) {
    const privateKey = createEd25519PrivateKey(seedHex);
    const messageBuffer = Buffer.isBuffer(message) ? message : Buffer.from(message, "utf8");
    return {
        public_key_hex: publicKeyHexFromSeedHex(seedHex),
        signature_hex: Buffer.from(signMessage(null, messageBuffer, privateKey)).toString("hex"),
    };
}
export function verifyEd25519Signature(message, publicKeyHex, signatureHex) {
    const signatureBytes = hexToBuffer(signatureHex, 64, "invalid_signature");
    const key = createEd25519PublicKey(publicKeyHex);
    return verifySignature(null, Buffer.isBuffer(message) ? message : Buffer.from(message, "utf8"), key, signatureBytes);
}
//# sourceMappingURL=crypto.js.map