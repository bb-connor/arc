import { isValidEd25519PublicKeyHex, publicKeyHexMatches, verifyEd25519Signature } from "./crypto.js";
import { canonicalizeJson } from "./json.js";
import { parseJsonText } from "./errors.js";
function validateManifestStructure(manifest) {
    if (manifest.schema !== "chio.manifest.v1") {
        return false;
    }
    if (manifest.tools.length === 0) {
        return false;
    }
    const seen = new Set();
    for (const tool of manifest.tools) {
        if (seen.has(tool.name)) {
            return false;
        }
        seen.add(tool.name);
    }
    return true;
}
export function parseSignedManifestJson(input) {
    return parseJsonText(input);
}
export function signedManifestBodyCanonicalJson(signedManifest) {
    return canonicalizeJson(signedManifest.manifest);
}
export function verifySignedManifest(signedManifest) {
    const embedded_public_key_valid = isValidEd25519PublicKeyHex(signedManifest.manifest.public_key);
    return {
        structure_valid: validateManifestStructure(signedManifest.manifest),
        signature_valid: verifyEd25519Signature(signedManifestBodyCanonicalJson(signedManifest), signedManifest.signer_key, signedManifest.signature),
        embedded_public_key_valid,
        embedded_public_key_matches_signer: embedded_public_key_valid &&
            publicKeyHexMatches(signedManifest.manifest.public_key, signedManifest.signer_key),
    };
}
export function verifySignedManifestJson(input) {
    return verifySignedManifest(parseSignedManifestJson(input));
}
//# sourceMappingURL=manifest.js.map