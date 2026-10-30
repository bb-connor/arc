import {
  isValidEd25519PublicKeyHex,
  isValidEd25519SignatureHex,
  publicKeyFromSeedEd25519,
  publicKeyHexMatches,
  signWrappedCanonicalEd25519,
  verifyWrappedCanonical,
} from "./crypto.ts";
import { canonicalizeJsonString } from "./json.ts";

export interface WrappedJsonSignature {
  schema_id: string;
  canonical_json: string;
  public_key_hex: string;
  signature_hex: string;
}

export function isValidPublicKeyHex(value: string): boolean {
  return isValidEd25519PublicKeyHex(value);
}

export function isValidSignatureHex(value: string): boolean {
  return isValidEd25519SignatureHex(value);
}

export function signWrappedJsonEd25519(
  schemaId: string,
  inputJson: string,
  seedHex: string,
): WrappedJsonSignature {
  const canonical_json = canonicalizeJsonString(inputJson);
  const signed = signWrappedCanonicalEd25519(schemaId, canonical_json, seedHex);
  return {
    schema_id: schemaId,
    canonical_json,
    public_key_hex: signed.public_key_hex,
    signature_hex: signed.signature_hex,
  };
}

/** Throws a `ChioInvariantError` unless the signature covers the wrapper of `inputJson`. */
export function verifyWrappedJson(
  schemaId: string,
  inputJson: string,
  publicKeyHex: string,
  signatureHex: string,
): void {
  verifyWrappedCanonical(schemaId, canonicalizeJsonString(inputJson), publicKeyHex, signatureHex);
}

export { publicKeyFromSeedEd25519, publicKeyHexMatches };
