import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signMessage,
  verify as verifySignature,
} from "node:crypto";

import { KNOWN_SIGNED_ARTIFACT_SCHEMAS } from "./_generated/signed_artifact_schemas.ts";
import { ChioInvariantError } from "./errors.ts";

/** Opens every Chio signing wrapper; byte 23 is 0x00. */
export const SIGNING_WRAPPER_PREFIX = Buffer.from("chio.signing-wrapper.v1\0", "utf8");

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

// SPKI prefix bytes preceding a raw 65-byte uncompressed SEC1 point (0x04 || X || Y)
// for the prime256v1 (P-256) named curve. Encodes the SubjectPublicKeyInfo header:
// SEQUENCE { AlgorithmIdentifier { id-ecPublicKey, prime256v1 }, BIT STRING ... }.
const P256_SPKI_PREFIX = Buffer.from(
  "3059301306072a8648ce3d020106082a8648ce3d030107034200",
  "hex",
);

// SPKI prefix bytes for the secp384r1 (P-384) named curve preceding a raw 97-byte
// uncompressed SEC1 point.
const P384_SPKI_PREFIX = Buffer.from(
  "3076301006072a8648ce3d020106052b81040022036200",
  "hex",
);

const P256_RAW_POINT_BYTES = 65;
const P384_RAW_POINT_BYTES = 97;

function normalizeHex(hex: string): string {
  return hex.startsWith("0x") ? hex.slice(2).toLowerCase() : hex.toLowerCase();
}

function hexToBuffer(
  hex: string,
  expectedBytes: number,
  code: "invalid_hex" | "invalid_public_key" | "invalid_signature",
): Buffer {
  const normalized = normalizeHex(hex);
  if (!/^[0-9a-f]+$/i.test(normalized)) {
    throw new ChioInvariantError(code, "value is not valid hexadecimal");
  }
  if (normalized.length !== expectedBytes * 2) {
    throw new ChioInvariantError(code, `expected ${expectedBytes} bytes of hex, got ${normalized.length / 2}`);
  }
  return Buffer.from(normalized, "hex");
}

function createEd25519PrivateKey(seedHex: string) {
  try {
    return createPrivateKey({
      key: Buffer.concat([ED25519_PKCS8_PREFIX, hexToBuffer(seedHex, 32, "invalid_hex")]),
      format: "der",
      type: "pkcs8",
    });
  } catch (cause) {
    if (cause instanceof ChioInvariantError) {
      throw cause;
    }
    throw new ChioInvariantError("invalid_hex", "value is not a valid Ed25519 seed", { cause });
  }
}

function createEd25519PublicKey(publicKeyHex: string) {
  try {
    return createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, hexToBuffer(publicKeyHex, 32, "invalid_public_key")]),
      format: "der",
      type: "spki",
    });
  } catch (cause) {
    if (cause instanceof ChioInvariantError) {
      throw cause;
    }
    throw new ChioInvariantError("invalid_public_key", "value is not a valid Ed25519 public key", { cause });
  }
}

export function sha256Hex(input: string | Buffer): string {
  return createHash("sha256").update(input).digest("hex");
}

export function isValidEd25519PublicKeyHex(publicKeyHex: string): boolean {
  try {
    hexToBuffer(publicKeyHex, 32, "invalid_public_key");
    return true;
  } catch {
    return false;
  }
}

export function isValidEd25519SignatureHex(signatureHex: string): boolean {
  try {
    hexToBuffer(signatureHex, 64, "invalid_signature");
    return true;
  } catch {
    return false;
  }
}

export function publicKeyHexMatches(left: string, right: string): boolean {
  return normalizeHex(left) === normalizeHex(right);
}

export function publicKeyFromSeedEd25519(seedHex: string): string {
  const privateKey = createEd25519PrivateKey(seedHex);
  const publicKeyDer = createPublicKey(privateKey).export({
    format: "der",
    type: "spki",
  });
  return Buffer.from(publicKeyDer).subarray(ED25519_SPKI_PREFIX.length).toString("hex");
}

/** The 88 bytes a Chio signature covers; refuses an unregistered schema id. */
export function signingWrapper(schemaId: string, canonicalJson: string): Buffer {
  if (!KNOWN_SIGNED_ARTIFACT_SCHEMAS.has(schemaId)) {
    throw new ChioInvariantError(
      "unregistered_schema_id",
      `unregistered signed-artifact schema id: ${schemaId}`,
    );
  }
  return Buffer.concat([
    SIGNING_WRAPPER_PREFIX,
    createHash("sha256").update(schemaId, "utf8").digest(),
    createHash("sha256").update(canonicalJson, "utf8").digest(),
  ]);
}

export function signWrappedCanonicalEd25519(
  schemaId: string,
  canonicalJson: string,
  seedHex: string,
): { public_key_hex: string; signature_hex: string } {
  const wrapper = signingWrapper(schemaId, canonicalJson);
  const privateKey = createEd25519PrivateKey(seedHex);
  return {
    public_key_hex: publicKeyFromSeedEd25519(seedHex),
    signature_hex: Buffer.from(signMessage(null, wrapper, privateKey)).toString("hex"),
  };
}

function encodedAlgorithm(value: string): string {
  for (const prefix of ["p256", "p384", "hybrid"]) {
    if (value.startsWith(`${prefix}:`)) {
      return prefix;
    }
  }
  return "ed25519";
}

function stripAlgorithmPrefix(value: string, algorithm: string): string {
  return algorithm === "ed25519" ? value : value.slice(algorithm.length + 1);
}

/**
 * Verify a signature over the wrapper of `canonicalJson` under `schemaId`. The
 * pinned key's encoding alone selects the algorithm; a signature encoded for
 * another algorithm throws before any cryptographic check.
 */
export function verifyWrappedCanonical(
  schemaId: string,
  canonicalJson: string,
  publicKey: string,
  signature: string,
): void {
  const wrapper = signingWrapper(schemaId, canonicalJson);
  const keyAlgorithm = encodedAlgorithm(publicKey);
  const signatureAlgorithm = encodedAlgorithm(signature);
  if (keyAlgorithm !== signatureAlgorithm) {
    throw new ChioInvariantError(
      "signature_algorithm_mismatch",
      `signature algorithm ${signatureAlgorithm} does not match the pinned key algorithm ${keyAlgorithm}`,
    );
  }
  let verified: boolean;
  if (keyAlgorithm === "ed25519") {
    const signatureBytes = hexToBuffer(signature, 64, "invalid_signature");
    verified = verifySignature(null, wrapper, createEd25519PublicKey(publicKey), signatureBytes);
  } else if (keyAlgorithm === "p256" || keyAlgorithm === "p384") {
    verified = verifyEcdsaSignature(
      wrapper,
      stripAlgorithmPrefix(publicKey, keyAlgorithm),
      stripAlgorithmPrefix(signature, keyAlgorithm),
      keyAlgorithm === "p256" ? "P-256" : "P-384",
    );
  } else {
    throw new ChioInvariantError(
      "unsupported_algorithm",
      `signature algorithm ${keyAlgorithm} is not supported by this SDK`,
    );
  }
  if (!verified) {
    throw new ChioInvariantError("signature_rejected", "signature rejected");
  }
}

/** A rejected signature is `false`; every other refusal throws. */
export function wrappedSignatureValid(
  schemaId: string,
  canonicalJson: string,
  publicKey: string,
  signature: string,
): boolean {
  try {
    verifyWrappedCanonical(schemaId, canonicalJson, publicKey, signature);
    return true;
  } catch (error) {
    if (error instanceof ChioInvariantError && error.code === "signature_rejected") {
      return false;
    }
    throw error;
  }
}

function hexBodyToBuffer(hexBody: string): Buffer {
  if (hexBody.length === 0 || hexBody.length % 2 !== 0) {
    throw new ChioInvariantError(
      "invalid_signature",
      "signature hex body must be a non-empty even-length string",
    );
  }
  if (!/^[0-9a-f]+$/i.test(hexBody)) {
    throw new ChioInvariantError("invalid_signature", "signature hex body is not valid hexadecimal");
  }
  return Buffer.from(hexBody, "hex");
}

function createEcdsaPublicKey(
  publicKeyHex: string,
  curve: "P-256" | "P-384",
): ReturnType<typeof createPublicKey> {
  const rawHex = normalizeHex(publicKeyHex);
  if (!/^[0-9a-f]+$/i.test(rawHex)) {
    throw new ChioInvariantError("invalid_public_key", "public key is not valid hexadecimal");
  }

  const rawBytes = Buffer.from(rawHex, "hex");
  const expectedRawLen = curve === "P-256" ? P256_RAW_POINT_BYTES : P384_RAW_POINT_BYTES;
  const prefix = curve === "P-256" ? P256_SPKI_PREFIX : P384_SPKI_PREFIX;

  // Accept either a raw uncompressed SEC1 point (0x04 || X || Y) which we wrap in
  // the curve's fixed SPKI prefix, or a full DER-encoded SPKI blob (callers pass
  // either form depending on key origin).
  let spki: Buffer;
  if (rawBytes.length === expectedRawLen && rawBytes[0] === 0x04) {
    spki = Buffer.concat([prefix, rawBytes]);
  } else if (rawBytes.length > expectedRawLen) {
    spki = rawBytes;
  } else {
    throw new ChioInvariantError(
      "invalid_public_key",
      `value is not a valid ${curve} public key (expected ${expectedRawLen} raw bytes or SPKI DER)`,
    );
  }

  try {
    return createPublicKey({
      key: spki,
      format: "der",
      type: "spki",
    });
  } catch (cause) {
    throw new ChioInvariantError(
      "invalid_public_key",
      `value is not a valid ${curve} public key`,
      { cause },
    );
  }
}

function verifyEcdsaSignature(
  message: Buffer,
  publicKeyHex: string,
  signatureHexBody: string,
  curve: "P-256" | "P-384",
): boolean {
  const hashAlgorithm = curve === "P-256" ? "sha256" : "sha384";
  const signatureDer = hexBodyToBuffer(signatureHexBody);
  const key = createEcdsaPublicKey(publicKeyHex, curve);
  try {
    return verifySignature(
      hashAlgorithm,
      message,
      { key, dsaEncoding: "der" },
      signatureDer,
    );
  } catch (cause) {
    throw new ChioInvariantError(
      "invalid_signature",
      `value is not a valid ${curve} signature`,
      { cause },
    );
  }
}
