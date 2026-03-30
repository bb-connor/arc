import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signMessage,
  verify as verifySignature,
} from "node:crypto";

import { ArcInvariantError } from "./errors.ts";

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

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
    throw new ArcInvariantError(code, "value is not valid hexadecimal");
  }
  if (normalized.length !== expectedBytes * 2) {
    throw new ArcInvariantError(code, `expected ${expectedBytes} bytes of hex, got ${normalized.length / 2}`);
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
    if (cause instanceof ArcInvariantError) {
      throw cause;
    }
    throw new ArcInvariantError("invalid_hex", "value is not a valid Ed25519 seed", { cause });
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
    if (cause instanceof ArcInvariantError) {
      throw cause;
    }
    throw new ArcInvariantError("invalid_public_key", "value is not a valid Ed25519 public key", { cause });
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

function publicKeyHexFromSeedHex(seedHex: string): string {
  const privateKey = createEd25519PrivateKey(seedHex);
  const publicKeyDer = createPublicKey(privateKey).export({
    format: "der",
    type: "spki",
  });
  return Buffer.from(publicKeyDer).subarray(ED25519_SPKI_PREFIX.length).toString("hex");
}

export function signEd25519Message(
  message: string | Buffer,
  seedHex: string,
): { public_key_hex: string; signature_hex: string } {
  const privateKey = createEd25519PrivateKey(seedHex);
  const messageBuffer = Buffer.isBuffer(message) ? message : Buffer.from(message, "utf8");
  return {
    public_key_hex: publicKeyHexFromSeedHex(seedHex),
    signature_hex: Buffer.from(signMessage(null, messageBuffer, privateKey)).toString("hex"),
  };
}

export function verifyEd25519Signature(
  message: string | Buffer,
  publicKeyHex: string,
  signatureHex: string,
): boolean {
  const signatureBytes = hexToBuffer(signatureHex, 64, "invalid_signature");
  const key = createEd25519PublicKey(publicKeyHex);
  return verifySignature(
    null,
    Buffer.isBuffer(message) ? message : Buffer.from(message, "utf8"),
    key,
    signatureBytes,
  );
}
