import { createHash, timingSafeEqual } from "node:crypto";

import { canonicalizeJson, parseJsonTextUniqueKeys } from "./json.ts";
import { ChioInvariantError } from "./errors.ts";

export const RECEIPT_DISCLOSURE_SCHEMA = "chio.receipt-disclosure.v1";

const MAX_DISCLOSURE_OPENINGS = 64;
const PARAMETERS_DOMAIN = Buffer.from("chio.receipt.parameters.v1\u0000", "utf8");
const CONTENT_DOMAIN = Buffer.from("chio.receipt.content.v1\u0000", "utf8");
const RECEIPT_ID = /^[0-9a-f]{64}$/;
const SALT_REF = /^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$/;
const SALT = /^b64u:[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
const DISCLOSURE_MEMBERS = ["schema", "receipt_id", "openings"];
const OPENING_MEMBERS = ["salt_ref", "salt", "payload"];
const COMMITMENT_MEMBERS = ["alg", "value", "salt_ref"];

export type FieldVerdict = "verified" | "rejected" | "unverifiable";

/** One salt opening. `payload` is opaque to the opener; `null` is a salt-only opening. */
export interface DisclosureOpening {
  saltRef: string;
  salt: Buffer;
  payload: unknown;
}

export interface ReceiptDisclosure {
  receiptId: string;
  openings: DisclosureOpening[];
}

export interface ReceiptCommitment {
  alg: string;
  value: string;
  salt_ref: string;
}

/** `disclosure_valid` is false exactly when the document is tampered disclosure. */
export interface OpeningReport {
  parameters: FieldVerdict;
  content: FieldVerdict;
  disclosure_valid: boolean;
}

function refuse(message: string): ChioInvariantError {
  return new ChioInvariantError("disclosure", message);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireExactMembers(value: Record<string, unknown>, members: string[], path: string): void {
  for (const key of Object.keys(value).sort()) {
    if (!members.includes(key)) {
      throw refuse(`unknown disclosure member: ${path}/${key}`);
    }
  }
  for (const key of members) {
    if (!Object.hasOwn(value, key)) {
      throw refuse(`missing disclosure member: ${path}/${key}`);
    }
  }
}

/** Accepts only the canonical `b64u:` form of 32 bytes. */
export function decodeSalt(encoded: unknown): Buffer {
  if (typeof encoded !== "string" || !SALT.test(encoded)) {
    throw refuse("salt is not the canonical b64u form of 32 bytes");
  }
  const raw = Buffer.from(encoded.slice("b64u:".length), "base64url");
  if (raw.length !== 32 || `b64u:${raw.toString("base64url")}` !== encoded) {
    throw refuse("salt is not the canonical b64u form of 32 bytes");
  }
  return raw;
}

/** Decodes a parsed `chio.receipt-disclosure.v1` document; refuses anything outside its wire form. */
export function parseReceiptDisclosure(value: unknown): ReceiptDisclosure {
  if (!isObject(value)) {
    throw refuse("disclosure must be a JSON object");
  }
  requireExactMembers(value, DISCLOSURE_MEMBERS, "");
  if (value.schema !== RECEIPT_DISCLOSURE_SCHEMA) {
    throw refuse("schema is not chio.receipt-disclosure.v1");
  }
  const receiptId = value.receipt_id;
  if (typeof receiptId !== "string" || !RECEIPT_ID.test(receiptId)) {
    throw refuse("receipt_id is not 64 lowercase hex characters");
  }
  const entries = value.openings;
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > MAX_DISCLOSURE_OPENINGS) {
    throw refuse("openings must hold 1 to 64 entries");
  }
  const openings = entries.map((entry, index): DisclosureOpening => {
    if (!isObject(entry)) {
      throw refuse("opening must be a JSON object");
    }
    requireExactMembers(entry, OPENING_MEMBERS, `/openings/${index}`);
    const saltRef = entry.salt_ref;
    if (typeof saltRef !== "string" || saltRef.length > 64 || !SALT_REF.test(saltRef)) {
      throw refuse("salt_ref is not a valid salt reference");
    }
    return { saltRef, salt: decodeSalt(entry.salt), payload: entry.payload };
  });
  return { receiptId, openings };
}

/** Decodes disclosure text; a repeated object key at any depth is refused. */
export function parseReceiptDisclosureJson(input: string): ReceiptDisclosure {
  return parseReceiptDisclosure(parseJsonTextUniqueKeys<unknown>(input));
}

function structurallyValid(receiptId: string, disclosure: ReceiptDisclosure): boolean {
  if (disclosure.receiptId !== receiptId) {
    return false;
  }
  const openings = disclosure.openings;
  return openings.every((opening, index) =>
    openings
      .slice(index + 1)
      .every((other) => opening.saltRef !== other.saltRef && !timingSafeEqual(opening.salt, other.salt)),
  );
}

function openField(
  disclosure: ReceiptDisclosure,
  commitment: unknown,
  position: string,
  domain: Buffer,
  preimage: Buffer | undefined,
): FieldVerdict {
  if (
    !isObject(commitment) ||
    Object.keys(commitment).length !== COMMITMENT_MEMBERS.length ||
    !COMMITMENT_MEMBERS.every((member) => Object.hasOwn(commitment, member)) ||
    commitment.alg !== "sha256-salted" ||
    commitment.salt_ref !== position ||
    typeof commitment.value !== "string"
  ) {
    return "rejected";
  }
  const opening = disclosure.openings.find((entry) => entry.saltRef === position);
  if (opening === undefined || preimage === undefined) {
    return "unverifiable";
  }
  const expected = Buffer.from(
    `sha256:${createHash("sha256").update(domain).update(opening.salt).update(preimage).digest("hex")}`,
    "utf8",
  );
  const actual = Buffer.from(commitment.value, "utf8");
  return expected.length === actual.length && timingSafeEqual(expected, actual) ? "verified" : "rejected";
}

/**
 * Opens a receipt's parameter and content commitments over the caller's own arguments and
 * content preimage; a payload never supplies a preimage. An absent own preimage leaves that field
 * unverifiable. A document for another receipt, a repeated salt_ref or a salt shared by two
 * openings rejects every field; any rejected field marks the disclosure invalid.
 */
export function openCommitments(
  receiptId: string,
  parameterCommitment: unknown,
  contentCommitment: unknown,
  disclosure: ReceiptDisclosure,
  ownParameters?: unknown,
  ownContent?: Buffer,
): OpeningReport {
  if (!structurallyValid(receiptId, disclosure)) {
    return { parameters: "rejected", content: "rejected", disclosure_valid: false };
  }
  let parametersPreimage: Buffer | undefined;
  if (ownParameters !== undefined) {
    try {
      parametersPreimage = Buffer.from(canonicalizeJson(ownParameters), "utf8");
    } catch {
      return { parameters: "rejected", content: "rejected", disclosure_valid: false };
    }
  }
  const parameters = openField(disclosure, parameterCommitment, "params", PARAMETERS_DOMAIN, parametersPreimage);
  const content = openField(disclosure, contentCommitment, "content", CONTENT_DOMAIN, ownContent);
  return {
    parameters,
    content,
    disclosure_valid: parameters !== "rejected" && content !== "rejected",
  };
}
