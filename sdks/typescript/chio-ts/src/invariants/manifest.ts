import { isValidEd25519PublicKeyHex, publicKeyHexMatches, verifyEd25519Signature } from "./crypto.ts";
import { canonicalizeJson } from "./json.ts";
import { parseJsonText } from "./errors.ts";

export interface MonetaryAmount {
  units: number;
  currency: string;
}

export type PricingModel = "flat" | "per_invocation" | "per_unit" | "hybrid";

export interface ToolPricing {
  pricing_model: PricingModel;
  base_price?: MonetaryAmount;
  unit_price?: MonetaryAmount;
  billing_unit?: string;
}

export interface ToolManifest {
  schema: string;
  server_id: string;
  name: string;
  description?: string;
  version: string;
  tools: Array<{
    name: string;
    description: string;
    input_schema: unknown;
    output_schema?: unknown;
    pricing?: ToolPricing;
    has_side_effects: boolean;
    latency_hint?: "instant" | "fast" | "moderate" | "slow";
  }>;
  required_permissions?: {
    read_paths?: string[];
    write_paths?: string[];
    network_hosts?: string[];
    environment_variables?: string[];
  };
  public_key: string;
}

export interface SignedManifest {
  manifest: ToolManifest;
  signature: string;
  signer_key: string;
}

export interface ManifestVerification {
  structure_valid: boolean;
  signature_valid: boolean;
  embedded_public_key_valid: boolean;
  embedded_public_key_matches_signer: boolean;
}

const REQUIRED_PERMISSION_FIELDS = [
  "read_paths",
  "write_paths",
  "network_hosts",
  "environment_variables",
] as const;
const REQUIRED_PERMISSION_FIELD_SET = new Set<string>(REQUIRED_PERMISSION_FIELDS);
const PRICING_MODEL_SET = new Set<string>([
  "flat",
  "per_invocation",
  "per_unit",
  "hybrid",
]);

function validateManifestStructure(manifest: ToolManifest): boolean {
  if (manifest.schema !== "chio.manifest.v1") {
    return false;
  }
  if (
    !isValidManifestTextField(manifest.server_id) ||
    !isValidManifestTextField(manifest.name) ||
    !isValidManifestTextField(manifest.version)
  ) {
    return false;
  }
  if (!Array.isArray(manifest.tools) || manifest.tools.length === 0) {
    return false;
  }

  const seen = new Set<string>();
  for (const tool of manifest.tools) {
    if (!isJsonObject(tool)) {
      return false;
    }
    if (!isValidToolName(tool.name)) {
      return false;
    }
    if (seen.has(tool.name)) {
      return false;
    }
    seen.add(tool.name);
    if (!isJsonObject(tool.input_schema)) {
      return false;
    }
    if (
      tool.output_schema !== undefined &&
      tool.output_schema !== null &&
      !isJsonObject(tool.output_schema)
    ) {
      return false;
    }
    if (!validateToolPricing(tool.pricing)) {
      return false;
    }
  }

  return validateRequiredPermissions(manifest.required_permissions);
}

function isValidManifestTextField(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0 && value.trim() === value;
}

function isValidToolName(name: unknown): name is string {
  return isValidManifestTextField(name);
}

function isJsonObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validateToolPricing(pricing: unknown): boolean {
  if (pricing === undefined || pricing === null) {
    return true;
  }
  if (!isJsonObject(pricing)) {
    return false;
  }
  const model = pricing.pricing_model;
  if (typeof model !== "string" || !PRICING_MODEL_SET.has(model)) {
    return false;
  }
  switch (model) {
    case "flat":
      if (!requirePricingAmount(pricing.base_price)) {
        return false;
      }
      break;
    case "per_invocation":
    case "per_unit":
      if (!requirePricingAmount(pricing.unit_price) || !isValidManifestTextField(pricing.billing_unit)) {
        return false;
      }
      break;
    case "hybrid":
      if (
        !requirePricingAmount(pricing.base_price) ||
        !requirePricingAmount(pricing.unit_price) ||
        !isValidManifestTextField(pricing.billing_unit)
      ) {
        return false;
      }
      break;
  }
  if (!validateOptionalPricingAmount(pricing.base_price)) {
    return false;
  }
  if (!validateOptionalPricingAmount(pricing.unit_price)) {
    return false;
  }
  if (
    pricing.billing_unit !== undefined &&
    pricing.billing_unit !== null &&
    !isValidManifestTextField(pricing.billing_unit)
  ) {
    return false;
  }
  return true;
}

function requirePricingAmount(amount: unknown): boolean {
  return amount !== undefined && amount !== null && validatePricingAmount(amount);
}

function validateOptionalPricingAmount(amount: unknown): boolean {
  if (amount === undefined || amount === null) {
    return true;
  }
  return validatePricingAmount(amount);
}

function validatePricingAmount(amount: unknown): boolean {
  if (!isJsonObject(amount)) {
    return false;
  }
  return (
    typeof amount.units === "number" &&
    Number.isSafeInteger(amount.units) &&
    amount.units >= 0 &&
    isIso4217CurrencyCode(amount.currency)
  );
}

function isIso4217CurrencyCode(currency: unknown): currency is string {
  return typeof currency === "string" && /^[A-Z]{3}$/.test(currency);
}

function validateRequiredPermissions(permissions: unknown): boolean {
  if (permissions === undefined || permissions === null) {
    return true;
  }
  if (!isJsonObject(permissions)) {
    return false;
  }
  for (const field of Object.keys(permissions)) {
    if (!REQUIRED_PERMISSION_FIELD_SET.has(field)) {
      return false;
    }
  }
  for (const field of REQUIRED_PERMISSION_FIELDS) {
    if (!validateRequiredPermissionValues(permissions[field])) {
      return false;
    }
  }
  return true;
}

function validateRequiredPermissionValues(values: unknown): boolean {
  if (values === undefined || values === null) {
    return true;
  }
  if (!Array.isArray(values)) {
    return false;
  }
  const seen = new Set<string>();
  for (const value of values) {
    if (!isValidManifestTextField(value) || seen.has(value)) {
      return false;
    }
    seen.add(value);
  }
  return true;
}

export function parseSignedManifestJson(input: string): SignedManifest {
  return parseJsonText(input);
}

export function signedManifestBodyCanonicalJson(signedManifest: SignedManifest): string {
  return canonicalizeJson(signedManifest.manifest);
}

export function verifySignedManifest(signedManifest: SignedManifest): ManifestVerification {
  const embedded_public_key_valid = isValidEd25519PublicKeyHex(signedManifest.manifest.public_key);

  return {
    structure_valid: validateManifestStructure(signedManifest.manifest),
    signature_valid: verifyEd25519Signature(
      signedManifestBodyCanonicalJson(signedManifest),
      signedManifest.signer_key,
      signedManifest.signature,
    ),
    embedded_public_key_valid,
    embedded_public_key_matches_signer:
      embedded_public_key_valid &&
      publicKeyHexMatches(signedManifest.manifest.public_key, signedManifest.signer_key),
  };
}

export function verifySignedManifestJson(input: string): ManifestVerification {
  return verifySignedManifest(parseSignedManifestJson(input));
}
