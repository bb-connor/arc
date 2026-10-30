import { canonicalizeJson } from "./json.ts";
import { isValidEd25519PublicKeyHex, publicKeyHexMatches, wrappedSignatureValid } from "./crypto.ts";
import { ChioInvariantError, parseJsonText } from "./errors.ts";

export type CapabilityTimeStatus = "valid" | "not_yet_valid" | "expired";

export interface DelegationLink {
  capability_id: string;
  delegator: string;
  delegatee: string;
  attenuations?: unknown[];
  timestamp: number;
  scope_hash?: string;
  signature: string;
}

export const CAPABILITY_SCHEMA = "chio.capability.v1";
export const DELEGATION_LINK_SCHEMA = "chio.delegation-link.v1";

const CAPABILITY_MEMBERS: ReadonlySet<string> = new Set([
  "schema",
  "id",
  "issuer",
  "subject",
  "scope",
  "issued_at",
  "expires_at",
  "delegation_chain",
  "aggregate_invocation_budget",
  "caveats",
  "scope_attenuations",
  "attenuation_proof",
  "budget_share_bps",
  "signature",
]);

const DELEGATION_LINK_MEMBERS: ReadonlySet<string> = new Set([
  "capability_id",
  "delegator",
  "delegatee",
  "attenuations",
  "timestamp",
  "scope_hash",
  "aggregate_budget",
  "cumulative_approval",
  "signature",
]);

function rejectUnknownMembers(value: object, allowed: ReadonlySet<string>, kind: string): void {
  for (const key of Object.keys(value).sort()) {
    if (!allowed.has(key)) {
      throw new ChioInvariantError("json", `${kind} has unknown member ${key}`);
    }
  }
}

export interface CapabilityToken {
  schema: typeof CAPABILITY_SCHEMA;
  id: string;
  issuer: string;
  subject: string;
  scope: unknown;
  issued_at: number;
  expires_at: number;
  delegation_chain?: DelegationLink[];
  aggregate_invocation_budget?: unknown;
  caveats?: unknown[];
  scope_attenuations?: unknown[];
  attenuation_proof?: unknown;
  budget_share_bps?: number;
  signature: string;
}

export interface CapabilityVerification {
  signature_valid: boolean;
  delegation_chain_shape_valid: boolean;
  time_valid: boolean;
  time_status: CapabilityTimeStatus;
}

function delegationLinkBody(link: DelegationLink): Omit<DelegationLink, "signature"> {
  const { signature: _signature, ...body } = link;
  return body;
}

function isNonEmptyArray(value: unknown): value is unknown[] {
  return Array.isArray(value) && value.length > 0;
}

function verifyDelegationChain(
  chain: DelegationLink[],
  rootDelegator: string | undefined,
  maxDelegationDepth?: number,
): boolean {
  if (rootDelegator !== undefined && rootDelegator !== "" && !isValidEd25519PublicKeyHex(rootDelegator)) {
    throw new ChioInvariantError("invalid_public_key", "root delegator is not a valid Ed25519 public key");
  }
  if (chain.length === 0) {
    return true;
  }
  if (rootDelegator === undefined || rootDelegator === "") {
    throw new ChioInvariantError(
      "delegation_root_unresolved",
      "delegation chain root delegator was not supplied by the verifier",
    );
  }
  if (maxDelegationDepth !== undefined && chain.length > maxDelegationDepth) {
    return false;
  }

  let expectedDelegator = rootDelegator;
  let previous: DelegationLink | undefined;
  for (const current of chain) {
    rejectUnknownMembers(current, DELEGATION_LINK_MEMBERS, "delegation link");
    if (!publicKeyHexMatches(current.delegator, expectedDelegator)) {
      return false;
    }
    if (
      !wrappedSignatureValid(
        DELEGATION_LINK_SCHEMA,
        canonicalizeJson(delegationLinkBody(current)),
        expectedDelegator,
        current.signature,
      )
    ) {
      return false;
    }
    if (previous && current.timestamp < previous.timestamp) {
      return false;
    }
    expectedDelegator = current.delegatee;
    previous = current;
  }

  return true;
}

export function parseCapabilityJson(input: string): CapabilityToken {
  const parsed = parseJsonText<unknown>(input);
  if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new ChioInvariantError("json", "capability must be a JSON object");
  }
  requireCapabilitySchema(parsed as CapabilityToken);
  return parsed as CapabilityToken;
}

function requireCapabilitySchema(capability: CapabilityToken): void {
  if (capability.schema !== CAPABILITY_SCHEMA) {
    throw new ChioInvariantError("json", `capability schema must be "${CAPABILITY_SCHEMA}"`);
  }
  rejectUnknownMembers(capability, CAPABILITY_MEMBERS, "capability");
}

function capabilityBody(capability: CapabilityToken): Omit<CapabilityToken, "signature"> {
  const {
    attenuation_proof: _attenuationProof,
    budget_share_bps: _budgetShareBps,
    caveats: _caveats,
    scope_attenuations: _scopeAttenuations,
    signature: _signature,
    ...body
  } = capability;
  return body;
}

export function capabilitySigningBody(capability: CapabilityToken): Record<string, unknown> {
  requireCapabilitySchema(capability);
  const body = capabilityBody(capability);
  const signingBody: Record<string, unknown> = { ...body };

  if (!isNonEmptyArray(signingBody.delegation_chain)) {
    delete signingBody.delegation_chain;
  }
  if (isNonEmptyArray(capability.caveats)) {
    signingBody.caveats = capability.caveats;
  }
  if (isNonEmptyArray(capability.scope_attenuations)) {
    signingBody.scope_attenuations = capability.scope_attenuations;
  }
  if (capability.attenuation_proof !== undefined && capability.attenuation_proof !== null) {
    signingBody.attenuation_proof = capability.attenuation_proof;
  }
  if (capability.budget_share_bps !== undefined && capability.budget_share_bps !== null) {
    signingBody.budget_share_bps = capability.budget_share_bps;
  }

  return signingBody;
}

export function capabilitySigningBodyCanonicalJson(capability: CapabilityToken): string {
  return canonicalizeJson(capabilitySigningBody(capability));
}

/**
 * `rootDelegator` is the subject key of the parent capability the delegation chain starts
 * from. A delegated token verified without it throws `delegation_root_unresolved`.
 */
export function verifyCapability(
  capability: CapabilityToken,
  rootDelegator: string | undefined,
  now: number,
  maxDelegationDepth?: number,
): CapabilityVerification {
  let time_status: CapabilityTimeStatus;
  if (now < capability.issued_at) {
    time_status = "not_yet_valid";
  } else if (now >= capability.expires_at) {
    time_status = "expired";
  } else {
    time_status = "valid";
  }

  return {
    signature_valid: wrappedSignatureValid(
      CAPABILITY_SCHEMA,
      capabilitySigningBodyCanonicalJson(capability),
      capability.issuer,
      capability.signature,
    ),
    delegation_chain_shape_valid: verifyDelegationChain(capability.delegation_chain ?? [], rootDelegator, maxDelegationDepth),
    time_valid: time_status === "valid",
    time_status,
  };
}

export function verifyCapabilityJson(
  input: string,
  rootDelegator: string | undefined,
  now: number,
  maxDelegationDepth?: number,
): CapabilityVerification {
  return verifyCapability(parseCapabilityJson(input), rootDelegator, now, maxDelegationDepth);
}
