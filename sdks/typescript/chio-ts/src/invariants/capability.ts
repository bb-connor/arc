import { canonicalizeJson, parseJsonTextUniqueKeys } from "./json.ts";
import { wrappedSignatureValid } from "./crypto.ts";
import { ChioInvariantError } from "./errors.ts";

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
  "root_anchor",
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

const ROOT_ANCHOR_REQUIRED = [
  "kind",
  "context_digest",
  "root_policy_digest",
  "anchored_at",
  "assertion_exp",
] as const;

const ROOT_ANCHOR_MEMBERS: ReadonlySet<string> = new Set(ROOT_ANCHOR_REQUIRED);

const ROOT_ANCHOR_KINDS: ReadonlySet<unknown> = new Set([
  "oauth_id_jag",
  "entra_jwt",
  "entra_agent_id",
  "oidc_jwt",
  "oauth_introspection",
  "chio_local_as",
  "chio_operator_key",
  "operator_static_bearer",
]);

const ROOT_ANCHOR_DIGEST = /^sha256:[0-9a-f]{64}$/;

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
  root_anchor?: RootAnchor;
  signature: string;
}

export interface RootAnchor {
  kind: string;
  context_digest: string;
  root_policy_digest: string;
  anchored_at: number;
  assertion_exp: number;
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

function verifyDelegationChain(chain: DelegationLink[], maxDelegationDepth?: number): boolean {
  if (maxDelegationDepth !== undefined && chain.length > maxDelegationDepth) {
    return false;
  }

  let previous: DelegationLink | undefined;
  for (const current of chain) {
    rejectUnknownMembers(current, DELEGATION_LINK_MEMBERS, "delegation link");
    if (
      !wrappedSignatureValid(
        DELEGATION_LINK_SCHEMA,
        canonicalizeJson(delegationLinkBody(current)),
        current.delegator,
        current.signature,
      )
    ) {
      return false;
    }

    if (previous) {
      if (previous.delegatee !== current.delegator) {
        return false;
      }
      if (current.timestamp < previous.timestamp) {
        return false;
      }
    }
    previous = current;
  }

  return true;
}

export function parseCapabilityJson(input: string): CapabilityToken {
  const parsed = parseJsonTextUniqueKeys<unknown>(input);
  if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new ChioInvariantError("json", "capability must be a JSON object");
  }
  requireCapabilitySchema(parsed as CapabilityToken);
  return parsed as CapabilityToken;
}

function validateRootAnchor(value: unknown): void {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new ChioInvariantError("json", "root_anchor must be a JSON object");
  }
  rejectUnknownMembers(value, ROOT_ANCHOR_MEMBERS, "root_anchor");
  const anchor = value as Record<string, unknown>;
  for (const member of ROOT_ANCHOR_REQUIRED) {
    if (!Object.hasOwn(anchor, member)) {
      throw new ChioInvariantError("json", `root_anchor is missing member ${member}`);
    }
  }
  if (!ROOT_ANCHOR_KINDS.has(anchor.kind)) {
    throw new ChioInvariantError("json", "root_anchor kind is not a known anchor kind");
  }
  for (const member of ["context_digest", "root_policy_digest"]) {
    const digest = anchor[member];
    if (typeof digest !== "string" || !ROOT_ANCHOR_DIGEST.test(digest)) {
      throw new ChioInvariantError("json", `root_anchor ${member} must be a sha256 digest`);
    }
  }
  for (const member of ["anchored_at", "assertion_exp"]) {
    const integer = anchor[member];
    if (!Number.isSafeInteger(integer) || (integer as number) < 0) {
      throw new ChioInvariantError("json", `root_anchor ${member} must be an unsigned integer`);
    }
  }
}

function requireCapabilitySchema(capability: CapabilityToken): void {
  if (capability.schema !== CAPABILITY_SCHEMA) {
    throw new ChioInvariantError("json", `capability schema must be "${CAPABILITY_SCHEMA}"`);
  }
  rejectUnknownMembers(capability, CAPABILITY_MEMBERS, "capability");
  if (Object.hasOwn(capability, "root_anchor")) {
    validateRootAnchor(capability.root_anchor);
  }
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

export function verifyCapability(
  capability: CapabilityToken,
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
    delegation_chain_shape_valid: verifyDelegationChain(capability.delegation_chain ?? [], maxDelegationDepth),
    time_valid: time_status === "valid",
    time_status,
  };
}

export function verifyCapabilityJson(
  input: string,
  now: number,
  maxDelegationDepth?: number,
): CapabilityVerification {
  return verifyCapability(parseCapabilityJson(input), now, maxDelegationDepth);
}
