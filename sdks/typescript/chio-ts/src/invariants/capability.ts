import { canonicalizeJson } from "./json.ts";
import { verifyEd25519Signature } from "./crypto.ts";
import { parseJsonText } from "./errors.ts";

export type CapabilityTimeStatus = "valid" | "not_yet_valid" | "expired";

export interface DelegationLink {
  capability_id: string;
  delegator: string;
  delegatee: string;
  attenuations?: unknown[];
  timestamp: number;
  signature: string;
}

export interface CapabilityToken {
  id: string;
  issuer: string;
  subject: string;
  scope: unknown;
  issued_at: number;
  expires_at: number;
  delegation_chain?: DelegationLink[];
  signature: string;
}

export interface CapabilityVerification {
  signature_valid: boolean;
  delegation_chain_valid: boolean;
  time_valid: boolean;
  time_status: CapabilityTimeStatus;
}

function delegationLinkBody(link: DelegationLink): Omit<DelegationLink, "signature"> {
  const { signature: _signature, ...body } = link;
  return body;
}

function verifyDelegationChain(chain: DelegationLink[], maxDelegationDepth?: number): boolean {
  if (maxDelegationDepth !== undefined && chain.length > maxDelegationDepth) {
    return false;
  }

  let previous: DelegationLink | undefined;
  for (const current of chain) {
    if (!verifyEd25519Signature(canonicalizeJson(delegationLinkBody(current)), current.delegator, current.signature)) {
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
  return parseJsonText(input);
}

export function capabilityBody(capability: CapabilityToken): Omit<CapabilityToken, "signature"> {
  const { signature: _signature, ...body } = capability;
  return body;
}

export function capabilityBodyCanonicalJson(capability: CapabilityToken): string {
  return canonicalizeJson(capabilityBody(capability));
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
    signature_valid: verifyEd25519Signature(
      capabilityBodyCanonicalJson(capability),
      capability.issuer,
      capability.signature,
    ),
    delegation_chain_valid: verifyDelegationChain(capability.delegation_chain ?? [], maxDelegationDepth),
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
