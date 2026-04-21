import { canonicalizeJson } from "./json.js";
import { verifyEd25519Signature } from "./crypto.js";
import { parseJsonText } from "./errors.js";
function delegationLinkBody(link) {
    const { signature: _signature, ...body } = link;
    return body;
}
function verifyDelegationChain(chain, maxDelegationDepth) {
    if (maxDelegationDepth !== undefined && chain.length > maxDelegationDepth) {
        return false;
    }
    let previous;
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
export function parseCapabilityJson(input) {
    return parseJsonText(input);
}
export function capabilityBody(capability) {
    const { signature: _signature, ...body } = capability;
    return body;
}
export function capabilityBodyCanonicalJson(capability) {
    return canonicalizeJson(capabilityBody(capability));
}
export function verifyCapability(capability, now, maxDelegationDepth) {
    let time_status;
    if (now < capability.issued_at) {
        time_status = "not_yet_valid";
    }
    else if (now >= capability.expires_at) {
        time_status = "expired";
    }
    else {
        time_status = "valid";
    }
    return {
        signature_valid: verifyEd25519Signature(capabilityBodyCanonicalJson(capability), capability.issuer, capability.signature),
        delegation_chain_valid: verifyDelegationChain(capability.delegation_chain ?? [], maxDelegationDepth),
        time_valid: time_status === "valid",
        time_status,
    };
}
export function verifyCapabilityJson(input, now, maxDelegationDepth) {
    return verifyCapability(parseCapabilityJson(input), now, maxDelegationDepth);
}
//# sourceMappingURL=capability.js.map