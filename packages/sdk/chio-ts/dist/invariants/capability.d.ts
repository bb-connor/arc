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
export declare function parseCapabilityJson(input: string): CapabilityToken;
export declare function capabilityBody(capability: CapabilityToken): Omit<CapabilityToken, "signature">;
export declare function capabilityBodyCanonicalJson(capability: CapabilityToken): string;
export declare function verifyCapability(capability: CapabilityToken, now: number, maxDelegationDepth?: number): CapabilityVerification;
export declare function verifyCapabilityJson(input: string, now: number, maxDelegationDepth?: number): CapabilityVerification;
//# sourceMappingURL=capability.d.ts.map