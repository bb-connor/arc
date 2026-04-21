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
export declare function parseSignedManifestJson(input: string): SignedManifest;
export declare function signedManifestBodyCanonicalJson(signedManifest: SignedManifest): string;
export declare function verifySignedManifest(signedManifest: SignedManifest): ManifestVerification;
export declare function verifySignedManifestJson(input: string): ManifestVerification;
//# sourceMappingURL=manifest.d.ts.map