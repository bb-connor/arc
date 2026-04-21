export type ChioInvariantErrorCode = "json" | "canonical_json" | "invalid_hex" | "invalid_public_key" | "invalid_signature";
export declare class ChioInvariantError extends Error {
    readonly code: ChioInvariantErrorCode;
    constructor(code: ChioInvariantErrorCode, message: string, options?: {
        cause?: unknown;
    });
}
export declare function parseJsonText<T>(input: string): T;
//# sourceMappingURL=errors.d.ts.map