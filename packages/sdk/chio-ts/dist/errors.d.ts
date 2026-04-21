/**
 * SDK-level error hierarchy for Chio TypeScript SDK.
 *
 * ChioError is the base for all SDK-level errors.
 * ChioInvariantError (in invariants/errors.ts) is a separate, lower-level layer
 * and does NOT extend ChioError.
 */
export declare class ChioError extends Error {
    readonly code: string;
    constructor(code: string, message: string, options?: ErrorOptions);
}
export declare class DpopSignError extends ChioError {
    constructor(message: string, options?: ErrorOptions);
}
export declare class QueryError extends ChioError {
    readonly status: number | undefined;
    constructor(message: string, status?: number, options?: ErrorOptions);
}
export declare class TransportError extends ChioError {
    constructor(message: string, options?: ErrorOptions);
}
//# sourceMappingURL=errors.d.ts.map