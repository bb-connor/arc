/**
 * SDK-level error hierarchy for Chio TypeScript SDK.
 *
 * ChioError is the base for all SDK-level errors.
 * ChioInvariantError (in invariants/errors.ts) is a separate, lower-level layer
 * and does NOT extend ChioError.
 */
export class ChioError extends Error {
    code;
    constructor(code, message, options) {
        super(message, options);
        this.name = "ChioError";
        this.code = code;
    }
}
export class DpopSignError extends ChioError {
    constructor(message, options) {
        super("dpop_sign_error", message, options);
        this.name = "DpopSignError";
    }
}
export class QueryError extends ChioError {
    status;
    constructor(message, status, options) {
        super("query_error", message, options);
        this.name = "QueryError";
        this.status = status;
    }
}
export class TransportError extends ChioError {
    constructor(message, options) {
        super("transport_error", message, options);
        this.name = "TransportError";
    }
}
//# sourceMappingURL=errors.js.map