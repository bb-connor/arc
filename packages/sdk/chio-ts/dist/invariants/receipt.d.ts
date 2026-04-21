import { canonicalizeJsonString } from "./json.js";
export type ReceiptDecisionKind = "allow" | "deny" | "cancelled" | "incomplete";
export interface ToolCallAction {
    parameters: unknown;
    parameter_hash: string;
}
export interface ChioReceipt {
    id: string;
    timestamp: number;
    capability_id: string;
    tool_server: string;
    tool_name: string;
    action: ToolCallAction;
    decision: {
        verdict: ReceiptDecisionKind;
        reason?: string;
        guard?: string;
    };
    content_hash: string;
    policy_hash: string;
    evidence?: Array<{
        guard_name: string;
        verdict: boolean;
        details?: string;
    }>;
    metadata?: unknown;
    kernel_key: string;
    signature: string;
}
export interface ReceiptVerification {
    signature_valid: boolean;
    parameter_hash_valid: boolean;
    decision: ReceiptDecisionKind;
}
export declare function parseReceiptJson(input: string): ChioReceipt;
export declare function receiptBody(receipt: ChioReceipt): Omit<ChioReceipt, "signature">;
export declare function receiptBodyCanonicalJson(receipt: ChioReceipt): string;
export declare function verifyReceipt(receipt: ChioReceipt): ReceiptVerification;
export declare function verifyReceiptJson(input: string): ReceiptVerification;
export { canonicalizeJsonString };
//# sourceMappingURL=receipt.d.ts.map