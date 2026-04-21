import type { ChioReceipt } from "./invariants/receipt.js";
export interface ReceiptQueryParams {
    capabilityId?: string;
    toolServer?: string;
    toolName?: string;
    outcome?: string;
    since?: number;
    until?: number;
    minCost?: number;
    maxCost?: number;
    agentSubject?: string;
    cursor?: number;
    limit?: number;
}
export interface ReceiptQueryResponse {
    totalCount: number;
    nextCursor?: number;
    receipts: ChioReceipt[];
}
export declare class ReceiptQueryClient {
    private baseUrl;
    private authToken;
    private fetchImpl;
    constructor(baseUrl: string, authToken: string, fetchImpl?: typeof fetch);
    query(params?: ReceiptQueryParams): Promise<ReceiptQueryResponse>;
    paginate(params?: ReceiptQueryParams): AsyncGenerator<ChioReceipt[]>;
}
//# sourceMappingURL=receipt_query_client.d.ts.map