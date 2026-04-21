import { QueryError, TransportError } from "./errors.js";
export class ReceiptQueryClient {
    baseUrl;
    authToken;
    fetchImpl;
    constructor(baseUrl, authToken, fetchImpl) {
        this.baseUrl = baseUrl.replace(/\/$/, "");
        this.authToken = authToken;
        this.fetchImpl = fetchImpl ?? globalThis.fetch;
    }
    async query(params = {}) {
        const url = new URL(`${this.baseUrl}/v1/receipts/query`);
        for (const [key, value] of Object.entries(params)) {
            if (value !== undefined && value !== null) {
                url.searchParams.set(key, String(value));
            }
        }
        let response;
        try {
            response = await this.fetchImpl(url.toString(), {
                method: "GET",
                headers: { Authorization: `Bearer ${this.authToken}` },
            });
        }
        catch (cause) {
            throw new TransportError("failed to fetch receipts", { cause });
        }
        if (!response.ok) {
            throw new QueryError(`receipt query failed with status ${response.status}`, response.status);
        }
        return (await response.json());
    }
    async *paginate(params = {}) {
        let cursor = params.cursor;
        while (true) {
            const response = cursor === undefined
                ? await this.query(params)
                : await this.query({ ...params, cursor });
            if (response.receipts.length > 0) {
                yield response.receipts;
            }
            if (response.nextCursor === undefined || response.nextCursor === null) {
                break;
            }
            cursor = response.nextCursor;
        }
    }
}
//# sourceMappingURL=receipt_query_client.js.map