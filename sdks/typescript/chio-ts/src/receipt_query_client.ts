import { QueryError, TransportError } from "./errors.ts";
import type { ChioReceipt } from "./invariants/receipt.ts";

export interface ReceiptQueryParams {
  capabilityId?: string;
  toolServer?: string;
  toolName?: string;
  outcome?: string;
  since?: number;
  until?: number;
  minCost?: bigint;
  maxCost?: bigint;
  costCurrency?: string;
  agentSubject?: string;
  cursor?: number;
  limit?: number;
}

export interface ReceiptQueryResponse {
  totalCount: number;
  nextCursor?: number | null;
  receipts: ChioReceipt[];
  snapshot?: ReceiptQuerySnapshot;
}

export interface ReceiptQuerySnapshot {
  id: string;
  throughEntrySeq: number;
  checkpointSeq: number | null;
  observedAt: number;
  recertifiedAt: number;
}

export interface ReceiptQueryClientOptions {
  /** Total attempts, including the initial request. Set to 1 to disable retries. */
  maxAttempts?: number;
  /** Monotonic budget per query/page. Zero permits one initial request. */
  retryBudgetMs?: number;
}

export interface ReceiptQueryRequestOptions {
  signal?: AbortSignal;
}

const RETRY_CODES = new Set([
  "receipt_query_snapshot_building", "receipt_query_snapshot_stale", "receipt_query_busy",
]);
const DEFAULT_BUDGET_MS = 30_000;
const MAX_ERROR_BYTES = 16 * 1024;

function retryDelay(header: string | null): number {
  if (header !== null && /^\d+$/.test(header.trim())) return Number(header.trim()) * 1000;
  if (header !== null && /^(?:[A-Za-z]{3},|[A-Za-z]+,|[A-Za-z]{3} )/.test(header)) {
    const date = Date.parse(header);
    if (Number.isFinite(date)) return Math.max(0, date - Date.now());
  }
  return 1000;
}

async function serverCode(response: Response, signal: AbortSignal): Promise<string | undefined> {
  const reader = response.body?.getReader();
  if (!reader) return undefined;
  const cancel = () => { void reader.cancel().catch(() => {}); };
  signal.addEventListener("abort", cancel, { once: true });
  try {
    const bytes = new Uint8Array(MAX_ERROR_BYTES);
    let size = 0;
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      if (chunk.value.byteLength > MAX_ERROR_BYTES - size) return undefined;
      bytes.set(chunk.value, size);
      size += chunk.value.byteLength;
    }
    const body: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, size)));
    if (body !== null && typeof body === "object" &&
        typeof (body as { error?: unknown }).error === "string" &&
        typeof (body as { code?: unknown }).code === "string") {
      return (body as { code: string }).code;
    }
  } catch {
    signal.throwIfAborted();
  } finally {
    signal.removeEventListener("abort", cancel);
    cancel();
    reader.releaseLock();
  }
  return undefined;
}

async function wait(delay: number, signal?: AbortSignal): Promise<void> {
  signal?.throwIfAborted();
  await new Promise<void>((resolve, reject) => {
    const done = () => { signal?.removeEventListener("abort", aborted); resolve(); };
    const timer = setTimeout(done, delay);
    const aborted = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", aborted);
      reject(signal?.reason);
    };
    signal?.addEventListener("abort", aborted, { once: true });
  });
}

async function timed<T>(operation: (signal: AbortSignal) => Promise<T>, duration: number, signal?: AbortSignal): Promise<T> {
  signal?.throwIfAborted();
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let aborted: (() => void) | undefined;
  try {
    const interrupted = new Promise<never>((_resolve, reject) => {
      aborted = () => { controller.abort(signal?.reason); reject(signal?.reason); };
      signal?.addEventListener("abort", aborted, { once: true });
      timer = setTimeout(() => {
        const error = new DOMException("receipt query deadline expired", "TimeoutError");
        controller.abort(error);
        reject(error);
      }, duration);
    });
    return await Promise.race([operation(controller.signal), interrupted]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    if (aborted !== undefined) signal?.removeEventListener("abort", aborted);
  }
}

export class ReceiptQueryClient {
  private baseUrl: string;
  private authToken: string;
  private fetchImpl: typeof fetch;
  private maxAttempts: number;
  private retryBudgetMs: number;

  constructor(baseUrl: string, authToken: string, fetchImpl?: typeof fetch, options: ReceiptQueryClientOptions = {}) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.authToken = authToken;
    this.fetchImpl = fetchImpl ?? globalThis.fetch;
    this.maxAttempts = options.maxAttempts === undefined ? 5 : options.maxAttempts;
    this.retryBudgetMs = options.retryBudgetMs === undefined ? DEFAULT_BUDGET_MS : options.retryBudgetMs;
    if (!Number.isSafeInteger(this.maxAttempts) || this.maxAttempts < 1 ||
        !Number.isFinite(this.retryBudgetMs) || this.retryBudgetMs < 0) {
      throw new RangeError("receipt query retry options require a positive integer attempt count and finite nonnegative budget");
    }
  }

  async query(params: ReceiptQueryParams = {}, options: ReceiptQueryRequestOptions = {}): Promise<ReceiptQueryResponse> {
    const url = new URL(`${this.baseUrl}/v1/receipts/query`);
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null) {
        url.searchParams.set(key, String(value));
      }
    }

    const deadline = performance.now() + this.retryBudgetMs;
    let lastError: QueryError | undefined;
    for (let attempt = 1; attempt <= this.maxAttempts; attempt++) {
      options.signal?.throwIfAborted();
      const remaining = deadline - performance.now();
      if (attempt > 1 && remaining <= 0) throw lastError;
      let response: Response | undefined;
      let code: string | undefined;
      let payload: ReceiptQueryResponse | undefined;
      try {
        await timed(async (signal) => {
          try {
            response = await this.fetchImpl(url.toString(), {
              method: "GET", headers: { Authorization: `Bearer ${this.authToken}` }, signal,
            });
          } catch (cause) {
            signal.throwIfAborted();
            throw new TransportError("failed to fetch receipts", { cause });
          }
          if (response.ok) payload = await response.json() as ReceiptQueryResponse;
          else code = await serverCode(response, signal);
        }, this.retryBudgetMs === 0 ? DEFAULT_BUDGET_MS : Math.max(0, Math.min(remaining, DEFAULT_BUDGET_MS)), options.signal);
      } catch (cause) {
        options.signal?.throwIfAborted();
        if (cause instanceof DOMException && cause.name === "TimeoutError") {
          if (response && !response.ok) throw new QueryError(`receipt query failed with status ${response.status}`, response.status);
          if (lastError) throw lastError;
          throw new TransportError("receipt query deadline expired", { cause });
        }
        throw cause;
      }
      if (response!.ok) {
        if (this.retryBudgetMs > 0 && performance.now() >= deadline) {
          if (lastError) throw lastError;
          throw new TransportError("receipt query deadline expired");
        }
        return payload!;
      }
      lastError = new QueryError(`receipt query failed with status ${response!.status}`, response!.status,
        code === undefined ? undefined : { serverCode: code });
      const delay = retryDelay(response!.headers.get("Retry-After"));
      if (response!.status !== 503 || code === undefined || !RETRY_CODES.has(code) ||
          attempt === this.maxAttempts || this.retryBudgetMs === 0 ||
          delay >= deadline - performance.now() || delay > 2_147_483_647) throw lastError;
      await wait(delay, options.signal);
    }
    throw lastError;
  }

  async *paginate(params: ReceiptQueryParams = {}, options: ReceiptQueryRequestOptions = {}): AsyncGenerator<ChioReceipt[]> {
    let cursor: number | undefined = params.cursor;
    while (true) {
      const response =
        cursor === undefined
          ? await this.query(params, options)
          : await this.query({ ...params, cursor }, options);
      if (
        cursor !== undefined &&
        response.nextCursor !== undefined &&
        response.nextCursor !== null &&
        response.nextCursor <= cursor
      ) {
        throw new QueryError("receipt query pagination cursor did not advance");
      }
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
