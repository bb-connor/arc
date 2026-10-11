import test from "node:test";
import type { TestContext } from "node:test";
import assert from "node:assert/strict";

import { ReceiptQueryClient } from "../src/receipt_query_client.ts";
import { QueryError, TransportError } from "../src/errors.ts";
import type { ReceiptQueryResponse } from "../src/receipt_query_client.ts";

const SNAPSHOT = {
  id: "version:42", throughEntrySeq: 120345, checkpointSeq: null,
  observedAt: 1760000000123, recertifiedAt: 1759996400456,
};
const RETRY_CODE = "receipt_query_snapshot_building";

function retryClock(t: TestContext) {
  const now = Date.UTC(2026, 9, 9);
  t.mock.timers.enable({ apis: ["setTimeout", "Date"], now });
  t.mock.method(performance, "now", () => Date.now() - now);
}

async function flush() {
  await new Promise<void>((resolve) => setImmediate(resolve));
}

function sequenceFetch(responses: Array<Response | Error>) {
  const requests: RequestInit[] = [];
  const fetchImpl: typeof fetch = async (_url, options) => {
    requests.push(options ?? {});
    const next = responses.shift();
    assert.ok(next, "unexpected extra request");
    if (next instanceof Error) throw next;
    return next;
  };
  return { fetchImpl, requests };
}

function failure(status = 503, code = RETRY_CODE, retryAfter?: string) {
  return new Response(JSON.stringify({ error: "snapshot pending", code }), {
    status, headers: retryAfter === undefined ? {} : { "Retry-After": retryAfter },
  });
}

function success(body: unknown = { totalCount: 0, nextCursor: null, receipts: [], snapshot: SNAPSHOT }) {
  return new Response(JSON.stringify(body), { status: 200 });
}

test("query retries only the three transient snapshot codes and preserves metadata", async (t) => {
  for (const code of [RETRY_CODE, "receipt_query_snapshot_stale", "receipt_query_busy"]) {
    await t.test(code, async (t) => {
      retryClock(t);
      const { fetchImpl, requests } = sequenceFetch([failure(503, code, "2"), success()]);
      const client = new ReceiptQueryClient("http://localhost", "tok", fetchImpl);
      const pending = client.query();
      const checked = assert.doesNotReject(pending);
      await flush();
      assert.equal(requests.length, 1);
      t.mock.timers.tick(1999);
      await flush();
      assert.equal(requests.length, 1);
      t.mock.timers.tick(1);
      await checked;
      assert.deepEqual((await pending).snapshot, SNAPSHOT);
      assert.equal(requests.length, 2);
    });
  }
});

test("serverCode preserves HTTP status and query_error category without retrying terminal errors", async () => {
  for (const [status, code] of [
    [422, "receipt_query_work_budget_exhausted"], [500, "receipt_query_snapshot_invalid"],
    [503, "receipt_query_snapshot_unavailable"], [503, "unknown"], [500, RETRY_CODE],
  ] as const) {
    const { fetchImpl, requests } = sequenceFetch([failure(status, code)]);
    const client = new ReceiptQueryClient("http://localhost", "tok", fetchImpl);
    await assert.rejects(client.query(), (error) => {
      assert.ok(error instanceof QueryError);
      assert.equal(error.code, "query_error");
      assert.equal(error.status, status);
      assert.equal(error.serverCode, code);
      return true;
    });
    assert.equal(requests.length, 1);
  }
});

test("attempt count and zero budget preserve typed last error and one initial request", async (t) => {
  retryClock(t);
  for (const options of [{ maxAttempts: 3 }, { retryBudgetMs: 0 }, { maxAttempts: 1 }]) {
    const { fetchImpl, requests } = sequenceFetch(Array.from({ length: 3 }, () => failure(503, RETRY_CODE, "0")));
    const client = new ReceiptQueryClient("http://localhost", "tok", fetchImpl, options);
    const checked = assert.rejects(client.query(), (error) => {
      assert.ok(error instanceof QueryError);
      assert.equal(error.serverCode, RETRY_CODE);
      return true;
    });
    await flush();
    t.mock.timers.tick(0);
    await flush();
    t.mock.timers.tick(0);
    await checked;
    assert.equal(requests.length, options.maxAttempts ?? 1);
  }
});

test("Retry-After HTTP dates are honored and excessive seconds/date/overflow never retry early", async (t) => {
  retryClock(t);
  const date = new Date(Date.now() + 2000).toUTCString();
  const { fetchImpl, requests } = sequenceFetch([failure(503, RETRY_CODE, date), success()]);
  const pending = new ReceiptQueryClient("http://localhost", "tok", fetchImpl).query();
  const checked = assert.doesNotReject(pending);
  await flush();
  t.mock.timers.tick(1999);
  await flush();
  assert.equal(requests.length, 1);
  t.mock.timers.tick(1);
  await checked;
  for (const header of ["31", "9".repeat(400), new Date(Date.now() + 60000).toUTCString()]) {
    const attempt = sequenceFetch([failure(503, RETRY_CODE, header)]);
    await assert.rejects(new ReceiptQueryClient("http://localhost", "tok", attempt.fetchImpl).query(), (error) => {
      assert.ok(error instanceof QueryError);
      assert.equal(error.serverCode, RETRY_CODE);
      return true;
    });
    assert.equal(attempt.requests.length, 1);
  }
});

test("missing/invalid Retry-After uses a bounded delay and elapsed retry budget stops requests", async (t) => {
  retryClock(t);
  const { fetchImpl, requests } = sequenceFetch([failure(), failure(503, RETRY_CODE, "invalid"), success()]);
  const client = new ReceiptQueryClient("http://localhost", "tok", fetchImpl, { retryBudgetMs: 1500 });
  const checked = assert.rejects(client.query(), (error) => {
    assert.ok(error instanceof QueryError);
    assert.equal(error.serverCode, RETRY_CODE);
    return true;
  });
  await flush();
  t.mock.timers.tick(999);
  await flush();
  assert.equal(requests.length, 1);
  t.mock.timers.tick(1);
  await checked;
  assert.equal(requests.length, 2);
});

test("malformed and oversized errors keep QueryError status and are not retried", async () => {
  for (const body of ["{broken", JSON.stringify({ code: RETRY_CODE }), JSON.stringify({ error: "x".repeat(17000), code: RETRY_CODE })]) {
    const { fetchImpl, requests } = sequenceFetch([new Response(body, { status: 503 })]);
    await assert.rejects(new ReceiptQueryClient("http://localhost", "tok", fetchImpl).query(), (error) => {
      assert.ok(error instanceof QueryError);
      assert.equal(error.status, 503);
      assert.equal(error.serverCode, undefined);
      return true;
    });
    assert.equal(requests.length, 1);
  }
});

test("caller cancellation propagates during fetch and retry delay", async (t) => {
  retryClock(t);
  for (const delayed of [false, true]) {
    const abort = new AbortController();
    const reason = new Error("caller stopped");
    let calls = 0;
    const fetchImpl: typeof fetch = async () => {
      calls += 1;
      if (delayed) return failure(503, RETRY_CODE, "5");
      return await new Promise<Response>(() => {});
    };
    const client = new ReceiptQueryClient("http://localhost", "tok", fetchImpl);
    const checked = assert.rejects(client.query({}, { signal: abort.signal }), (error) => error === reason);
    await flush();
    abort.abort(reason);
    await checked;
    assert.equal(calls, 1);
  }
});

test("a hung injected fetch or error body is bounded by the per-query deadline", async (t) => {
  retryClock(t);
  const fetchImpl: typeof fetch = async () => await new Promise<Response>(() => {});
  const client = new ReceiptQueryClient("http://localhost", "tok", fetchImpl, { retryBudgetMs: 1000 });
  const checked = assert.rejects(client.query(), TransportError);
  await flush();
  t.mock.timers.tick(1000);
  await checked;
});

test("paginate continues short and empty pages and keeps legacy responses", async () => {
  const { fetchImpl, requests } = sequenceFetch([
    success({ totalCount: 2, nextCursor: 1, receipts: [] }),
    success({ totalCount: 2, nextCursor: 2, receipts: [FAKE_RECEIPT] }),
    success({ totalCount: 2, nextCursor: null, receipts: [FAKE_RECEIPT] }),
  ]);
  const collected = [];
  for await (const page of new ReceiptQueryClient("http://localhost", "tok", fetchImpl).paginate({ limit: 100 })) collected.push(page);
  assert.equal(collected.length, 2);
  assert.equal(requests.length, 3);
});

test("retry options reject invalid counts and budgets instead of silently defaulting", () => {
  for (const maxAttempts of [0, -1, 1.5, Infinity, NaN, null, true, "3"]) {
    assert.throws(() => new ReceiptQueryClient("http://localhost", "tok", undefined, { maxAttempts } as never), RangeError);
  }
  for (const retryBudgetMs of [-1, Infinity, NaN, null, true, "30"]) {
    assert.throws(() => new ReceiptQueryClient("http://localhost", "tok", undefined, { retryBudgetMs } as never), RangeError);
  }
});

test("a hung error body retains HTTP category and is cancelled at the deadline", async (t) => {
  retryClock(t);
  let cancelled = false;
  const body = new ReadableStream<Uint8Array>({ cancel() { cancelled = true; } });
  const fetchImpl: typeof fetch = async () => new Response(body, { status: 503 });
  const checked = assert.rejects(new ReceiptQueryClient("http://localhost", "tok", fetchImpl, { retryBudgetMs: 1000 }).query(), (error) => {
    assert.ok(error instanceof QueryError);
    assert.equal(error.status, 503);
    assert.equal(error.serverCode, undefined);
    return true;
  });
  await flush();
  t.mock.timers.tick(1000);
  await checked;
  assert.equal(cancelled, true);
});

test("transport failure after a snapshot retry does not trigger another retry", async (t) => {
  retryClock(t);
  const { fetchImpl, requests } = sequenceFetch([failure(503, RETRY_CODE, "0"), new Error("connection lost")]);
  const checked = assert.rejects(new ReceiptQueryClient("http://localhost", "tok", fetchImpl).query(), TransportError);
  await flush();
  t.mock.timers.tick(0);
  await checked;
  assert.equal(requests.length, 2);
});

test("a later terminal HTTP error keeps its own status when its body hangs", async (t) => {
  retryClock(t);
  const { fetchImpl } = sequenceFetch([
    failure(503, RETRY_CODE, "0"), new Response(new ReadableStream(), { status: 500 }),
  ]);
  const checked = assert.rejects(new ReceiptQueryClient("http://localhost", "tok", fetchImpl, { retryBudgetMs: 1000 }).query(), (error) => {
    assert.ok(error instanceof QueryError);
    assert.equal(error.status, 500);
    assert.equal(error.serverCode, undefined);
    return true;
  });
  await flush();
  t.mock.timers.tick(0);
  await flush();
  t.mock.timers.tick(1000);
  await checked;
});

test("successful transport completion after the monotonic deadline is not accepted", async (t) => {
  retryClock(t);
  let elapsed = 0;
  t.mock.method(performance, "now", () => elapsed);
  const fetchImpl: typeof fetch = async () => { elapsed = 1001; return success(); };
  await assert.rejects(new ReceiptQueryClient("http://localhost", "tok", fetchImpl, { retryBudgetMs: 1000 }).query(), TransportError);
});

// Minimal ChioReceipt fixture for response mocking
const FAKE_RECEIPT = {
  id: "receipt-001",
  timestamp: 1700000000,
  capability_id: "cap-001",
  tool_server: "tool.example.com",
  tool_name: "read_file",
  action: { parameters: {}, parameter_hash: "abc123" },
  decision: { verdict: "allow" },
  content_hash: "deadbeef",
  policy_hash: "cafebabe",
  kernel_key: "aa".repeat(32),
  signature: "bb".repeat(64),
};

function makeMockFetch(
  status: number,
  body: unknown,
  capturedRequests?: Array<{ url: string; options: RequestInit }>,
): typeof fetch {
  return async (url: string | URL | Request, options?: RequestInit): Promise<Response> => {
    if (capturedRequests !== undefined) {
      capturedRequests.push({ url: String(url), options: options ?? {} });
    }
    const json = JSON.stringify(body);
    return new Response(json, {
      status,
      headers: { "Content-Type": "application/json" },
    });
  };
}

function makeThrowingFetch(error: Error): typeof fetch {
  return async (_url: string | URL | Request, _options?: RequestInit): Promise<Response> => {
    throw error;
  };
}

// --- Constructor and basic query() tests ---

test("query() with no params calls GET baseUrl/v1/receipts/query", async () => {
  const requests: Array<{ url: string; options: RequestInit }> = [];
  const mockFetch = makeMockFetch(
    200,
    { totalCount: 0, receipts: [] } satisfies ReceiptQueryResponse,
    requests,
  );

  const client = new ReceiptQueryClient("http://localhost:8080", "tok-123", mockFetch as typeof fetch);
  await client.query();

  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, "http://localhost:8080/v1/receipts/query");
  assert.equal(requests[0].options.method, "GET");
});

test("query() passes Authorization Bearer header", async () => {
  const requests: Array<{ url: string; options: RequestInit }> = [];
  const mockFetch = makeMockFetch(200, { totalCount: 0, receipts: [] }, requests);

  const client = new ReceiptQueryClient("http://localhost:8080", "my-token", mockFetch as typeof fetch);
  await client.query();

  const headers = requests[0].options.headers as Record<string, string>;
  assert.equal(headers["Authorization"], "Bearer my-token");
});

test("query() strips trailing slash from baseUrl", async () => {
  const requests: Array<{ url: string; options: RequestInit }> = [];
  const mockFetch = makeMockFetch(200, { totalCount: 0, receipts: [] }, requests);

  const client = new ReceiptQueryClient("http://localhost:8080/", "tok", mockFetch as typeof fetch);
  await client.query();

  assert.equal(requests[0].url, "http://localhost:8080/v1/receipts/query");
});

test("query() with params encodes them as URL query parameters", async () => {
  const requests: Array<{ url: string; options: RequestInit }> = [];
  const mockFetch = makeMockFetch(200, { totalCount: 0, receipts: [] }, requests);

  const client = new ReceiptQueryClient("http://localhost:8080", "tok", mockFetch as typeof fetch);
  await client.query({
    capabilityId: "cap-001",
    toolServer: "tool.example.com",
    toolName: "read_file",
    limit: 10,
    cursor: 5,
  });

  const requestUrl = new URL(requests[0].url);
  assert.equal(requestUrl.searchParams.get("capabilityId"), "cap-001");
  assert.equal(requestUrl.searchParams.get("toolServer"), "tool.example.com");
  assert.equal(requestUrl.searchParams.get("toolName"), "read_file");
  assert.equal(requestUrl.searchParams.get("limit"), "10");
  assert.equal(requestUrl.searchParams.get("cursor"), "5");
});

test("query() preserves exact u64 cost bounds and currency", async () => {
  const requests: Array<{ url: string; options: RequestInit }> = [];
  const mockFetch = makeMockFetch(200, { totalCount: 0, receipts: [] }, requests);
  const client = new ReceiptQueryClient("http://localhost:8080", "tok", mockFetch);

  await client.query({
    minCost: 18446744073709551615n,
    maxCost: 18446744073709551615n,
    costCurrency: "USD",
  });

  const requestUrl = new URL(requests[0].url);
  assert.equal(requestUrl.searchParams.get("minCost"), "18446744073709551615");
  assert.equal(requestUrl.searchParams.get("maxCost"), "18446744073709551615");
  assert.equal(requestUrl.searchParams.get("costCurrency"), "USD");
});

test("query() returns typed ReceiptQueryResponse with totalCount, nextCursor, receipts", async () => {
  const responseBody: ReceiptQueryResponse = {
    totalCount: 1,
    nextCursor: 42,
    receipts: [FAKE_RECEIPT as never],
  };
  const mockFetch = makeMockFetch(200, responseBody);

  const client = new ReceiptQueryClient("http://localhost:8080", "tok", mockFetch as typeof fetch);
  const result = await client.query();

  assert.equal(result.totalCount, 1);
  assert.equal(result.nextCursor, 42);
  assert.equal(result.receipts.length, 1);
  assert.equal(result.receipts[0].id, "receipt-001");
});

test("query() throws QueryError with status on non-200 HTTP response", async () => {
  const mockFetch = makeMockFetch(404, { error: "not found" });
  const client = new ReceiptQueryClient("http://localhost:8080", "tok", mockFetch as typeof fetch);

  await assert.rejects(
    () => client.query(),
    (err: unknown) => {
      assert.ok(err instanceof QueryError, `expected QueryError, got ${String(err)}`);
      assert.equal(err.status, 404);
      return true;
    },
  );
});

test("query() throws QueryError on 500 response", async () => {
  const mockFetch = makeMockFetch(500, { error: "internal server error" });
  const client = new ReceiptQueryClient("http://localhost:8080", "tok", mockFetch as typeof fetch);

  await assert.rejects(
    () => client.query(),
    (err: unknown) => {
      assert.ok(err instanceof QueryError);
      assert.equal(err.status, 500);
      return true;
    },
  );
});

test("query() throws TransportError on network failure", async () => {
  const networkError = new Error("ECONNREFUSED");
  const mockFetch = makeThrowingFetch(networkError);
  const client = new ReceiptQueryClient("http://localhost:8080", "tok", mockFetch as typeof fetch);

  await assert.rejects(
    () => client.query(),
    (err: unknown) => {
      assert.ok(err instanceof TransportError, `expected TransportError, got ${String(err)}`);
      assert.equal(err.cause, networkError);
      return true;
    },
  );
});

// --- paginate() tests ---

test("paginate() yields successive pages following nextCursor", async () => {
  let callCount = 0;
  const pages = [
    { totalCount: 4, nextCursor: 2, receipts: [{ ...FAKE_RECEIPT, id: "r1" }, { ...FAKE_RECEIPT, id: "r2" }] },
    { totalCount: 4, nextCursor: 4, receipts: [{ ...FAKE_RECEIPT, id: "r3" }, { ...FAKE_RECEIPT, id: "r4" }] },
    { totalCount: 4, nextCursor: undefined, receipts: [] },
  ];

  const mockFetch: typeof fetch = async () => {
    const page = pages[callCount++];
    return new Response(JSON.stringify(page), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };

  const client = new ReceiptQueryClient("http://localhost:8080", "tok", mockFetch);
  const collectedPages: string[][] = [];

  for await (const page of client.paginate()) {
    collectedPages.push(page.map((r) => r.id));
  }

  assert.equal(collectedPages.length, 2, "should yield 2 non-empty pages");
  assert.deepEqual(collectedPages[0], ["r1", "r2"]);
  assert.deepEqual(collectedPages[1], ["r3", "r4"]);
});

test("paginate() stops when nextCursor is undefined", async () => {
  const mockFetch = makeMockFetch(200, {
    totalCount: 1,
    nextCursor: undefined,
    receipts: [FAKE_RECEIPT],
  });

  const client = new ReceiptQueryClient("http://localhost:8080", "tok", mockFetch as typeof fetch);
  const pages: unknown[][] = [];

  for await (const page of client.paginate()) {
    pages.push(page);
  }

  assert.equal(pages.length, 1);
});

test("paginate() with empty first page yields nothing", async () => {
  const mockFetch = makeMockFetch(200, { totalCount: 0, receipts: [] });
  const client = new ReceiptQueryClient("http://localhost:8080", "tok", mockFetch as typeof fetch);
  const pages: unknown[][] = [];

  for await (const page of client.paginate()) {
    pages.push(page);
  }

  assert.equal(pages.length, 0, "empty first page should yield no pages");
});

test("paginate() fails when the server repeats a cursor", async () => {
  let callCount = 0;
  const responses = [
    { totalCount: 1, nextCursor: 5, receipts: [FAKE_RECEIPT] },
    { totalCount: 1, nextCursor: 5, receipts: [{ ...FAKE_RECEIPT, id: "dup" }] },
  ];
  const mockFetch: typeof fetch = async () => {
    const response = responses[Math.min(callCount, responses.length - 1)];
    callCount += 1;
    return new Response(JSON.stringify(response), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };

  const client = new ReceiptQueryClient("http://localhost:8080", "tok", mockFetch);
  const iterator = client.paginate();

  const first = await iterator.next();
  assert.equal(first.done, false);
  await assert.rejects(
    () => iterator.next(),
    (err: unknown) => {
      assert.ok(err instanceof QueryError);
      assert.match(err.message, /cursor did not advance/);
      return true;
    },
  );
});

test("paginate() fails when the server regresses a cursor", async () => {
  let callCount = 0;
  const responses = [
    { totalCount: 1, nextCursor: 10, receipts: [FAKE_RECEIPT] },
    { totalCount: 1, nextCursor: 5, receipts: [{ ...FAKE_RECEIPT, id: "dup" }] },
  ];
  const mockFetch: typeof fetch = async () => {
    const response = responses[Math.min(callCount, responses.length - 1)];
    callCount += 1;
    return new Response(JSON.stringify(response), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };

  const client = new ReceiptQueryClient("http://localhost:8080", "tok", mockFetch);
  const iterator = client.paginate();

  const first = await iterator.next();
  assert.equal(first.done, false);
  await assert.rejects(
    () => iterator.next(),
    (err: unknown) => {
      assert.ok(err instanceof QueryError);
      assert.match(err.message, /cursor did not advance/);
      return true;
    },
  );
});

// --- Package smoke tests ---

async function readPackageJson(): Promise<{ name: string; version: string; private?: boolean }> {
  const { readFile } = await import("node:fs/promises");
  const { fileURLToPath } = await import("node:url");
  const { dirname, resolve } = await import("node:path");
  const testDir = dirname(fileURLToPath(import.meta.url));
  const pkgPath = resolve(testDir, "../package.json");
  const raw = await readFile(pkgPath, "utf8");
  return JSON.parse(raw) as { name: string; version: string; private?: boolean };
}

test("package.json name is @chio-protocol/sdk", async () => {
  const pkg = await readPackageJson();
  assert.equal(pkg.name, "@chio-protocol/sdk");
});

test("package.json version is 0.1.0", async () => {
  const pkg = await readPackageJson();
  assert.equal(pkg.version, "0.1.0");
});

test("package.json private field is absent", async () => {
  const pkg = await readPackageJson();
  assert.equal(pkg.private, undefined);
});
