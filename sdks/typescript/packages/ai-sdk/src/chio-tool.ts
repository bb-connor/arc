/**
 * `chioTool` -- Vercel AI SDK 7 tool wrapper that gates each invocation
 * through the Chio sidecar without disturbing streaming.
 *
 * ## Streaming contract
 *
 * AI SDK 7 runs a tool by calling `execute` synchronously and checking the
 * return value for `Symbol.asyncIterator`. An async iterable is streamed as
 * preliminary results; anything else is awaited as the final output. The
 * wrapper preserves that distinction:
 *
 *   - Streaming (`streaming: true`, or by default a native async generator
 *     function): the wrapper is an async generator that authorizes on its
 *     first `next()`, calls `execute`, and delegates with `yield*` when the
 *     result is an async iterable. Nothing is buffered.
 *   - Otherwise the wrapper is an async function that authorizes, calls the
 *     original `execute`, and returns its result untouched. If `execute`
 *     returns an async iterable here, the call is refused after
 *     authorization with the receipt id on the error, because the
 *     asynchronous authorization step would turn the stream into a final
 *     output.
 *
 * ## Approvals
 *
 * `toolApproval` and `needsApproval` are evaluated by the AI SDK before it
 * calls `execute`, so Chio authorization always runs after any approval step
 * and approval fields pass through the wrapper unchanged. A tool without an
 * `execute` function (client-side or provider-executed tools) cannot be
 * mediated, so `chioTool` refuses to wrap it.
 */

import type { Tool, ToolExecutionOptions } from "ai";
import {
  ChioClient,
  type ChioClientOptions,
  ChioClientError,
} from "./client.js";
import { ChioToolError } from "./errors.js";

/**
 * Identity scope declared by the caller. Maps onto the sidecar's
 * capability / tool-server / tool-name evaluation input.
 */
export interface ChioToolScope {
  /** Capability token ID already granted to the caller. */
  capabilityId?: string | undefined;
  /** Raw capability token body, forwarded via `X-Chio-Capability`. */
  capabilityToken?: string | undefined;
  /** Logical tool-server identifier this tool belongs to. */
  toolServer: string;
  /**
   * Tool name registered with the sidecar. Defaults to the key the caller
   * binds this tool under in their `tools` map; callers can override here
   * when the key differs from the registered name.
   */
  toolName: string;
  /** Optional free-form metadata forwarded alongside the evaluation payload. */
  metadata?: Record<string, unknown> | undefined;
}

/**
 * Optional hook that resolves a raw capability token for a configured
 * capability ID. This is the only safe way to keep `capabilityId` as the
 * declarative scope handle while still presenting a signed token to the
 * sidecar.
 */
export type CapabilityTokenResolver =
  (capabilityId: string) => string | Promise<string | undefined> | undefined;

/** Receipt verification result accepted by `chioTool`. */
export interface ChioReceiptAuthority {
  receipt_kind?: "mediated_decision" | "trace_observation" | "advisory_evaluation" | undefined;
  boundary_class?: "prevent" | "detect_only" | "advisory_only" | undefined;
  trust_level?: "mediated" | "verified" | "advisory" | undefined;
  result?: string | undefined;
  authorized?: boolean | undefined;
  ok?: boolean | undefined;
  signer_trusted?: boolean | undefined;
  signature_valid?: boolean | undefined;
  receipt_id_valid?: boolean | undefined;
  parameter_hash_valid?: boolean | undefined;
}

/** Caller-supplied receipt verifier, usually from `@chio-protocol/sdk` invariants. */
export type ChioReceiptVerifier =
  (receipt: Record<string, unknown>) =>
    ChioReceiptAuthority
    | Promise<ChioReceiptAuthority>;

/** Chio binding fields accepted by `chioTool` alongside the AI SDK tool definition. */
export interface ChioToolSettings {
  /** Scope describing how this tool binds to Chio capability evaluation. */
  scope: ChioToolScope;
  /**
   * Pre-constructed `ChioClient`. Takes precedence over `client*` options.
   * Useful for sharing a single client across many tools.
   */
  client?: ChioClient | undefined;
  /** Inline `ChioClient` options used when `client` is not provided. */
  clientOptions?: ChioClientOptions | undefined;
  /**
   * Optional debug hook -- forwarded to the Chio client. The wrapper never
   * writes to stdout/stderr on its own.
   */
  debug?: ((message: string, data?: unknown) => void) | undefined;
  /**
   * Optional hook used when `scope.capabilityId` is configured without an
   * inline `scope.capabilityToken`. The resolver must return the full raw
   * capability token JSON that should be presented to the sidecar.
   */
  resolveCapabilityToken?: CapabilityTokenResolver | undefined;
  /**
   * Verifies the signed receipt before tool execution. When unset, the
   * wrapper falls back to POSTing the receipt to the sidecar's
   * `/chio/verify` route using the same default URL (`http://127.0.0.1:9090`
   * unless overridden via `clientOptions.sidecarUrl` or the
   * `CHIO_SIDECAR_URL` env var) the evaluate path uses, matching the
   * documented default-sidecar deployment. Either an explicit verifier or
   * a reachable sidecar `/chio/verify` is required for an allow-shaped
   * receipt to invoke the wrapped tool.
   */
  verifyReceipt?: ChioReceiptVerifier | undefined;
  /**
   * Whether `execute` streams preliminary results by returning an async
   * iterable synchronously. Defaults to whether `execute` is a native async
   * generator function. Set it to `true` for generators that are wrapped,
   * bound or transpiled, which the default cannot recognize.
   */
  streaming?: boolean | undefined;
}

/** An AI SDK 7 `tool()` definition extended with Chio binding fields. */
export type ChioToolOptions<
  INPUT,
  OUTPUT,
  CONTEXT extends Record<string, unknown>,
> = Tool<INPUT, OUTPUT, CONTEXT> & ChioToolSettings;

function resolveClient(opts: ChioToolSettings): ChioClient {
  if (opts.client != null) {
    return opts.client;
  }
  const clientOptions: ChioClientOptions = { ...(opts.clientOptions ?? {}) };
  if (clientOptions.debug == null && opts.debug != null) {
    clientOptions.debug = opts.debug;
  }
  return new ChioClient(clientOptions);
}

/**
 * Wrap an AI SDK 7 `tool()` definition so every invocation is evaluated by
 * the Chio sidecar before the underlying `execute` runs.
 *
 * The return value is the input tool without the Chio fields, so it drops
 * directly into `streamText({ tools: { ... } })`. Throws `ChioToolError`
 * when the tool has no `execute` function, because Chio cannot mediate
 * execution that happens in the client or at the provider.
 *
 * @example
 * ```ts
 * import { z } from "zod";
 * import { chioTool } from "@chio-protocol/ai-sdk";
 *
 * const searchTool = chioTool({
 *   description: "Search the web",
 *   inputSchema: z.object({ query: z.string() }),
 *   execute: async ({ query }) => runSearch(query),
 *   scope: { toolServer: "web-tools", toolName: "search" },
 * });
 * ```
 */
export function chioTool<
  INPUT,
  OUTPUT,
  CONTEXT extends Record<string, unknown> = Record<string, unknown>,
>(
  options: ChioToolOptions<INPUT, OUTPUT, CONTEXT>,
): Tool<INPUT, OUTPUT, CONTEXT> {
  const {
    scope,
    client: _client,
    clientOptions: _clientOptions,
    debug: _debug,
    resolveCapabilityToken,
    verifyReceipt,
    streaming,
    ...definition
  } = options;
  const originalExecute = (definition as { execute?: unknown }).execute;
  if (typeof originalExecute !== "function") {
    throw new ChioToolError({
      verdict: "incomplete",
      guard: "",
      reason: `chioTool(${scope.toolName}) requires an execute() function; tools executed by the client or the provider cannot be mediated`,
    });
  }
  const execute = originalExecute as ToolExecute;
  const client = resolveClient(options);

  const authorize = async (params: unknown): Promise<string> => {
    let receipt;
    try {
      const clientArgs: { capabilityToken?: string | undefined } = {};
      let capabilityToken = scope.capabilityToken;
      if (capabilityToken == null
        && scope.capabilityId != null
        && resolveCapabilityToken != null) {
        capabilityToken = await resolveCapabilityToken(scope.capabilityId);
      }
      if (capabilityToken == null && scope.capabilityId != null) {
        throw new ChioToolError({
          verdict: "incomplete",
          guard: "",
          reason:
            "scope.capabilityId is only a hint; provide scope.capabilityToken or resolveCapabilityToken so chioTool can present a signed capability token",
        });
      }
      if (capabilityToken != null) {
        clientArgs.capabilityToken = capabilityToken;
      }
      const request: Parameters<ChioClient["evaluateToolCall"]>[0] = {
        tool_server: scope.toolServer,
        tool_name: scope.toolName,
        arguments: params,
      };
      if (scope.capabilityId != null) {
        request.capability_id = scope.capabilityId;
      }
      if (scope.metadata != null) {
        request.metadata = scope.metadata;
      }
      receipt = await client.evaluateToolCall(request, clientArgs);
    } catch (error) {
      if (error instanceof ChioClientError) {
        throw new ChioToolError({
          verdict: "sidecar_unreachable",
          guard: "",
          reason: error.message,
        });
      }
      throw error;
    }

    const verdict = receipt.decision?.verdict;
    const authorized =
      receipt.receipt_kind === "mediated_decision"
      && receipt.boundary_class === "prevent"
      && receipt.observation_outcome == null
      && receipt.trust_level === "mediated"
      && verdict === "allow";
    if (verdict == null) {
      throw new ChioToolError({
        verdict: "incomplete",
        guard: "",
        reason: `Chio receipt ${receipt.id} is non-authorizing (${String(receipt.receipt_kind ?? "unknown")})`,
        receiptId: receipt.id,
      });
    }
    if (!authorized) {
      throw new ChioToolError({
        verdict: verdict === "allow" ? "incomplete" : verdict,
        guard: receipt.decision?.guard ?? "",
        reason: receipt.decision?.reason ?? `Chio verdict: ${verdict}`,
        receiptId: receipt.id,
      });
    }

    const authority = verifyReceipt != null
      ? await verifyReceipt(receipt)
      : await verifyReceiptViaSidecar(
        receipt,
        client,
      );
    if (!receiptAuthorityAllows(authority)) {
      throw new ChioToolError({
        verdict: "incomplete",
        guard: "",
        reason: `Chio receipt ${receipt.id} did not pass trusted receipt verification`,
        receiptId: receipt.id,
      });
    }
    return receipt.id;
  };

  const wrappedExecute: ToolExecute = (streaming ?? isAsyncGeneratorFunction(execute))
    ? async function* (params, executeOptions) {
      await authorize(params);
      const result = await execute(params, executeOptions);
      if (isAsyncIterable(result)) {
        yield* result;
      } else {
        yield result;
      }
    }
    : async (params, executeOptions) => {
      const receiptId = await authorize(params);
      const result = execute(params, executeOptions);
      if (isAsyncIterable(result)) {
        throw new ChioToolError({
          verdict: "incomplete",
          guard: "",
          reason: `chioTool(${scope.toolName}) execute() returned an async iterable but streaming is not enabled; set streaming: true so results stream`,
          receiptId,
        });
      }
      return result;
    };

  return { ...definition, execute: wrappedExecute } as unknown as Tool<INPUT, OUTPUT, CONTEXT>;
}

type ToolExecute = (
  params: unknown,
  options: ToolExecutionOptions<Record<string, unknown>>,
) => unknown;

function isAsyncGeneratorFunction(fn: ToolExecute): boolean {
  return Object.prototype.toString.call(fn) === "[object AsyncGeneratorFunction]";
}

function isAsyncIterable(value: unknown): value is AsyncIterable<unknown> {
  return value != null
    && typeof (value as { [Symbol.asyncIterator]?: unknown })[Symbol.asyncIterator] === "function";
}

/**
 * Default receipt-authority pathway when the caller did not supply a
 * `verifyReceipt`. Mirrors the chio-ai-sdk-middleware fallback: POST the
 * raw receipt body to the sidecar's `/chio/verify` route at the same
 * resolved sidecar URL the evaluate path used, and parse the response
 * into a `ChioReceiptAuthority`. Fails closed when the sidecar response
 * is non-OK, the body is not parseable, or fetch is unavailable.
 *
 * The Rust `/chio/verify` handler in
 * `crates/products/chio-api-protect/src/proxy.rs::sidecar_verify_handler`
 * deserializes the request body directly as an `HttpReceipt`, so the
 * receipt body MUST be sent unwrapped (not as `{ receipt: ... }`).
 */
async function verifyReceiptViaSidecar(
  receipt: Record<string, unknown> & { id?: string },
  client: ChioClient,
): Promise<ChioReceiptAuthority> {
  try {
    return readAuthorityFromVerifyResponse(await client.verifyReceipt(receipt));
  } catch (error) {
    const reason = error instanceof ChioClientError
      ? error.message
      : error instanceof Error
        ? error.message
        : String(error);
    throw new ChioToolError({
      verdict: "sidecar_unreachable",
      guard: "",
      reason,
      receiptId: typeof receipt.id === "string" ? receipt.id : undefined,
    });
  }
}

function readAuthorityFromVerifyResponse(value: unknown): ChioReceiptAuthority {
  if (value == null || typeof value !== "object") {
    return {};
  }
  const record = value as Record<string, unknown>;
  return {
    receipt_kind: receiptKindValue(stringField(record, "receipt_kind")),
    boundary_class: boundaryClassValue(stringField(record, "boundary_class")),
    trust_level: trustLevelValue(stringField(record, "trust_level")),
    result: stringField(record, "result"),
    authorized: booleanField(record, "authorized"),
    ok: booleanField(record, "ok"),
    signer_trusted: booleanField(record, "signer_trusted"),
    signature_valid: booleanField(record, "signature_valid"),
    receipt_id_valid: booleanField(record, "receipt_id_valid"),
    parameter_hash_valid: booleanField(record, "parameter_hash_valid"),
  };
}

function stringField(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  return typeof value === "string" ? value : undefined;
}

function booleanField(record: Record<string, unknown>, key: string): boolean | undefined {
  const value = record[key];
  return typeof value === "boolean" ? value : undefined;
}

function receiptKindValue(value: string | undefined): ChioReceiptAuthority["receipt_kind"] {
  return value === "mediated_decision"
    || value === "trace_observation"
    || value === "advisory_evaluation"
    ? value
    : undefined;
}

function boundaryClassValue(value: string | undefined): ChioReceiptAuthority["boundary_class"] {
  return value === "prevent" || value === "detect_only" || value === "advisory_only"
    ? value
    : undefined;
}

function trustLevelValue(value: string | undefined): ChioReceiptAuthority["trust_level"] {
  return value === "mediated" || value === "verified" || value === "advisory"
    ? value
    : undefined;
}

function receiptAuthorityAllows(authority: ChioReceiptAuthority): boolean {
  return authority.authorized === true
    && authority.ok === true
    && authority.signer_trusted === true
    && authority.signature_valid === true
    && authority.receipt_id_valid === true
    && authority.parameter_hash_valid === true
    && authority.receipt_kind === "mediated_decision"
    && authority.boundary_class === "prevent"
    && authority.trust_level === "mediated"
    && (
      authority.result === "allow"
      || authority.result === "authorized"
      || authority.result === "Authorized"
    );
}
