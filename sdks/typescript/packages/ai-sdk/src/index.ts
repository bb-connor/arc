/**
 * @chio-protocol/ai-sdk
 *
 * Vercel AI SDK 7 wrapper for the Chio protocol. Provides `chioTool()` which
 * evaluates each tool invocation through the Chio sidecar before delegating
 * to the underlying `execute`. Async generator tools keep streaming.
 *
 * @example
 * ```ts
 * import { streamText } from "ai";
 * import { z } from "zod";
 * import { chioTool } from "@chio-protocol/ai-sdk";
 *
 * const searchTool = chioTool({
 *   description: "Search the web",
 *   inputSchema: z.object({ query: z.string() }),
 *   execute: async ({ query }) => runSearch(query),
 *   scope: { toolServer: "web-tools", toolName: "search" },
 * });
 *
 * const result = streamText({
 *   model,
 *   tools: { search: searchTool },
 *   prompt: "Research quantum computing advances",
 * });
 * ```
 */

export {
  chioTool,
  type ChioToolOptions,
  type ChioToolScope,
  type ChioToolSettings,
  type CapabilityTokenResolver,
} from "./chio-tool.js";
export {
  ChioClient,
  ChioClientError,
  resolveSidecarUrl,
  type ChioClientOptions,
  type ChioDecision,
  type ChioEvaluateToolCallRequest,
  type ChioReceipt,
  type ChioVerdict,
} from "./client.js";
export { ChioToolError, type ChioToolErrorVerdict } from "./errors.js";
