/**
 * @arc-protocol/ai-sdk
 *
 * Vercel AI SDK wrapper for the ARC protocol. Provides `arcTool()` which
 * evaluates each tool invocation through the ARC sidecar before delegating
 * to the underlying `execute`. Streaming return values (`ReadableStream`,
 * async generators) pass through unchanged.
 *
 * @example
 * ```ts
 * import { streamText, tool } from "ai";
 * import { z } from "zod";
 * import { arcTool } from "@arc-protocol/ai-sdk";
 *
 * const searchTool = arcTool({
 *   description: "Search the web",
 *   parameters: z.object({ query: z.string() }),
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
  arcTool,
  type ArcToolOptions,
  type ArcToolScope,
  type CapabilityTokenResolver,
  type ToolLike,
  type ToolExecuteOptions,
} from "./arc-tool.js";
export {
  ArcClient,
  ArcClientError,
  resolveSidecarUrl,
  type ArcClientOptions,
  type ArcDecision,
  type ArcEvaluateToolCallRequest,
  type ArcReceipt,
  type ArcVerdict,
} from "./client.js";
export { ArcToolError, type ArcToolErrorVerdict } from "./errors.js";
