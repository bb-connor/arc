/**
 * @arc-protocol/node-http
 *
 * Common HTTP interception substrate for the ARC protocol.
 * Works with Node.js and Bun runtimes. Provides:
 *
 * - Identity extraction from Authorization headers, cookies, API keys
 * - ARC sidecar client for localhost HTTP evaluation
 * - Node.js (req, res) interception
 * - Web API (Request -> Response) interception
 * - Signed receipt production via ARC sidecar
 */

export * from "./types.js";
export * from "./identity.js";
export * from "./sidecar-client.js";
export {
  interceptNodeRequest,
  interceptWebRequest,
  buildArcHttpRequest,
  resolveConfig,
  type ResolvedConfig,
  type BuildRequestOptions,
} from "./interceptor.js";
