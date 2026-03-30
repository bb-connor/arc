import {
  postRpc,
  terminalMessage,
  type JsonRpcMessage,
} from "../transport/index.ts";
import { ArcSession } from "../session/index.ts";
import { staticBearerAuth, type StaticBearerAuth } from "../auth/index.ts";

export type ArcClientMessageHandler = (
  message: JsonRpcMessage,
  session: ArcSession,
) => void | Promise<void>;

export interface InitializeClientOptions {
  capabilities?: Record<string, unknown>;
  clientInfo?: {
    name: string;
    version: string;
  };
  onMessage?: ArcClientMessageHandler;
  protocolVersion?: string;
}

export interface ArcClientOptions extends StaticBearerAuth {
  baseUrl: string;
  fetchImpl?: typeof fetch;
}

export class ArcClient {
  readonly authToken: string;
  readonly baseUrl: string;

  #fetchImpl: typeof fetch;

  constructor(options: ArcClientOptions) {
    this.authToken = options.authToken;
    this.baseUrl = options.baseUrl;
    this.#fetchImpl = options.fetchImpl ?? fetch;
  }

  static withStaticBearer(baseUrl: string, authToken: string, fetchImpl?: typeof fetch): ArcClient {
    const options: ArcClientOptions = {
      baseUrl,
      ...staticBearerAuth(authToken),
    };
    if (fetchImpl !== undefined) {
      options.fetchImpl = fetchImpl;
    }
    return new ArcClient(options);
  }

  async initialize(options: InitializeClientOptions = {}): Promise<ArcSession> {
    const initializeRequest = {
      jsonrpc: "2.0" as const,
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: options.protocolVersion ?? "2025-11-25",
        capabilities: options.capabilities ?? {},
        clientInfo: options.clientInfo ?? {
          name: "@arc-protocol/sdk",
          version: "0.1.0",
        },
      },
    };
    const initializeResponse = await postRpc(
      this.baseUrl,
      this.authToken,
      null,
      null,
      initializeRequest,
      async () => {},
      this.#fetchImpl,
    );
    const initializeMessage = terminalMessage(
      initializeResponse.messages,
      initializeRequest.id,
    );
    if (initializeResponse.status !== 200) {
      throw new Error(`initialize returned HTTP ${initializeResponse.status}`);
    }
    const sessionId = initializeResponse.headers["mcp-session-id"];
    if (!sessionId) {
      throw new Error("initialize response did not include MCP-Session-Id");
    }
    const initializeResult = initializeMessage.result;
    const protocolVersion =
      initializeResult &&
      typeof initializeResult === "object" &&
      "protocolVersion" in initializeResult
        ? initializeResult.protocolVersion
        : undefined;
    if (typeof protocolVersion !== "string" || protocolVersion.length === 0) {
      throw new Error("initialize response did not include protocolVersion");
    }

    const session = new ArcSession({
      authToken: this.authToken,
      baseUrl: this.baseUrl,
      handshake: null,
      sessionId,
      protocolVersion,
      fetchImpl: this.#fetchImpl,
    });
    if (options.onMessage) {
      session.setMessageHandler(async (message) => {
        await options.onMessage?.(message, session);
      });
    }

    const initializedResponse = await session.notification(
      "notifications/initialized",
      undefined,
      async (message) => {
        if (options.onMessage) {
          await options.onMessage(message, session);
        }
      },
    );
    if (![200, 202].includes(initializedResponse.status)) {
      throw new Error(
        `notifications/initialized returned HTTP ${initializedResponse.status}`,
      );
    }
    session.handshake = {
      initializeResponse,
      initializedResponse,
    };
    return session;
  }
}
