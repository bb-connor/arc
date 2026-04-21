import { postRpc, terminalMessage, } from "../transport/index.js";
import { ChioSession } from "../session/index.js";
import { staticBearerAuth } from "../auth/index.js";
export class ChioClient {
    authToken;
    baseUrl;
    #fetchImpl;
    constructor(options) {
        this.authToken = options.authToken;
        this.baseUrl = options.baseUrl;
        this.#fetchImpl = options.fetchImpl ?? fetch;
    }
    static withStaticBearer(baseUrl, authToken, fetchImpl) {
        const options = {
            baseUrl,
            ...staticBearerAuth(authToken),
        };
        if (fetchImpl !== undefined) {
            options.fetchImpl = fetchImpl;
        }
        return new ChioClient(options);
    }
    async initialize(options = {}) {
        const initializeRequest = {
            jsonrpc: "2.0",
            id: 1,
            method: "initialize",
            params: {
                protocolVersion: options.protocolVersion ?? "2025-11-25",
                capabilities: options.capabilities ?? {},
                clientInfo: options.clientInfo ?? {
                    name: "@chio-protocol/sdk",
                    version: "1.0.0",
                },
            },
        };
        const initializeResponse = await postRpc(this.baseUrl, this.authToken, null, null, initializeRequest, async () => { }, this.#fetchImpl);
        const initializeMessage = terminalMessage(initializeResponse.messages, initializeRequest.id);
        if (initializeResponse.status !== 200) {
            throw new Error(`initialize returned HTTP ${initializeResponse.status}`);
        }
        const sessionId = initializeResponse.headers["mcp-session-id"];
        if (!sessionId) {
            throw new Error("initialize response did not include MCP-Session-Id");
        }
        const initializeResult = initializeMessage.result;
        const protocolVersion = initializeResult &&
            typeof initializeResult === "object" &&
            "protocolVersion" in initializeResult
            ? initializeResult.protocolVersion
            : undefined;
        if (typeof protocolVersion !== "string" || protocolVersion.length === 0) {
            throw new Error("initialize response did not include protocolVersion");
        }
        const session = new ChioSession({
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
        const initializedResponse = await session.notification("notifications/initialized", undefined, async (message) => {
            if (options.onMessage) {
                await options.onMessage(message, session);
            }
        });
        if (![200, 202].includes(initializedResponse.status)) {
            throw new Error(`notifications/initialized returned HTTP ${initializedResponse.status}`);
        }
        session.handshake = {
            initializeResponse,
            initializedResponse,
        };
        return session;
    }
}
//# sourceMappingURL=client.js.map