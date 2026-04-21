import { readRpcMessagesUntilTerminal, terminalMessage, } from "./messages.js";
function responseHeaders(response) {
    return Object.fromEntries(response.headers.entries());
}
export function buildRpcHeaders(authToken, sessionId, protocolVersion) {
    const headers = {
        Authorization: `Bearer ${authToken}`,
        Accept: "application/json, text/event-stream",
        "Content-Type": "application/json",
    };
    if (sessionId) {
        headers["MCP-Session-Id"] = sessionId;
    }
    if (protocolVersion) {
        headers["MCP-Protocol-Version"] = protocolVersion;
    }
    return headers;
}
export function buildSessionDeleteHeaders(authToken, sessionId) {
    return {
        Authorization: `Bearer ${authToken}`,
        "MCP-Session-Id": sessionId,
    };
}
export async function postRpc(baseUrl, authToken, sessionId, protocolVersion, body, onMessage = async () => { }, fetchImpl = fetch) {
    const response = await fetchImpl(`${baseUrl}/mcp`, {
        method: "POST",
        headers: buildRpcHeaders(authToken, sessionId, protocolVersion),
        body: JSON.stringify(body),
    });
    return {
        request: body,
        status: response.status,
        headers: responseHeaders(response),
        messages: await readRpcMessagesUntilTerminal(response, body.id, onMessage),
    };
}
export async function postNotification(baseUrl, authToken, sessionId, protocolVersion, body, onMessage = async () => { }, fetchImpl = fetch) {
    const response = await fetchImpl(`${baseUrl}/mcp`, {
        method: "POST",
        headers: buildRpcHeaders(authToken, sessionId, protocolVersion),
        body: JSON.stringify(body),
    });
    return {
        request: body,
        status: response.status,
        headers: responseHeaders(response),
        messages: await readRpcMessagesUntilTerminal(response, undefined, onMessage),
    };
}
export async function deleteSession(baseUrl, authToken, sessionId, fetchImpl = fetch) {
    const response = await fetchImpl(`${baseUrl}/mcp`, {
        method: "DELETE",
        headers: buildSessionDeleteHeaders(authToken, sessionId),
    });
    return {
        status: response.status,
        headers: responseHeaders(response),
    };
}
export async function initializeSession(baseUrl, authToken, initializeBody, onInitializedMessage = async () => { }, fetchImpl = fetch) {
    const initializeResponse = await postRpc(baseUrl, authToken, null, null, initializeBody, async () => { }, fetchImpl);
    const initializeId = initializeBody.id;
    const message = terminalMessage(initializeResponse.messages, initializeId ?? null);
    if (initializeResponse.status !== 200) {
        throw new Error(`initialize returned HTTP ${initializeResponse.status}`);
    }
    const sessionId = initializeResponse.headers["mcp-session-id"];
    if (!sessionId) {
        throw new Error("initialize response did not include MCP-Session-Id");
    }
    const result = message.result;
    const protocolVersion = result && typeof result === "object" && "protocolVersion" in result
        ? result.protocolVersion
        : undefined;
    if (typeof protocolVersion !== "string" || protocolVersion.length === 0) {
        throw new Error("initialize response did not include protocolVersion");
    }
    const initializedResponse = await postNotification(baseUrl, authToken, sessionId, protocolVersion, {
        jsonrpc: "2.0",
        method: "notifications/initialized",
    }, async (message) => {
        await onInitializedMessage(message, { sessionId, protocolVersion });
    }, fetchImpl);
    if (![200, 202].includes(initializedResponse.status)) {
        throw new Error(`notifications/initialized returned HTTP ${initializedResponse.status}`);
    }
    return {
        sessionId,
        protocolVersion,
        initializeResponse,
        initializedResponse,
    };
}
//# sourceMappingURL=session.js.map