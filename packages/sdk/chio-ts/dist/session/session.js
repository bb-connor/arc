import { deleteSession, postNotification, postRpc, terminalMessage, } from "../transport/index.js";
import { isJsonRpcFailure } from "../types.js";
export class ChioSession {
    authToken;
    baseUrl;
    handshake;
    protocolVersion;
    sessionId;
    #fetchImpl;
    #nextRequestId;
    #onMessage;
    constructor(options) {
        this.authToken = options.authToken;
        this.baseUrl = options.baseUrl;
        this.handshake = options.handshake ?? null;
        this.protocolVersion = options.protocolVersion;
        this.sessionId = options.sessionId;
        this.#fetchImpl = options.fetchImpl ?? fetch;
        this.#nextRequestId = 2;
        this.#onMessage = options.onMessage ?? (async () => { });
    }
    setMessageHandler(onMessage) {
        this.#onMessage = onMessage;
    }
    async request(method, params, onMessage = this.#onMessage) {
        const request = {
            jsonrpc: "2.0",
            id: this.#nextId(),
            method,
        };
        if (params !== undefined) {
            request.params = params;
        }
        return postRpc(this.baseUrl, this.authToken, this.sessionId, this.protocolVersion, request, onMessage, this.#fetchImpl);
    }
    async sendEnvelope(body, onMessage = this.#onMessage) {
        return postRpc(this.baseUrl, this.authToken, this.sessionId, this.protocolVersion, body, onMessage, this.#fetchImpl);
    }
    async requestResult(method, params, onMessage = this.#onMessage) {
        const exchange = await this.request(method, params, onMessage);
        return terminalMessage(exchange.messages, exchange.request.id);
    }
    async notification(method, params, onMessage = this.#onMessage) {
        const notification = {
            jsonrpc: "2.0",
            method,
        };
        if (params !== undefined) {
            notification.params = params;
        }
        return postNotification(this.baseUrl, this.authToken, this.sessionId, this.protocolVersion, notification, onMessage, this.#fetchImpl);
    }
    async listTools(params = {}) {
        return this.#result("tools/list", params);
    }
    async callTool(name, args = {}) {
        return this.#result("tools/call", {
            name,
            arguments: args,
        });
    }
    async listResources(params = {}) {
        return this.#result("resources/list", params);
    }
    async readResource(uri) {
        return this.#result("resources/read", { uri });
    }
    async subscribeResource(uri) {
        return this.#result("resources/subscribe", { uri });
    }
    async unsubscribeResource(uri) {
        return this.#result("resources/unsubscribe", { uri });
    }
    async listResourceTemplates(params = {}) {
        return this.#result("resources/templates/list", params);
    }
    async listPrompts(params = {}) {
        return this.#result("prompts/list", params);
    }
    async getPrompt(name, args) {
        const params = { name };
        if (args) {
            params.arguments = args;
        }
        return this.#result("prompts/get", params);
    }
    async complete(params) {
        return this.#result("completion/complete", params);
    }
    async setLogLevel(level) {
        return this.notification("logging/setLevel", { level });
    }
    async listTasks(params = {}) {
        return this.#result("tasks/list", params);
    }
    async getTask(taskId) {
        return this.#result("tasks/get", { taskId });
    }
    async getTaskResult(taskId) {
        return this.#result("tasks/result", { taskId });
    }
    async cancelTask(taskId) {
        return this.#result("tasks/cancel", { taskId });
    }
    async close() {
        return deleteSession(this.baseUrl, this.authToken, this.sessionId, this.#fetchImpl);
    }
    #nextId() {
        const id = this.#nextRequestId;
        this.#nextRequestId += 1;
        return id;
    }
    async #result(method, params) {
        const response = await this.requestResult(method, params);
        if (isJsonRpcFailure(response)) {
            throw new Error(response.error.message);
        }
        return response.result;
    }
}
//# sourceMappingURL=session.js.map