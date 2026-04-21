import { type RpcExchange, type RpcMessageHandler, type SessionState } from "../transport/index.js";
import { type JsonRpcResponse } from "../types.js";
export interface ChioSessionHandshake {
    initializeResponse: RpcExchange;
    initializedResponse: RpcExchange;
}
export interface ChioSessionOptions extends SessionState {
    authToken: string;
    baseUrl: string;
    fetchImpl?: typeof fetch;
    onMessage?: RpcMessageHandler;
    handshake?: ChioSessionHandshake | null;
}
export declare class ChioSession {
    #private;
    readonly authToken: string;
    readonly baseUrl: string;
    handshake: ChioSessionHandshake | null;
    readonly protocolVersion: string;
    readonly sessionId: string;
    constructor(options: ChioSessionOptions);
    setMessageHandler(onMessage: RpcMessageHandler): void;
    request<TParams = unknown>(method: string, params?: TParams, onMessage?: RpcMessageHandler): Promise<RpcExchange>;
    sendEnvelope(body: Record<string, unknown>, onMessage?: RpcMessageHandler): Promise<RpcExchange>;
    requestResult<TResult = unknown, TParams = unknown>(method: string, params?: TParams, onMessage?: RpcMessageHandler): Promise<JsonRpcResponse<TResult>>;
    notification<TParams = unknown>(method: string, params?: TParams, onMessage?: RpcMessageHandler): Promise<RpcExchange>;
    listTools(params?: Record<string, unknown>): Promise<unknown>;
    callTool(name: string, args?: Record<string, unknown>): Promise<unknown>;
    listResources(params?: Record<string, unknown>): Promise<unknown>;
    readResource(uri: string): Promise<unknown>;
    subscribeResource(uri: string): Promise<unknown>;
    unsubscribeResource(uri: string): Promise<unknown>;
    listResourceTemplates(params?: Record<string, unknown>): Promise<unknown>;
    listPrompts(params?: Record<string, unknown>): Promise<unknown>;
    getPrompt(name: string, args?: Record<string, unknown>): Promise<unknown>;
    complete(params: Record<string, unknown>): Promise<unknown>;
    setLogLevel(level: string): Promise<RpcExchange>;
    listTasks(params?: Record<string, unknown>): Promise<unknown>;
    getTask(taskId: string): Promise<unknown>;
    getTaskResult(taskId: string): Promise<unknown>;
    cancelTask(taskId: string): Promise<unknown>;
    close(): Promise<{
        status: number;
        headers: Record<string, string>;
    }>;
}
//# sourceMappingURL=session.d.ts.map