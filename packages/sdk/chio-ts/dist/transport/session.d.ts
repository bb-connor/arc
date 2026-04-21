import { type JsonRpcMessage, type RpcMessageHandler } from "./messages.js";
export interface SessionState {
    sessionId: string;
    protocolVersion: string;
}
export interface RpcExchange {
    request: Record<string, unknown>;
    status: number;
    headers: Record<string, string>;
    messages: JsonRpcMessage[];
}
export interface InitializeSessionResult extends SessionState {
    initializeResponse: RpcExchange;
    initializedResponse: RpcExchange;
}
export type InitializeSessionMessageHandler = (message: JsonRpcMessage, session: SessionState) => void | Promise<void>;
type FetchImpl = typeof fetch;
export declare function buildRpcHeaders(authToken: string, sessionId?: string | null, protocolVersion?: string | null): Record<string, string>;
export declare function buildSessionDeleteHeaders(authToken: string, sessionId: string): Record<string, string>;
export declare function postRpc(baseUrl: string, authToken: string, sessionId: string | null, protocolVersion: string | null, body: Record<string, unknown>, onMessage?: RpcMessageHandler, fetchImpl?: FetchImpl): Promise<RpcExchange>;
export declare function postNotification(baseUrl: string, authToken: string, sessionId: string, protocolVersion: string | null, body: Record<string, unknown>, onMessage?: RpcMessageHandler, fetchImpl?: FetchImpl): Promise<RpcExchange>;
export declare function deleteSession(baseUrl: string, authToken: string, sessionId: string, fetchImpl?: FetchImpl): Promise<{
    status: number;
    headers: Record<string, string>;
}>;
export declare function initializeSession(baseUrl: string, authToken: string, initializeBody: Record<string, unknown>, onInitializedMessage?: InitializeSessionMessageHandler, fetchImpl?: FetchImpl): Promise<InitializeSessionResult>;
export {};
//# sourceMappingURL=session.d.ts.map