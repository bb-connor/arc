export type JsonRpcId = string | number | null;
export type JsonRpcMessage = Record<string, unknown> & {
    id?: JsonRpcId;
    method?: string;
};
export type RpcMessageHandler = (message: JsonRpcMessage) => void | Promise<void>;
export declare function parseRpcMessages(rawBody: string): JsonRpcMessage[];
export declare function readRpcMessagesUntilTerminal(response: Response, expectedId?: JsonRpcId, onMessage?: RpcMessageHandler): Promise<JsonRpcMessage[]>;
export declare function terminalMessage(messages: JsonRpcMessage[], expectedId: JsonRpcId): JsonRpcMessage;
//# sourceMappingURL=messages.d.ts.map