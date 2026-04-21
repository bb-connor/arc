import { type JsonRpcMessage } from "../transport/index.js";
import { ChioSession } from "../session/index.js";
import { type StaticBearerAuth } from "../auth/index.js";
export type ChioClientMessageHandler = (message: JsonRpcMessage, session: ChioSession) => void | Promise<void>;
export interface InitializeClientOptions {
    capabilities?: Record<string, unknown>;
    clientInfo?: {
        name: string;
        version: string;
    };
    onMessage?: ChioClientMessageHandler;
    protocolVersion?: string;
}
export interface ChioClientOptions extends StaticBearerAuth {
    baseUrl: string;
    fetchImpl?: typeof fetch;
}
export declare class ChioClient {
    #private;
    readonly authToken: string;
    readonly baseUrl: string;
    constructor(options: ChioClientOptions);
    static withStaticBearer(baseUrl: string, authToken: string, fetchImpl?: typeof fetch): ChioClient;
    initialize(options?: InitializeClientOptions): Promise<ChioSession>;
}
//# sourceMappingURL=client.d.ts.map