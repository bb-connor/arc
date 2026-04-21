export type JsonPrimitive = null | boolean | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | {
    [key: string]: JsonValue;
};
export declare function canonicalizeJson(value: unknown): string;
export declare function canonicalizeJsonString(input: string): string;
//# sourceMappingURL=json.d.ts.map