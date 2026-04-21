import { ChioInvariantError, parseJsonText } from "./errors.js";
function compareUtf16(a, b) {
    if (a < b) {
        return -1;
    }
    if (a > b) {
        return 1;
    }
    return 0;
}
export function canonicalizeJson(value) {
    if (value === null) {
        return "null";
    }
    switch (typeof value) {
        case "boolean":
            return value ? "true" : "false";
        case "number":
            if (!Number.isFinite(value)) {
                throw new ChioInvariantError("canonical_json", "canonical JSON does not support non-finite numbers");
            }
            return JSON.stringify(value);
        case "string":
            return JSON.stringify(value);
        case "object":
            if (Array.isArray(value)) {
                return `[${value.map((item) => canonicalizeJson(item)).join(",")}]`;
            }
            return `{${Object.entries(value)
                .sort(([left], [right]) => compareUtf16(left, right))
                .map(([key, entryValue]) => `${JSON.stringify(key)}:${canonicalizeJson(entryValue)}`)
                .join(",")}}`;
        default:
            throw new ChioInvariantError("canonical_json", `canonical JSON does not support values of type ${typeof value}`);
    }
}
export function canonicalizeJsonString(input) {
    return canonicalizeJson(parseJsonText(input));
}
//# sourceMappingURL=json.js.map