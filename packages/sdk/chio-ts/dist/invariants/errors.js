export class ChioInvariantError extends Error {
    code;
    constructor(code, message, options) {
        super(message, options);
        this.name = "ChioInvariantError";
        this.code = code;
    }
}
export function parseJsonText(input) {
    try {
        return JSON.parse(input);
    }
    catch (cause) {
        throw new ChioInvariantError("json", "input is not valid JSON", { cause });
    }
}
//# sourceMappingURL=errors.js.map