/**
 * Parse wire JSON text with JSON.parse semantics after rejecting a repeated
 * object key at any depth of the original text. Both failures throw SyntaxError.
 */
export function parseWireJson(text: string): unknown {
  const value: unknown = JSON.parse(text);
  rejectDuplicateKeys(text);
  return value;
}

// Runs only on text JSON.parse accepted, so string tokens and structural
// characters are the only grammar left to track. A null frame is an array.
function rejectDuplicateKeys(text: string): void {
  const frames: Array<Set<string> | null> = [];
  let expectKey = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (char === "{") {
      frames.push(new Set());
      expectKey = true;
    } else if (char === "[") {
      frames.push(null);
      expectKey = false;
    } else if (char === "}" || char === "]") {
      frames.pop();
      expectKey = false;
    } else if (char === ",") {
      expectKey = frames[frames.length - 1] != null;
    } else if (char === "\"") {
      const start = index;
      index += 1;
      while (text[index] !== "\"") index += text[index] === "\\" ? 2 : 1;
      const keys = frames[frames.length - 1];
      if (expectKey && keys != null) {
        const key = JSON.parse(text.slice(start, index + 1)) as string;
        if (keys.has(key)) throw new SyntaxError("JSON text contains a duplicate object key");
        keys.add(key);
        expectKey = false;
      }
    }
  }
}
