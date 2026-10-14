/** A JSON number whose original representation cannot be retained as a JS number. */
export class LosslessJsonNumber {
  readonly source: string;

  private constructor(source: string) {
    this.source = source;
    Object.freeze(this);
  }

  static fromToken(source: string): LosslessJsonNumber {
    if (typeof source !== "string" || source.length > 262144 ||
        !/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/.test(source)) {
      throw new Error("invalid JSON number token");
    }
    return new LosslessJsonNumber(source);
  }

  /** Exact integer conversion. Decimal or exponent syntax remains a number token. */
  toBigInt(): bigint {
    if (!/^-?(?:0|[1-9][0-9]*)$/.test(this.source)) throw new Error("JSON token is not an integer literal");
    return BigInt(this.source);
  }

  /** Explicit conversion only when the decimal value survives a number round trip. */
  toNumber(): number {
    const value = Number(this.source);
    if (!Number.isFinite(value) || normalizeDecimal(this.source) !== normalizeDecimal(JSON.stringify(value))) {
      throw new Error("JSON number cannot be converted without losing precision");
    }
    return value;
  }

  toJSON(): never {
    throw new Error("use the original JSON source to serialize a lossless number");
  }
}

export type LosslessJsonValue = null | boolean | string | number | LosslessJsonNumber
  | LosslessJsonValue[] | { [key: string]: LosslessJsonValue };

export interface LosslessJsonDocument {
  readonly value: LosslessJsonValue;
  /** Exact source for the requested value, excluding surrounding separator whitespace. */
  readonly capturedSource: string | undefined;
}

/** Parse bounded JSON before any numeric conversion or property normalization. */
export function parseLosslessJson(source: string, capturePath?: readonly (string | number)[]): LosslessJsonDocument {
  return boundedReader(source, capturePath).read();
}

/** Replace only the captured value in a raw resource-accounting projection. */
export function parseLosslessJsonWithProjection(source: string, capturePath?: readonly (string | number)[]):
    LosslessJsonDocument & { readonly resourceProjection: string } {
  return boundedReader(source, capturePath).readWithProjection();
}

function boundedReader(source: string, capturePath?: readonly (string | number)[]): JsonReader {
  if (new TextEncoder().encode(source).length > 262144) throw new Error("JSON exceeds the response bound");
  return new JsonReader(source, capturePath);
}

const numberToken = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

class JsonReader {
  private position = 0;
  private capturedSource: string | undefined;
  private capturedRange: readonly [number, number] | undefined;
  private readonly path: (string | number)[] = [];

  constructor(private readonly source: string, private readonly capturePath?: readonly (string | number)[]) {}

  read(): LosslessJsonDocument {
    const value = this.value(0);
    this.whitespace();
    if (this.position !== this.source.length) throw new Error("trailing JSON data");
    return { value, capturedSource: this.capturedSource };
  }

  readWithProjection(): LosslessJsonDocument & { readonly resourceProjection: string } {
    const document = this.read();
    const resourceProjection = this.capturedRange === undefined ? this.source
      : this.source.slice(0, this.capturedRange[0]) + "null" + this.source.slice(this.capturedRange[1]);
    return { ...document, resourceProjection };
  }

  private value(depth: number): LosslessJsonValue {
    if (depth > 64) throw new Error("JSON exceeds the nesting bound");
    this.whitespace();
    const start = this.position;
    const char = this.source[this.position];
    if (depth >= 64 && (char === "{" || char === "[")) throw new Error("JSON exceeds the nesting bound");
    let value: LosslessJsonValue;
    if (char === "{") value = this.object(depth);
    else if (char === "[") value = this.array(depth);
    else if (char === '"') value = this.string();
    else if (char === "t" && this.literal("true")) value = true;
    else if (char === "f" && this.literal("false")) value = false;
    else if (char === "n" && this.literal("null")) value = null;
    else {
      numberToken.lastIndex = this.position;
      const matched = numberToken.exec(this.source);
      if (!matched) throw new Error("invalid JSON value");
      const token = matched[0];
      this.position += token.length;
      const numeric = Number(token);
      value = Number.isFinite(numeric) && (!Number.isInteger(numeric) || Number.isSafeInteger(numeric))
        && JSON.stringify(numeric) === token ? numeric : LosslessJsonNumber.fromToken(token);
    }
    if (this.capturePath?.length === this.path.length &&
        this.path.every((part, index) => part === this.capturePath?.[index])) {
      this.capturedSource = this.source.slice(start, this.position);
      this.capturedRange = [start, this.position];
    }
    return value;
  }

  private object(depth: number): { [key: string]: LosslessJsonValue } {
    this.position++;
    const value: { [key: string]: LosslessJsonValue } = {};
    const names = new Set<string>();
    this.whitespace();
    if (this.source[this.position] === "}") { this.position++; return value; }
    while (true) {
      this.whitespace();
      const name = this.string();
      if (names.has(name)) throw new Error("duplicate JSON member");
      names.add(name);
      this.whitespace();
      if (this.source[this.position++] !== ":") throw new Error("missing JSON member separator");
      this.path.push(name);
      const child = this.value(depth + 1);
      this.path.pop();
      // Assignment would invoke Object.prototype.__proto__ for this valid key.
      Object.defineProperty(value, name, { value: child, writable: true, enumerable: true, configurable: true });
      this.whitespace();
      const separator = this.source[this.position++];
      if (separator === "}") return value;
      if (separator !== ",") throw new Error("invalid JSON object separator");
    }
  }

  private array(depth: number): LosslessJsonValue[] {
    this.position++;
    const value: LosslessJsonValue[] = [];
    this.whitespace();
    if (this.source[this.position] === "]") { this.position++; return value; }
    while (true) {
      this.path.push(value.length);
      value.push(this.value(depth + 1));
      this.path.pop();
      this.whitespace();
      const separator = this.source[this.position++];
      if (separator === "]") return value;
      if (separator !== ",") throw new Error("invalid JSON array separator");
    }
  }

  private string(): string {
    const start = this.position;
    if (this.source[this.position++] !== '"') throw new Error("JSON member requires a string");
    while (this.position < this.source.length) {
      const char = this.source[this.position++];
      if (char === "\\") this.position++;
      else if (char === '"') {
        const value: string = JSON.parse(this.source.slice(start, this.position));
        requireScalarString(value);
        return value;
      }
    }
    throw new Error("unterminated JSON string");
  }

  private literal(literal: string): boolean {
    if (!this.source.startsWith(literal, this.position)) return false;
    this.position += literal.length;
    return true;
  }

  private whitespace(): void {
    while (/[ \t\r\n]/.test(this.source[this.position] ?? "")) this.position++;
  }
}

function requireScalarString(value: string): void {
  for (let index = 0; index < value.length; index++) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++index);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error("JSON refuses an unpaired surrogate");
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new Error("JSON refuses an unpaired surrogate");
    }
  }
}

function normalizeDecimal(source: string): string {
  const [mantissa = "", exponentText = "0"] = source.toLowerCase().split("e");
  const negative = mantissa.startsWith("-");
  const unsigned = negative ? mantissa.slice(1) : mantissa;
  const [whole = "", fraction = ""] = unsigned.split(".");
  const digits = (whole + fraction).replace(/^0+/, "");
  if (digits.length === 0) return "0";
  const significant = digits.replace(/0+$/, "");
  const exponent = BigInt(exponentText) - BigInt(fraction.length) + BigInt(digits.length - significant.length);
  return `${negative ? "-" : ""}${significant}e${exponent}`;
}
