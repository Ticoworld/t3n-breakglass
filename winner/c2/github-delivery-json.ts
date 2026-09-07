export interface LosslessGithubDelivery {
  id: string;
  guid: string;
  event: string;
  installation_id?: number | null;
  repository_id?: number | null;
  redelivery: boolean;
  delivered_at?: string | null;
  status?: string | null;
  status_code?: number | null;
  response_code?: number | null;
  [key: string]: unknown;
}

const DECIMAL_ID = /^[0-9]+$/;
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NUMERIC_ID_TOKEN = Symbol("github-delivery-numeric-id-token");

type NumericIdToken = { [NUMERIC_ID_TOKEN]: true; value: string };

class LosslessJsonError extends Error {}

class LosslessJsonReader {
  private index = 0;

  constructor(private readonly input: string) {}

  parse(): unknown {
    const value = this.value();
    this.whitespace();
    if (this.index !== this.input.length) throw new LosslessJsonError("trailing JSON data");
    return value;
  }

  private whitespace(): void {
    while (this.index < this.input.length && /\s/.test(this.input[this.index])) this.index += 1;
  }

  private value(objectKey?: string): unknown {
    this.whitespace();
    const character = this.input[this.index];
    if (character === '"') return this.string();
    if (character === "{") return this.object();
    if (character === "[") return this.array();
    if (character === "t" && this.input.slice(this.index, this.index + 4) === "true") { this.index += 4; return true; }
    if (character === "f" && this.input.slice(this.index, this.index + 5) === "false") { this.index += 5; return false; }
    if (character === "n" && this.input.slice(this.index, this.index + 4) === "null") { this.index += 4; return null; }
    if (character === "-" || /[0-9]/.test(character ?? "")) return this.number(objectKey);
    throw new LosslessJsonError(`unexpected JSON token at offset ${this.index}`);
  }

  private string(): string {
    const start = this.index;
    this.index += 1;
    let escaped = false;
    while (this.index < this.input.length) {
      const character = this.input[this.index++];
      if (escaped) { escaped = false; continue; }
      if (character === "\\") { escaped = true; continue; }
      if (character === '"') return JSON.parse(this.input.slice(start, this.index)) as string;
      if (character < " ") throw new LosslessJsonError("control character in JSON string");
    }
    throw new LosslessJsonError("unterminated JSON string");
  }

  private number(objectKey?: string): unknown {
    const start = this.index;
    if (this.input[this.index] === "-") this.index += 1;
    if (this.input[this.index] === "0") this.index += 1;
    else {
      if (!/[1-9]/.test(this.input[this.index] ?? "")) throw new LosslessJsonError("malformed JSON number");
      while (/[0-9]/.test(this.input[this.index] ?? "")) this.index += 1;
    }
    if (this.input[this.index] === ".") {
      this.index += 1;
      if (!/[0-9]/.test(this.input[this.index] ?? "")) throw new LosslessJsonError("malformed JSON fraction");
      while (/[0-9]/.test(this.input[this.index] ?? "")) this.index += 1;
    }
    if (this.input[this.index] === "e" || this.input[this.index] === "E") {
      this.index += 1;
      if (this.input[this.index] === "+" || this.input[this.index] === "-") this.index += 1;
      if (!/[0-9]/.test(this.input[this.index] ?? "")) throw new LosslessJsonError("malformed JSON exponent");
      while (/[0-9]/.test(this.input[this.index] ?? "")) this.index += 1;
    }
    const token = this.input.slice(start, this.index);
    if (objectKey === "id") {
      const value = Object.create(null) as NumericIdToken;
      value[NUMERIC_ID_TOKEN] = true;
      value.value = token;
      return value;
    }
    const parsed = Number(token);
    if (!Number.isFinite(parsed)) throw new LosslessJsonError("non-finite JSON number");
    return parsed;
  }

  private object(): Record<string, unknown> {
    const result: Record<string, unknown> = {};
    this.index += 1;
    this.whitespace();
    if (this.input[this.index] === "}") { this.index += 1; return result; }
    while (true) {
      this.whitespace();
      if (this.input[this.index] !== '"') throw new LosslessJsonError("JSON object key is not a string");
      const key = this.string();
      if (Object.prototype.hasOwnProperty.call(result, key)) throw new LosslessJsonError(`duplicate JSON object key: ${key}`);
      this.whitespace();
      if (this.input[this.index] !== ":") throw new LosslessJsonError("JSON object key is missing a colon");
      this.index += 1;
      result[key] = this.value(key);
      this.whitespace();
      if (this.input[this.index] === "}") { this.index += 1; return result; }
      if (this.input[this.index] !== ",") throw new LosslessJsonError("JSON object is missing a comma");
      this.index += 1;
    }
  }

  private array(): unknown[] {
    const result: unknown[] = [];
    this.index += 1;
    this.whitespace();
    if (this.input[this.index] === "]") { this.index += 1; return result; }
    while (true) {
      result.push(this.value());
      this.whitespace();
      if (this.input[this.index] === "]") { this.index += 1; return result; }
      if (this.input[this.index] !== ",") throw new LosslessJsonError("JSON array is missing a comma");
      this.index += 1;
    }
  }
}

export function parseLosslessGithubJson(raw: string): unknown {
  return new LosslessJsonReader(raw).parse();
}

function safeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function requiredDeliveryString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) throw new LosslessJsonError(`delivery ${field} is missing`);
  return value;
}

export function parseGithubDeliveryObject(raw: string): LosslessGithubDelivery {
  const value = parseLosslessGithubJson(raw);
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new LosslessJsonError("delivery response is not an object");
  return validateDelivery(value as Record<string, unknown>);
}

export function parseGithubDeliveryList(raw: string): LosslessGithubDelivery[] {
  const value = parseLosslessGithubJson(raw);
  if (!Array.isArray(value)) throw new LosslessJsonError("delivery list response is not an array");
  return value.map((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new LosslessJsonError("delivery list contains a malformed object");
    return validateDelivery(entry as Record<string, unknown>);
  });
}

function validateDelivery(value: Record<string, unknown>): LosslessGithubDelivery {
  const idToken = value.id;
  if (!idToken || typeof idToken !== "object" || (idToken as Partial<NumericIdToken>)[NUMERIC_ID_TOKEN] !== true) {
    throw new LosslessJsonError("delivery id must be an unquoted JSON integer token");
  }
  const id = (idToken as NumericIdToken).value;
  if (!DECIMAL_ID.test(id) || id === "") throw new LosslessJsonError("delivery id must be an exact decimal string");
  if (!GUID.test(requiredDeliveryString(value.guid, "guid"))) throw new LosslessJsonError("delivery guid is malformed");
  const event = requiredDeliveryString(value.event, "event");
  if (value.installation_id !== undefined && value.installation_id !== null && !safeInteger(value.installation_id)) throw new LosslessJsonError("delivery installation identity is not a safe integer");
  if (value.repository_id !== undefined && value.repository_id !== null && !safeInteger(value.repository_id)) throw new LosslessJsonError("delivery repository identity is not a safe integer");
  if (typeof value.redelivery !== "boolean") throw new LosslessJsonError("delivery redelivery flag is malformed");
  if (value.status_code !== undefined && value.status_code !== null && !safeInteger(value.status_code)) throw new LosslessJsonError("delivery status_code is malformed");
  if (value.response_code !== undefined && value.response_code !== null && !safeInteger(value.response_code)) throw new LosslessJsonError("delivery response_code is malformed");
  return { ...value, id } as LosslessGithubDelivery;
}

export interface OriginalDeliveryQuery {
  guid: string;
  event: string;
  installation_id: number;
  repository_id: number;
}

export function selectOriginalDelivery(rows: readonly LosslessGithubDelivery[], query: OriginalDeliveryQuery): LosslessGithubDelivery {
  const matches = rows.filter((row) => row.guid === query.guid && row.event === query.event && row.installation_id === query.installation_id && row.repository_id === query.repository_id && row.redelivery === false);
  if (matches.length !== 1) throw new LosslessJsonError(`expected exactly one original delivery, found ${matches.length}`);
  return matches[0];
}

export function selectRedelivery(rows: readonly LosslessGithubDelivery[], query: OriginalDeliveryQuery, originalId: string): LosslessGithubDelivery {
  const matches = rows.filter((row) => row.guid === query.guid && row.event === query.event && row.installation_id === query.installation_id && row.repository_id === query.repository_id && row.redelivery === true && row.id !== originalId);
  if (matches.length !== 1) throw new LosslessJsonError(`expected exactly one redelivery, found ${matches.length}`);
  return matches[0];
}

export function unsafeNumberRoundtripChangesId(id: string): boolean {
  return String(Number(id)) !== id;
}
