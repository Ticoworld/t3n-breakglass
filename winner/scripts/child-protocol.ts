export function parseChildJson<T extends Record<string, unknown> = Record<string, unknown>>(stdout: string): T {
  const document = stdout.trim();
  if (!document) throw new Error("child stdout is empty");
  let parsed: unknown;
  try {
    parsed = JSON.parse(document);
  } catch {
    throw new Error("child stdout must be one complete JSON document");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("child stdout must contain a JSON object");
  return parsed as T;
}
