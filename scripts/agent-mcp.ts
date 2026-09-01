import { createInterface } from "node:readline";
import { executeReplacementIncident, redactAgentError } from "./agent-execution.js";
import { BREAKGLASS_AGENT_TOOL, breakglassAgentToolDefinition } from "./agent-tool.js";

function response(id: unknown, result: unknown) {
  return JSON.stringify({ jsonrpc: "2.0", id, result });
}

function errorResponse(id: unknown, code: number, message: string) {
  return JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } });
}

async function handle(message: unknown): Promise<string | null> {
  if (!message || typeof message !== "object" || Array.isArray(message)) return null;
  const request = message as { jsonrpc?: string; id?: unknown; method?: string; params?: Record<string, unknown> };
  const id = request.id ?? null;
  if (request.jsonrpc !== "2.0" || typeof request.method !== "string") return errorResponse(id, -32600, "invalid JSON-RPC request");
  if (request.method === "notifications/initialized" || request.method === "notifications/cancelled") return null;
  if (request.method === "initialize") {
    return response(id, {
      protocolVersion: typeof request.params?.protocolVersion === "string" ? request.params.protocolVersion : "2025-06-18",
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: "breakglass-agent", version: "2.0.0" },
    });
  }
  if (request.method === "tools/list") return response(id, { tools: [breakglassAgentToolDefinition()] });
  if (request.method === "tools/call") {
    const params = request.params ?? {};
    if (params.name !== BREAKGLASS_AGENT_TOOL) return errorResponse(id, -32602, "unknown agent tool");
    try {
      const structured = await executeReplacementIncident(params.arguments);
      return response(id, { content: [{ type: "text", text: JSON.stringify(structured) }], structuredContent: structured, isError: false });
    } catch (error) {
      return response(id, { content: [{ type: "text", text: redactAgentError(error) }], isError: true });
    }
  }
  if (request.method === "ping") return response(id, {});
  return errorResponse(id, -32601, "method not found");
}

if (process.env.GITHUB_PAT || process.env.T3N_API_KEY) {
  process.stderr.write("breakglass agent refuses operator or GitHub credentials\n");
  process.exitCode = 1;
} else {
  const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
  input.on("line", async (line) => {
    if (!line.trim()) return;
    try {
      const result = await handle(JSON.parse(line));
      if (result) process.stdout.write(`${result}\n`);
    } catch {
      process.stdout.write(`${errorResponse(null, -32700, "invalid JSON") }\n`);
    }
  });
}
