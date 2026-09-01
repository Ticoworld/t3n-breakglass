export const BREAKGLASS_AGENT_TOOL = "breakglass_execute_incident";

export function breakglassAgentToolDefinition() {
  return {
    name: BREAKGLASS_AGENT_TOOL,
    description: "Execute an existing one-use BreakGlass Incident Authority. The authority supplies the target, action, expiry, and use limit; the caller supplies only incident_id.",
    inputSchema: {
      type: "object",
      properties: {
        incident_id: { type: "string", minLength: 1, maxLength: 128, description: "The operator-created Incident Authority identifier." },
      },
      required: ["incident_id"],
      additionalProperties: false,
    },
  } as const;
}
