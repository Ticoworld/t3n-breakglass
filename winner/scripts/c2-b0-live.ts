import path from "node:path";
import { createC2B0LiveWebhookServer, C2_B0_ROUTE } from "../c2/live-webhook-server.js";

const webhookSecret = process.env.C2_WEBHOOK_SECRET;
const host = process.env.C2_B0_LISTEN_HOST ?? "127.0.0.1";
const port = Number(process.env.C2_B0_LISTEN_PORT ?? "8787");
const capturePath = process.env.C2_B0_CAPTURE_PATH ?? path.join(process.env.TEMP ?? process.env.TMP ?? ".", "t3n-c2-b0-delivery.json");
const dedupeDirectory = process.env.C2_B0_DEDUPE_DIRECTORY ?? path.join(process.env.TEMP ?? process.env.TMP ?? ".", "t3n-c2-b0-dedupe");

if (!webhookSecret) throw new Error("C2_WEBHOOK_SECRET is required");
if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error("C2_B0_LISTEN_PORT is invalid");

const server = createC2B0LiveWebhookServer({ webhookSecret, capturePath, dedupeDirectory, route: C2_B0_ROUTE });
server.listen(port, host, () => {
  process.stdout.write(`${JSON.stringify({ status: "LISTENING", host, port, route: C2_B0_ROUTE })}\n`);
});

function close(): void {
  server.close(() => process.exit(0));
}

process.once("SIGINT", close);
process.once("SIGTERM", close);
