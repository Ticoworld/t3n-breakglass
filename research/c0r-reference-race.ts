/**
 * C-0R R8 research fixture.
 *
 * This is deliberately a local model of the public circle-call-centre
 * reference's ordering: read the idempotency marker, call an external relay,
 * then write the marker. It never imports or invokes the reference contract,
 * never talks to Circle, and never moves money. The result is therefore a
 * model/evidence artifact, not a claim that Circle received duplicate
 * payments.
 */
import { createServer } from "node:http";

type Call = {
  contender: string;
  started_at_ms: number;
  relay_request_at_ms?: number;
  marker_read: boolean;
  marker_written: boolean;
  error?: string;
};

const port = 18_000 + Math.floor(Math.random() * 1_000);
const idempotencyKey = "c0r-reference-race-fixture-01";
const calls: Call[] = [];
let relayRequests = 0;
let markerUsed = false;
const releaseRelays: Array<() => void> = [];

const server = createServer(async (_req, res) => {
  relayRequests += 1;
  await new Promise<void>((resolve) => {
    releaseRelays.push(resolve);
  });
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ ok: true, idempotency_key: idempotencyKey }));
});

await new Promise<void>((resolve) => server.listen(port, "127.0.0.1", resolve));

async function referenceLikeCall(contender: string): Promise<Call> {
  const call: Call = { contender, started_at_ms: Date.now(), marker_read: markerUsed, marker_written: false };
  calls.push(call);
  if (call.marker_read) return call;

  call.relay_request_at_ms = Date.now();
  const request = fetch(`http://127.0.0.1:${port}/pay`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ idempotency_key: idempotencyKey }),
  });

  // Keep both fixture requests in the external stage before releasing either.
  while (relayRequests < 2) await new Promise((resolve) => setTimeout(resolve, 1));
  while (releaseRelays.length) releaseRelays.shift()?.();
  await request;
  markerUsed = true;
  call.marker_written = true;
  return call;
}

const barrier = Promise.resolve();
await barrier;
const results = await Promise.all([
  referenceLikeCall("contender-a"),
  referenceLikeCall("contender-b"),
]);

await new Promise((resolve) => setTimeout(resolve, 10));
server.close();

console.log(JSON.stringify({
  experiment: "R8 local model of call-centre read -> relay -> marker ordering",
  date_utc: new Date().toISOString(),
  destructive: false,
  provider: "127.0.0.1 disposable HTTP fixture; no Circle/GitHub/provider resource",
  idempotency_key: idempotencyKey,
  results,
  relay_request_count: relayRequests,
  final_marker_used: markerUsed,
  classification: "MODEL_PROVES_OUTBOUND_RACE_WINDOW; DUPLICATE_PROVIDER_EFFECT_NOT_PROVEN",
  conclusion: "Both modeled calls can pass the uncommitted marker check and issue relay requests before either marker write. The reference source and the live T3N OCC result establish the same ordering hazard at the contract-to-relay boundary. This artifact does not prove that Circle executes duplicate payment effects.",
}, null, 2));
