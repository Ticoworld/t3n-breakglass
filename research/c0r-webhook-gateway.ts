import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { writeFile } from "node:fs/promises";
import path from "node:path";

// Test fixture only. This value is not a deployment secret and is never read
// from an environment file or sent to GitHub.
const TEST_FIXTURE_SECRET = "c0r-local-webhook-fixture-secret";

type RecordEntry = { delivery_id: string; body_sha256: string; event: string; accepted_at: string };
const accepted = new Map<string, RecordEntry>();

function digest(body: Buffer): string { return createHash("sha256").update(body).digest("hex"); }
function sign(body: Buffer): string { return `sha256=${createHmac("sha256", TEST_FIXTURE_SECRET).update(body).digest("hex")}`; }

function verify(body: Buffer, signature: string): boolean {
  if (!/^sha256=[0-9a-f]{64}$/.test(signature)) return false;
  const expected = Buffer.from(sign(body).slice("sha256=".length), "hex");
  const provided = Buffer.from(signature.slice("sha256=".length), "hex");
  return expected.length === provided.length && timingSafeEqual(expected, provided);
}

function receive(body: Buffer, signature: string, deliveryId: string): { accepted: boolean; reason: string; body_sha256: string } {
  const bodySha = digest(body);
  if (!verify(body, signature)) return { accepted: false, reason: "invalid_signature", body_sha256: bodySha };
  let event: string;
  try { event = String((JSON.parse(body.toString("utf8")) as Record<string, unknown>).action ?? ""); }
  catch { return { accepted: false, reason: "malformed_verified_body", body_sha256: bodySha }; }
  const previous = accepted.get(deliveryId);
  if (previous) {
    return { accepted: false, reason: previous.body_sha256 === bodySha ? "duplicate_delivery" : "delivery_id_body_conflict", body_sha256: bodySha };
  }
  accepted.set(deliveryId, { delivery_id: deliveryId, body_sha256: bodySha, event, accepted_at: new Date().toISOString() });
  return { accepted: true, reason: "accepted_once", body_sha256: bodySha };
}

const body = Buffer.from(JSON.stringify({ action: "created", repository: { full_name: "disposable/example" }, deploy_key: { id: 123 } }));
const altered = Buffer.from(JSON.stringify({ action: "deleted", repository: { full_name: "disposable/example" }, deploy_key: { id: 999 } }));
const validSignature = sign(body);
const cases = [
  { name: "valid_signed_delivery", result: receive(body, validSignature, "delivery-1") },
  { name: "replay_exact_delivery", result: receive(body, validSignature, "delivery-1") },
  { name: "altered_body_old_signature", result: receive(altered, validSignature, "delivery-2") },
  { name: "same_body_wrong_signature", result: receive(body, "sha256=" + "00".repeat(32), "delivery-3") },
  { name: "same_delivery_id_altered_body_with_valid_signature", result: receive(altered, sign(altered), "delivery-1") },
];

const evidence = {
  experiment: "R6 raw-body GitHub webhook HMAC and delivery dedupe",
  date_utc: new Date().toISOString(),
  implementation: "research-only Node gateway; no product import",
  algorithm: ["verify HMAC-SHA256 over exact raw bytes", "parse canonical event only after verification", "dedupe by delivery ID and body digest"],
  fixture: { secret: "not published; deterministic test-only fixture in gateway source", delivery_id: "delivery-1", body_sha256: digest(body) },
  cases,
  accepted_record_count: accepted.size,
  accepted_records: [...accepted.values()],
  real_github_ingress: "not exercised: creating a GitHub webhook and public ingress requires owner/UI configuration; local raw-byte and dedupe semantics are proven here",
};

const root = path.resolve(import.meta.dirname, "..");
await writeFile(path.join(root, "research", "C-0R-webhook-result.json"), JSON.stringify(evidence, null, 2) + "\n");
console.log(JSON.stringify(evidence, null, 2));
