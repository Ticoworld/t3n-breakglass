import assert from "node:assert/strict";
import test from "node:test";
import { publicRouteStatus, requirePublicRoute404, type PublicRouteFetch } from "../c2/public-route.js";

const URL = "https://example.invalid/c2-b0/github-push";

function response(status: number): PublicRouteFetch {
  return async () => new Response("diagnostic", { status });
}

test("canonical Node public probe accepts the receiver's GET 404", async () => {
  assert.equal(await requirePublicRoute404(URL, response(404)), 404);
});

test("canonical public probe rejects a 200 interstitial or handler response", async () => {
  await assert.rejects(() => requirePublicRoute404(URL, response(200)), /expected receiver 404/);
});

test("canonical public probe preserves redirect failure", async () => {
  const redirect: PublicRouteFetch = async () => { throw new Error("redirect rejected"); };
  await assert.rejects(() => publicRouteStatus(URL, redirect), /redirect rejected/);
});

test("canonical public probe preserves timeout failure", async () => {
  const timeout: PublicRouteFetch = async () => { throw new Error("timeout"); };
  await assert.rejects(() => publicRouteStatus(URL, timeout), /timeout/);
});

test("canonical public probe preserves DNS failure", async () => {
  const dns: PublicRouteFetch = async () => { throw new Error("getaddrinfo ENOTFOUND"); };
  await assert.rejects(() => publicRouteStatus(URL, dns), /ENOTFOUND/);
});

test("canonical public probe preserves TLS failure", async () => {
  const tls: PublicRouteFetch = async () => { throw new Error("TLS handshake failed"); };
  await assert.rejects(() => publicRouteStatus(URL, tls), /TLS handshake failed/);
});

test("canonical public probe rejects non-HTTPS URLs", async () => {
  await assert.rejects(() => publicRouteStatus("http://127.0.0.1:8787/c2-b0/github-push", response(404)), /HTTPS/);
});

test("curl-only incompatibility cannot override canonical Node 404", async () => {
  const curlFailure = { exit_code: 56, stderr: "schannel: server closed abruptly" };
  assert.equal(curlFailure.exit_code, 56);
  assert.equal(await requirePublicRoute404(URL, response(404)), 404);
});

test("Node transport failure cannot be converted to success by another client", async () => {
  const nodeFailure: PublicRouteFetch = async () => { throw new Error("TLS handshake failed"); };
  await assert.rejects(() => requirePublicRoute404(URL, nodeFailure), /TLS handshake failed/);
});
