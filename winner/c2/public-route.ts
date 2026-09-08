export type PublicRouteFetch = (input: string | URL, init?: RequestInit) => Promise<Response>;

function validateHttpsUrl(url: string): void {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:") throw new Error("public webhook route must use HTTPS");
}

/**
 * Canonical readiness probe for the exact public webhook route. The production
 * receiver is POST-only, so a successful GET must return its deliberate 404.
 */
export async function publicRouteStatus(url: string, fetchImpl: PublicRouteFetch = (input, init) => fetch(input, init)): Promise<number> {
  validateHttpsUrl(url);
  const response = await fetchImpl(url, {
    method: "GET",
    redirect: "error",
    signal: AbortSignal.timeout(30_000),
  });
  await response.arrayBuffer();
  return response.status;
}

export async function requirePublicRoute404(url: string, fetchImpl?: PublicRouteFetch): Promise<number> {
  const status = await publicRouteStatus(url, fetchImpl);
  if (status !== 404) throw new Error(`public webhook route returned HTTP ${status}, expected receiver 404`);
  return status;
}
