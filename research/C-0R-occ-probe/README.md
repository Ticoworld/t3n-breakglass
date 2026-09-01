# C-0R KV/OCC reservation probe

Research-only contract. It uses one fresh tenant map and one fresh key per run.
Each invocation performs `kv_store::get`, a bounded local computation, then
`kv_store::put` in the same host call. There is no HTTP, secret, provider, or
BreakGlass import. Two SDK calls are launched behind a common barrier by the
companion runner; the runner records all responses, errors, timestamps, logs,
and the final control-plane readback.
