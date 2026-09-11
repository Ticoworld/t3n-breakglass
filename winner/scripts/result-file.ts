import { randomBytes } from "node:crypto";
import { mkdir, open, readFile, rename, unlink } from "node:fs/promises";
import path from "node:path";

/** Persist a machine result by replacement so a parent failure cannot erase a completed child result. */
export async function writeAtomicJson(file: string, value: unknown): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  const temporary = `${file}.${process.pid}.${Date.now()}.${randomBytes(6).toString("hex")}.tmp`;
  const handle = await open(temporary, "wx", 0o600);
  try {
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`, "utf8");
    await handle.sync();
  } finally { await handle.close(); }
  try { await rename(temporary, file); }
  catch (error) { try { await unlink(temporary); } catch { /* preserve rename failure */ } throw error; }
}

export async function readJsonFile<T = Record<string, unknown>>(file: string): Promise<T> {
  return JSON.parse(await readFile(file, "utf8")) as T;
}

export async function readOptionalJson(file: string): Promise<unknown | null> {
  try { return await readJsonFile(file); } catch { return null; }
}

export async function readChildResultBundle(directory: string): Promise<Record<string, unknown>> {
  return {
    broker_a: await readOptionalJson(path.join(directory, "broker-a.result.json")),
    broker_b: await readOptionalJson(path.join(directory, "broker-b.result.json")),
    replay: await readOptionalJson(path.join(directory, "replay.result.json")),
  };
}
