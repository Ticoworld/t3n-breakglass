import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

/** Persist a machine result by replacement so a parent failure cannot erase a completed child result. */
export async function writeAtomicJson(file: string, value: unknown): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  const temporary = `${file}.${process.pid}.${Date.now()}.tmp`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, "utf8");
  await rename(temporary, file);
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
