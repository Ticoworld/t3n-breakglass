import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

const evidenceDir = path.resolve(import.meta.dirname, "..", "evidence");
const files = (await readdir(evidenceDir)).filter((name) => name.endsWith(".json")).sort();
const secretPatterns = [
  /gh[pousr]_[A-Za-z0-9_]+/,
  /github_pat_[A-Za-z0-9_]{20,}/,
  /Bearer\s+[A-Za-z0-9._-]{12,}/i,
  /-----BEGIN (?:OPENSSH|RSA|EC|PRIVATE) KEY-----/,
];

const contents = await Promise.all(files.map(async (name) => ({
  name,
  text: await readFile(path.join(evidenceDir, name), "utf8"),
})));
const leaks = contents.flatMap(({ name, text }) =>
  secretPatterns.filter((pattern) => pattern.test(text)).map((pattern) => `${name}: ${pattern}`),
);

if (leaks.length > 0) {
  throw new Error(`evidence secret check failed: ${leaks.join(", ")}`);
}

console.log(JSON.stringify({ status: "sanitized", evidence_dir: evidenceDir, files }, null, 2));
