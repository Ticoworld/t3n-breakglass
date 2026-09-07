import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export function parseRemoteBranchHead(output: string, expectedRef: string): string {
  const rows = output.split(/\r?\n/).map((row) => row.trim()).filter(Boolean);
  if (rows.length !== 1) throw new Error(`expected exactly one ls-remote row for ${expectedRef}`);
  const fields = rows[0].split(/\s+/);
  if (fields.length !== 2 || fields[1] !== expectedRef || !/^[0-9a-f]{40}$/i.test(fields[0])) {
    throw new Error(`ls-remote did not return one valid ${expectedRef} row`);
  }
  return fields[0].toLowerCase();
}

export async function remoteBranchHead(cwd: string, remote: string, branch: string): Promise<string> {
  const expectedRef = `refs/heads/${branch}`;
  const result = await execFileAsync("git", ["ls-remote", "--heads", remote, expectedRef], { cwd, encoding: "utf8", maxBuffer: 100_000, windowsHide: true });
  return parseRemoteBranchHead(String(result.stdout), expectedRef);
}

export function assertLocalMatchesRemote(localHead: string, remoteHead: string): void {
  if (!/^[0-9a-f]{40}$/i.test(localHead) || !/^[0-9a-f]{40}$/i.test(remoteHead) || localHead.toLowerCase() !== remoteHead.toLowerCase()) {
    throw new Error("local winner branch head does not match the exact remote branch head");
  }
}
