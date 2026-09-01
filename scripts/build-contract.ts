import { execFileSync, spawn } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const manifest = path.join(root, "contract", "Cargo.toml");
const cargoArgs = ["build", "--manifest-path", manifest, "--target", "wasm32-wasip2", "--release"];

function run(command: string, args: string[]): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: root, stdio: "inherit", windowsHide: true });
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve(code ?? (signal ? 1 : 0)));
  });
}

function output(command: string, args: string[]): string | null {
  try {
    return execFileSync(command, args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return null;
  }
}

function wslPath(value: string): string {
  const normalized = value.replaceAll("\\", "/");
  const drive = normalized.match(/^([A-Za-z]):\/(.*)$/);
  return drive ? `/mnt/${drive[1].toLowerCase()}/${drive[2]}` : normalized;
}

async function main() {
  const isWindows = process.platform === "win32";
  const rustcVersion = output("rustc", ["-vV"]) ?? "";
  const targetLib = output("rustc", ["--print", "target-libdir", "--target", "wasm32-wasip2"]);
  const targetMissing = !targetLib || !existsSync(targetLib);

  if (isWindows && targetMissing && rustcVersion.includes("windows-gnullvm")) {
    const wslRoot = wslPath(root).replaceAll("'", "'\\''");
    const command = `cd '${wslRoot}' && cargo build --manifest-path contract/Cargo.toml --target wasm32-wasip2 --release`;
    const wslCode = await run("wsl.exe", ["-d", "Ubuntu", "--", "bash", "-lc", command]);
    process.exitCode = wslCode;
    return;
  }

  process.exitCode = await run("cargo", cargoArgs);
}

main().catch((error) => {
  console.error(`contract build failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
