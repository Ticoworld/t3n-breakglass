import { spawn } from "node:child_process";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "../..");
const manifest = path.join(root, "winner", "contract", "Cargo.toml");

function run(command: string, args: string[]): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: root, stdio: "inherit", windowsHide: true });
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve(code ?? (signal ? 1 : 0)));
  });
}

async function main() {
  const code = await run("cargo", ["build", "--manifest-path", manifest, "--target", "wasm32-wasip2", "--release"]);
  if (code === 0) return;
  if (process.platform === "win32") {
    const wslRoot = root.replaceAll("\\", "/").replace(/^([A-Za-z]):/, (_, drive: string) => `/mnt/${drive.toLowerCase()}`);
    process.exitCode = await run("wsl.exe", ["-d", "Ubuntu", "--", "bash", "-lc", `cd '${wslRoot}' && cargo build --manifest-path winner/contract/Cargo.toml --target wasm32-wasip2 --release`]);
    return;
  }
  process.exitCode = code;
}

main().catch((error) => { console.error(`C1 contract build failed: ${error instanceof Error ? error.message : String(error)}`); process.exitCode = 1; });
