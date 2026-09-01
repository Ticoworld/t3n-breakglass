import { readFile } from "node:fs/promises";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const pkg = JSON.parse(await readFile(path.join(root, "node_modules", "@terminal3", "t3n-sdk", "package.json"), "utf8"));
console.log(JSON.stringify({
  package: pkg.name,
  version: pkg.version,
  expected_surfaces: [
    "T3nClient",
    "TenantClient",
    "TenantClient.contracts.register",
    "TenantClient.contracts.execute",
    "TenantClient.maps.create",
    "TenantClient.executeControl",
    "T3nClient.execute",
    "host:interfaces/http@2.1.0",
  ],
}, null, 2));
