import { cp, mkdir, rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const root = new URL("../", import.meta.url);
const output = new URL("dist/chrome-extension/", root);
await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
await cp(new URL("extension/", root), output, { recursive: true });
await cp(new URL("shared/", root), new URL("shared/", output), { recursive: true });
console.log(`Chrome extension ready: ${fileURLToPath(output)}`);
