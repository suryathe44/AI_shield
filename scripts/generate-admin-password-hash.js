import process from "node:process";
import { loadLocalEnvFile } from "../src/utils/loadEnv.js";
import { createPasswordHash } from "../src/utils/adminSecurity.js";

loadLocalEnvFile();

const password = process.argv[2];

if (!password) {
  console.error("Usage: node scripts/generate-admin-password-hash.js \"YourStrongPassword\"");
  process.exit(1);
}

console.log(createPasswordHash(password));
