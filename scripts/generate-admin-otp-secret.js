import process from "node:process";
import { loadLocalEnvFile } from "../src/utils/loadEnv.js";
import { generateBase32Secret, generateTotpCode } from "../src/utils/adminSecurity.js";

loadLocalEnvFile();

const providedSecret = process.argv[2]?.trim();
const envSecret = process.env.AI_SHIELD_ADMIN_OTP_SECRET?.trim();
const secret = providedSecret || envSecret || generateBase32Secret();
const generatedNewSecret = !providedSecret && !envSecret;

if (generatedNewSecret) {
  console.log("Generated a new OTP secret. Save this once in AI_SHIELD_ADMIN_OTP_SECRET.");
} else {
  console.log("Using existing OTP secret to print the current valid code.");
}

console.log(`Secret: ${secret}`);
console.log(`CurrentCode: ${generateTotpCode(secret)}`);