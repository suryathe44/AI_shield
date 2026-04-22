import { loadLocalEnvFile } from "./utils/loadEnv.js";
import { createAiShieldApp } from "./app.js";

loadLocalEnvFile();

const { server, config, logger } = createAiShieldApp();

await logger.ensureReady();

// 🔥 IMPORTANT FIX FOR RENDER
const PORT = process.env.PORT || config.port || 10000;
const HOST = "0.0.0.0"; // force public binding

server.listen(PORT, HOST, () => {
  console.log(`AI Shield listening on http://${HOST}:${PORT}`);

  if (config.authDebug) {
    console.log(
      `AI Shield admin auth loaded for username "${config.adminUsername}" with whitelist: ${
        config.adminIpWhitelist.length ? config.adminIpWhitelist.join(", ") : "*"
      }`
    );
  }

  if (logger.getStorageMetadata().usesEphemeralKey) {
    console.log(
      "AI Shield is using an ephemeral encryption key. Set AI_SHIELD_MASTER_KEY for production persistence."
    );
  }
});

// graceful shutdown
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
  });
}
