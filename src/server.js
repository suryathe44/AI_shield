import { loadLocalEnvFile } from "./utils/loadEnv.js";
import { createAiShieldApp } from "./app.js";

loadLocalEnvFile();

const { server, config, logger } = createAiShieldApp();

await logger.ensureReady();

server.listen(config.port, config.host, () => {
  console.log(`AI Shield listening on http://${config.host}:${config.port}`);
  if (config.authDebug) {
    console.log(
      `AI Shield admin auth loaded for username "${config.adminUsername}" with whitelist: ${config.adminIpWhitelist.join(", ") || "*"}`,
    );
  }
  if (logger.getStorageMetadata().usesEphemeralKey) {
    console.log("AI Shield is using an ephemeral encryption key. Set AI_SHIELD_MASTER_KEY for production persistence.");
  }
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
  });
}
