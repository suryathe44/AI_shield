import { createAiShieldApp } from "./app.js";

const { server, config, logger } = createAiShieldApp();

await logger.ensureReady();

server.listen(config.port, config.host, () => {
  console.log(`AI Shield listening on http://${config.host}:${config.port}`);
  if (logger.getStorageMetadata().usesEphemeralKey) {
    console.log("AI Shield is using an ephemeral encryption key. Set AI_SHIELD_MASTER_KEY for production persistence.");
  }
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
  });
}