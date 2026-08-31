export function getSecurityConfigWarnings(config) {
  const warnings = [];

  if (!config.masterKey) {
    warnings.push("AI_SHIELD_MASTER_KEY is missing; encrypted logs will not survive restarts.");
  } else if (Buffer.byteLength(config.masterKey, "utf8") < 32) {
    warnings.push("AI_SHIELD_MASTER_KEY should contain at least 32 random bytes.");
  }

  if (!config.adminRequireTotp) {
    warnings.push("Admin TOTP is disabled; enable it for stronger account protection.");
  }

  if (config.databaseUrl && !config.databaseSsl) {
    warnings.push("PostgreSQL TLS is disabled. Use it unless the database is only on a trusted private network.");
  } else if (config.databaseSsl && !config.databaseSslRejectUnauthorized) {
    warnings.push("PostgreSQL TLS certificate verification is disabled.");
  }

  return warnings;
}
