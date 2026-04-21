import process from "node:process";

export function loadLocalEnvFile(path = ".env") {
  if (typeof process.loadEnvFile !== "function") {
    return false;
  }

  try {
    process.loadEnvFile(path);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") {
      return false;
    }

    throw error;
  }
}