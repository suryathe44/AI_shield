import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  randomUUID,
  scryptSync,
} from "node:crypto";
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { normalizeText, safePreview } from "../../shared/textUtils.js";

const ENVELOPE_VERSION = 2;

function encryptValue(value, key, context = "secure-log-value") {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(context, "utf8"));
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    version: ENVELOPE_VERSION,
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    ciphertext: encrypted.toString("base64"),
  };
}

function decryptValue(payload, key, context = "secure-log-value") {
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(payload.iv, "base64"),
  );
  if (payload.version === ENVELOPE_VERSION) {
    decipher.setAAD(Buffer.from(context, "utf8"));
  } else if (payload.version !== undefined && payload.version !== 1) {
    throw new Error("Unsupported encrypted log format.");
  }
  decipher.setAuthTag(Buffer.from(payload.tag, "base64"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(payload.ciphertext, "base64")),
    decipher.final(),
  ]);

  return decrypted.toString("utf8");
}

function hashValue(value, key) {
  return createHmac("sha256", key).update(String(value ?? "")).digest("hex");
}

export class SecureLogger {
  constructor({ logFilePath, masterKey }) {
    this.logFilePath = logFilePath;
    this.key = masterKey
      ? scryptSync(masterKey, "ai-shield-secure-log", 32)
      : randomBytes(32);
    this.digestKey = scryptSync(
      masterKey || this.key,
      "ai-shield-secure-log-digests",
      32,
    );
    this.usesEphemeralKey = !masterKey;
    this.queue = Promise.resolve();
  }

  async ensureReady() {
    await mkdir(path.dirname(this.logFilePath), { recursive: true });

    try {
      await readFile(this.logFilePath, "utf8");
    } catch (error) {
      if (error.code === "ENOENT") {
        await this.writeEntries([]);
        return;
      }

      throw error;
    }
  }

  async withLock(task) {
    const nextTask = this.queue.then(task, task);
    this.queue = nextTask.catch(() => {});
    return nextTask;
  }

  async readEntries() {
    await this.ensureReady();
    const raw = await readFile(this.logFilePath, "utf8");

    if (!raw.trim()) {
      return [];
    }

    const envelope = JSON.parse(raw);
    const plaintext = decryptValue(envelope, this.key, "ai-shield-log-file");
    return JSON.parse(plaintext);
  }

  async writeEntries(entries) {
    await mkdir(path.dirname(this.logFilePath), { recursive: true });
    const envelope = encryptValue(JSON.stringify(entries), this.key, "ai-shield-log-file");
    const temporaryPath = `${this.logFilePath}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`;
    await writeFile(temporaryPath, JSON.stringify(envelope, null, 2), {
      encoding: "utf8",
      mode: 0o600,
    });
    await rename(temporaryPath, this.logFilePath);
    await chmod(this.logFilePath, 0o600);
  }

  async appendLog({ analysis, content, source, consent, actorHint, metadata = {} }) {
    return this.withLock(async () => {
      const entries = await this.readEntries();
      const entry = {
        id: randomUUID(),
        createdAt: new Date().toISOString(),
        source,
        classification: analysis.classification,
        riskScore: analysis.riskScore,
        tags: [
          ...analysis.factors.rules.map((rule) => rule.label),
          ...analysis.factors.behaviors.map((behavior) => behavior.label),
        ]
          .filter(Boolean)
          .slice(0, 6),
        explanation: analysis.explanation.slice(0, 4),
        actorHash: hashValue(actorHint || metadata.sessionId || "anonymous", this.digestKey),
        sessionHash: metadata.sessionId ? hashValue(metadata.sessionId, this.digestKey) : null,
        contentDigest: hashValue(normalizeText(content), this.digestKey),
        encryptedSnippet: consent.persistContentSnippet
          ? encryptValue(safePreview(content), this.key, "ai-shield-log-snippet")
          : null,
      };

      entries.unshift(entry);
      await this.writeEntries(entries);

      return {
        id: entry.id,
        createdAt: entry.createdAt,
      };
    });
  }

  async readAllLogs() {
    return this.withLock(async () => {
      const entries = await this.readEntries();
      return entries.map((entry) => ({
        ...entry,
        snippet: entry.encryptedSnippet
          ? decryptValue(entry.encryptedSnippet, this.key, "ai-shield-log-snippet")
          : null,
        encryptedSnippet: undefined,
      }));
    });
  }

  async deleteLog(id) {
    return this.withLock(async () => {
      const entries = await this.readEntries();
      const filtered = entries.filter((entry) => entry.id !== id);

      if (filtered.length === entries.length) {
        return false;
      }

      await this.writeEntries(filtered);
      return true;
    });
  }

  async deleteAll() {
    return this.withLock(async () => {
      const entries = await this.readEntries();
      await this.writeEntries([]);
      return entries.length;
    });
  }

  getStorageMetadata() {
    return {
      encrypted: true,
      deletionSupported: true,
      usesEphemeralKey: this.usesEphemeralKey,
    };
  }
}
