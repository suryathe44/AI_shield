import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomUUID,
  scryptSync,
} from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { normalizeText, safePreview } from "../../shared/textUtils.js";

function encryptValue(value, key) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    ciphertext: encrypted.toString("base64"),
  };
}

function decryptValue(payload, key) {
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(payload.iv, "base64"),
  );
  decipher.setAuthTag(Buffer.from(payload.tag, "base64"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(payload.ciphertext, "base64")),
    decipher.final(),
  ]);

  return decrypted.toString("utf8");
}

function hashValue(value) {
  return createHash("sha256").update(String(value ?? "")).digest("hex");
}

export class SecureLogger {
  constructor({ logFilePath, masterKey }) {
    this.logFilePath = logFilePath;
    this.key = masterKey
      ? scryptSync(masterKey, "ai-shield-secure-log", 32)
      : randomBytes(32);
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
    const plaintext = decryptValue(envelope, this.key);
    return JSON.parse(plaintext);
  }

  async writeEntries(entries) {
    await mkdir(path.dirname(this.logFilePath), { recursive: true });
    const envelope = encryptValue(JSON.stringify(entries), this.key);
    await writeFile(this.logFilePath, JSON.stringify(envelope, null, 2), "utf8");
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
        actorHash: hashValue(actorHint || metadata.sessionId || "anonymous"),
        sessionHash: metadata.sessionId ? hashValue(metadata.sessionId) : null,
        contentDigest: hashValue(normalizeText(content)),
        encryptedSnippet: consent.persistContentSnippet
          ? encryptValue(safePreview(content), this.key)
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
        snippet: entry.encryptedSnippet ? decryptValue(entry.encryptedSnippet, this.key) : null,
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