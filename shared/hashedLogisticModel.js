/**
 * Tiny offline scorer for the optional hashed logistic-regression model.
 *
 * The model is deliberately dependency-free: its quantized weights are stored
 * as Base64 and decoded only once inside the AI Shield bundle. It never fetches
 * a model, telemetry, or a URL. `explainableSignals` remain in
 * detectionEngine.js, where users see human-readable reasons rather than hash
 * bucket numbers.
 */
import { normalizeText, tokenize } from "./textUtils.js";

function fnv1a(value) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

function decodeInt8(base64) {
  const binary = atob(base64);
  const values = new Int8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) values[index] = binary.charCodeAt(index) - 128;
  return values;
}

function featureKeys(text) {
  const normalized = normalizeText(text);
  const tokens = tokenize(normalized).slice(0, 600);
  const keys = tokens.map((token) => `w:${token}`);
  // Character n-grams improve resilience to spelling variants such as
  // "kyc", "K.Y.C", "kyc-update", and common Hinglish forms.
  // A scam's actionable request is normally near the start. Bounding input
  // keeps both latency and model influence stable for pasted email threads.
  const compact = normalized.replace(/\s+/g, " ").slice(0, 512);
  for (const width of [3, 4]) {
    for (let index = 0; index + width <= compact.length; index += 1) {
      keys.push(`c${width}:${compact.slice(index, index + width)}`);
    }
  }
  return keys;
}

export function scoreHashedLogisticModel(text, model) {
  if (!model?.weightsBase64 || !Number.isInteger(model.dimension) || model.dimension < 256) {
    throw new Error("Invalid hashed logistic model.");
  }
  const weights = decodeInt8(model.weightsBase64);
  if (weights.length !== model.dimension) throw new Error("Hashed logistic model dimension mismatch.");

  const buckets = new Map();
  for (const key of featureKeys(text)) {
    const hash = fnv1a(key);
    const bucket = hash % model.dimension;
    const sign = hash & 0x80000000 ? -1 : 1;
    buckets.set(bucket, (buckets.get(bucket) ?? 0) + sign);
  }

  let logit = Number(model.bias ?? 0);
  for (const [bucket, count] of buckets) {
    logit += weights[bucket] * Number(model.quantizationScale) * Math.sign(count) * Math.log1p(Math.abs(count));
  }
  // Clamp avoids overflow on unusually long pasted messages.
  const probability = 1 / (1 + Math.exp(-Math.max(-30, Math.min(30, logit))));
  return { probability, activeFeatures: buckets.size };
}
