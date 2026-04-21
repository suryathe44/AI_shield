import { MAX_CONTENT_LENGTH } from "./constants.js";

const CONTROL_CHARS = /[\u0000-\u001f\u007f]/g;
const WORD_REGEX = /[a-z0-9]+/g;
const URL_REGEX = /\b(?:https?:\/\/|www\.|[a-z0-9-]+\.[a-z]{2,})(?:[^\s<>"']*)/gi;

export function sanitizeContent(value, maxLength = MAX_CONTENT_LENGTH) {
  const cleaned = String(value ?? "")
    .replace(CONTROL_CHARS, " ")
    .replace(/\s+/g, " ")
    .trim();

  return {
    content: cleaned.slice(0, maxLength),
    wasTruncated: cleaned.length > maxLength,
  };
}

export function normalizeText(value = "") {
  return String(value)
    .toLowerCase()
    .replace(CONTROL_CHARS, " ")
    .replace(/\s+/g, " ")
    .trim();
}

export function tokenize(value = "") {
  const normalized = normalizeText(value);
  const words = normalized.match(WORD_REGEX) ?? [];
  const tokens = words.filter((word) => word.length > 1);

  for (let index = 0; index < words.length - 1; index += 1) {
    if (words[index].length > 1 && words[index + 1].length > 1) {
      tokens.push(`${words[index]}_${words[index + 1]}`);
    }
  }

  return tokens;
}

export function extractUrls(value = "") {
  return Array.from(new Set(value.match(URL_REGEX) ?? []));
}

export function extractDomain(url) {
  if (!url) {
    return "";
  }

  try {
    const normalized = url.startsWith("http://") || url.startsWith("https://") ? url : `https://${url}`;
    return new URL(normalized).hostname.toLowerCase();
  } catch {
    return "";
  }
}

export function stripSubdomain(domain) {
  return domain.replace(/^www\./, "");
}

export function findMatchedTerms(text, terms) {
  const normalized = normalizeText(text);
  return terms.filter((term, index) => normalized.includes(term) && terms.indexOf(term) === index);
}

export function safePreview(text, maxLength = 180) {
  const normalized = String(text ?? "").replace(/\s+/g, " ").trim();
  if (normalized.length <= maxLength) {
    return normalized;
  }

  return `${normalized.slice(0, maxLength - 1)}…`;
}

export function makeSnippet(text, term, radius = 48) {
  const source = String(text ?? "");
  const termIndex = source.toLowerCase().indexOf(String(term ?? "").toLowerCase());

  if (termIndex === -1) {
    return safePreview(source, radius * 2);
  }

  const start = Math.max(0, termIndex - radius);
  const end = Math.min(source.length, termIndex + term.length + radius);
  const prefix = start > 0 ? "…" : "";
  const suffix = end < source.length ? "…" : "";

  return `${prefix}${source.slice(start, end).trim()}${suffix}`;
}

export function dedupeBy(items, keySelector) {
  const seen = new Set();
  return items.filter((item) => {
    const key = keySelector(item);
    if (seen.has(key)) {
      return false;
    }

    seen.add(key);
    return true;
  });
}

export function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}