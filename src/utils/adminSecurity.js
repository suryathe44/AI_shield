import {
  createHash,
  createHmac,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const LOCALHOST_IPV4 = "127.0.0.1";

function toBuffer(value) {
  return Buffer.isBuffer(value) ? value : Buffer.from(String(value ?? ""), "utf8");
}

export function safeTextEqual(left, right) {
  const leftBuffer = toBuffer(left);
  const rightBuffer = toBuffer(right);

  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function base64UrlEncode(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlDecode(value) {
  const normalized = String(value).replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return Buffer.from(`${normalized}${padding}`, "base64");
}

function encodeBase32(buffer) {
  let bits = "";
  for (const byte of buffer) {
    bits += byte.toString(2).padStart(8, "0");
  }

  let encoded = "";
  for (let index = 0; index < bits.length; index += 5) {
    const chunk = bits.slice(index, index + 5).padEnd(5, "0");
    encoded += BASE32_ALPHABET[Number.parseInt(chunk, 2)];
  }

  return encoded;
}

function decodeBase32(secret) {
  const sanitized = String(secret ?? "")
    .toUpperCase()
    .replace(/[^A-Z2-7]/g, "");

  if (!sanitized) {
    return Buffer.alloc(0);
  }

  let bits = "";
  for (const character of sanitized) {
    const value = BASE32_ALPHABET.indexOf(character);
    if (value === -1) {
      throw new Error("Invalid base32 TOTP secret.");
    }

    bits += value.toString(2).padStart(5, "0");
  }

  const bytes = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  }

  return Buffer.from(bytes);
}

function makeCounterBuffer(counter) {
  const buffer = Buffer.alloc(8);
  buffer.writeUInt32BE(Math.floor(counter / 0x1_0000_0000), 0);
  buffer.writeUInt32BE(counter >>> 0, 4);
  return buffer;
}

function ipToInt(ipAddress) {
  const octets = String(ipAddress)
    .split(".")
    .map((part) => Number.parseInt(part, 10));

  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return null;
  }

  return (((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3]) >>> 0;
}

function matchesIpv4Cidr(ipAddress, cidr) {
  const [base, prefixLengthText] = cidr.split("/");
  const prefixLength = Number.parseInt(prefixLengthText, 10);
  const ipValue = ipToInt(ipAddress);
  const baseValue = ipToInt(base);

  if (
    ipValue === null ||
    baseValue === null ||
    !Number.isInteger(prefixLength) ||
    prefixLength < 0 ||
    prefixLength > 32
  ) {
    return false;
  }

  const mask = prefixLength === 0 ? 0 : ((0xffffffff << (32 - prefixLength)) >>> 0);
  return (ipValue & mask) === (baseValue & mask);
}

export function normalizeIp(ipAddress) {
  const rawIp = String(ipAddress ?? "").trim();
  if (!rawIp) {
    return "unknown";
  }

  const forwarded = rawIp.includes(",") ? rawIp.split(",")[0].trim() : rawIp;
  const ipv4Mapped = forwarded.replace(/^::ffff:/i, "");

  if (ipv4Mapped === "::1") {
    return LOCALHOST_IPV4;
  }

  return ipv4Mapped;
}

export function isIpAllowed(ipAddress, whitelist = []) {
  if (!Array.isArray(whitelist) || whitelist.length === 0) {
    return true;
  }

  const normalizedIp = normalizeIp(ipAddress);

  return whitelist.some((entry) => {
    const normalizedEntry = String(entry ?? "").trim();
    if (!normalizedEntry) {
      return false;
    }

    if (normalizedEntry === "*") {
      return true;
    }

    if (normalizedEntry.toLowerCase() === "localhost") {
      return normalizedIp === LOCALHOST_IPV4 || normalizedIp === "::1";
    }

    if (normalizedEntry.includes("/")) {
      return matchesIpv4Cidr(normalizedIp, normalizedEntry);
    }

    return normalizeIp(normalizedEntry) === normalizedIp;
  });
}

export function createPasswordHash(password, options = {}) {
  const salt = options.salt ?? randomBytes(16);
  const parameters = {
    N: options.N ?? 16_384,
    r: options.r ?? 8,
    p: options.p ?? 1,
    keyLength: options.keyLength ?? 64,
  };
  const derived = scryptSync(password, salt, parameters.keyLength, {
    N: parameters.N,
    r: parameters.r,
    p: parameters.p,
    maxmem: 64 * 1024 * 1024,
  });

  return [
    "scrypt",
    parameters.N,
    parameters.r,
    parameters.p,
    salt.toString("base64"),
    derived.toString("base64"),
  ].join("$");
}

export function verifyPasswordHash(password, storedHash) {
  const parts = String(storedHash ?? "").split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") {
    return false;
  }

  const [_, nText, rText, pText, saltText, hashText] = parts;
  const N = Number.parseInt(nText, 10);
  const r = Number.parseInt(rText, 10);
  const p = Number.parseInt(pText, 10);
  const salt = Buffer.from(saltText, "base64");
  const expected = Buffer.from(hashText, "base64");

  if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p) || expected.length === 0) {
    return false;
  }

  const derived = scryptSync(password, salt, expected.length, {
    N,
    r,
    p,
    maxmem: 64 * 1024 * 1024,
  });

  return derived.length === expected.length && timingSafeEqual(derived, expected);
}

export function generateBase32Secret(byteLength = 20) {
  return encodeBase32(randomBytes(byteLength));
}

export function generateTotpCode(secret, timestamp = Date.now(), stepSeconds = 30, digits = 6) {
  const secretBuffer = decodeBase32(secret);
  if (secretBuffer.length === 0) {
    throw new Error("TOTP secret is not configured.");
  }

  const counter = Math.floor(timestamp / 1000 / stepSeconds);
  const hmac = createHmac("sha1", secretBuffer).update(makeCounterBuffer(counter)).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binaryCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return String(binaryCode % 10 ** digits).padStart(digits, "0");
}

export function verifyTotpCode(secret, token, options = {}) {
  const normalizedToken = String(token ?? "").trim();
  if (!/^\d{6}$/.test(normalizedToken)) {
    return false;
  }

  const window = options.window ?? 1;
  const timestamp = options.timestamp ?? Date.now();
  const stepSeconds = options.stepSeconds ?? 30;
  const digits = options.digits ?? 6;

  for (let offset = -window; offset <= window; offset += 1) {
    const expectedCode = generateTotpCode(
      secret,
      timestamp + offset * stepSeconds * 1000,
      stepSeconds,
      digits,
    );

    if (safeTextEqual(expectedCode, normalizedToken)) {
      return true;
    }
  }

  return false;
}

export function createHmacHash(value, secret) {
  return createHmac("sha256", secret).update(String(value ?? "")).digest("hex");
}

export function createSignedToken(payload, secret) {
  const header = {
    alg: "HS256",
    typ: "JWT",
  };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signature = createHmac("sha256", secret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

export function verifySignedToken(token, secret) {
  const parts = String(token ?? "").split(".");
  if (parts.length !== 3) {
    throw new Error("Malformed token.");
  }

  const [encodedHeader, encodedPayload, providedSignature] = parts;
  const expectedSignature = createHmac("sha256", secret)
    .update(`${encodedHeader}.${encodedPayload}`)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

  if (!safeTextEqual(expectedSignature, providedSignature)) {
    throw new Error("Invalid token signature.");
  }

  return {
    header: JSON.parse(base64UrlDecode(encodedHeader).toString("utf8")),
    payload: JSON.parse(base64UrlDecode(encodedPayload).toString("utf8")),
  };
}

export function createFingerprintHash(fingerprint, secret) {
  return createHmacHash(String(fingerprint ?? "").trim(), secret);
}

export function createIpHash(ipAddress, secret) {
  return createHmacHash(normalizeIp(ipAddress), secret);
}

export function hashText(value) {
  return createHash("sha256").update(String(value ?? "")).digest("hex");
}