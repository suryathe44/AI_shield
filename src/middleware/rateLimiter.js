export function createRateLimiter({ windowMs, analyzeLimit, adminLimit }) {
  const buckets = new Map();

  function prune(now) {
    for (const [key, entry] of buckets.entries()) {
      if (entry.resetAt <= now) {
        buckets.delete(key);
      }
    }
  }

  function resolveLimit(bucket) {
    return bucket === "admin" ? adminLimit : analyzeLimit;
  }

  function consume({ ip, bucket = "analyze" }) {
    const now = Date.now();
    if (buckets.size > 500 || Math.random() < 0.05) {
      prune(now);
    }

    const key = `${bucket}:${ip}`;
    const limit = resolveLimit(bucket);
    let entry = buckets.get(key);

    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + windowMs };
    }

    entry.count += 1;
    buckets.set(key, entry);

    return {
      allowed: entry.count <= limit,
      limit,
      remaining: Math.max(limit - entry.count, 0),
      resetAt: entry.resetAt,
    };
  }

  return {
    consume,
  };
}