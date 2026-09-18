export function createRateLimiter({
  windowMs, analyzeLimit, adminLimit, adminAuthLimit, feedbackLimit,
  maxBuckets = 10_000,
}) {
  if (!Number.isFinite(windowMs) || windowMs <= 0 || windowMs > 2_147_483_647) {
    throw new RangeError("windowMs must be a positive timer-safe duration");
  }
  if (!Number.isSafeInteger(maxBuckets) || maxBuckets < 1) {
    throw new RangeError("maxBuckets must be a positive integer");
  }
  const buckets = new Map();
  const cleanupMs = Math.min(windowMs, 60_000);
  let nextPruneAt = Date.now() + cleanupMs;

  function prune(now) {
    for (const [key, entry] of buckets) {
      if (entry.resetAt <= now) buckets.delete(key);
    }
    nextPruneAt = now + cleanupMs;
  }

  // Deterministic idle cleanup; this timer must not keep Node alive.
  const cleanupTimer = setInterval(() => prune(Date.now()), cleanupMs);
  cleanupTimer.unref();

  function resolveLimit(bucket) {
    if (bucket === "admin") return adminLimit;
    if (bucket === "admin-auth") return adminAuthLimit;
    if (bucket === "feedback") return feedbackLimit ?? analyzeLimit;
    return analyzeLimit;
  }

  function consume({ ip, bucket = "analyze" }) {
    const now = Date.now();
    // Covers delayed timers without scanning the Map on every request.
    if (now >= nextPruneAt) prune(now);
    const key = `${bucket}:${ip}`;
    const limit = resolveLimit(bucket);
    let entry = buckets.get(key);

    if (!entry && buckets.size >= maxBuckets) {
      // Do not evict live counters: cycling IPs must not reset existing limits.
      return { allowed: false, limit, remaining: 0, resetAt: nextPruneAt };
    }
    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + windowMs };
    }
    entry.count = Math.min(entry.count + 1, limit + 1);
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
    get size() { return buckets.size; },
    dispose() { clearInterval(cleanupTimer); buckets.clear(); },
  };
}
