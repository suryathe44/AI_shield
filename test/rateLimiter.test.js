import test from "node:test";
import assert from "node:assert/strict";
import { createRateLimiter } from "../src/middleware/rateLimiter.js";

const options = { windowMs: 1000, analyzeLimit: 2, adminLimit: 3, adminAuthLimit: 1, feedbackLimit: 4, maxBuckets: 2 };

test("limiter bounds IP churn without evicting live counters", (t) => {
  const limiter = createRateLimiter(options);
  t.after(() => limiter.dispose());
  assert.equal(limiter.consume({ ip: "a" }).allowed, true);
  assert.equal(limiter.consume({ ip: "a" }).remaining, 0);
  limiter.consume({ ip: "b" });
  for (let i = 0; i < 10000; i++) assert.equal(limiter.consume({ ip: `new-${i}` }).allowed, false);
  assert.equal(limiter.size, 2);
  assert.equal(limiter.consume({ ip: "a" }).allowed, false);
});

test("idle cleanup releases expired entries and admits new clients", (t) => {
  t.mock.timers.enable({ apis: ["Date", "setInterval"], now: 10000 });
  const limiter = createRateLimiter(options);
  t.after(() => limiter.dispose());
  limiter.consume({ ip: "a" });
  limiter.consume({ ip: "b" });
  t.mock.timers.tick(1000);
  assert.equal(limiter.size, 0);
  assert.equal(limiter.consume({ ip: "c" }).allowed, true);
  limiter.dispose();
  assert.equal(limiter.size, 0);
});

test("fixed windows reset and route budgets remain independent", (t) => {
  t.mock.timers.enable({ apis: ["Date", "setInterval"], now: 10000 });
  const limiter = createRateLimiter({ ...options, maxBuckets: 10 });
  t.after(() => limiter.dispose());
  assert.equal(limiter.consume({ ip: "a", bucket: "admin-auth" }).allowed, true);
  assert.equal(limiter.consume({ ip: "a", bucket: "admin-auth" }).allowed, false);
  assert.equal(limiter.consume({ ip: "a", bucket: "analyze" }).remaining, 1);
  assert.equal(limiter.consume({ ip: "a", bucket: "feedback" }).remaining, 3);
  t.mock.timers.tick(1000);
  assert.equal(limiter.consume({ ip: "a", bucket: "admin-auth" }).allowed, true);
});
