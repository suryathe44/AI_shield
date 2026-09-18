# AI Shield scoped security audit — September 13, 2026

Scope: extension offline behavior, SAFE wording, shared risk scoring, and in-memory rate-limiter lifecycle. Reviewed the local tree previously verified identical to GitHub main be482c6. This is a scoped source audit with regression tests, not a penetration test or a guarantee of complete security.

## Findings and patches

### High — unbounded live rate-limit buckets and CPU amplification (fixed)

`src/middleware/rateLimiter.js` previously admitted an unlimited number of distinct IP/bucket pairs within a window. Pruning removes only expired entries, so a burst of distinct identities can grow memory without bound. Above 500 entries every request scanned the entire Map, including rejected requests, making sustained high-cardinality traffic expensive. Below the threshold cleanup was probabilistic; when traffic stopped, expired entries remained until subsequent requests.

Patch: cap the Map at 10,000 entries by default; reject new identities at capacity without evicting existing live counters. Run deterministic cleanup at most every min(windowMs, 60 seconds), including idle periods. A request-side deadline handles delayed timers without doing a full scan per request. Saturate blocked counters. Validate timer duration and capacity. Unref the cleanup timer and dispose the app-owned limiter on server close. Injected limiters remain caller-owned.

Tradeoff: at capacity, previously unseen clients receive HTTP 429 until capacity becomes available. This deliberately preserves existing rate limits rather than evicting counters. The cap is per process, not distributed rate limiting. Cleanup work is bounded by the cap; reclamation occurs by the first sweep after expiration, subject to event-loop scheduling.

### SAFE wording — requested clarification (updated; no absolute-safety bug found)

No generated SAFE verdict claimed “100% safe”. Previous text already advised caution. Nonempty SAFE summaries now read: “No suspicious patterns found, but verify via official channel.” SAFE recommendations explicitly advise official-channel verification before sensitive disclosures or payments. Empty input retains “No content was provided for analysis.” The web and extension consume this shared result. Confidence is a model-confidence field, not a probability that content is safe.

### Extension offline analysis — no network-call bug found (unchanged)

Reviewed extension JavaScript, HTML/CSS, the manifest, capture function, and the five shared JavaScript modules shipped in the build. No fetch, XMLHttpRequest, WebSocket, EventSource, beacon, remote imports, remote resource references, or backend calls occur in this flow. URL strings in the corpus and parser are analyzed as text; they are not requested. Icons and all runtime code are packaged locally. The manifest homepage URL is metadata, not an automatic request.

`connect-src 'none'` already blocks fetch and related connections from extension pages. Permissions remain only activeTab and scripting. The isolated capture function only reads the selected text, or URL and body text; it does not make network calls. No fetch monkey patch was added because there is no offending call and CSP already enforces the popup restriction.

Limits: this is not a claim that Chrome or the visited website is offline. The extension-pages CSP does not automatically apply to an injected content script's isolated world, and connect-src is not a blanket policy against every possible future resource type or navigation. Current code is offline; future changes need review. The new source regression check catches direct network-call patterns, not arbitrary obfuscated JavaScript.

Reference: https://developer.chrome.com/docs/extensions/reference/manifest/content-security-policy
Reference: https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts

### Risk-score consistency — no bug found (unchanged)

Both local web analysis and extension use the same analyzeContent implementation. Raw score is round(clamp(0.50 × ruleScore + 0.24 × behaviorScore + 0.26 × mlRiskScore + combinationBonus, 0, 100)). Rules can promote a classification; the final score is lifted to the relevant threshold so the verdict agrees with its band: SAFE 0–34, SUSPICIOUS 35–69, SCAM 70–100. Source labels affect metadata, not scores.

The built extension and web returned deeply equal results for all 40 embedded corpus samples. Regression checks also cover empty/whitespace/Unicode input, integer/range invariants, band consistency, and five source labels. This is consistency verification, not an independent accuracy evaluation.

Optional web API URL reputation can intentionally upgrade a result to SCAM and at least 95. That online enrichment is separate from the local model and is absent from the extension. Page URL inclusion, different selected text, and UI input limits can also change the analyzed content; parity applies to identical input.

## Validation and deliverables

- All existing 49 tests still pass; 5 new audit/rate-limiter regressions pass (54 total).
- Tested fixed-window reset, independent route budgets, 10,000 rejected new identities against a full small-cap limiter, and idle expiration with a mocked clock.
- Rebuilt dist/chrome-extension and releases/ai-shield-chrome-1.0.0.zip with updated SAFE wording.
- git diff --check passes.
- Code changes and new tests are provided in security-audit.patch at repository root. The regenerated ZIP is a separate binary artifact.
- Audit patches are local; this audit did not submit to Chrome Web Store or upload these follow-up changes to GitHub.
