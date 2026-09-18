# AI Shield v1 paper review and v2 audit notes

## Decision

The v1 paper was appropriately candid, but its evidence supported only a narrow warning-layer claim. The v2 experiment fixes the reported low-recall result on its deterministic held-out split and keeps the privacy boundary intact. It still does not support a production-ready claim.

## What v2 fixes

- Replaces the 40-message runtime-trained corpus with a deterministic 130 KB embedded model trained from 800 phishing and 800 legitimate Nazario messages after selecting 1,000 examples per class and applying an 80/20 stratified split.
- Removes exact normalized duplicates before sampling and checks exact overlap against UCI by SHA-tracked inputs. No Nazario/UCI exact overlaps were present; retiring the old 40-message corpus eliminates the four UCI-versus-embedded-corpus overlaps reported in v1.
- Replaces generic UCI spam as the domain-shift headline with 200 synthetic Hindi/Hinglish UPI scams and 200 synthetic English banking scams. Matched benign controls are retained as a deliberately harder false-positive stress test.
- Adds Unicode tokens, IP-in-URL, punycode, URL shortener, suspicious-TLD, and sender display-name/domain mismatch signals while preserving 0–100 scoring and thresholds 35/70.
- Adds a held-out precision–recall curve, percentage confusion matrix, deterministic 1,000-resample bootstrap intervals, hashes, and recorded latency.

## Claims that must stay qualified

1. **Random split leakage risk.** Exact deduplication does not eliminate campaign templates or near duplicates. A grouped or temporal split is needed before treating 94.5% recall as robust external evidence.
2. **Synthetic test circularity.** The scam templates contain the exact behaviors the rules were designed to find. They demonstrate scenario coverage, not real-world generalization or prevalence.
3. **False positives and negation.** Synthetic benign controls containing phrases such as “never share OTP” initially triggered warnings. A narrow reminder rule now clears those cases, but it is not general language understanding and was tuned against the same synthetic controls.
4. **Sender authentication wording.** The implementation detects a textual display-name/domain mismatch. It does not validate SPF, DKIM, DMARC, message routing, or domain ownership. The extension may not receive a sender header from ordinary rendered page text.
5. **URL scope.** URL signals are lexical and local. They do not resolve redirects or assess reputation. This is consistent with the privacy design but limits protection.
6. **Latency scope.** The under-5 ms median covers detector execution, not full popup response time, DOM extraction, browser scheduling, or slower devices.
7. **Confidence calibration.** The displayed confidence heuristic is not a calibrated probability and should not be described as one.

## Recommended next experiment

Freeze a newer labeled phishing corpus, group messages by campaign or near-duplicate cluster, reserve the newest groups for testing, and publish the split identifiers before tuning. Add naturally collected Hindi/Hinglish scam and benign messages with documented annotation, then report calibration, per-scenario errors, and user-level decision outcomes.
