# AI Shield startup readiness

AI Shield 1.1 is a privacy-first advisory prototype for two audiences: individuals checking UPI/banking messages and banks or fintech teams evaluating an on-device warning layer. It is **not yet validated as a production security control**. Chrome Web Store publication remains deferred.

## Current product boundary

- The Chrome extension runs locally, requests only `activeTab` and `scripting`, and blocks extension network connections. No scan contents or results are retained.
- The shared detector returns a 0–100 score with thresholds 35 and 70. SAFE means “No suspicious patterns found, but verify via official channel.”
- The existing website has separate, explicitly optional API, logging, and OCR workflows. Those are outside the extension's local-only promise and need separate product/privacy review before a commercial launch.
- Sender display-name/domain mismatch is a text heuristic, not SPF/DKIM/DMARC authentication. URL checks inspect lexical form without visiting links or resolving redirects.

## Evidence available today

The deterministic Nazario held-out experiment detected 189/200 phishing emails and correctly cleared 191/200 legitimate emails: 94.5% recall, 95.5% specificity, and 95.45% precision. The model is 130,042 bytes. Median local detector execution was 4.67 ms on one development host, with a 19.62 ms 95th percentile. These figures come from a random historical split and cannot be generalized to current UPI fraud.

A synthetic scenario set contains 200 Hindi/Hinglish UPI scams, 200 English banking scams, and 400 benign controls. The latest detector classified all these generated examples correctly. Because templates and detector rules are closely related, this is a regression suite, **not** an independent field benchmark. The prior version misclassified genuine receipts and safety reminders; regression cases now cover both those negatives and collect-request scams.

## Release gates before a production claim

1. **Independent data:** Obtain consented, de-identified, naturally occurring UPI scam and benign-message samples in Hindi, Hinglish, and English. Freeze a campaign-grouped and newer-in-time holdout before tuning. Publish class definitions, deduplication rules, and subgroup results.
2. **Safety targets:** Agree on false-negative and false-positive budgets with pilot partners. Report precision, recall, specificity, calibration, confusion matrices, and intervals per language/scam type and on realistic class prevalence. Test obfuscation, screenshots/QR-only messages, impersonation, and adversarial safety-preface wording.
3. **Privacy/security:** Complete an independent extension and website security review, dependency/SBOM and supply-chain checks, data-flow review, penetration test, privacy notice, incident response, and signed release process. Verify the packaged extension has the same permission and offline behavior as source.
4. **Product pilot:** Run an opt-in advisory pilot with reversible rollout, error reporting that never uploads message text by default, accessible Hindi/English explanations, and a process for correcting harmful warnings. Measure whether users actually verify through official channels.
5. **B2B integration:** Package the shared engine as a versioned offline SDK with a stable result schema, deterministic model updates, auditability, and partner-specific integration tests. Do not promise authenticated-sender checks unless verified header data is supplied by the partner.

## Commercial path

Start with a consumer extension pilot to validate the UPI warning flow and false-alarm burden. In parallel, offer banks/fintech teams a scoped on-device SDK proof of concept with their own consented test data. Revenue, regulatory obligations, distribution, and support terms should be defined after field evidence; the present repository does not establish those claims.
