# AI Shield offline ML upgrade plan

## Decision

Use a **hybrid quantized logistic-regression model plus the existing explainable rules**. Do not use ONNX Runtime Web for this product stage: the runtime dependency is much larger than the detector and provides little benefit for short scam messages. A hashed linear model handles spelling variants and Hinglish better than the current word-count Naive Bayes model, while the rules preserve clear human explanations for UPI PIN, collect-request, OTP, URL, sender, urgency, and impersonation signals.

The detector remains fully local. The model is bundled inside AI Shield's web/extension feature and no `fetch`, API call, telemetry, scan history, or user message storage is involved. `demonix.site` remains a separate 6KB marketing site and must not import this model.

## Model contract

| Item | Choice |
| --- | --- |
| Classifier | L2-regularised logistic regression with signed feature hashing |
| Text features | Word unigrams/bigrams, character 3-grams/4-grams, Unicode Hindi tokens |
| Rule features | UPI collect/QR/PIN, OTP, KYC, account freeze, sender mismatch, suspicious URL, urgency/fear/reward patterns |
| Model format | 8,192 quantized `int8` weights as Base64 JSON |
| Expected model size | about 15KB raw weights; normally under 100KB including metadata |
| Browser runtime | `shared/hashedLogisticModel.js`, pure JavaScript, no runtime dependency |
| Verdict score | Existing calibrated 0–100 rule + ML blend; thresholds remain 35 and 70 |

The classifier probability is evidence, not proof. The existing explanation layer must always show the actual matching user-visible reason. A SAFE verdict must continue to say: **“No suspicious patterns found, but verify via official channel.”**

## Indian data plan

Build a reviewed JSONL or CSV dataset with one message per row and these fields:

```text
id,text,label,language,scam_family,source,verified_at,contains_url
```

Use labels `safe` and `scam`; keep `language` as `hi`, `hinglish`, or `en`; and use scam families `upi_collect`, `upi_pin`, `kyc`, `account_freeze`, `otp`, `fake_bank`, `loan_job_lottery`, and `other`.

Collect only public scam advisories, consented user reports after removal of personal data, and internally authored realistic examples reviewed by a human. Never train directly on unreviewed user scans. Deduplicate using SHA-256 of normalised text, keep source-level groups together, and remove exact overlaps across train/test. Hold out 20% stratified by both language and family. Keep a separate untouched test set of at least 200 Hindi/Hinglish and 200 English banking/UPI scams, plus benign bank receipts, merchant offers, security reminders, and real UPI payment confirmations for false-positive testing.

Release gate: recall and precision must be reported separately for every language/family; benign UPI receipts and safety advice must have specificity above 90%; no version ships based only on aggregate accuracy.

## Training and export

`research/train_hashed_logreg.py` is a dependency-free baseline trainer. It reads a deduplicated balanced corpus, trains the compact model, quantizes it, and produces `research/v3/model.json`. It intentionally does not replace the active model automatically. First add reviewed Indian examples and evaluation reporting; then inspect the model byte size and metrics before switching the production `shared/modelData.js` artifact.

```bash
python3 research/train_hashed_logreg.py
```

The runtime implementation is in `shared/hashedLogisticModel.js`. A production switch must be a small, reviewed change in `shared/detectionEngine.js`: dispatch to `scoreHashedLogisticModel` only when `MODEL_DATA.algorithm === "hashed-logistic-regression-int8"`; otherwise retain the current Naive Bayes path as a safe rollback.

## Evaluation checklist

1. Measure precision, recall, specificity, F1, and confusion matrices by `language` and `scam_family`.
2. Bootstrap 95% confidence intervals with 1,000 resamples.
3. Benchmark 1,000 local scans in Chrome and keep median inference below 5ms for normal-length text.
4. Test offline in the unpacked extension with DevTools Network set to Offline.
5. Run the complete test suite, including SAFE UPI receipts, reminders, Hindi UPI scams, malicious URLs, and display-name/domain mismatches.
6. Review false positives manually before changing the 35/70 thresholds.
