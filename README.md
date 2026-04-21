# AI Shield

AI Shield is a privacy-first cybersecurity system that analyzes suspicious messages or visible screen text and flags scams, phishing attempts, coercive social engineering, and malicious intent in real time.

## What it does

- Combines three layers of detection:
  - A local machine-learning classifier trained from an embedded scam corpus
  - A rule-based risk engine for phishing links, credential theft, payment redirection, and malware-style prompts
  - Behavioral pattern detection for urgency, fear, fake authority, secrecy pressure, and reward bait
- Produces:
  - A `0-100` risk score
  - A verdict of `SAFE`, `SUSPICIOUS`, or `SCAM`
  - Explainable reasons, highlighted patterns, and next-step recommendations
- Uses a privacy-first workflow:
  - No analysis happens without explicit consent
  - Local browser analysis is available before any API submission
  - Logging is optional, minimal, encrypted, and deletable
  - Stored records are anonymized and never shared with third parties

## Architecture

### Backend

- `src/app.js`: HTTP server composition, route dispatch, rate limiting, static asset serving
- `src/routes/analyzeRoutes.js`: consent-gated analysis endpoints
- `src/routes/adminRoutes.js`: admin-only log viewing and deletion
- `src/services/secureLogger.js`: AES-256-GCM encrypted minimal log store
- `src/middleware/`: admin authentication and in-memory rate limiting
- `src/config/env.js`: runtime configuration

### Shared detection engine

- `shared/detectionEngine.js`: ML + rules + behavioral analysis
- `shared/trainingCorpus.js`: embedded local training corpus
- `shared/constants.js` and `shared/textUtils.js`: reusable heuristics and normalization

### Frontend

- `public/index.html`: real-time dashboard
- `public/app.js`: local-first UX, optional protected API verification, browser screen capture flow
- `public/styles.css`: responsive cybersecurity-themed interface

## Privacy model

- Analysis requires explicit consent via `consent.process`
- Screen analysis additionally requires `consent.screenScan`
- Logging requires `consent.storeLog`
- Persisting any content snippet requires `consent.persistContentSnippet`
- Stored data is minimized to:
  - verdict
  - score
  - explanation tags
  - anonymized hashes
  - optional encrypted short snippet

## Security controls

- Input sanitization and body-size limits
- Rate limiting for analysis and admin routes
- Admin API-key protection for log access
- Secure response headers and restrictive CSP
- AES-256-GCM encrypted log storage
- User-triggered deletion for individual logs or all logs

## API endpoints

- `GET /api/health`
- `GET /api/features`
- `POST /api/analyze`
- `POST /api/analyze/screen`
- `GET /api/admin/logs`
- `DELETE /api/admin/logs`
- `DELETE /api/admin/logs/:id`

### Example request

```json
{
  "content": "Urgent: confirm your bank password now.",
  "source": "email",
  "consent": {
    "process": true,
    "storeLog": false,
    "persistContentSnippet": false
  }
}
```

### Example response shape

```json
{
  "analysis": {
    "classification": "SCAM",
    "riskScore": 91,
    "summary": "This content shows multiple coordinated scam indicators and should be treated as hostile."
  },
  "privacy": {
    "processed": true,
    "stored": false,
    "thirdPartySharing": false
  }
}
```

## Running locally

1. Copy `.env.example` to `.env` and set:
   - `AI_SHIELD_ADMIN_API_KEY`
   - `AI_SHIELD_MASTER_KEY`
2. Start the app:

```bash
node src/server.js
```

3. Open [http://127.0.0.1:3000](http://127.0.0.1:3000)

## Testing

```bash
node --test
```

## Production notes

- Set a strong `AI_SHIELD_MASTER_KEY` so encrypted logs remain readable across restarts.
- Replace the in-memory rate limiter with Redis or another distributed store for multi-instance deployments.
- Terminate TLS in front of the service and restrict `AI_SHIELD_ALLOWED_ORIGINS`.
- Move admin features behind stronger authentication if exposed beyond an internal network.

## Future enhancements

- Voice scam detection and transcript analysis
- Browser extension for inline page and message scanning
- Model updates from new scam patterns with curated offline retraining
- OCR hardening and secure mobile integrations