# Chrome Web Store listing — AI Shield 1.0.0

## Name
AI Shield

## Summary
Inspect messages, selected text and pages for scam signals locally.

## Description
Pause before you click, reply, or share sensitive information. AI Shield helps you inspect suspicious messages and webpage text for scam and phishing signals, directly in your browser.

• Paste an email, SMS, chat, or suspicious URL and analyze it.
• Select text on a webpage and scan your selection.
• Scan the current page's URL and rendered text with one click.
• Review a 0–100 risk score, SAFE / SUSPICIOUS / SCAM verdict, explanations, and practical next steps.

Analysis runs locally using a bundled classifier, security rules, and behavioral signals. No account or backend is needed. No message uploads, analytics, saved scan history, or background monitoring. Every scan starts with your click.

AI Shield analyzes up to 20,000 characters per scan. Page scans read main-frame rendered text and the current URL; they do not inspect hidden link destinations, images, cross-origin frames, downloads, or live URL reputation. Chrome's restricted pages cannot be scanned; paste the text instead.

Results are heuristic guidance, not a guarantee of safety. Always independently verify requests for passwords, one-time codes, payments, or personal information.

## Category and language
Productivity / Tools (choose the closest available dashboard category); English.

## URLs
Homepage: https://github.com/suryathe44/AI_shield
Support: https://github.com/suryathe44/AI_shield/issues
Privacy policy: https://github.com/suryathe44/AI_shield/blob/main/docs/chrome-web-store/PRIVACY.md

## Single purpose
Help users assess scam and phishing signals in text they explicitly choose to analyze, with on-device scores and explanations.

## Permission justifications
activeTab: Gives temporary access to the active webpage when the user invokes the extension. Used only after a scan-button click to read the current URL and selected or rendered main-frame text.
scripting: Runs the bundled captureText function in that active tab to return text for local scam analysis. No persistent content scripts or background monitoring.

## Data and remote code disclosures
No user data is collected or transmitted off-device. Website content is processed temporarily and locally only for the requested scan. No remote code is used; all JavaScript and classifier data ship in the ZIP. Select disclosures matching this behavior; read dashboard certification statements before submitting.

## Reviewer test instructions
No login, payment, API key, or server setup is needed to use the extension.
1. Open the popup and paste: Urgent: your bank account will be suspended. Verify your password and OTP at https://secure-bank-login.example
2. Click Analyze message. Expect a SCAM verdict with a high score and explanations.
3. Click Clear; paste: Team lunch is scheduled for tomorrow at noon in the office cafeteria. Expect a SAFE verdict, which does not guarantee safety.
4. On a normal HTTPS webpage, select some text, open the popup, and click Scan selected text.
5. Click Scan current page to inspect its URL and rendered main-frame text.
6. Empty selection should explain how to retry. Internal Chrome pages should offer paste as a fallback.

## Files
Upload releases/ai-shield-chrome-1.0.0.zip. Icons are inside the package.
Use promo-440x280.png as the small promotional tile.
A real UI screenshot at 1280×800 or 640×400 must also be supplied.

## Publication status
Prepared for submission; not yet submitted or approved. Developer registration is required before upload. Google controls review and public availability.
