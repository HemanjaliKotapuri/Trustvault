# THREATS.md — TrustVault threat notes

| Threat | Mitigation in this MVP | Remaining limitation |
|---|---|---|
| User guesses another document ID | Server checks permission on every document route | Add rate limiting and security monitoring |
| User downloads a file by guessing its storage name | Files are outside the static web directory; download goes through an authorized route | Protect server filesystem and backups |
| Owner revokes access but old link still works | Permission is checked again on every download | A file already downloaded cannot be remotely erased |
| Malicious or oversized upload | Extension allowlist and 10 MB limit | Add antivirus scanning and content-signature/MIME validation |
| Audit record edited through application | SQLite triggers block UPDATE/DELETE; HMAC chain links records | A privileged host/database attacker could replace DB and key; export logs to separate append-only storage |
| Password guessing | Werkzeug password hashing | Add login throttling, MFA and password reset flow |
| Cross-user document access | Automated isolation tests | Expand tests to every endpoint and role |
| Session theft / CSRF | Flask session cookie | Configure HTTPS, Secure/HttpOnly/SameSite cookies and CSRF protection before production |
