# VaultShare Security Architecture & Limitations

## Security Mitigations Implemented

VaultShare is designed as a zero-knowledge secure document distribution platform employing multi-layer defense in depth:

1. **Security Headers & Strict CSP**:
   - **Content-Security-Policy (CSP)**: `default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';`. Strictly prohibits `'unsafe-inline'` and `'unsafe-eval'`. All dynamic user interactions and confirmation dialogs rely on unobtrusive JavaScript and data attributes.
   - **Subresource Integrity (SRI)**: Bootstrap CSS and JS bundles are loaded with validated official cryptographic integrity digests.
   - **Hardening Headers**: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`, and `Cross-Origin-Opener-Policy: same-origin`.
   - **HSTS**: `Strict-Transport-Security: max-age=31536000; includeSubDomains` enforced under production/HTTPS.
   - **Cache Protection**: `Cache-Control: no-store` and `Pragma: no-cache` enforced across all authenticated, non-static responses.

2. **CSRF Protection**:
   - Every state-altering action requires an explicit POST method protected with Flask-WTF CSRF tokens. Expired tokens trigger graceful user-friendly error redirection without leaking session state.

3. **Rate Limiting**:
   - Global default request rate limits (Flask-Limiter) combined with per-endpoint protection: 5 logins per minute and 5 registrations per hour per IP.

4. **Per-Account Lockout**:
   - Enforced dynamically using audit log history without altering schema: accounts with 5 or more failed login attempts within 15 minutes are locked for the remainder of the window. Generic failure responses prevent enumeration of lock status, and a single `LOGIN_LOCKED` audit row is recorded per lockout window.

5. **Timing Attack & Enumeration Defenses**:
   - Login authentication executes a dummy password hash verification when the requested username does not exist, keeping execution latency consistent with valid accounts.
   - Session fixation defense: existing session state is completely purged before binding an authenticated session.

6. **Password Policy**:
   - Enforced 12 to 128 character password length (preventing scrypt DoS). Rejects passwords matching or containing the user's username or email local-part (case-insensitive) and blocks known common insecure passwords from a built-in blocklist.

7. **Cryptographic Integrity & Hash-Chained Audit Log**:
   - Tamper-evident linear SHA-256 hash chaining with canonical JSON representations.
   - Comprehensive multi-stage cryptographic verification: ciphertext SHA-256 validation, RSA key unwrapping, AES-256-GCM authentication tag verification, and plaintext digest match.

8. **Silent 404 Access Control (404-not-403)**:
   - Unauthorized attempts to view, manage, download, or revoke documents return silent HTTP 404 responses rather than 403 Forbidden to prevent enumeration of document existence.

9. **In-Memory-Only Plaintext & Ephemeral Decryption**:
   - Plaintext private keys and document contents exist exclusively in server memory during active streaming or verification and are never written to disk unencrypted or stored in client-accessible cookies.

10. **Atomic Ciphertext Writes & File Validation**:
    - Ciphertext uploads are written to temporary files with owner-only permissions (`0o600`), then atomically moved (`os.replace`) into storage under cryptographically random filenames.
    - Magic-byte inspection validates file format integrity (PDF, PNG, JPEG, ZIP/DOCX/XLSX/PPTX) and UTF-8 text decoding for plain text files before processing. Storage quotas prevent disk exhaustion.

---

## Known Security Limitations

An honest assessment of the system's operational and threat boundaries:

1. **Server-Side Decryption (Not End-to-End Encryption)**:
   - Decryption takes place server-side in the application process. While private keys and documents are encrypted at rest, the server acts as a trusted processing intermediary. This is not end-to-end client-side encryption.
2. **Compromised Server Exposure**:
   - If the application server process or operating system is compromised while user sessions are active, decrypted private keys stored in the in-memory key cache and plaintext data in transit could be accessed by an attacker.
3. **No Memory Zeroing Guarantee in Python**:
   - The Python runtime, dynamic memory allocator, and garbage collector do not guarantee deterministic wiping or zeroing of cryptographic keys or buffers from RAM upon object deallocation.
4. **Revocation Cannot Recall Downloaded Copies**:
   - Revoking access deletes the recipient's wrapped symmetric key from the database, preventing future decryption via VaultShare. However, it cannot revoke, delete, or recall document copies previously downloaded to a recipient's local filesystem.
5. **Audit Chain Tail Truncation**:
   - While internal tampering, entry modification, insertion, or reordering breaks the SHA-256 hash chain and is immediately detected, deleting the most recent audit records (tail truncation) leaves an internally valid prefix. Complete tail-truncation defense requires external hash anchoring or witness logs.
6. **No Administrative Role**:
   - VaultShare intentionally provides no superuser or administrator role capable of bypassing document permissions or accessing private vaults.
7. **Single-Process Key Cache and Rate Limiting**:
   - The in-memory unlocked key cache and default rate limiter are local to a single Python process. A multi-process or multi-worker cluster requires a shared secure storage mechanism (e.g., Redis with mTLS) or sticky sessions.
8. **Forgotten Passwords Are Unrecoverable by Design**:
   - Because a user's RSA private key is encrypted with an AES key derived from their password via scrypt, a lost or forgotten password permanently prevents decryption of their private key and inaccessible documents. There is no backdoor or recovery mechanism.
9. **Single-Node Storage & Database**:
   - SQLite and local disk storage are designed for single-node deployments and are not suitable for multi-server active-active clustering without network file locking or clustered database engines.
