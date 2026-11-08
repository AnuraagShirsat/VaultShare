# VaultShare

VaultShare is a secure document distribution web application built with Python, Flask, SQLite, and the `cryptography` library. It enables users to upload documents that are encrypted at rest with AES-256-GCM, securely distribute wrapped encryption keys to specified recipients via RSA-3072 / RSA-OAEP, and record all security-critical operations in a tamper-evident audit log.

---

## Security Model & Known Limitations

- **Zero-Knowledge Private Key Storage**:
  When a user registers, an RSA-3072 keypair is generated. The private key is encrypted using AES-256-GCM with a key derived from the user's password via `scrypt` ($n=2^{15}$, $r=8$, $p=1$). The plaintext private key is never saved to disk, logged, or flashed.
  > [!IMPORTANT]
  > **TODO / Security Note on Forgotten Passwords**: A forgotten password **cannot** be recovered or reset, because the RSA private key is encrypted directly with a password-derived key. Password reset is intentionally not implemented to preserve the security boundary.

- **Server-Side Key Unlocking**:
  Upon successful login, the server unlocks the private key into a server-side in-memory cache keyed by a random session token.
  *Known limitation*: Because decryption and cryptographic wrapping happen server-side, this architecture is end-to-rest rather than true client-side end-to-end encryption. Additionally, the in-memory key cache is single-process and lost upon application restarts.

- **Access Revocation Limitation**:
  Revoking recipient access deletes the recipient's RSA-wrapped key (`DocumentKey` record) from the database, preventing any future key unwrapping or server-side document decryption through VaultShare.
  *Known limitation*: Revocation takes effect immediately for all subsequent VaultShare operations, but it cannot retroactively un-share, recall, or delete copies of documents that a recipient previously downloaded to their local machine.

- **Tamper-Proof Hash-Chained Audit Log**:
  Every sensitive action is written to `audit_logs` where each record's `entry_hash` cryptographically chains to the previous record's `entry_hash` (starting with `0` * 64 at genesis). SQLite triggers prevent `UPDATE` and `DELETE` at the database level.
  *Known limitation*: Deleting the most recent entries from the tail of the log (tail truncation) cannot be detected from the internal hash chain alone, as the remaining prefix remains internally consistent. Full protection against tail truncation requires periodic anchoring of the latest head hash to an external witness or timestamping service.

---

## Tech Stack

- **Backend**: Python 3.13, Flask 3.1 (Application Factory Pattern)
- **Database & ORM**: SQLite, Flask-SQLAlchemy 3.1 / SQLAlchemy 2.x
- **Authentication & Security**: Flask-Login, Flask-WTF (CSRF), Flask-Limiter
- **Cryptography**: `cryptography` library hazmat primitives (AES-256-GCM, RSA-3072, RSA-OAEP with SHA-256, scrypt)
- **Frontend**: Jinja2 templates, Bootstrap 5 (CDN), Bootstrap Icons
- **Testing**: `pytest`

---

## Getting Started

### 1. Initialize the Database
```powershell
.\venv\Scripts\flask --app wsgi init-db
```

### 2. Run the Development Server
```powershell
.\venv\Scripts\flask run
```
Access the application at [http://127.0.0.1:5000](http://127.0.0.1:5000).

### 3. Run the Test Suite
```powershell
.\venv\Scripts\pytest -v
```

### 4. Verify Audit Log Hash Chain
```powershell
.\venv\Scripts\flask --app wsgi verify-audit
```

### 5. Audit Log Tampering Demonstration
To simulate an attacker attempting to tamper with audit records directly on disk:
```powershell
.\venv\Scripts\python scripts/tamper_audit_demo.py instance/vaultshare.db 1
.\venv\Scripts\flask --app wsgi verify-audit
```
