# VaultShare Live Demonstration Guide

This presentation script guides you step-by-step through a live demonstration of VaultShare. Follow each step in order using PowerShell on Windows.

---

## Prerequisites & Setup

Ensure you are in the project root directory with your virtual environment activated:

```powershell
.\venv\Scripts\Activate.ps1
```

Set the Flask application environment variable:

```powershell
$env:FLASK_APP = "wsgi.py"
```

---

## Demonstration Script

### Step 1: Database Reset, Demo Seeding, and Server Launch

**Commands:**
```powershell
flask reset-db --yes
flask seed-demo
flask run
```

**Expected Result:**
- `reset-db` drops any existing tables, purges `.enc` files in `storage/`, and re-creates tables with immutability triggers.
- `seed-demo` registers `alice`, `bob`, and `carol` with the policy-compliant demo password `DemoVaultPass2026!#`, generates documents, shares them, simulates decryptions, revokes carol, and outputs a summary table along with `AUDIT LOG OK (16 entries verified)`.
- `flask run` starts the server at `http://127.0.0.1:5000`.

**Presentation Action:**
- Open **two separate browser windows**:
  - Window 1: Normal browser window (for Alice).
  - Window 2: Private / Incognito window (for Bob).
- Navigate both to `http://127.0.0.1:5000`.

> **What to say:**
> *"VaultShare is a zero-knowledge secure document distribution platform. We start with a fresh environment by running `flask reset-db` and `flask seed-demo`. This creates standard accounts for Alice, Bob, and Carol with genuine cryptographic keypairs and populates initial activity through real application code paths."*

---

### Step 2: Upload a New Document as Alice

**Action:**
1. In Window 1 (Normal browser), log in as **alice** using password `DemoVaultPass2026!#`.
2. Notice the Dashboard showing Alice's vault metrics.
3. Click **Upload** in the navigation bar.
4. Choose any permitted file (e.g., a `.txt`, `.pdf`, or `.png` file, or create `Confidential_Strategy.txt` on your desktop).
5. Click **Upload & Encrypt**.

**Expected Result:**
- Alice is redirected to `/documents` with a success alert: *"Document uploaded and encrypted successfully."*
- The document appears in Alice's "Owned Documents" table.

> **What to say:**
> *"When Alice uploads a file, VaultShare generates a unique 256-bit AES-GCM symmetric key. The file is encrypted with AES-256-GCM at rest, and the document key is wrapped with Alice's RSA-3072 public key. The raw symmetric key and plaintext are immediately purged from memory."*

---

### Step 3: Inspect the Encrypted Storage on Disk

**Commands (in a second PowerShell terminal):**
```powershell
Get-ChildItem storage/ -Filter *.enc
```
Pick the newest `.enc` file and inspect its raw bytes:
```powershell
$file = (Get-ChildItem storage/*.enc | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
Format-Hex $file | Select-Object -First 10
```

**Expected Result:**
- Random hex bytes are displayed.
- The original plaintext is completely unreadable and absent from disk.
- Filenames in `storage/` are random 32-character hex tokens (e.g. `a1b2c3d4e5f6...enc`), preventing directory enumeration or metadata leakage.

> **What to say:**
> *"Looking directly at the storage directory on disk, we see random 32-character hex filenames. Inspecting the bytes with Format-Hex confirms that no plaintext, document title, or header leaks into the ciphertext on the server."*

---

### Step 4: Share the Document with Bob

**Action:**
1. In Alice's browser window, locate the uploaded document in `/documents` and click **Manage**.
2. Under "Share Document", select or enter `bob` in the recipient field.
3. Click **Share Document**.

**Expected Result:**
- Success banner: *"Shared with bob."*
- Bob appears in the "Authorized Recipients" table on Alice's Manage page with `Decrypt Count: 0`.

> **What to say:**
> *"To share the document, the server uses Alice's unlocked session key to unwrap the document key, then re-wraps it under Bob's RSA-3072 public key. Bob now has an authorized `DocumentKey` record, without Alice ever needing to reveal her private key or share her password."*

---

### Step 5: Log in as Bob and Decrypt/Download

**Action:**
1. In Window 2 (Incognito window), log in as **bob** using password `DemoVaultPass2026!#`.
2. On Bob's dashboard, notice "Shared With You: 2" (or more).
3. Navigate to **Documents** (`/documents`).
4. Locate the document Alice just shared under "Documents Shared With You".
5. Click **Download / Decrypt**.
6. Switch back to Window 1 (Alice's Manage page) and refresh the page.

**Expected Result:**
- Bob's browser downloads the decrypted file with its original filename and content intact.
- On Alice's Manage page, Bob's **Decrypt Count** increments from `0` to `1`, and `Last Decrypted` updates to the current timestamp.

> **What to say:**
> *"When Bob clicks Download, the server uses Bob's unlocked private key to unwrap his copy of the document key, verifies the ciphertext hash, authenticates the AES-GCM tag, checks the plaintext hash, and streams the decrypted bytes. Every access is tracked: Alice can see in real-time that Bob has downloaded the file."*

---

### Step 6: Review the Audit Record

**Action:**
1. In Window 1 (Alice), click **Activity** in the top navigation.
2. Filter or review recent log entries.

**Expected Result:**
- View chronological events: `LOGIN`, `UPLOAD`, `SHARE`, and `DECRYPT` by Bob.
- Shows timestamp, IP address, actor, and document reference.
- Click **Export CSV** to demonstrate the export feature with formula-injection defenses.

> **What to say:**
> *"All operations are recorded in an append-only, tamper-evident audit log. Notice that Bob's decryption is visible to Alice as the document owner, giving complete visibility over data access."*

---

### Step 7: Revoke Bob's Access and Demonstrate Silent 404

**Action:**
1. In Window 1 (Alice), navigate back to the document's **Manage** page (`/documents/<id>/manage`).
2. Under "Authorized Recipients", locate **bob** and click **Revoke**. Confirm the dialog.
3. Switch to Window 2 (Bob).
4. Refresh Bob's Documents page: the document has disappeared from his list.
5. In Bob's browser, attempt to access the document URL directly or replay a download POST.

**Expected Result:**
- Alice sees a success alert: *"Access has been successfully revoked."*
- Bob receives a clean **404 Not Found** error (silent denial to prevent existence enumeration).
- An `ACCESS_DENIED` event is logged in the audit trail.

> **What to say:**
> *"Revocation immediately deletes Bob's wrapped DocumentKey record. If Bob attempts to download or query the document, VaultShare returns a silent 404 Not Found rather than 403 Forbidden. This prevents unauthorized users from inferring whether a document exists."*

---

### Step 8: Storage Ciphertext Tampering Demonstration

**Commands (in PowerShell terminal):**
```powershell
python scripts/tamper_demo.py
```

**Action:**
1. In Window 1 (Alice), click **Integrity** in the navigation bar (`/integrity`).
2. Locate the tampered document.
3. Click **Verify** next to that document.

**Expected Result:**
- `tamper_demo.py` flips the first byte of the encrypted file on disk.
- On the Integrity page, the verification result shows:
  - `file_present`: **PASS**
  - `ciphertext_hash`: **FAIL (digest mismatch)**
  - `key_unwrap`: **SKIPPED**
  - `gcm_authentication`: **SKIPPED**
  - `plaintext_hash`: **SKIPPED**
- The dashboard highlights the new **Integrity Failure** alert.

> **What to say:**
> *"If an attacker gains raw disk access and modifies an encrypted file, VaultShare's multi-stage integrity check immediately detects the corruption. Because the SHA-256 ciphertext hash mismatches, downstream operations like AES-GCM decryption are skipped to avoid side-channel attacks."*

---

### Step 9: Audit Log Tampering Demonstration

**Commands (in PowerShell terminal):**
1. Demonstrate that database triggers block direct SQL modification:
```powershell
python scripts/tamper_audit_demo.py instance/vaultshare.db 1
```

2. Run the audit log verification CLI tool:
```powershell
flask verify-audit
```

**Action in Browser:**
3. In Window 1 (Alice), go to the **Integrity** page (`/integrity`).
4. In the "Audit Log Hash Chain" card, click **Verify Hash Chain**.

**Expected Result:**
- `tamper_audit_demo.py` demonstrates:
  - Step 1: Standard SQL `UPDATE` is **BLOCKED** by SQLite trigger `audit_logs_no_update`.
  - Step 2: Simulating an attacker with direct file access who drops triggers and edits row 1 details.
- CLI output:
  ```
  TAMPERING DETECTED at entry 1: entry_hash_mismatch
  ```
  Command exits with code `1`.
- Browser Integrity page updates to show **TAMPERING DETECTED** with badge alert and exact entry details.

> **What to say:**
> *"The audit log is protected by two layers. First, SQLite BEFORE UPDATE and BEFORE DELETE triggers prevent alteration through standard queries. Second, if an attacker with physical disk access drops the triggers and modifies a row, the SHA-256 hash chain is broken. Both the CLI command `flask verify-audit` and the web UI immediately catch the discrepancy."*

---

### Step 10: Reset Before the Next Demo

**Commands:**
```powershell
flask reset-db --yes
flask seed-demo
```

**Expected Result:**
- Restores clean database state and re-establishes triggers and clean audit log chain.

---

## Troubleshooting Guide

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| **HTTP 429 Too Many Requests** | Exceeded authentication limit (5 logins/min, 5 registrations/hr). | Wait 60 seconds for the window to reset, or run `flask reset-db --yes` and `flask seed-demo`. |
| **"Your session has expired"** | The 30-minute idle key cache expired, or the Flask development server restarted. | Log out and log back in with `DemoVaultPass2026!#` to re-unlock your private key into the server cache. |
| **"Database already contains users"** | Ran `flask seed-demo` on a non-empty database. | Run `flask seed-demo --reset` or run `flask reset-db --yes` first. |
| **OperationalError: no such table** | Database not initialized or wrong working directory. | Verify PowerShell is in the `VaultShare` root directory and run `flask init-db` or `flask reset-db --yes`. |
| **Script execution policy error** | PowerShell execution policy restricts scripts. | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`. |
