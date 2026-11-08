#!/usr/bin/env python3
"""Demonstration script: Simulates audit log tampering in VaultShare.

DEMONSTRATION ONLY:
This script illustrates how database triggers protect the audit log from
modification via standard SQL commands, and how dropping triggers via direct
file access is caught by the cryptographic hash-chain verification (`flask verify-audit`).

Usage:
    python scripts/tamper_audit_demo.py [db_path] [row_id]

Example:
    python scripts/tamper_audit_demo.py instance/vaultshare.db 1
"""

from pathlib import Path
import sqlite3
import sys


def main():
    print("=" * 60)
    print("VaultShare Audit Log Tampering Demonstration (FOR TESTING ONLY)")
    print("=" * 60)

    # 1. Determine database path and row ID
    default_db = Path("instance") / "vaultshare.db"

    args = sys.argv[1:]
    db_path = None
    row_id = 1

    if len(args) == 0:
        db_path = default_db
    elif len(args) == 1:
        if args[0].endswith(".db"):
            db_path = Path(args[0])
        elif args[0].isdigit():
            db_path = default_db
            row_id = int(args[0])
        else:
            db_path = Path(args[0])
    elif len(args) >= 2:
        db_path = Path(args[0])
        try:
            row_id = int(args[1])
        except ValueError:
            print(f"Error: Invalid row_id '{args[1]}'. Must be an integer.")
            sys.exit(1)

    # Validate that db_path ends with .db
    if not str(db_path).endswith(".db"):
        print(f"Error: Refused database path '{db_path}'. Path must end in .db")
        sys.exit(1)

    if not db_path.exists():
        print(f"Error: Database file '{db_path}' does not exist.")
        print("Please initialize the database and perform some actions first:")
        print("    flask --app wsgi init-db")
        print("    flask run")
        sys.exit(1)

    print(f"Target Database : {db_path.resolve()}")
    print(f"Target Row ID   : {row_id}\n")

    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    # Verify target row exists
    cursor.execute("SELECT id, action, details, prev_hash, entry_hash FROM audit_logs WHERE id = ?", (row_id,))
    row = cursor.fetchone()
    if not row:
        print(f"Error: No audit log entry found with ID = {row_id}.")
        cursor.execute("SELECT id FROM audit_logs ORDER BY id ASC")
        existing_ids = [r[0] for r in cursor.fetchall()]
        if existing_ids:
            print(f"Available audit row IDs: {existing_ids}")
        else:
            print("The audit log table is currently empty.")
        conn.close()
        sys.exit(1)

    orig_id, orig_action, orig_details, orig_prev, orig_entry = row
    print(f"Found Audit Row #{orig_id}:")
    print(f"  Action      : {orig_action}")
    print(f"  Details     : {orig_details}")
    print(f"  Entry Hash  : {orig_entry[:16]}...\n")

    # Step 1: Demonstrate that normal UPDATE is blocked by the SQLite trigger
    print("[Step 1] Attempting standard UPDATE statement through database connection...")
    try:
        cursor.execute(
            "UPDATE audit_logs SET details = ? WHERE id = ?",
            ('{"tampered": "unauthorized edit"}', row_id),
        )
        conn.commit()
        print("  WARNING: UPDATE succeeded unexpectedly! Immutability triggers may be missing.")
    except sqlite3.DatabaseError as exc:
        print(f"  [BLOCKED BY TRIGGER] As expected, SQLite trigger prevented modification:")
        print(f"  --> {exc}\n")

    # Step 2: Simulate an attacker with raw disk access by dropping triggers
    print("[Step 2] Simulating attacker with raw file access by dropping triggers and tampering row...")
    cursor.execute("DROP TRIGGER IF EXISTS audit_logs_no_update")
    cursor.execute("DROP TRIGGER IF EXISTS audit_logs_no_delete")
    conn.commit()

    # Tamper with the details field
    tampered_details = '{"tampered": true, "note": "Attacker modified record directly"}'
    cursor.execute(
        "UPDATE audit_logs SET details = ? WHERE id = ?",
        (tampered_details, row_id),
    )
    conn.commit()
    print(f"  [TAMPERED] Row #{row_id} details updated to: {tampered_details}")
    print("  Note: Triggers were dropped and NOT recreated (as an attacker would leave them).")
    # Note: We do not restore the triggers here (an attacker wouldn't).
    # Running 'flask init-db' on a fresh database will restore them.
    conn.close()

    # Step 3: Inform user how to verify tampering detection
    print("\n[Step 3] Cryptographic verification:")
    print("  Now run the following command to check hash chain integrity:")
    print("      flask --app wsgi verify-audit")
    print("  You should see: TAMPERING DETECTED at entry <id>: entry_hash_mismatch\n")


if __name__ == "__main__":
    main()
