#!/usr/bin/env python3
"""Demonstration script: Simulates ciphertext tampering in VaultShare document storage.

DEMONSTRATION ONLY:
This script flips a single byte in an encrypted storage file (.enc) to demonstrate
how VaultShare detects ciphertext corruption or tampering during integrity verification.

Usage:
    python scripts/tamper_demo.py [storage_file_path]

Example:
    python scripts/tamper_demo.py storage/abc12345.enc
"""

from pathlib import Path
import sys


def main():
    print("=" * 60)
    print("VaultShare Encrypted File Tampering Demo (FOR TESTING ONLY)")
    print("=" * 60)

    args = sys.argv[1:]
    target_file = None

    if len(args) >= 1:
        target_file = Path(args[0])
    else:
        # Default to first .enc file in storage/
        storage_dir = Path("storage")
        if storage_dir.exists():
            enc_files = list(storage_dir.glob("*.enc"))
            if enc_files:
                target_file = enc_files[0]

    if not target_file:
        print("Error: No storage file specified and none found in 'storage/'.")
        print("Please upload a document first via the web application.")
        sys.exit(1)

    if not target_file.exists():
        print(f"Error: Target file '{target_file}' does not exist.")
        sys.exit(1)

    data = target_file.read_bytes()
    if not data:
        print(f"Error: Target file '{target_file}' is empty.")
        sys.exit(1)

    # Flip the first byte of the ciphertext
    orig_byte = data[0]
    tampered_byte = orig_byte ^ 0xFF
    tampered_data = bytes([tampered_byte]) + data[1:]

    target_file.write_bytes(tampered_data)

    print(f"Target File  : {target_file.resolve()}")
    print(f"File Size    : {len(data)} bytes")
    print(f"Tampered Byte: Offset 0 changed from 0x{orig_byte:02x} to 0x{tampered_byte:02x}\n")
    print("Success: File has been tampered with.")
    print("Now open http://127.0.0.1:5000/integrity in your browser and click 'Verify'.")
    print("You should observe:")
    print("  1. file_present    : PASS")
    print("  2. ciphertext_hash : FAIL (digest mismatch)")
    print("  3. key_unwrap      : SKIPPED")
    print("  4. gcm_auth        : SKIPPED")
    print("  5. plaintext_hash  : SKIPPED\n")


if __name__ == "__main__":
    main()
