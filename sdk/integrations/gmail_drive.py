"""Gmail + Google Drive integration example.

Gmail: encrypt email body before sending — Google never indexes the content.
Drive: encrypt a file before uploading — Google cannot read it.

Usage:
    python sdk/integrations/gmail_drive.py
"""

import json
from pathlib import Path
from sdk import SumitKey

sk = SumitKey()
shared_key = sk.new_key()

# ── Gmail: encrypt email body ────────────────────────────────────────────────
print("=== Gmail ===")
email_body = """
Hi Sarah,

The contract terms are: 12% equity, €240k seed, 18-month cliff.
Please confirm by Thursday.

Regards, Alex
"""
encrypted_body = sk.encrypt_text(email_body.strip(), shared_key, context="gmail")
print("Subject: [SUMIT KEY ENCRYPTED]")
print("Body sent to Gmail (Google cannot read this):")
print(encrypted_body[:140] + "...\n")

# Recipient decrypts after receiving
print("Recipient decrypts:")
print(sk.decrypt_text(encrypted_body, shared_key))
print()

# ── Google Drive: encrypt a document before upload ───────────────────────────
print("=== Google Drive ===")
document_content = b"CONFIDENTIAL BOARD MINUTES\n\nItem 1: Budget approval...\nItem 2: Acquisition targets..."
filename = "board_minutes_Q2_2026.txt"

encrypted_doc = sk.encrypt_file(document_content, filename, shared_key, context="gdrive")

# Save as .sumitkey file for upload
output_path = Path(f"/tmp/{filename}.sumitkey")
output_path.write_text(encrypted_doc, encoding="utf-8")
print(f"Encrypted '{filename}' → upload '{filename}.sumitkey' to Drive")
print(f"File size: {len(document_content)} bytes → {len(encrypted_doc)} bytes (envelope)")
print(f"Key fingerprint: {sk.fingerprint(shared_key)}")
print()

# Decrypt after downloading
raw = sk.decrypt(encrypted_doc, shared_key)
print("After download + decrypt:")
print(raw.decode("utf-8")[:80] + "...")
