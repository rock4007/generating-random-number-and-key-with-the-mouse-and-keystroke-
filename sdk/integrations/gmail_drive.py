"""Gmail + Google Drive integration — individual user identities.

Gmail:  Each user identity ties their key to their email address.
        Messages between two people use a Channel bound to both email addresses.

Drive:  Personal documents use the personal_key() — only the owner can decrypt.
        Shared documents use a Channel key — only the two parties can decrypt.

Usage:
    python -m sdk.integrations.gmail_drive
"""

from sdk.identity import UserIdentity

# ── Individual identities tied to email addresses ────────────────────────────

alice = UserIdentity("alice@company.com", platform="gmail",  display_name="Alice")
bob   = UserIdentity("bob@company.com",   platform="gmail",  display_name="Bob")

alice_drive = UserIdentity("alice@company.com", platform="gdrive", display_name="Alice")
bob_drive   = UserIdentity("bob@company.com",   platform="gdrive", display_name="Bob")

print("=== Gmail Identities ===")
print(f"  Alice : {alice.public_id()}  {alice.identity_hash()}")
print(f"  Bob   : {bob.public_id()}    {bob.identity_hash()}")
print()

# ── Gmail: Alice → Bob encrypted email ───────────────────────────────────────
# One-time setup: Alice shares a secret with Bob (e.g. via a QR code in a meeting)
secret_email = alice.new_shared_secret()
ch_alice = alice.channel_to(bob.public_id(), shared_secret=secret_email)
ch_bob   = bob.channel_to(alice.public_id(), shared_secret=secret_email)

email_body = (
    "Hi Bob,\n\n"
    "The merger terms are: 12% equity, €240k seed, 18-month cliff.\n"
    "Please confirm by Thursday.\n\n"
    "Regards, Alice"
)

print("=== Gmail: Alice → Bob ===")
print(f"From    : {alice.display_name} <{alice.user_id}>")
print(f"To      : {bob.display_name} <{bob.user_id}>")
print(f"Subject : [SUMIT KEY ENCRYPTED]")
envelope = ch_alice.encrypt(email_body)
print(f"Body    : {envelope[:120]}...\n")

print("Bob decrypts:")
print(ch_bob.decrypt(envelope))
print()

# ── Gmail: Bob replies ────────────────────────────────────────────────────────
reply = "Confirmed. I'll have legal review it tonight. — Bob"
env_reply = ch_bob.encrypt(reply)
print(f"=== Gmail: Bob → Alice (reply) ===")
print(f"Alice reads: {ch_alice.decrypt(env_reply)}\n")

# ── Google Drive: Alice encrypts a personal document (only she can open) ─────
personal_doc = b"PERSONAL NOTES - Q3 targets, salary review, board agenda."
personal_key = alice_drive.personal_key()
from sdk.core import SumitKey
sk = SumitKey()
personal_env = sk.encrypt_file(personal_doc, "personal_notes.txt", personal_key,
                                context=f"gdrive:{alice_drive.user_id}:personal")
print("=== Drive: Alice personal document ===")
print(f"Encrypted with Alice's personal key (fp: {sk.fingerprint(personal_key)})")
print(f"Envelope size: {len(personal_env)} bytes")
recovered = sk.decrypt(personal_env, personal_key)
assert recovered == personal_doc
print("Alice opens her own document: OK ✓\n")

# ── Google Drive: Alice shares a document with Bob ────────────────────────────
secret_drive = alice_drive.new_shared_secret()
ch_alice_d   = alice_drive.channel_to(bob_drive.public_id(), shared_secret=secret_drive)
ch_bob_d     = bob_drive.channel_to(alice_drive.public_id(), shared_secret=secret_drive)

board_minutes = b"CONFIDENTIAL BOARD MINUTES\nItem 1: Budget approval E4.2M\nItem 2: Acquisition targets"
env_file = ch_alice_d.encrypt_file(board_minutes, "board_minutes_Q2_2026.pdf")

print("=== Drive: Alice → Bob shared document ===")
print(f"Channel : {ch_alice_d.channel_id()}")
print(f"Upload  : board_minutes_Q2_2026.pdf.sumitkey → Google Drive")
print(f"Size    : {len(board_minutes)} → {len(env_file)} bytes")
recovered_doc = ch_bob_d.decrypt_file(env_file)
assert recovered_doc == board_minutes
print("Bob opens the shared document: OK ✓")
print(f"Content : {recovered_doc[:60].decode()}...")
print()

# ── Security: wrong identity cannot open Bob's file ───────────────────────────
eve = UserIdentity("eve@hacker.com", platform="gdrive", display_name="Eve")
ch_eve = eve.channel_to(alice_drive.public_id(), shared_secret=eve.new_shared_secret())
try:
    ch_eve.decrypt_file(env_file)
    print("ERROR: Eve should not be able to open Alice+Bob's file!")
except Exception:
    print("Security: Eve cannot open Alice↔Bob channel file ✓")
