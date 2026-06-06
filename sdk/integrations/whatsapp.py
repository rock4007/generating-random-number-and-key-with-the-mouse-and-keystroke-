"""WhatsApp integration example.

Pattern: encrypt before sending, decrypt after receiving.
The WhatsApp message body carries only the opaque JSON envelope.
WhatsApp (Meta) never sees the plaintext.

Usage:
    python sdk/integrations/whatsapp.py
"""

from sdk import SumitKey

sk = SumitKey()

# ── Step 1: Both parties generate and exchange a shared key ──────────────────
# (do this once; share via QR code, in-person, or a different channel)
shared_key = sk.new_key()
print("Share this key with your contact (QR code or separate channel):")
print("Key     :", shared_key[:20] + "...")
print("QR data :", sk.key_to_qr_payload(shared_key, "WhatsApp"))
print()

# ── Step 2: Sender encrypts before hitting "Send" ───────────────────────────
message = "Meet at the corner at 6pm — bring the documents."
envelope = sk.encrypt_text(message, shared_key, context="whatsapp")
print("What WhatsApp sends (opaque blob):")
print(envelope[:120] + "...\n")

# ── Step 3: Recipient decrypts after receiving ───────────────────────────────
recovered = sk.decrypt_text(envelope, shared_key)
print("Decrypted message:")
print(recovered)
