"""Telegram integration example.

Telegram stores messages on its servers. With SUMIT KEY,
the Telegram server only ever sees an encrypted envelope.
End-to-end encryption on top of Telegram's own TLS layer.

Usage:
    python sdk/integrations/telegram.py
"""

from sdk import SumitKey

sk = SumitKey()

# Shared key (exchanged once via QR code or separate channel)
shared_key = sk.new_key()

# Encrypt a group of messages
messages = [
    "The project deadline is Friday.",
    "Password for the shared folder: see the encrypted file.",
    "Call me on Signal when you're ready.",
]

print("=== Sender side (before Telegram send) ===")
envelopes = []
for msg in messages:
    env = sk.encrypt_text(msg, shared_key, context="telegram")
    envelopes.append(env)
    print(f"  Original : {msg}")
    print(f"  Encrypted: {env[:80]}...\n")

print("=== Receiver side (after Telegram receive) ===")
for env in envelopes:
    print(" ", sk.decrypt_text(env, shared_key))
