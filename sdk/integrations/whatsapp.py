"""WhatsApp integration — individual user identities.

Each person has their own UserIdentity tied to their WhatsApp phone number.
Messages between two people use a Channel whose key is bound to both identities
and to the "whatsapp" platform label.

Usage:
    python -m sdk.integrations.whatsapp
"""

from sdk.identity import UserIdentity

# ── Step 1: Each person creates their own identity ───────────────────────────
# In production: device_secret is stored locally (e.g. keychain / secure storage)
# and never shared with anyone.

alice = UserIdentity(
    user_id      = "+44-7700-900001",   # Alice's WhatsApp number
    platform     = "whatsapp",
    display_name = "Alice",
)

bob = UserIdentity(
    user_id      = "+44-7700-900002",   # Bob's WhatsApp number
    platform     = "whatsapp",
    display_name = "Bob",
)

print("=== Individual Identities ===")
print(f"Alice  public_id : {alice.public_id()}")
print(f"Alice  id_hash   : {alice.identity_hash()}")
print(f"Bob    public_id : {bob.public_id()}")
print(f"Bob    id_hash   : {bob.identity_hash()}")
print()

# ── Step 2: Alice generates a shared secret and shares it with Bob ───────────
# This happens ONCE — via QR code, ghost code, or in person.
# After this, all messages use the channel key.

shared_secret = alice.new_shared_secret()
print(f"Alice shares secret with Bob (out-of-band): {shared_secret[:30]}...")
print()

# ── Step 3: Each person creates a channel using the shared secret ─────────────
ch_alice = alice.channel_to(bob.public_id(),  shared_secret=shared_secret)
ch_bob   = bob.channel_to(alice.public_id(), shared_secret=shared_secret)

print("=== Channel Info ===")
print(f"Channel ID : {ch_alice.channel_id()}")
print(f"Key fp     : {ch_alice.info()['key_fp']}")
print()

# ── Step 4: Alice sends an encrypted message ─────────────────────────────────
message = "Meet at the corner at 6pm — bring the documents."
envelope = ch_alice.encrypt(message)

print("=== Alice → Bob (what WhatsApp transmits) ===")
print(envelope[:140] + "...\n")

# ── Step 5: Bob decrypts the received message ─────────────────────────────────
decrypted = ch_bob.decrypt(envelope)
print(f"Bob reads: {decrypted}\n")

# ── Step 6: Bob replies back ──────────────────────────────────────────────────
reply   = "Got it — I'll be there. Don't text me again on this number after."
env_reply = ch_bob.encrypt(reply)
print("=== Bob → Alice (reply) ===")
alice_reads = ch_alice.decrypt(env_reply)
print(f"Alice reads: {alice_reads}\n")

# ── Verify wrong identity cannot decrypt ─────────────────────────────────────
charlie = UserIdentity("+44-7700-900099", platform="whatsapp", display_name="Charlie")
ch_charlie = charlie.channel_to(bob.public_id(), shared_secret=charlie.new_shared_secret())
try:
    ch_charlie.decrypt(envelope)
    print("ERROR: Charlie should not be able to decrypt Alice's message!")
except Exception:
    print("Security check: Charlie cannot decrypt Alice→Bob message ✓")
