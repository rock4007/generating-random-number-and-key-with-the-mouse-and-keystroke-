"""Telegram integration — individual user identities.

Each Telegram user has their own UserIdentity tied to their @username.
Group conversations use separate Channel objects per participant pair.

Usage:
    python -m sdk.integrations.telegram
"""

from sdk.identity import UserIdentity

# ── Individual Telegram identities ───────────────────────────────────────────

alice = UserIdentity("@alice_tg",   platform="telegram", display_name="Alice")
bob   = UserIdentity("@bob_tg",     platform="telegram", display_name="Bob")
carol = UserIdentity("@carol_tg",   platform="telegram", display_name="Carol")

print("=== Telegram Identities ===")
for user in (alice, bob, carol):
    print(f"  {user.display_name:6s}  {user.public_id()}  {user.identity_hash()}")
print()

# ── Alice ↔ Bob private channel ───────────────────────────────────────────────
secret_ab = alice.new_shared_secret()
ch_alice_bob = alice.channel_to(bob.public_id(),   shared_secret=secret_ab)
ch_bob_alice = bob.channel_to(alice.public_id(),   shared_secret=secret_ab)

print("=== Alice ↔ Bob private channel ===")
print(f"Channel : {ch_alice_bob.channel_id()}")

messages_ab = [
    "The project deadline is Friday.",
    "Password for the shared folder: see the encrypted file.",
    "Call me on Signal when you're ready.",
]
for msg in messages_ab:
    env = ch_alice_bob.encrypt(msg)
    out = ch_bob_alice.decrypt(env)
    print(f"  Alice → Bob : {msg}")
    print(f"  Bob decrypts: {out}")
    assert out == msg
print()

# ── Bob ↔ Carol private channel (separate key from Alice↔Bob) ────────────────
secret_bc = bob.new_shared_secret()
ch_bob_carol  = bob.channel_to(carol.public_id(),  shared_secret=secret_bc)
ch_carol_bob  = carol.channel_to(bob.public_id(),  shared_secret=secret_bc)

print("=== Bob ↔ Carol private channel ===")
print(f"Channel : {ch_bob_carol.channel_id()}")
env_bc = ch_bob_carol.encrypt("Don't tell Alice about the surprise party.")
print(f"  Bob → Carol  : {ch_carol_bob.decrypt(env_bc)}")
print()

# ── Alice cannot read Bob↔Carol messages ─────────────────────────────────────
try:
    ch_alice_carol_fake = alice.channel_to(carol.public_id(), shared_secret=secret_bc)
    ch_alice_carol_fake.decrypt(env_bc)
    print("ERROR: Alice should not be able to read Bob→Carol!")
except Exception:
    print("Security: Alice cannot read Bob↔Carol channel ✓")

# ── Platform isolation: same secret, different platform → different key ───────
alice_wa = UserIdentity("@alice_tg", platform="whatsapp", display_name="Alice WA")
secret_same = alice.new_shared_secret()
ch_tg = alice.channel_to(bob.public_id(),    shared_secret=secret_same)
ch_wa = alice_wa.channel_to(bob.public_id(), shared_secret=secret_same)

env_tg = ch_tg.encrypt("telegram only message")
try:
    ch_wa.decrypt(env_tg)
    print("ERROR: WhatsApp channel should not decrypt Telegram envelope!")
except Exception:
    print("Security: Telegram envelope cannot be replayed on WhatsApp ✓")
