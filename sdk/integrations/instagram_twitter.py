"""Instagram DM + Twitter/X DM integration — individual user identities.

Each account has its own UserIdentity tied to their @handle.
DM channels between two accounts use a key bound to both handles and the platform.

Usage:
    python -m sdk.integrations.instagram_twitter
"""

from sdk.identity import UserIdentity

# ── Individual Instagram identities ──────────────────────────────────────────

alice_ig  = UserIdentity("@alice.photo",  platform="instagram", display_name="Alice")
bob_ig    = UserIdentity("@bob.arts",     platform="instagram", display_name="Bob")

print("=== Instagram Identities ===")
print(f"  Alice : {alice_ig.public_id()}  {alice_ig.identity_hash()}")
print(f"  Bob   : {bob_ig.public_id()}    {bob_ig.identity_hash()}")
print()

# One-time key exchange (QR code / ghost code / in-person)
secret_ig = alice_ig.new_shared_secret()
ch_alice_ig = alice_ig.channel_to(bob_ig.public_id(),   shared_secret=secret_ig)
ch_bob_ig   = bob_ig.channel_to(alice_ig.public_id(),   shared_secret=secret_ig)

print("=== Instagram DM: Alice → Bob ===")
print(f"Channel : {ch_alice_ig.channel_id()}")

# Alice sends a private DM
dm_message = "I'll be at the venue at 9. Don't post this — it's private."
env_ig = ch_alice_ig.encrypt(dm_message)
# Instagram DM format: prepend emoji so it looks like a sticker to the platform
dm_body = f"🔒 {env_ig}"
print(f"Instagram sees: {dm_body[:120]}...")

# Bob decrypts by stripping the prefix
raw_env = dm_body[len("🔒 "):]
decrypted_dm = ch_bob_ig.decrypt(raw_env)
print(f"Bob reads   : {decrypted_dm}\n")
assert decrypted_dm == dm_message

# ── Individual Twitter/X identities ──────────────────────────────────────────

alice_tw = UserIdentity("@alice_x",  platform="twitter", display_name="Alice")
bob_tw   = UserIdentity("@bob_x",    platform="twitter", display_name="Bob")

print("=== Twitter/X Identities ===")
print(f"  Alice : {alice_tw.public_id()}  {alice_tw.identity_hash()}")
print(f"  Bob   : {bob_tw.public_id()}    {bob_tw.identity_hash()}")
print()

secret_tw    = alice_tw.new_shared_secret()
ch_alice_tw  = alice_tw.channel_to(bob_tw.public_id(),   shared_secret=secret_tw)
ch_bob_tw    = bob_tw.channel_to(alice_tw.public_id(),   shared_secret=secret_tw)

print("=== Twitter DM: Alice → Bob ===")
print(f"Channel : {ch_alice_tw.channel_id()}")

tw_message = "Off the record: acquisition offer is $4.2M. Keep this off the timeline."
env_tw = ch_alice_tw.encrypt(tw_message)
print(f"Twitter sees: {env_tw[:120]}...")
print(f"Bob reads   : {ch_bob_tw.decrypt(env_tw)}\n")
assert ch_bob_tw.decrypt(env_tw) == tw_message

# ── Cross-platform security check ─────────────────────────────────────────────
print("=== Security checks ===")

# 1. Instagram envelope cannot be decrypted on Twitter (different platform label)
try:
    ch_bob_tw.decrypt(env_ig)
    print("ERROR: Twitter channel decrypted Instagram envelope!")
except Exception:
    print("✓  Instagram envelope cannot be replayed on Twitter")

# 2. Different Instagram user cannot decrypt Alice→Bob DM
charlie_ig = UserIdentity("@charlie.snap", platform="instagram", display_name="Charlie")
ch_charlie  = charlie_ig.channel_to(bob_ig.public_id(), shared_secret=charlie_ig.new_shared_secret())
try:
    ch_charlie.decrypt(env_ig)
    print("ERROR: Charlie read Alice's DM to Bob!")
except Exception:
    print("✓  Charlie cannot read Alice→Bob Instagram DM")

# 3. Platform-specific keys: same user_id on Instagram ≠ Twitter
alice_ig2 = UserIdentity("@alice.photo", platform="instagram", display_name="Alice IG")
alice_tw2 = UserIdentity("@alice.photo", platform="twitter",   display_name="Alice TW")
k_ig = alice_ig2.personal_key()
k_tw = alice_tw2.personal_key()
print(f"✓  Same user_id: instagram key fp = {alice_ig2._sk.fingerprint(k_ig)}")
print(f"   Same user_id: twitter key    fp = {alice_tw2._sk.fingerprint(k_tw)}")
assert k_ig != k_tw, "Platform must produce different keys!"
print("✓  Instagram and Twitter keys are distinct for the same user_id")
