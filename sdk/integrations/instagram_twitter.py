"""Instagram DM / Twitter (X) DM integration example.

Both platforms scan private messages for ads/moderation.
SUMIT KEY turns any DM into an opaque string they cannot read.

Usage:
    python sdk/integrations/instagram_twitter.py
"""

from sdk import SumitKey

sk = SumitKey()
shared_key = sk.new_key()


def send_instagram_dm(plaintext: str, key: str) -> str:
    """Returns the DM body to paste into Instagram."""
    env = sk.encrypt_text(plaintext, key, context="instagram")
    # Instagram has a 1000-char DM limit; the envelope is ~300-400 chars
    return f"🔒 {env}"


def read_instagram_dm(dm_body: str, key: str) -> str:
    """Strip the emoji prefix and decrypt."""
    envelope = dm_body.lstrip("🔒 ")
    return sk.decrypt_text(envelope, key)


def send_twitter_dm(plaintext: str, key: str) -> str:
    """Twitter DMs have a 10,000-char limit — plenty of room."""
    return sk.encrypt_text(plaintext, key, context="twitter")


# ── Demo ─────────────────────────────────────────────────────────────────────
print("=== Instagram DM ===")
dm = send_instagram_dm("I'll be at the venue at 9. Don't post this.", shared_key)
print("DM body Instagram sees:")
print(dm[:120] + "...\n")
print("After decrypt:")
print(read_instagram_dm(dm, shared_key))
print()

print("=== Twitter / X DM ===")
tw = send_twitter_dm("The acquisition offer is $4.2M. Keep this off the timeline.", shared_key)
print("DM Twitter sees:")
print(tw[:120] + "...\n")
print("After decrypt:")
print(sk.decrypt_text(tw, shared_key))
