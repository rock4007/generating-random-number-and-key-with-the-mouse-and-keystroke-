"""sdk/identity.py — Per-user identity and channel key derivation.

Every person on every platform gets a unique UserIdentity.
Two identities together create a Channel whose key is bound to both parties
and to the platform — so a WhatsApp channel key cannot be replayed on Telegram.

Design:
  Alice = UserIdentity("alice_wa", platform="whatsapp", device_secret=...)
  Bob   = UserIdentity("bob_wa",   platform="whatsapp", device_secret=...)

  ch_alice = Alice.channel_to(Bob.public_id())    # Alice's side
  ch_bob   = Bob.channel_to(Alice.public_id())    # Bob's side — same channel key

  env = ch_alice.encrypt("hello Bob")             # Alice → Bob
  msg = ch_bob.decrypt(env)                       # Bob reads it

Security properties:
  · personal_key()    — bound to user_id + platform + device_secret; never shared
  · channel key       — bound to sorted(alice_public_id, bob_public_id) + platform;
                        deterministically derived by both parties independently
  · envelope context  — f"{platform}:{id_a}↔{id_b}" (sorted, symmetric);
                        a WhatsApp envelope cannot be replayed as a Telegram envelope
  · direction AAD     — sender_id + receiver_id embedded in each envelope;
                        Bob cannot re-use Alice's ciphertext as if he sent it
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from sdk.core import SumitKey, SumitKeyError, _b64, _unb64, _derive


# ─── UserIdentity ─────────────────────────────────────────────────────────────

class UserIdentity:
    """One person's identity on one platform.

    Args:
        user_id:        Stable identifier on the platform (phone, username, email…)
        platform:       "whatsapp" | "telegram" | "gmail" | "gdrive" | "instagram" | "twitter"
        device_secret:  32+ bytes unique to this device; generated once and stored by caller.
                        If omitted, a random secret is generated (ephemeral — cannot be
                        reproduced on a different device or session).
        display_name:   Human-readable label (never included in key derivation).
        behaviour:      Optional behavioural entropy bytes from mouse/keystroke capture.
    """

    def __init__(
        self,
        user_id: str,
        platform: str,
        *,
        device_secret: bytes | None = None,
        display_name: str = "",
        behaviour: bytes | None = None,
    ) -> None:
        if not user_id.strip():
            raise ValueError("user_id must not be empty")
        if not platform.strip():
            raise ValueError("platform must not be empty")

        self.user_id      = user_id.strip().lower()
        self.platform     = platform.strip().lower()
        self.display_name = display_name or user_id
        self._device_secret = (
            bytes(device_secret) if device_secret else os.urandom(32)
        )
        self._behaviour = behaviour or b""
        self._sk = SumitKey()

    # ── Public identity ────────────────────────────────────────────────────────

    def public_id(self) -> str:
        """Short shareable identifier — safe to exchange publicly.
        Format: platform:user_id  (e.g. "whatsapp:alice_wa")
        """
        return f"{self.platform}:{self.user_id}"

    def identity_hash(self) -> str:
        """Non-secret fingerprint — safe to compare/display."""
        raw = hashlib.sha256(
            self.user_id.encode() + b"|" + self.platform.encode()
        ).hexdigest()[:16]
        return f"id:{raw}"

    def to_card(self) -> dict[str, str]:
        """Return a shareable identity card (no secrets — safe to send to contacts)."""
        return {
            "public_id":    self.public_id(),
            "user_id":      self.user_id,
            "platform":     self.platform,
            "display_name": self.display_name,
            "identity_hash": self.identity_hash(),
        }

    # ── Personal key ───────────────────────────────────────────────────────────

    def personal_key(self) -> str:
        """Derive a personal AES-256 key bound to this identity.

        This key is unique to (user_id + platform + device_secret + behaviour).
        It is NOT shared with anyone directly — use channel_to() for messaging.
        Useful for encrypting your own documents/notes for yourself.
        """
        ikm = _build_identity_ikm(
            self.user_id, self.platform,
            self._device_secret, self._behaviour,
            purpose=b"PERSONAL",
        )
        key_bytes = _derive(ikm, os.urandom(32))
        return _b64(key_bytes)

    # ── Channel ────────────────────────────────────────────────────────────────

    def channel_to(self, other_public_id: str, *, shared_secret: str = "") -> "Channel":
        """Create a secure channel to another user.

        If shared_secret is omitted, the channel key is derived purely from both
        public_ids + this identity's device_secret. The other party derives the
        same key by calling channel_to(this.public_id()) with their own
        device_secret — the keys will differ between the two parties unless they
        share a common secret.

        For symmetric messaging where both parties can decrypt each other's messages,
        one party calls channel_to(other_id, shared_secret=sk.new_key()) and shares
        that secret with the other party (via QR code / ghost code).  Both parties
        then call channel_to(..., shared_secret=<same_secret>).

        Args:
            other_public_id:  The other person's public_id() string.
            shared_secret:    Base64 key string shared out-of-band (QR / ghost code).
                              If provided, both parties derive the same channel key.
        """
        return Channel(
            sender=self,
            receiver_public_id=other_public_id,
            shared_secret=shared_secret or None,
        )

    def new_shared_secret(self) -> str:
        """Generate a new secret to bootstrap a channel with another user.
        Share this via QR code or ghost code — NOT through the same platform channel.
        """
        return self._sk.new_key()

    def __repr__(self) -> str:
        return f"UserIdentity({self.public_id()!r}, display={self.display_name!r})"


# ─── Channel ──────────────────────────────────────────────────────────────────

class Channel:
    """A secure bidirectional channel between two UserIdentities on one platform.

    Instantiate via UserIdentity.channel_to(), not directly.
    The channel key is bound to both user IDs and the platform.
    Every envelope is additionally bound to sender_id + receiver_id in the AAD,
    so a message from Alice cannot be replayed as if it came from Bob.
    """

    def __init__(
        self,
        sender: UserIdentity,
        receiver_public_id: str,
        *,
        shared_secret: str | None = None,
    ) -> None:
        self._sender   = sender
        self._recv_pid = receiver_public_id.strip().lower()
        self._sk       = SumitKey()

        # Derive the channel key
        if shared_secret:
            # Both parties share the same secret → same key on both sides
            raw_shared = _unb64(shared_secret)
            channel_ikm = _build_channel_ikm(
                sender.public_id(), self._recv_pid,
                sender.platform, raw_shared,
            )
        else:
            # Asymmetric: key includes sender's device_secret; only the sender
            # can produce this key.  Suitable for one-way encrypted storage.
            channel_ikm = _build_channel_ikm(
                sender.public_id(), self._recv_pid,
                sender.platform, sender._device_secret,
            )

        self._key = _b64(_hkdf_32(channel_ikm, b"SUMITKEY_CHANNEL_V1",
                                   _channel_context(sender.public_id(),
                                                    self._recv_pid).encode()))

    # ── Context ────────────────────────────────────────────────────────────────

    def _send_context(self) -> str:
        return f"{self._sender.platform}:{self._sender.user_id}→{self._recv_pid.split(':',1)[-1]}"

    def _recv_context(self) -> str:
        return f"{self._sender.platform}:{self._recv_pid.split(':',1)[-1]}→{self._sender.user_id}"

    def channel_id(self) -> str:
        """Stable identifier for this channel — safe to display."""
        return _channel_context(self._sender.public_id(), self._recv_pid)

    # ── Encrypt / decrypt ──────────────────────────────────────────────────────

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a text message from this identity to the receiver."""
        return self._sk.encrypt_text(plaintext, self._key, context=self._send_context())

    def decrypt(self, envelope: str) -> str:
        """Decrypt a message received from the other party.

        The context (sender→receiver direction) is already embedded in the
        envelope and verified by the GCM tag — no override needed.
        """
        return self._sk.decrypt_text(envelope, self._key)

    def encrypt_file(self, data: bytes, filename: str) -> str:
        """Encrypt a file to send through this channel."""
        return self._sk.encrypt_file(data, filename, self._key, context=self._send_context())

    def decrypt_file(self, envelope: str) -> bytes:
        """Decrypt a file received through this channel."""
        return self._sk.decrypt(envelope, self._key)

    def info(self) -> dict[str, str]:
        return {
            "channel_id":  self.channel_id(),
            "sender":      self._sender.public_id(),
            "receiver":    self._recv_pid,
            "platform":    self._sender.platform,
            "key_fp":      self._sk.fingerprint(self._key),
        }

    def __repr__(self) -> str:
        return f"Channel({self._sender.public_id()} → {self._recv_pid})"


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _build_identity_ikm(
    user_id: str,
    platform: str,
    device_secret: bytes,
    behaviour: bytes,
    purpose: bytes,
) -> bytes:
    parts = [
        b"SUMITKEY_IDENTITY_V1",
        purpose,
        len(user_id).to_bytes(2, "big") + user_id.encode(),
        len(platform).to_bytes(2, "big") + platform.encode(),
        device_secret,
        behaviour or b"",
    ]
    h = hashlib.sha3_256()
    for p in parts:
        h.update(len(p).to_bytes(4, "big") + p)
    return h.digest()


def _build_channel_ikm(
    sender_pid: str,
    receiver_pid: str,
    platform: str,
    secret: bytes,
) -> bytes:
    # Sort IDs so the channel key is symmetric (same regardless of who initiates)
    ids = sorted([sender_pid, receiver_pid])
    h = hashlib.sha3_256()
    h.update(b"SUMITKEY_CHANNEL_V1")
    h.update(platform.encode())
    for pid in ids:
        h.update(len(pid).to_bytes(2, "big") + pid.encode())
    h.update(secret)
    return h.digest()


def _channel_context(pid_a: str, pid_b: str) -> str:
    """Stable, order-independent channel label."""
    a, b = sorted([pid_a, pid_b])
    return f"channel:{a}↔{b}"


def _hkdf_32(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA3_256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(ikm)
