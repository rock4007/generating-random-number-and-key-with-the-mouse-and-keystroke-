"""sdk/core.py — SUMIT KEY lightweight core.

Only one external dependency: cryptography (AES-256-GCM + HKDF).
Everything else is stdlib (os, hashlib, hmac, struct, base64, json).

Designed as an external security layer:
  plaintext → [SumitKey.encrypt] → opaque blob → [any channel] → [SumitKey.decrypt] → plaintext

The blob is a self-contained JSON envelope — copy-paste it into WhatsApp,
paste into a Telegram message, attach to an email, store in Drive.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import os
import struct
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# ─── Constants ────────────────────────────────────────────────────────────────

_MAGIC    = "SUMITKEY1"   # identifies our envelope in any text channel
_VERSION  = 1
_NONCE    = 12            # AES-GCM nonce size
_KEY_LEN  = 32            # AES-256 = 32 bytes


class SumitKeyError(Exception):
    """Raised for any SUMIT KEY operation failure."""


# ─── Public API ───────────────────────────────────────────────────────────────

class SumitKey:
    """Lightweight encrypt / decrypt for any channel.

    Instantiate once; share the key via a secure side-channel (QR code,
    ghost code, in-person, etc.).  Everything else travels over the normal
    social/messaging platform.

    Example — WhatsApp:
        sk  = SumitKey()
        key = sk.new_key()              # exchange this key with your contact
        msg = sk.encrypt_text("meet at noon", key)  # paste into WhatsApp
        # recipient: sk.decrypt(msg, key) → "meet at noon"

    Example — Google Drive:
        blob = sk.encrypt_file(Path("report.pdf"), key)
        # upload blob["file"] to Drive; share key separately
    """

    # ── Key generation ────────────────────────────────────────────────────────

    def new_key(
        self,
        *,
        mouse_events: list[dict] | None = None,
        keystroke_events: list[dict] | None = None,
        passphrase: str | None = None,
    ) -> str:
        """Generate a fresh AES-256 key, returned as a URL-safe base64 string.

        Priority: passphrase > behavioural events > pure OS randomness.
        All modes mix in os.urandom — even a weak input yields a secure key.
        """
        system = os.urandom(_KEY_LEN)

        if passphrase:
            # Stretch passphrase with HKDF so any passphrase gives 256 bits
            ikm = passphrase.encode("utf-8")
        elif mouse_events or keystroke_events:
            ikm = _pool_behaviour(mouse_events or [], keystroke_events or [])
        else:
            ikm = os.urandom(_KEY_LEN)

        key_bytes = _derive(ikm, system)
        return _b64(key_bytes)

    def new_key_pair(self) -> dict[str, str]:
        """Generate a sender key + shared secret for two-party channel setup.

        Returns {"sender_key", "receiver_key", "channel_id"}.
        Exchange receiver_key with your contact via any side-channel.
        """
        sender_key   = self.new_key()
        receiver_key = self.new_key()
        channel_id   = _b64(os.urandom(8))
        return {
            "sender_key":   sender_key,
            "receiver_key": receiver_key,
            "channel_id":   channel_id,
        }

    # ── Encryption ────────────────────────────────────────────────────────────

    def encrypt_text(
        self,
        plaintext: str,
        key_b64: str,
        *,
        context: str = "",
    ) -> str:
        """Encrypt a text message.  Returns a compact JSON string safe to paste
        into any messaging platform, social media DM, or email body.

        context — optional label (e.g. 'whatsapp', 'telegram', 'gmail')
                  bound into the GCM tag; must match on decrypt.
        """
        pkg = self._encrypt_bytes(
            plaintext.encode("utf-8"), key_b64,
            content_type="text", context=context,
        )
        return json.dumps(pkg, separators=(",", ":"))

    def encrypt_file(
        self,
        data: bytes,
        filename: str,
        key_b64: str,
        *,
        context: str = "",
    ) -> str:
        """Encrypt binary data (document, image, PDF, etc.).
        Returns JSON string safe to save as a .sumitkey file or attach anywhere.
        """
        pkg = self._encrypt_bytes(
            data, key_b64,
            content_type="file",
            filename=filename,
            context=context,
        )
        return json.dumps(pkg, separators=(",", ":"))

    # ── Decryption ────────────────────────────────────────────────────────────

    def decrypt(self, envelope: str, key_b64: str) -> bytes:
        """Decrypt any envelope produced by encrypt_text or encrypt_file.
        Returns raw bytes — caller decodes as text if content_type is 'text'.
        """
        try:
            pkg = json.loads(envelope)
        except json.JSONDecodeError as exc:
            raise SumitKeyError("envelope is not valid JSON") from exc

        if pkg.get("magic") != _MAGIC:
            raise SumitKeyError("not a SUMIT KEY envelope")
        if pkg.get("version") != _VERSION:
            raise SumitKeyError(f"unsupported envelope version {pkg.get('version')}")

        key  = _unb64(key_b64)
        aad  = _make_aad(pkg["content_type"], pkg.get("filename", ""),
                         pkg.get("context", ""))
        try:
            return AESGCM(key).decrypt(
                _unb64(pkg["nonce"]),
                _unb64(pkg["ciphertext"]),
                aad,
            )
        except Exception as exc:
            raise SumitKeyError("decryption failed — wrong key or tampered envelope") from exc

    def decrypt_text(self, envelope: str, key_b64: str) -> str:
        """Convenience wrapper: decrypt and decode as UTF-8 text."""
        raw = self.decrypt(envelope, key_b64)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SumitKeyError("decrypted bytes are not valid UTF-8 text") from exc

    # ── Key management helpers ────────────────────────────────────────────────

    def fingerprint(self, key_b64: str) -> str:
        """Return a short non-secret fingerprint for a key.
        Safe to compare / display; never reveals key material.
        """
        return "fp:" + hashlib.sha256(_unb64(key_b64)).hexdigest()[:16]

    def key_to_qr_payload(self, key_b64: str, label: str = "SUMIT KEY") -> str:
        """Return a string suitable for encoding into a QR code for key exchange.
        Format: SUMITKEY://v1/<key_b64>?label=<label>
        """
        return f"SUMITKEY://v1/{key_b64}?label={label}"

    @staticmethod
    def key_from_qr_payload(payload: str) -> str:
        """Extract the key from a QR payload string."""
        if not payload.startswith("SUMITKEY://v1/"):
            raise SumitKeyError("not a SUMIT KEY QR payload")
        key_part = payload[len("SUMITKEY://v1/"):]
        return key_part.split("?")[0]

    # ── Internal ──────────────────────────────────────────────────────────────

    def _encrypt_bytes(
        self,
        plaintext: bytes,
        key_b64: str,
        *,
        content_type: str,
        filename: str = "",
        context: str = "",
    ) -> dict[str, Any]:
        key   = _unb64(key_b64)
        nonce = os.urandom(_NONCE)
        aad   = _make_aad(content_type, filename, context)
        ct    = AESGCM(key).encrypt(nonce, plaintext, aad)
        return {
            "magic":        _MAGIC,
            "version":      _VERSION,
            "content_type": content_type,
            "filename":     filename,
            "context":      context,
            "nonce":        _b64(nonce),
            "ciphertext":   _b64(ct),
            "fp":           self.fingerprint(key_b64),
        }


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")

def _unb64(s: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(s + "==")
    except Exception as exc:
        raise SumitKeyError(f"invalid base64: {exc}") from exc

def _make_aad(content_type: str, filename: str, context: str) -> bytes:
    """Bind content_type + filename + context into the GCM tag."""
    return f"{content_type}|{filename}|{context}".encode("utf-8")

def _derive(ikm: bytes, system_random: bytes) -> bytes:
    """HKDF-SHA3-256: mix IKM + OS randomness → 32-byte key."""
    combined = (
        b"SUMITKEY_SDK_V1"
        + len(ikm).to_bytes(4, "big") + ikm
        + system_random
    )
    hkdf = HKDF(
        algorithm=hashes.SHA3_256(),
        length=_KEY_LEN,
        salt=b"SUMITKEY_SDK_SALT_V1",
        info=b"aes256-gcm-key",
    )
    return hkdf.derive(combined)

def _pool_behaviour(
    mouse_events: list[dict],
    keystroke_events: list[dict],
) -> bytes:
    """Compact entropy extraction — no external deps, pure stdlib."""
    from math import sqrt

    # Mouse: velocity mean + stdev + step sizes
    velocities = [float(e.get("velocity_px_per_s", 0)) for e in mouse_events]
    steps = []
    for i in range(1, len(mouse_events)):
        dx = float(mouse_events[i].get("x", 0)) - float(mouse_events[i-1].get("x", 0))
        dy = float(mouse_events[i].get("y", 0)) - float(mouse_events[i-1].get("y", 0))
        steps.append(sqrt(dx*dx + dy*dy))

    mean_v = sum(velocities) / max(1, len(velocities))
    var_v  = sum((v - mean_v)**2 for v in velocities) / max(1, len(velocities))

    # Keystrokes: dwell + flight
    dwell  = [float(e.get("dwell_time_ms",  0)) for e in keystroke_events]
    flight = [float(e.get("flight_time_ms", 0)) for e in keystroke_events]

    # Pack all features deterministically
    buf = struct.pack(
        ">6dII",
        mean_v, var_v,
        sum(steps) / max(1, len(steps)),
        sum(dwell)  / max(1, len(dwell))  if dwell  else 0.0,
        sum(flight) / max(1, len(flight)) if flight else 0.0,
        len(steps) * var_v,
        len(mouse_events),
        len(keystroke_events),
    )
    return hashlib.sha3_256(buf).digest()
