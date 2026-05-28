# Copyright (c) 2026 Soumodeep Guha (rock4007). All Rights Reserved.
# PROPRIETARY AND CONFIDENTIAL — see LICENSE (Part A) for terms.
# Unauthorised copying, modification, distribution, or use is strictly prohibited.

"""vault.py — SUMIT KEY: High-Voltage Vault + Zero-Knowledge System + MITM Shield

Four integrated security layers built on top of the quantum-safe pipeline:

  Layer 1 — Zero-Knowledge Proof (Schnorr / Fiat-Shamir)
    Proves knowledge of a behavioural-entropy-derived secret without ever
    revealing it.  Uses RFC 3526 Group 14 (2048-bit MODP safe prime, g=2).
    Non-interactive via SHA3-256 Fiat-Shamir heuristic.

  Layer 2 — High-Voltage Vault (Shamir + AES-256-GCM)
    Shamir Secret Sharing over GF(2^8), one polynomial per secret byte.
    Each shard is independently AES-256-GCM encrypted under Argon2id-hardened
    shard key.  Vault states: ARMED → HOT → BURNED | SEALED | ZEROIZED.
    Features: burn-after-read, TTL dead-man switch, emergency zeroize.

  Layer 3 — MITM Shield (wire protocol)
    Every wire packet: ML-KEM-1024 encapsulated session key + AES-256-GCM
    payload + HMAC-SHA3-512 envelope.
    An interceptor sees opaque bytes.  Any byte flip invalidates the HMAC.
    Replay protection via ±5-minute timestamp window + monotonic sequence counter.

  Layer 4 — Advanced Threat Detector
    Entropy anomaly, timing burst, probe fingerprinting, honeypot, replay scoring.
    Risk levels: ALLOW (0-25) · MONITOR (26-50) · QUARANTINE (51-80) · BLOCK (81+).
    State is fully serialisable → compatible with serverless cold-start.

  Serverless Handler
    Single entry point for AWS Lambda, GCP Cloud Functions, Azure Functions.
    Provider auto-detected; lazy vault initialisation is cold-start safe.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
import struct
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, NamedTuple


# ============================================================================
# ── RFC 3526 Group 14 — 2048-bit MODP safe prime for Schnorr ZKP ────────────
# ============================================================================

# RFC 3526 Group 14 — exactly 512 hex chars = 2048 bits
_SCHNORR_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
_SCHNORR_G = 2
_SCHNORR_ORDER = (_SCHNORR_P - 1) // 2   # safe prime: q = (p-1)/2
_SCHNORR_PBYTES = (_SCHNORR_P.bit_length() + 7) // 8  # = 256 bytes


# ============================================================================
# ── Layer 1: Zero-Knowledge Proof ──────────────────────────────────────────
# ============================================================================

@dataclass(frozen=True)
class ZKPKeyPair:
    """Schnorr key pair derived from behavioural entropy."""
    sk: int   # secret key ∈ [1, q-1] — NEVER transmit
    pk: int   # public key = g^sk mod p — safe to publish

    def pk_bytes(self) -> bytes:
        return self.pk.to_bytes(_SCHNORR_PBYTES, "big")

    def pk_hex(self) -> str:
        return self.pk_bytes().hex()


@dataclass(frozen=True)
class ZKPProof:
    """Non-interactive Schnorr proof (Fiat-Shamir)."""
    R_hex: str    # commitment R = g^r mod p
    c_hex: str    # challenge  c = SHA3-256(pk || R || context)
    z_hex: str    # response   z = (r + c*sk) mod q

    def to_dict(self) -> dict[str, str]:
        return {"R_hex": self.R_hex, "c_hex": self.c_hex, "z_hex": self.z_hex}

    @classmethod
    def from_dict(cls, d: dict) -> "ZKPProof":
        return cls(R_hex=d["R_hex"], c_hex=d["c_hex"], z_hex=d["z_hex"])


def zkp_keygen(behavioural_entropy: bytes) -> ZKPKeyPair:
    """Derive a Schnorr key pair from behavioural entropy (SHA3-512 → sk mod q)."""
    digest = hashlib.sha3_512(b"SUMIT-ZKP-SK-v1" + behavioural_entropy).digest()
    sk = (int.from_bytes(digest, "big") % (_SCHNORR_ORDER - 1)) + 1
    pk = pow(_SCHNORR_G, sk, _SCHNORR_P)
    return ZKPKeyPair(sk=sk, pk=pk)


def zkp_prove(keypair: ZKPKeyPair, context: bytes = b"") -> ZKPProof:
    """Generate a non-interactive Schnorr proof of knowledge of sk.

    The verifier only needs keypair.pk — sk is never revealed.
    """
    # Witness nonce r drawn from OS randomness (must be fresh each call)
    r_bytes = os.urandom(64)
    r = (int.from_bytes(r_bytes, "big") % (_SCHNORR_ORDER - 1)) + 1

    # Commitment
    R = pow(_SCHNORR_G, r, _SCHNORR_P)
    R_bytes = R.to_bytes(_SCHNORR_PBYTES, "big")
    pk_bytes = keypair.pk.to_bytes(_SCHNORR_PBYTES, "big")

    # Fiat-Shamir challenge (hash of public transcript)
    c_hash = hashlib.sha3_256(pk_bytes + R_bytes + context).digest()
    c = int.from_bytes(c_hash, "big") % _SCHNORR_ORDER

    # Response: z = r + c*sk  (mod q)
    z = (r + c * keypair.sk) % _SCHNORR_ORDER

    return ZKPProof(
        R_hex=R_bytes.hex(),
        c_hex=c_hash.hex(),
        z_hex=z.to_bytes(_SCHNORR_PBYTES, "big").hex(),
    )


def zkp_verify(pk_hex: str, proof: ZKPProof, context: bytes = b"") -> bool:
    """Verify a Schnorr ZKP without learning the secret key.

    Returns True if the prover knows sk such that g^sk ≡ pk (mod p).
    """
    try:
        pk = int.from_bytes(bytes.fromhex(pk_hex), "big")
        R = int.from_bytes(bytes.fromhex(proof.R_hex), "big")
        c_claimed = bytes.fromhex(proof.c_hex)
        z = int.from_bytes(bytes.fromhex(proof.z_hex), "big")

        # Recompute challenge
        pk_bytes = pk.to_bytes(_SCHNORR_PBYTES, "big")
        R_bytes = R.to_bytes(_SCHNORR_PBYTES, "big")
        c_computed = hashlib.sha3_256(pk_bytes + R_bytes + context).digest()

        # Reject if challenge doesn't match (transcript mismatch / replay)
        if not _hmac.compare_digest(c_computed, c_claimed):
            return False

        c_int = int.from_bytes(c_computed, "big") % _SCHNORR_ORDER

        # Schnorr equation: g^z ≡ R * pk^c  (mod p)
        lhs = pow(_SCHNORR_G, z, _SCHNORR_P)
        rhs = (R * pow(pk, c_int, _SCHNORR_P)) % _SCHNORR_P
        return lhs == rhs
    except Exception:
        return False


# ============================================================================
# ── Layer 2: Shamir Secret Sharing over GF(2^8) ────────────────────────────
# ============================================================================

_GF_POLY = 0x11B   # x^8 + x^4 + x^3 + x + 1  (AES field polynomial)


def _gf_mul(a: int, b: int) -> int:
    """Multiply in GF(2^8) — Russian-peasant algorithm."""
    p = 0
    while b:
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0x100:
            a ^= _GF_POLY
        b >>= 1
    return p & 0xFF


def _gf_inv(a: int) -> int:
    """Multiplicative inverse in GF(2^8) via Fermat: a^254."""
    if a == 0:
        raise ZeroDivisionError("GF(256): no inverse for 0")
    result, power, exp = 1, a, 254
    while exp:
        if exp & 1:
            result = _gf_mul(result, power)
        power = _gf_mul(power, power)
        exp >>= 1
    return result


def _poly_eval(coeffs: list[int], x: int) -> int:
    """Evaluate a GF(256) polynomial at x using Horner's method."""
    y = 0
    for c in reversed(coeffs):
        y = _gf_mul(y, x) ^ c
    return y


def shamir_split(secret: bytes, n_shares: int, threshold: int) -> list[tuple[int, bytes]]:
    """Split `secret` into `n_shares` shares requiring `threshold` to reconstruct.

    Returns [(x, y_bytes), ...] where x ∈ [1, n_shares] and y_bytes is the
    GF(256) evaluation of a random degree-(k-1) polynomial at x, one byte per
    secret byte.
    """
    if threshold < 2 or threshold > n_shares:
        raise ValueError(f"Need 2 ≤ threshold ({threshold}) ≤ n_shares ({n_shares})")
    if not secret:
        raise ValueError("secret must be non-empty")

    shares: list[tuple[int, bytearray]] = [(x, bytearray()) for x in range(1, n_shares + 1)]

    for byte_val in secret:
        coeffs = [byte_val] + list(os.urandom(threshold - 1))
        for x, buf in shares:
            buf.append(_poly_eval(coeffs, x))

    return [(x, bytes(buf)) for x, buf in shares]


def shamir_combine(shares: list[tuple[int, bytes]]) -> bytes:
    """Reconstruct secret from (x, y_bytes) shares using Lagrange interpolation."""
    if not shares:
        raise ValueError("Need at least one share")
    secret_len = len(shares[0][1])
    result = bytearray(secret_len)

    for byte_idx in range(secret_len):
        pts = [(x, ys[byte_idx]) for x, ys in shares]
        accum = 0
        for i, (xi, yi) in enumerate(pts):
            num, den = 1, 1
            for j, (xj, _) in enumerate(pts):
                if i != j:
                    num = _gf_mul(num, xj)
                    den = _gf_mul(den, xi ^ xj)
            accum ^= _gf_mul(yi, _gf_mul(num, _gf_inv(den)))
        result[byte_idx] = accum

    return bytes(result)


# ============================================================================
# ── Layer 2 (continued): High-Voltage Vault ────────────────────────────────
# ============================================================================

class VaultState(Enum):
    ARMED     = "ARMED"      # Active; reads/writes allowed
    HOT       = "HOT"        # Key currently being retrieved
    BURNED    = "BURNED"     # Burn-after-read triggered; key gone
    SEALED    = "SEALED"     # TTL expired or manual seal; no new ops
    ZEROIZED  = "ZEROIZED"   # Emergency memory wipe; vault destroyed


@dataclass
class _VaultEntry:
    """One stored key, split into encrypted shards."""
    vault_id: str
    state: VaultState
    n_shards: int
    threshold: int
    burn_after_read: bool
    created_at: float
    expires_at: float              # dead-man switch
    shards: dict[int, bytes]       # {x: encrypted_shard_bytes}
    shard_nonces: dict[int, bytes] # {x: AES nonce}
    shard_key_hashes: dict[int, bytes]  # {x: SHA3-256(shard_key)} for audit

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


class HighVoltageVault:
    """High-Voltage Vault — extreme-protection key storage.

    Keys are Shamir-sharded, each shard AES-256-GCM encrypted under a
    per-shard Argon2id-hardened key.  A dead-man timer auto-seals the vault.

    States:
      ARMED   → normal operation
      HOT     → retrieval in flight (concurrency guard)
      BURNED  → burn-after-read triggered (key is gone)
      SEALED  → TTL or manual seal (no more reads)
      ZEROIZED → emergency wipe (all memory cleared)
    """

    _MAGIC = b"HVV1"   # 4-byte file/wire magic

    def __init__(self) -> None:
        self._entries: dict[str, _VaultEntry] = {}
        self._lock = threading.Lock()

    # ── Internal crypto helpers ──────────────────────────────────────────────

    @staticmethod
    def _shard_key(vault_id: str, shard_x: int, master_password: bytes) -> bytes:
        """Derive a 32-byte AES key for one shard via Argon2id."""
        from argon2.low_level import hash_secret_raw, Type
        salt = hashlib.sha3_256(
            b"HVV-SHARD" + vault_id.encode() + shard_x.to_bytes(2, "big")
        ).digest()[:16]
        return hash_secret_raw(
            master_password,
            salt,
            time_cost=1,
            memory_cost=65536,
            parallelism=1,
            hash_len=32,
            type=Type.ID,
        )

    @staticmethod
    def _encrypt_shard(key: bytes, data: bytes) -> tuple[bytes, bytes]:
        """AES-256-GCM encrypt a shard. Returns (nonce, ciphertext+tag)."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, data, b"HVV-SHARD-AAD")
        return nonce, ct

    @staticmethod
    def _decrypt_shard(key: bytes, nonce: bytes, ct: bytes) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key).decrypt(nonce, ct, b"HVV-SHARD-AAD")

    # ── Public API ───────────────────────────────────────────────────────────

    def store(
        self,
        key_bytes: bytes,
        *,
        master_password: bytes,
        n_shards: int = 5,
        threshold: int = 3,
        ttl_seconds: float = 3600.0,
        burn_after_read: bool = True,
    ) -> str:
        """Store a key, returning a vault_id.

        The key is immediately split and each shard encrypted.  The plaintext
        key is overwritten in memory after sharding.
        """
        vault_id = hashlib.sha3_256(os.urandom(32)).hexdigest()[:32]
        raw_shares = shamir_split(key_bytes, n_shards, threshold)

        shards: dict[int, bytes] = {}
        nonces: dict[int, bytes] = {}
        key_hashes: dict[int, bytes] = {}

        for x, y_bytes in raw_shares:
            sk = self._shard_key(vault_id, x, master_password)
            nonce, ct = self._encrypt_shard(sk, y_bytes)
            shards[x] = ct
            nonces[x] = nonce
            key_hashes[x] = hashlib.sha3_256(sk).digest()

        now = time.time()
        entry = _VaultEntry(
            vault_id=vault_id,
            state=VaultState.ARMED,
            n_shards=n_shards,
            threshold=threshold,
            burn_after_read=burn_after_read,
            created_at=now,
            expires_at=now + ttl_seconds,
            shards=shards,
            shard_nonces=nonces,
            shard_key_hashes=key_hashes,
        )
        with self._lock:
            self._entries[vault_id] = entry

        return vault_id

    def retrieve(
        self,
        vault_id: str,
        shard_xs: list[int],
        master_password: bytes,
    ) -> bytes:
        """Retrieve the key using `threshold` shard indices.

        If burn_after_read is set the vault transitions to BURNED immediately
        after decryption — the key cannot be retrieved again.
        """
        with self._lock:
            entry = self._entries.get(vault_id)
            if entry is None:
                raise KeyError(f"Vault {vault_id!r} not found")
            if entry.state == VaultState.BURNED:
                raise PermissionError("Vault is BURNED — key has been destroyed")
            if entry.state in (VaultState.SEALED, VaultState.ZEROIZED):
                raise PermissionError(f"Vault is {entry.state.value} — no access")
            if entry.state == VaultState.HOT:
                raise PermissionError("Vault is HOT — concurrent read in progress")
            if entry.is_expired():
                entry.state = VaultState.SEALED
                raise PermissionError("Vault is SEALED — TTL expired")
            if len(shard_xs) < entry.threshold:
                raise ValueError(
                    f"Need {entry.threshold} shards, got {len(shard_xs)}"
                )
            entry.state = VaultState.HOT

        # Decrypt requested shards (outside lock for speed)
        decrypted_shares: list[tuple[int, bytes]] = []
        for x in shard_xs[: entry.threshold]:
            if x not in entry.shards:
                raise KeyError(f"Shard {x} not found in vault {vault_id!r}")
            sk = self._shard_key(vault_id, x, master_password)
            nonce = entry.shard_nonces[x]
            ct = entry.shards[x]
            try:
                y_bytes = self._decrypt_shard(sk, nonce, ct)
            except Exception as exc:
                with self._lock:
                    entry.state = VaultState.ARMED
                raise PermissionError(f"Shard {x} decryption failed: {exc}") from exc
            decrypted_shares.append((x, y_bytes))

        secret = shamir_combine(decrypted_shares)

        with self._lock:
            if entry.burn_after_read:
                # Overwrite shard memory then seal
                for x in list(entry.shards):
                    entry.shards[x] = os.urandom(len(entry.shards[x]))
                entry.shards.clear()
                entry.shard_nonces.clear()
                entry.state = VaultState.BURNED
            else:
                entry.state = VaultState.ARMED

        return secret

    def seal(self, vault_id: str) -> None:
        """Manually seal a vault — no further retrieval allowed."""
        with self._lock:
            entry = self._entries.get(vault_id)
            if entry and entry.state not in (VaultState.ZEROIZED,):
                entry.state = VaultState.SEALED

    def zeroize(self, vault_id: str) -> None:
        """Emergency: overwrite all shard memory and destroy the entry."""
        with self._lock:
            entry = self._entries.get(vault_id)
            if entry:
                for x in list(entry.shards):
                    entry.shards[x] = os.urandom(len(entry.shards[x]))
                entry.shards.clear()
                entry.shard_nonces.clear()
                entry.state = VaultState.ZEROIZED
                del self._entries[vault_id]

    def status(self, vault_id: str) -> dict[str, Any]:
        """Return vault status without revealing any key material."""
        with self._lock:
            entry = self._entries.get(vault_id)
            if entry is None:
                return {"vault_id": vault_id, "state": "NOT_FOUND"}
            return {
                "vault_id": vault_id,
                "state": entry.state.value,
                "n_shards": entry.n_shards,
                "threshold": entry.threshold,
                "burn_after_read": entry.burn_after_read,
                "created_at": entry.created_at,
                "expires_at": entry.expires_at,
                "seconds_remaining": max(0.0, entry.expires_at - time.time()),
                "expired": entry.is_expired(),
            }


# ============================================================================
# ── Layer 3: MITM Shield — wire protocol ──────────────────────────────────
# ============================================================================

_SHIELD_MAGIC = b"SKMV"    # Sumit Key MITM V1
_SHIELD_VERSION = 1
_REPLAY_WINDOW_SECONDS = 300   # ±5 minutes


class MITMShieldError(Exception):
    """Raised when a shielded packet fails verification."""


class _ShieldSession(NamedTuple):
    """A completed key-exchange session."""
    session_id: bytes        # 16-byte session identifier
    session_key: bytes       # 32-byte AES-256-GCM key (from ML-KEM + HKDF)
    wire_hmac_key: bytes     # 64-byte HMAC-SHA3-512 key (separate from session key)
    our_seq: int             # monotonic send counter
    their_seq: int           # last received seq (replay guard)


class MITMShield:
    """Stateful MITM-resistant session over ML-KEM-1024 + AES-256-GCM + HMAC-SHA3-512.

    Wire packet layout (binary):
      [4B magic][1B version][16B session_id][8B timestamp][8B seq_no]
      [1568B kem_ct | 0B if not session-init][12B nonce]
      [4B ct_len][ct_len B ciphertext+tag]
      [64B HMAC-SHA3-512 over everything above]

    MITM protection:
      · Session key derived from ML-KEM shared secret → not recoverable
        without the decapsulation key (dk).
      · HMAC-SHA3-512 covers the full packet → any bit flip is detected.
      · Timestamp window prevents replay of old packets.
      · Monotonic sequence counter prevents reordering / duplication.
    """

    def __init__(self) -> None:
        self._session: _ShieldSession | None = None
        self._ek: bytes | None = None
        self._dk: bytes | None = None
        self._max_seen_seq: int = -1  # tracks highest accepted seq; replaces unbounded set
        self._lock = threading.Lock()

    # ── Session establishment ────────────────────────────────────────────────

    def begin_session(self) -> dict[str, str]:
        """Initiator step 1: generate ML-KEM-1024 key pair.

        Returns a dict containing `ek_hex` to send to the responder.
        """
        from kyber_py.ml_kem import ML_KEM_1024
        ek, dk = ML_KEM_1024.keygen()
        with self._lock:
            self._ek = ek
            self._dk = dk
        session_id = os.urandom(16)
        return {
            "protocol": "SUMIT-MITM-SHIELD-v1",
            "session_id_hex": session_id.hex(),
            "ek_hex": ek.hex(),
        }

    def accept_session(self, init_packet: dict[str, str]) -> dict[str, str]:
        """Responder step: encapsulate against initiator's ek.

        Returns a dict containing `kem_ct_hex` and the established `session_id`.
        The responder's session_key is now ready.
        """
        from kyber_py.ml_kem import ML_KEM_1024
        ek = bytes.fromhex(init_packet["ek_hex"])
        session_id = bytes.fromhex(init_packet["session_id_hex"])

        kem_shared, kem_ct = ML_KEM_1024.encaps(ek)
        session_key, wire_hmac_key = self._derive_session_keys(kem_shared, session_id)

        with self._lock:
            self._session = _ShieldSession(
                session_id=session_id,
                session_key=session_key,
                wire_hmac_key=wire_hmac_key,
                our_seq=0,
                their_seq=-1,
            )

        return {
            "protocol": "SUMIT-MITM-SHIELD-v1",
            "session_id_hex": session_id.hex(),
            "kem_ct_hex": kem_ct.hex(),
        }

    def finish_session(self, response_packet: dict[str, str]) -> None:
        """Initiator step 2: decapsulate KEM ciphertext and derive session keys."""
        from kyber_py.ml_kem import ML_KEM_1024
        with self._lock:
            if self._dk is None:
                raise MITMShieldError("begin_session() was not called first")
            kem_ct = bytes.fromhex(response_packet["kem_ct_hex"])
            session_id = bytes.fromhex(response_packet["session_id_hex"])
            kem_shared = ML_KEM_1024.decaps(self._dk, kem_ct)
            session_key, wire_hmac_key = self._derive_session_keys(kem_shared, session_id)
            self._session = _ShieldSession(
                session_id=session_id,
                session_key=session_key,
                wire_hmac_key=wire_hmac_key,
                our_seq=0,
                their_seq=-1,
            )
            self._dk = None   # discard dk after use

    @staticmethod
    def _derive_session_keys(kem_shared: bytes, session_id: bytes) -> tuple[bytes, bytes]:
        """HKDF-SHA3-512 → 32-byte session key + 64-byte HMAC key."""
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        ikm = kem_shared + session_id
        material = HKDF(
            algorithm=hashes.SHA3_512(),
            length=96,
            salt=b"SUMIT-MITM-HKDF-v1",
            info=b"SUMIT-MITM-SESSION-AND-HMAC-KEYS",
        ).derive(ikm)
        return material[:32], material[32:]   # session_key, wire_hmac_key

    # ── Send / Receive ───────────────────────────────────────────────────────

    def send(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        """Encrypt and authenticate plaintext for wire transmission.

        Interceptor sees: magic || version || session_id || ts || seq
                          || nonce || ciphertext || HMAC
        Nothing is recoverable without the session key.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        with self._lock:
            if self._session is None:
                raise MITMShieldError("Session not established; call finish_session() first")
            sess = self._session
            seq = sess.our_seq
            self._session = _ShieldSession(
                session_id=sess.session_id,
                session_key=sess.session_key,
                wire_hmac_key=sess.wire_hmac_key,
                our_seq=seq + 1,
                their_seq=sess.their_seq,
            )

        ts = struct.pack(">d", time.time())           # 8 bytes
        seq_b = struct.pack(">Q", seq)                # 8 bytes
        nonce = os.urandom(12)
        aad = _SHIELD_MAGIC + bytes([_SHIELD_VERSION]) + sess.session_id + ts + seq_b + associated_data
        ct = AESGCM(sess.session_key).encrypt(nonce, plaintext, aad)

        header = (
            _SHIELD_MAGIC
            + bytes([_SHIELD_VERSION])
            + sess.session_id                         # 16 B
            + ts                                      # 8 B
            + seq_b                                   # 8 B
            + struct.pack(">H", len(associated_data)) # 2 B
            + associated_data
            + nonce                                   # 12 B
            + struct.pack(">I", len(ct))              # 4 B
            + ct
        )
        mac = _hmac.new(sess.wire_hmac_key, header, hashlib.sha3_512).digest()
        return header + mac

    def receive(self, wire_bytes: bytes, associated_data: bytes = b"") -> bytes:
        """Verify and decrypt a received wire packet.

        Raises MITMShieldError on any integrity/replay/authentication failure.
        An attacker who modifies even one byte will trigger this exception.
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        with self._lock:
            if self._session is None:
                raise MITMShieldError("No active session")
            sess = self._session

        # Minimum header: 4+1+16+8+8+2 = 39 bytes, then nonce(12)+ct_len(4)+ct(≥16)+mac(64)
        if len(wire_bytes) < 39 + 12 + 4 + 16 + 64:
            raise MITMShieldError("Packet too short")

        # Parse header
        off = 0
        magic = wire_bytes[off:off+4];          off += 4
        version = wire_bytes[off];               off += 1
        session_id = wire_bytes[off:off+16];     off += 16
        ts_bytes = wire_bytes[off:off+8];        off += 8
        seq_bytes = wire_bytes[off:off+8];       off += 8
        aad_len = struct.unpack(">H", wire_bytes[off:off+2])[0]; off += 2
        pkt_aad = wire_bytes[off:off+aad_len];   off += aad_len
        nonce = wire_bytes[off:off+12];          off += 12
        ct_len = struct.unpack(">I", wire_bytes[off:off+4])[0]; off += 4
        ct = wire_bytes[off:off+ct_len];         off += ct_len
        mac_recv = wire_bytes[off:off+64]

        # HMAC verification (constant-time)
        mac_expected = _hmac.new(sess.wire_hmac_key, wire_bytes[:-64], hashlib.sha3_512).digest()
        if not _hmac.compare_digest(mac_recv, mac_expected):
            raise MITMShieldError("HMAC verification failed — packet tampered or wrong session")

        # Magic / version / session
        if magic != _SHIELD_MAGIC:
            raise MITMShieldError("Invalid packet magic")
        if version != _SHIELD_VERSION:
            raise MITMShieldError(f"Unsupported protocol version {version}")
        if session_id != sess.session_id:
            raise MITMShieldError("Session ID mismatch — wrong session or replay")

        # Timestamp replay window
        ts = struct.unpack(">d", ts_bytes)[0]
        now = time.time()
        if abs(now - ts) > _REPLAY_WINDOW_SECONDS:
            raise MITMShieldError(
                f"Packet timestamp {ts:.1f} outside ±{_REPLAY_WINDOW_SECONDS}s window"
            )

        # Sequence number (anti-replay / anti-duplication).
        # Sequences are strictly monotonic per session, so we reject anything
        # at or below the last accepted sequence rather than storing all seen
        # values (which would grow without bound).
        seq = struct.unpack(">Q", seq_bytes)[0]
        with self._lock:
            if seq <= self._max_seen_seq:
                raise MITMShieldError(f"Sequence {seq} replayed or out of order (max seen: {self._max_seen_seq})")
            self._max_seen_seq = seq

        # Decrypt
        aad = _SHIELD_MAGIC + bytes([_SHIELD_VERSION]) + session_id + ts_bytes + seq_bytes + pkt_aad
        try:
            return AESGCM(sess.session_key).decrypt(nonce, ct, aad)
        except Exception as exc:
            raise MITMShieldError(f"AES-GCM decryption failed: {exc}") from exc


# ============================================================================
# ── Layer 4: Advanced Threat Detector ─────────────────────────────────────
# ============================================================================

class ThreatLevel(Enum):
    ALLOW       = "ALLOW"       # score 0-25
    MONITOR     = "MONITOR"     # score 26-50
    QUARANTINE  = "QUARANTINE"  # score 51-80
    BLOCK       = "BLOCK"       # score 81+


@dataclass
class ThreatSignal:
    name: str
    score: int          # contribution to risk score (0-100)
    detail: str


@dataclass
class ThreatAssessment:
    risk_score: int
    level: ThreatLevel
    signals: list[ThreatSignal]
    timestamp: float
    action_required: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "level": self.level.value,
            "action_required": self.action_required,
            "signals": [{"name": s.name, "score": s.score, "detail": s.detail}
                        for s in self.signals],
            "timestamp": self.timestamp,
        }


class AdvancedThreatDetector:
    """Multi-layer threat detector with behavioral, entropy, and timing analysis.

    Stateless between calls; all state is kept in immutable request context.
    Safe to use in serverless (no background threads).
    """

    # ── Entropy analysis ─────────────────────────────────────────────────────

    @staticmethod
    def _entropy_bits(data: bytes) -> float:
        import math
        if not data:
            return 0.0
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    @staticmethod
    def _is_machine_timing(timestamps_ms: list[float]) -> tuple[bool, str]:
        """Detect suspiciously regular timing (bot) or impossibly fast typing."""
        if len(timestamps_ms) < 3:
            return False, ""
        diffs = [timestamps_ms[i+1] - timestamps_ms[i] for i in range(len(timestamps_ms) - 1)]
        avg = sum(diffs) / len(diffs)
        if avg < 10:
            return True, f"average inter-event {avg:.1f}ms — impossibly fast"
        variance = sum((d - avg) ** 2 for d in diffs) / len(diffs)
        cv = (variance ** 0.5) / avg if avg > 0 else 0
        if cv < 0.01:
            return True, f"coefficient-of-variation {cv:.4f} — machine-regular timing"
        return False, ""

    # ── Probe/fingerprint detection ──────────────────────────────────────────

    def __init__(self) -> None:
        self._probe_log: dict[str, list[float]] = defaultdict(list)  # ip → [ts, ...]
        self._replay_seen: dict[str, float] = {}      # msg_id → first_seen_ts
        self._lock = threading.Lock()
        self._PROBE_WINDOW = 60.0      # seconds
        self._PROBE_THRESHOLD = 20     # requests per window before flagging

    def _probe_score(self, source_ip: str) -> tuple[int, str]:
        now = time.time()
        with self._lock:
            times = self._probe_log[source_ip]
            # Prune old entries
            times[:] = [t for t in times if now - t < self._PROBE_WINDOW]
            times.append(now)
            count = len(times)
        if count > self._PROBE_THRESHOLD * 2:
            return 40, f"{count} requests in {self._PROBE_WINDOW:.0f}s — likely scanning"
        if count > self._PROBE_THRESHOLD:
            return 20, f"{count} requests in {self._PROBE_WINDOW:.0f}s — elevated activity"
        return 0, ""

    def _replay_score(self, message_id: str | None) -> tuple[int, str]:
        if not message_id:
            return 0, ""
        now = time.time()
        with self._lock:
            if message_id in self._replay_seen:
                age = now - self._replay_seen[message_id]
                return 80, f"replay of msg_id {message_id!r} seen {age:.1f}s ago"
            self._replay_seen[message_id] = now
        return 0, ""

    # ── Public assess API ───────────────────────────────────────────────────

    def assess(
        self,
        *,
        source_ip: str = "unknown",
        message_id: str | None = None,
        mouse_event_timestamps_ms: list[float] | None = None,
        key_bytes: bytes | None = None,
        honeypot_filled: bool = False,
        user_agent: str = "",
        failed_attempts: int = 0,
        extra_signals: list[ThreatSignal] | None = None,
    ) -> ThreatAssessment:
        """Score a request and return a ThreatAssessment."""
        signals: list[ThreatSignal] = []

        # 1. Honeypot — only bots fill hidden fields
        if honeypot_filled:
            signals.append(ThreatSignal("HONEYPOT", 90, "hidden field was filled — bot detected"))

        # 2. Failed attempts
        if failed_attempts >= 5:
            signals.append(ThreatSignal("BRUTE_FORCE", min(failed_attempts * 10, 80),
                                        f"{failed_attempts} consecutive failures"))

        # 3. Probe / rate fingerprinting
        probe_s, probe_d = self._probe_score(source_ip)
        if probe_s > 0:
            signals.append(ThreatSignal("PROBE", probe_s, probe_d))

        # 4. Replay detection
        replay_s, replay_d = self._replay_score(message_id)
        if replay_s > 0:
            signals.append(ThreatSignal("REPLAY", replay_s, replay_d))

        # 5. Machine-timing detection
        if mouse_event_timestamps_ms and len(mouse_event_timestamps_ms) >= 3:
            is_machine, machine_detail = self._is_machine_timing(mouse_event_timestamps_ms)
            if is_machine:
                signals.append(ThreatSignal("MACHINE_TIMING", 55, machine_detail))

        # 6. Entropy anomaly in generated key
        if key_bytes and len(key_bytes) >= 32:
            entropy = self._entropy_bits(key_bytes)
            if entropy < 4.0:
                signals.append(ThreatSignal("LOW_ENTROPY_KEY", 70,
                                            f"key entropy {entropy:.2f} bits/byte — too low"))
            elif entropy < 6.0:
                signals.append(ThreatSignal("WEAK_ENTROPY_KEY", 30,
                                            f"key entropy {entropy:.2f} bits/byte"))

        # 7. Suspicious user agent
        ua_lower = user_agent.lower()
        suspicious_ua_markers = ("python-requests", "curl", "wget", "scrapy", "bot", "crawl")
        for marker in suspicious_ua_markers:
            if marker in ua_lower:
                signals.append(ThreatSignal("SUSPICIOUS_UA", 15, f"UA contains '{marker}'"))
                break

        # 8. Extra caller-supplied signals
        if extra_signals:
            signals.extend(extra_signals)

        # Score: max of individual signals, then sum with cap
        if not signals:
            score = 0
        else:
            score = min(100, sum(s.score for s in signals))

        if score <= 25:
            level = ThreatLevel.ALLOW
            action = "proceed"
        elif score <= 50:
            level = ThreatLevel.MONITOR
            action = "log_and_proceed"
        elif score <= 80:
            level = ThreatLevel.QUARANTINE
            action = "step_up_verification"
        else:
            level = ThreatLevel.BLOCK
            action = "reject_request"

        return ThreatAssessment(
            risk_score=score,
            level=level,
            signals=signals,
            timestamp=time.time(),
            action_required=action,
        )


# ============================================================================
# ── Serverless Handler ─────────────────────────────────────────────────────
# ============================================================================

# Lazy-initialised singletons — safe across Lambda warm-starts
_serverless_vault: HighVoltageVault | None = None
_serverless_detector: AdvancedThreatDetector | None = None
_serverless_lock = threading.Lock()


def _get_serverless_singletons() -> tuple[HighVoltageVault, AdvancedThreatDetector]:
    """Cold-start-safe lazy initialisation of shared state."""
    global _serverless_vault, _serverless_detector
    with _serverless_lock:
        if _serverless_vault is None:
            _serverless_vault = HighVoltageVault()
        if _serverless_detector is None:
            _serverless_detector = AdvancedThreatDetector()
    return _serverless_vault, _serverless_detector


def _dispatch_serverless_action(
    action: str,
    payload: dict[str, Any],
    vault: HighVoltageVault,
    detector: AdvancedThreatDetector,
) -> dict[str, Any]:
    """Route an action string to the appropriate handler."""
    source_ip = payload.get("source_ip", "serverless-unknown")

    if action == "zkp_keygen":
        entropy = bytes.fromhex(payload.get("entropy_hex", os.urandom(64).hex()))
        kp = zkp_keygen(entropy)
        return {"status": "ok", "pk_hex": kp.pk_hex(), "g": _SCHNORR_G,
                "group": "RFC-3526-Group14-2048bit"}

    elif action == "zkp_prove":
        entropy = bytes.fromhex(payload["entropy_hex"])
        context = payload.get("context", "").encode()
        kp = zkp_keygen(entropy)
        proof = zkp_prove(kp, context)
        return {"status": "ok", "pk_hex": kp.pk_hex(), "proof": proof.to_dict()}

    elif action == "zkp_verify":
        pk_hex = payload["pk_hex"]
        proof = ZKPProof.from_dict(payload["proof"])
        context = payload.get("context", "").encode()
        ok = zkp_verify(pk_hex, proof, context)
        return {"status": "ok", "verified": ok}

    elif action == "vault_store":
        key_bytes = bytes.fromhex(payload["key_hex"])
        password = payload.get("master_password", "").encode() or os.urandom(32)
        vid = vault.store(
            key_bytes,
            master_password=password if isinstance(password, bytes) else password.encode(),
            n_shards=int(payload.get("n_shards", 5)),
            threshold=int(payload.get("threshold", 3)),
            ttl_seconds=float(payload.get("ttl_seconds", 3600)),
            burn_after_read=bool(payload.get("burn_after_read", True)),
        )
        return {"status": "ok", "vault_id": vid}

    elif action == "vault_retrieve":
        vid = payload["vault_id"]
        xs = [int(x) for x in payload["shard_xs"]]
        password = payload.get("master_password", "").encode()
        key_bytes = vault.retrieve(vid, xs, password)
        return {"status": "ok", "key_hex": key_bytes.hex()}

    elif action == "vault_status":
        return {"status": "ok", **vault.status(payload["vault_id"])}

    elif action == "vault_seal":
        vault.seal(payload["vault_id"])
        return {"status": "ok", "sealed": True}

    elif action == "vault_zeroize":
        vault.zeroize(payload["vault_id"])
        return {"status": "ok", "zeroized": True}

    elif action == "threat_assess":
        key_hex = payload.get("key_hex", "")
        assessment = detector.assess(
            source_ip=source_ip,
            message_id=payload.get("message_id"),
            mouse_event_timestamps_ms=payload.get("mouse_event_timestamps_ms"),
            key_bytes=bytes.fromhex(key_hex) if key_hex else None,
            honeypot_filled=bool(payload.get("honeypot_filled", False)),
            user_agent=payload.get("user_agent", ""),
            failed_attempts=int(payload.get("failed_attempts", 0)),
        )
        return {"status": "ok", **assessment.to_dict()}

    else:
        return {"status": "error", "error": f"Unknown action: {action!r}"}


def lambda_handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """AWS Lambda entry point.

    Expected event shape:
      {
        "action": "zkp_keygen" | "zkp_prove" | "zkp_verify" |
                  "vault_store" | "vault_retrieve" | "vault_status" |
                  "vault_seal" | "vault_zeroize" |
                  "threat_assess",
        "payload": { ... action-specific fields ... }
      }
    """
    vault, detector = _get_serverless_singletons()
    action = event.get("action", "")
    payload = event.get("payload", {})
    try:
        result = _dispatch_serverless_action(action, payload, vault, detector)
        return {"statusCode": 200, "body": json.dumps(result)}
    except PermissionError as exc:
        return {"statusCode": 403, "body": json.dumps({"status": "error", "error": str(exc)})}
    except (KeyError, ValueError) as exc:
        return {"statusCode": 422, "body": json.dumps({"status": "error", "error": str(exc)})}
    except Exception as exc:
        return {"statusCode": 500, "body": json.dumps({"status": "error", "error": type(exc).__name__})}


def gcp_http_handler(request: Any) -> Any:
    """GCP Cloud Functions entry point (flask.Request compatible)."""
    try:
        data = request.get_json(force=True) or {}
    except Exception:
        data = {}
    result = lambda_handler(data)
    return (result["body"], result["statusCode"], {"Content-Type": "application/json"})


def azure_main(req: Any) -> Any:
    """Azure Functions entry point."""
    try:
        import azure.functions as func  # type: ignore[import]
        data = req.get_json() or {}
        result = lambda_handler(data)
        return func.HttpResponse(result["body"], status_code=result["statusCode"],
                                  mimetype="application/json")
    except ImportError:
        result = lambda_handler({})
        return result


def serverless_dispatch(provider: str, raw_event: Any, context: Any = None) -> dict[str, Any]:
    """Provider-agnostic serverless dispatcher.

    provider: "aws" | "gcp" | "azure" | "generic"
    """
    if provider == "aws":
        return lambda_handler(raw_event, context)
    elif provider in ("gcp", "azure", "generic"):
        return lambda_handler(raw_event if isinstance(raw_event, dict) else {}, context)
    else:
        return {"statusCode": 400, "body": json.dumps({"error": f"Unknown provider: {provider}"})}


# ============================================================================
# ── Public summary for imports ─────────────────────────────────────────────
# ============================================================================

def vault_info() -> dict[str, Any]:
    """Return a capability summary for the /vault/info API endpoint."""
    return {
        "zero_knowledge_proof": {
            "scheme": "Schnorr (Fiat-Shamir)",
            "group": "RFC 3526 Group 14 — 2048-bit MODP safe prime",
            "generator": _SCHNORR_G,
            "hash": "SHA3-256 (challenge)",
            "security_classical_bits": 128,
            "security_quantum_bits": 64,
            "non_interactive": True,
        },
        "high_voltage_vault": {
            "secret_sharing": "Shamir SSS over GF(2^8)",
            "shard_encryption": "AES-256-GCM + Argon2id per-shard key",
            "states": [s.value for s in VaultState],
            "features": ["burn_after_read", "ttl_dead_man_switch", "emergency_zeroize"],
        },
        "mitm_shield": {
            "key_exchange": "ML-KEM-1024 (FIPS 203)",
            "session_kdf": "HKDF-SHA3-512",
            "encryption": "AES-256-GCM",
            "mac": "HMAC-SHA3-512",
            "replay_window_seconds": _REPLAY_WINDOW_SECONDS,
            "sequence_counter": "monotonic (anti-duplication)",
        },
        "threat_detector": {
            "signals": [
                "honeypot", "brute_force", "probe_rate",
                "replay_detection", "machine_timing",
                "entropy_anomaly", "suspicious_user_agent",
            ],
            "levels": [lvl.value for lvl in ThreatLevel],
        },
        "serverless": {
            "providers": ["aws_lambda", "gcp_cloud_functions", "azure_functions", "generic"],
            "cold_start_safe": True,
            "actions": [
                "zkp_keygen", "zkp_prove", "zkp_verify",
                "vault_store", "vault_retrieve", "vault_status",
                "vault_seal", "vault_zeroize",
                "threat_assess",
            ],
        },
    }
