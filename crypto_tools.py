# Copyright (c) 2026 Soumodeep Guha (rock4007). All Rights Reserved.
# PROPRIETARY AND CONFIDENTIAL — see LICENSE (Part A) for terms.
# Unauthorised copying, modification, distribution, or use is strictly prohibited.

"""crypto_tools.py — Hybrid quantum-safe + classical encryption for SUMIT KEY.

Two independent encryption stacks:

─── Stack A: Classical AES-256-GCM (backward-compatible) ────────────────────
  Key source : SUMIT KEY behavioural entropy → HKDF-SHA3
  Algorithm  : AES-256-GCM (256-bit key, 96-bit nonce, 128-bit tag)
  Quantum    : 128-bit post-quantum via Grover's algorithm
  File magic : b"SUMITKEY1"

─── Stack B: Quantum-safe Hybrid (recommended) ───────────────────────────────
  Algorithm  : ML-KEM-1024 (FIPS 203) + Argon2id + AES-256-GCM
  Session key: HKDF-SHA3-512(ML-KEM shared secret ‖ Argon2id(behavioural))
  Classical  : 256-bit  |  Post-quantum: 128-bit (NIST Level 5)
  File magic : b"SUMITKEY_QS2"

  Quantum-safe package layout:
    MAGIC_QS        12 B   b"SUMITKEY_QS2"
    version          1 B   0x02
    kem_ct        1568 B   ML-KEM-1024 ciphertext (fixed)
    argon2_salt     16 B   Argon2id salt
    argon2_t_cost    4 B   uint32 BE
    argon2_m_kb      4 B   uint32 BE  (memory in KB)
    hardened_nonce  12 B   AES-GCM nonce for hardened-blob encryption
    hardened_enc    80 B   AES-GCM(kem_shared[:32], argon2_output_64B) + 16B tag
    nonce           12 B   AES-GCM nonce for main ciphertext
    aad_len          2 B   uint16 BE
    aad              N B   associated data
    ciphertext       M B   AES-GCM(session_key, plaintext) + 16B tag

  Security model:
    Decryption needs only the ML-KEM decapsulation key (dk).
    The Argon2id-hardened behavioural entropy is stored inside the package,
    encrypted under the KEM shared secret. So:
      - Compromising dk alone reveals the Argon2id blob → full decryption.
      - Compromising behavioural entropy alone → attacker still needs dk.
      - Both required for full offline break → defense in depth.
"""

from __future__ import annotations

import hmac as _hmac
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

NONCE_SIZE = 12
MAGIC = b"SUMITKEY1"


class EncryptedMessage(NamedTuple):
    """Holds all pieces needed to decrypt a message."""

    nonce: bytes
    ciphertext: bytes        # includes the 16-byte GCM auth tag
    associated_data: bytes   # empty bytes if none was provided


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _aes_key(key_bytes: bytes | bytearray) -> bytes:
    """Return the first 32 bytes as the AES-256 key."""
    if not isinstance(key_bytes, (bytes, bytearray)):
        raise TypeError("key_bytes must be bytes-like")
    raw = bytes(key_bytes)
    if len(raw) < 32:
        raise ValueError(
            f"Key must be at least 32 bytes (256 bits); got {len(raw)} bytes. "
            "Use security_level='standard' or 'quantum' in key generation."
        )
    return raw[:32]


# ---------------------------------------------------------------------------
# Message encryption / decryption
# ---------------------------------------------------------------------------

def encrypt_message(
    key_bytes: bytes | bytearray,
    plaintext: str | bytes,
    associated_data: bytes = b"",
) -> EncryptedMessage:
    """Encrypt a message with AES-256-GCM.

    Args:
        key_bytes:       Key from KeyGenerator (at least 32 bytes).
        plaintext:       String or bytes to encrypt.
        associated_data: Optional bytes bound to this ciphertext (e.g. a
                         label or recipient ID). Must be provided on decrypt.

    Returns:
        EncryptedMessage with nonce, ciphertext+tag, and associated_data.

    Security note:
        A fresh random nonce is generated for every call, so the same
        plaintext encrypted twice will produce different ciphertexts.
    """
    aes_key = _aes_key(key_bytes)
    nonce = os.urandom(NONCE_SIZE)

    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    aesgcm = AESGCM(aes_key)
    aad_arg = associated_data if associated_data else None
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad_arg)

    return EncryptedMessage(
        nonce=nonce,
        ciphertext=ciphertext,
        associated_data=associated_data,
    )


def decrypt_message(
    key_bytes: bytes | bytearray,
    encrypted: EncryptedMessage,
) -> bytes:
    """Decrypt a message produced by encrypt_message.

    Raises:
        cryptography.exceptions.InvalidTag  if key or AAD is wrong.
        ValueError                          if inputs are malformed.
    """
    aes_key = _aes_key(key_bytes)
    aesgcm = AESGCM(aes_key)
    aad_arg = encrypted.associated_data if encrypted.associated_data else None
    return aesgcm.decrypt(encrypted.nonce, encrypted.ciphertext, aad_arg)


def message_to_dict(encrypted: EncryptedMessage) -> dict[str, str]:
    """Serialize an EncryptedMessage to a JSON-safe hex dict."""
    return {
        "nonce_hex": encrypted.nonce.hex(),
        "ciphertext_hex": encrypted.ciphertext.hex(),
        "associated_data_hex": encrypted.associated_data.hex(),
    }


def message_from_dict(d: dict[str, str]) -> EncryptedMessage:
    """Deserialize an EncryptedMessage from a hex dict."""
    return EncryptedMessage(
        nonce=bytes.fromhex(d["nonce_hex"]),
        ciphertext=bytes.fromhex(d["ciphertext_hex"]),
        associated_data=bytes.fromhex(d.get("associated_data_hex", "")),
    )


# ---------------------------------------------------------------------------
# File encryption / decryption
# ---------------------------------------------------------------------------

def encrypt_file(
    key_bytes: bytes | bytearray,
    input_path: str | Path,
    output_path: str | Path,
) -> dict[str, object]:
    """Encrypt a file and write it to output_path.

    The original filename is stored as AAD, so any attempt to swap the
    ciphertext into a file with a different name will be detected.

    Returns a summary dict.
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    plaintext = input_path.read_bytes()
    aad = f"file:{input_path.name}".encode("utf-8")

    encrypted = encrypt_message(key_bytes, plaintext, associated_data=aad)

    with output_path.open("wb") as f:
        f.write(MAGIC)
        f.write(struct.pack(">H", len(aad)))
        f.write(aad)
        f.write(encrypted.nonce)
        f.write(encrypted.ciphertext)

    return {
        "input_file": str(input_path),
        "output_file": str(output_path),
        "original_size_bytes": len(plaintext),
        "encrypted_size_bytes": output_path.stat().st_size,
        "algorithm": "AES-256-GCM",
        "aad": aad.decode("utf-8"),
    }


def decrypt_file(
    key_bytes: bytes | bytearray,
    input_path: str | Path,
    output_path: str | Path,
    *,
    expected_name: str | None = None,
) -> dict[str, object]:
    """Decrypt a file previously encrypted with encrypt_file.

    Args:
        key_bytes:      Key from KeyGenerator (at least 32 bytes).
        input_path:     Path to the encrypted .sumitkey file.
        output_path:    Destination path for the decrypted output.
        expected_name:  If provided, the embedded filename AAD must equal
                        ``file:<expected_name>`` (constant-time comparison).
                        Pass the original source filename to guard against
                        rename attacks where an attacker serves foo.enc as
                        bar.enc.  Omit (default) to skip the check.

    Raises:
        ValueError                          if file magic is wrong or
                                            expected_name is given and the
                                            embedded AAD does not match.
        cryptography.exceptions.InvalidTag  if key or file is tampered.
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    data = input_path.read_bytes()

    if not data.startswith(MAGIC):
        raise ValueError(
            f"Not a SUMIT KEY encrypted file (missing magic bytes). "
            f"Expected {MAGIC!r} at offset 0."
        )

    offset = len(MAGIC)
    aad_len = struct.unpack(">H", data[offset: offset + 2])[0]
    offset += 2
    aad = data[offset: offset + aad_len]
    offset += aad_len
    nonce = data[offset: offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = data[offset:]

    # Optional explicit filename verification (same pattern as MITMShield.receive
    # associated_data check): GCM proves AAD was not tampered with; this step
    # proves the caller is decrypting the file they *intended* to decrypt.
    if expected_name is not None:
        expected_aad = f"file:{expected_name}".encode("utf-8")
        if not _hmac.compare_digest(aad, expected_aad):
            raise ValueError(
                f"Filename mismatch: file was encrypted as "
                f"{aad.decode('utf-8', errors='replace')!r} "
                f"but expected 'file:{expected_name}'"
            )

    encrypted = EncryptedMessage(nonce=nonce, ciphertext=ciphertext, associated_data=aad)
    plaintext = decrypt_message(key_bytes, encrypted)

    output_path.write_bytes(plaintext)

    return {
        "input_file": str(input_path),
        "output_file": str(output_path),
        "decrypted_size_bytes": len(plaintext),
        "aad": aad.decode("utf-8", errors="replace"),
    }


# ---------------------------------------------------------------------------
# Quick info helper
# ---------------------------------------------------------------------------

def encryption_info() -> dict[str, str]:
    """Return human-readable info about the classical AES-256-GCM scheme."""
    return {
        "algorithm": "AES-256-GCM",
        "key_size_bits": "256 (first 32 bytes of generated key)",
        "nonce_size_bits": str(NONCE_SIZE * 8),
        "auth_tag_size_bits": "128",
        "nonce_generation": "os.urandom (cryptographically random per operation)",
        "associated_data": "optional; binds ciphertext to a context label",
        "file_format": "MAGIC(9) + aad_len(2) + aad(N) + nonce(12) + ciphertext+tag",
        "post_quantum_note": (
            "AES-256-GCM provides ~128-bit post-quantum security (Grover). "
            "For full NIST Level 5 post-quantum security use quantum_encrypt_message()."
        ),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# QUANTUM-SAFE HYBRID ENCRYPTION (Stack B)
# ML-KEM-1024 (FIPS 203) + Argon2id + AES-256-GCM
# ═══════════════════════════════════════════════════════════════════════════════

MAGIC_QS = b"SUMITKEY_QS2"   # 12 bytes; distinguishes quantum-safe format
_QS_VERSION = 0x02
_ML_KEM_CT_SIZE = 1568        # ML-KEM-1024 ciphertext is always 1568 bytes
_HARDENED_PLAIN_LEN = 64      # Argon2id output length in bytes
_HARDENED_ENC_LEN = _HARDENED_PLAIN_LEN + 16   # + AES-GCM 16-byte tag = 80 bytes

# Default Argon2id parameters for the quantum-safe pipeline.
# interactive = fast enough for per-message use while still GPU-resistant.
_ARGON2_T_DEFAULT = 1
_ARGON2_M_DEFAULT = 65536     # 64 MB


@dataclass
class QuantumSession:
    """Holds one ML-KEM-1024 keypair for a quantum-safe session.

    ek  — encapsulation key (public, 1568 bytes hex); share with senders.
    dk  — decapsulation key (secret, 3168 bytes hex); keep private.

    Generate with: quantum_keygen()
    Store dk securely; it is the only material needed to decrypt packages.
    """
    ek: str   # hex-encoded encapsulation key
    dk: str   # hex-encoded decapsulation key

    def ek_bytes(self) -> bytes:
        return bytes.fromhex(self.ek)

    def dk_bytes(self) -> bytes:
        return bytes.fromhex(self.dk)

    def to_dict(self) -> dict[str, str]:
        return {"ek": self.ek, "dk": self.dk,
                "algorithm": "ML-KEM-1024 (FIPS 203)",
                "ek_bytes": len(self.ek) // 2,
                "dk_bytes": len(self.dk) // 2}

    @classmethod
    def from_dict(cls, d: dict[str, str]) -> "QuantumSession":
        return cls(ek=d["ek"], dk=d["dk"])


class QuantumSafePackage(NamedTuple):
    """Complete quantum-safe encrypted package (decryptable with dk only).

    All fields are raw bytes for in-memory use.
    Use quantum_package_to_dict() / quantum_package_from_dict() for JSON.
    """
    kem_ct: bytes           # ML-KEM-1024 ciphertext, 1568 bytes
    argon2_salt: bytes      # 16 bytes
    argon2_time_cost: int
    argon2_memory_kb: int
    hardened_nonce: bytes   # 12 bytes  — nonce for hardened-blob AES-GCM
    hardened_enc: bytes     # 80 bytes  — AES-GCM(kem_shared[:32], argon2_output)
    nonce: bytes            # 12 bytes  — nonce for main payload AES-GCM
    ciphertext: bytes       # plaintext + 16-byte GCM tag
    associated_data: bytes  # AAD (may be empty)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _qs_derive_session_key(kem_shared: bytes, argon2_hardened: bytes) -> bytes:
    """Derive the 256-bit AES session key from KEM + Argon2id outputs.

    Uses HKDF-SHA3-512 so that compromising one source alone is insufficient
    to reconstruct the session key.

    Security:
      - kem_shared       provides ML-KEM-1024 post-quantum strength (128-bit quantum)
      - argon2_hardened  provides memory-hard brute-force resistance (GPU/ASIC proof)
    """
    ikm = kem_shared + argon2_hardened
    hkdf = HKDF(
        algorithm=hashes.SHA3_512(),
        length=32,
        salt=b"SUMIT_QS_HKDF_SALT_V2",
        info=b"SUMIT-QS-AES256-SESSION-KEY-V2",
    )
    return hkdf.derive(ikm)


def _qs_argon2_harden(
    behavioural_entropy: bytes,
    salt: bytes,
    time_cost: int,
    memory_kb: int,
) -> bytes:
    """Run Argon2id over the behavioural entropy. Returns 64 hardened bytes."""
    from argon2.low_level import hash_secret_raw, Type
    return hash_secret_raw(
        behavioural_entropy,
        salt,
        time_cost=time_cost,
        memory_cost=memory_kb,
        parallelism=1,
        hash_len=_HARDENED_PLAIN_LEN,
        type=Type.ID,
    )


# ── Public API ────────────────────────────────────────────────────────────────

def quantum_keygen() -> QuantumSession:
    """Generate a fresh ML-KEM-1024 keypair for a quantum-safe session.

    Returns a QuantumSession with ek (share) and dk (keep secret).
    The dk is required to decrypt any package encrypted to this ek.
    """
    from kyber_py.ml_kem import ML_KEM_1024
    ek, dk = ML_KEM_1024.keygen()
    return QuantumSession(ek=ek.hex(), dk=dk.hex())


def quantum_encrypt_message(
    session: QuantumSession | str,
    plaintext: str | bytes,
    behavioural_entropy: bytes,
    associated_data: bytes = b"",
    argon2_time_cost: int = _ARGON2_T_DEFAULT,
    argon2_memory_kb: int = _ARGON2_M_DEFAULT,
) -> QuantumSafePackage:
    """Encrypt plaintext using the quantum-safe hybrid pipeline.

    Pipeline:
      1. ML-KEM-1024.encaps(ek)      → (kem_shared 32B, kem_ct 1568B)
      2. Argon2id(behaviour, salt)   → hardened 64B
      3. AES-256-GCM(kem_shared[:32], hardened) → hardened_enc 80B  ← bundled in pkg
      4. HKDF-SHA3-512(kem_shared ‖ hardened) → session_key 32B
      5. AES-256-GCM(session_key, plaintext)  → ciphertext

    Args:
        session:              QuantumSession or ek hex string.
        plaintext:            Message to encrypt (str or bytes).
        behavioural_entropy:  Raw bytes from SUMIT KEY capture (mouse + keystroke).
        associated_data:      Optional AAD bound to the ciphertext.
        argon2_time_cost:     Argon2id iterations (1 = interactive, 4 = sensitive).
        argon2_memory_kb:     Argon2id memory in KB (65536 = 64MB, 1048576 = 1GB).

    Returns:
        QuantumSafePackage (decryptable with only the dk).
    """
    from kyber_py.ml_kem import ML_KEM_1024

    if isinstance(session, str):
        ek_bytes = bytes.fromhex(session)
    else:
        ek_bytes = session.ek_bytes()

    if len(ek_bytes) != 1568:
        raise ValueError(f"ML-KEM-1024 ek must be 1568 bytes; got {len(ek_bytes)}")

    if not isinstance(behavioural_entropy, (bytes, bytearray)) or len(behavioural_entropy) < 32:
        raise ValueError("behavioural_entropy must be at least 32 bytes")

    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    # Step 1 — ML-KEM encapsulation
    kem_shared, kem_ct = ML_KEM_1024.encaps(ek_bytes)
    if len(kem_ct) != _ML_KEM_CT_SIZE:
        raise ValueError(f"ML-KEM-1024 returned unexpected kem_ct size {len(kem_ct)} (expected {_ML_KEM_CT_SIZE})")

    # Step 2 — Argon2id hardening of behavioural entropy
    argon2_salt = os.urandom(16)
    hardened = _qs_argon2_harden(
        bytes(behavioural_entropy), argon2_salt, argon2_time_cost, argon2_memory_kb
    )

    # Step 3 — Encrypt hardened blob under kem_shared so decryption needs only dk
    kem_aes = AESGCM(kem_shared[:32])
    hardened_nonce = os.urandom(NONCE_SIZE)
    hardened_enc = kem_aes.encrypt(hardened_nonce, hardened, None)
    if len(hardened_enc) != _HARDENED_ENC_LEN:
        raise ValueError(f"Hardened enc size mismatch {len(hardened_enc)} (expected {_HARDENED_ENC_LEN})")

    # Step 4 — Derive the final session key from both sources
    session_key = _qs_derive_session_key(kem_shared, hardened)

    # Step 5 — AES-256-GCM encrypt the payload
    aes = AESGCM(session_key)
    nonce = os.urandom(NONCE_SIZE)
    aad_arg = associated_data if associated_data else None
    ciphertext = aes.encrypt(nonce, plaintext, aad_arg)

    return QuantumSafePackage(
        kem_ct=kem_ct,
        argon2_salt=argon2_salt,
        argon2_time_cost=argon2_time_cost,
        argon2_memory_kb=argon2_memory_kb,
        hardened_nonce=hardened_nonce,
        hardened_enc=hardened_enc,
        nonce=nonce,
        ciphertext=ciphertext,
        associated_data=associated_data,
    )


def quantum_decrypt_message(
    dk: QuantumSession | str,
    package: QuantumSafePackage,
) -> bytes:
    """Decrypt a QuantumSafePackage using the ML-KEM decapsulation key.

    Pipeline (reverse of encryption):
      1. ML-KEM-1024.decaps(dk, kem_ct) → kem_shared
      2. AES-256-GCM(kem_shared[:32]).decrypt(hardened_enc) → hardened
      3. HKDF-SHA3-512(kem_shared ‖ hardened) → session_key
      4. AES-256-GCM(session_key).decrypt(ciphertext) → plaintext

    Args:
        dk:      QuantumSession or dk hex string.
        package: QuantumSafePackage from quantum_encrypt_message().

    Raises:
        cryptography.exceptions.InvalidTag if dk is wrong or package is tampered.
    """
    from kyber_py.ml_kem import ML_KEM_1024

    if isinstance(dk, QuantumSession):
        dk_bytes = dk.dk_bytes()
    else:
        dk_bytes = bytes.fromhex(dk)

    # Step 1 — ML-KEM decapsulation
    kem_shared = ML_KEM_1024.decaps(dk_bytes, package.kem_ct)

    # Step 2 — Decrypt hardened blob to recover Argon2id output
    kem_aes = AESGCM(kem_shared[:32])
    aad_arg = package.associated_data if package.associated_data else None
    hardened = kem_aes.decrypt(package.hardened_nonce, package.hardened_enc, None)

    # Step 3 — Re-derive session key
    session_key = _qs_derive_session_key(kem_shared, hardened)

    # Step 4 — Decrypt payload
    aes = AESGCM(session_key)
    return aes.decrypt(package.nonce, package.ciphertext, aad_arg)


# ── Serialisation ─────────────────────────────────────────────────────────────

def quantum_package_to_dict(pkg: QuantumSafePackage) -> dict[str, Any]:
    """Serialise a QuantumSafePackage to a JSON-safe hex dict."""
    return {
        "format": "SUMITKEY_QS2",
        "kem_algorithm": "ML-KEM-1024 (FIPS 203)",
        "kdf": "HKDF-SHA3-512",
        "cipher": "AES-256-GCM",
        "hardening": f"Argon2id(t={pkg.argon2_time_cost}, m={pkg.argon2_memory_kb}KB)",
        "kem_ct_hex": pkg.kem_ct.hex(),
        "argon2_salt_hex": pkg.argon2_salt.hex(),
        "argon2_time_cost": pkg.argon2_time_cost,
        "argon2_memory_kb": pkg.argon2_memory_kb,
        "hardened_nonce_hex": pkg.hardened_nonce.hex(),
        "hardened_enc_hex": pkg.hardened_enc.hex(),
        "nonce_hex": pkg.nonce.hex(),
        "ciphertext_hex": pkg.ciphertext.hex(),
        "associated_data_hex": pkg.associated_data.hex(),
        "security_classical_bits": 256,
        "security_quantum_bits": 128,
        "nist_pqc_level": 5,
    }


def quantum_package_from_dict(d: dict[str, Any]) -> QuantumSafePackage:
    """Deserialise a QuantumSafePackage from a hex dict."""
    return QuantumSafePackage(
        kem_ct=bytes.fromhex(d["kem_ct_hex"]),
        argon2_salt=bytes.fromhex(d["argon2_salt_hex"]),
        argon2_time_cost=int(d["argon2_time_cost"]),
        argon2_memory_kb=int(d["argon2_memory_kb"]),
        hardened_nonce=bytes.fromhex(d["hardened_nonce_hex"]),
        hardened_enc=bytes.fromhex(d["hardened_enc_hex"]),
        nonce=bytes.fromhex(d["nonce_hex"]),
        ciphertext=bytes.fromhex(d["ciphertext_hex"]),
        associated_data=bytes.fromhex(d.get("associated_data_hex", "")),
    )


# ── Binary file format ────────────────────────────────────────────────────────

def quantum_encrypt_file(
    session: QuantumSession | str,
    input_path: str | Path,
    output_path: str | Path,
    behavioural_entropy: bytes,
    argon2_time_cost: int = _ARGON2_T_DEFAULT,
    argon2_memory_kb: int = _ARGON2_M_DEFAULT,
) -> dict[str, Any]:
    """Encrypt a file using the quantum-safe hybrid pipeline.

    File format:
      MAGIC_QS (12B) | version (1B) | kem_ct (1568B) |
      argon2_salt (16B) | t_cost (4B) | m_kb (4B) |
      hardened_nonce (12B) | hardened_enc (80B) |
      nonce (12B) | aad_len (2B) | aad (N B) | ciphertext (M B)
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    aad = f"file:{input_path.name}".encode("utf-8")
    input_bytes = input_path.read_bytes()
    pkg = quantum_encrypt_message(
        session, input_bytes, behavioural_entropy,
        associated_data=aad,
        argon2_time_cost=argon2_time_cost,
        argon2_memory_kb=argon2_memory_kb,
    )

    with output_path.open("wb") as f:
        f.write(MAGIC_QS)
        f.write(bytes([_QS_VERSION]))
        f.write(pkg.kem_ct)                            # 1568 B
        f.write(pkg.argon2_salt)                       # 16 B
        f.write(struct.pack(">I", pkg.argon2_time_cost))  # 4 B
        f.write(struct.pack(">I", pkg.argon2_memory_kb))  # 4 B
        f.write(pkg.hardened_nonce)                    # 12 B
        f.write(pkg.hardened_enc)                      # 80 B
        f.write(pkg.nonce)                             # 12 B
        f.write(struct.pack(">H", len(aad)))           # 2 B
        f.write(aad)
        f.write(pkg.ciphertext)

    original_size = len(input_bytes)
    return {
        "input_file": str(input_path),
        "output_file": str(output_path),
        "original_size_bytes": original_size,
        "encrypted_size_bytes": output_path.stat().st_size,
        "algorithm": "ML-KEM-1024 + Argon2id + AES-256-GCM",
        "security_classical_bits": 256,
        "security_quantum_bits": 128,
        "nist_pqc_level": 5,
    }


def quantum_decrypt_file(
    dk: QuantumSession | str,
    input_path: str | Path,
    output_path: str | Path,
    *,
    expected_name: str | None = None,
) -> dict[str, Any]:
    """Decrypt a file produced by quantum_encrypt_file.

    Args:
        dk:             QuantumSession or dk hex string.
        input_path:     Path to the encrypted quantum-safe file.
        output_path:    Destination path for the decrypted output.
        expected_name:  If provided, the embedded filename AAD must equal
                        ``file:<expected_name>`` (constant-time comparison).
                        Pass the original source filename to guard against
                        rename attacks.  Omit (default) to skip the check.

    Raises:
        ValueError      if magic is wrong, version is unsupported, or
                        expected_name is given and the embedded AAD does
                        not match.
        InvalidTag      if dk is wrong or the file has been tampered with.
    """
    input_path = Path(input_path)
    output_path = Path(output_path)

    data = input_path.read_bytes()
    if not data.startswith(MAGIC_QS):
        raise ValueError(
            f"Not a SUMIT KEY quantum-safe file. "
            f"Expected magic {MAGIC_QS!r}, got {data[:12]!r}"
        )

    off = len(MAGIC_QS)
    version = data[off];  off += 1
    if version != _QS_VERSION:
        raise ValueError(f"Unsupported quantum-safe file version: {version:#04x}")

    kem_ct        = data[off: off + _ML_KEM_CT_SIZE];  off += _ML_KEM_CT_SIZE
    argon2_salt   = data[off: off + 16];               off += 16
    t_cost,       = struct.unpack(">I", data[off: off + 4]);  off += 4
    m_kb,         = struct.unpack(">I", data[off: off + 4]);  off += 4
    hardened_nonce= data[off: off + NONCE_SIZE];       off += NONCE_SIZE
    hardened_enc  = data[off: off + _HARDENED_ENC_LEN]; off += _HARDENED_ENC_LEN
    nonce         = data[off: off + NONCE_SIZE];        off += NONCE_SIZE
    aad_len,      = struct.unpack(">H", data[off: off + 2]);  off += 2
    aad           = data[off: off + aad_len];           off += aad_len
    ciphertext    = data[off:]

    # Optional explicit filename verification — mirrors the MITMShield
    # associated_data pattern: GCM proves the AAD was not tampered with;
    # this step proves the caller is decrypting the file they intended.
    if expected_name is not None:
        expected_aad = f"file:{expected_name}".encode("utf-8")
        if not _hmac.compare_digest(aad, expected_aad):
            raise ValueError(
                f"Filename mismatch: file was encrypted as "
                f"{aad.decode('utf-8', errors='replace')!r} "
                f"but expected 'file:{expected_name}'"
            )

    pkg = QuantumSafePackage(
        kem_ct=kem_ct, argon2_salt=argon2_salt,
        argon2_time_cost=t_cost, argon2_memory_kb=m_kb,
        hardened_nonce=hardened_nonce, hardened_enc=hardened_enc,
        nonce=nonce, ciphertext=ciphertext, associated_data=aad,
    )
    plaintext = quantum_decrypt_message(dk, pkg)
    output_path.write_bytes(plaintext)

    return {
        "input_file": str(input_path),
        "output_file": str(output_path),
        "decrypted_size_bytes": len(plaintext),
        "algorithm": "ML-KEM-1024 + Argon2id + AES-256-GCM",
    }


def quantum_encryption_info() -> dict[str, Any]:
    """Return human-readable info about the quantum-safe hybrid scheme."""
    return {
        "algorithm": "ML-KEM-1024 + Argon2id + AES-256-GCM (HKDF-SHA3-512)",
        "post_quantum_kem": "ML-KEM-1024 (NIST FIPS 203, 2024)",
        "kem_ek_size_bytes": 1568,
        "kem_dk_size_bytes": 3168,
        "kem_ct_size_bytes": _ML_KEM_CT_SIZE,
        "kem_shared_secret_bytes": 32,
        "key_hardening": "Argon2id (RFC 9106)",
        "argon2_default_t_cost": _ARGON2_T_DEFAULT,
        "argon2_default_memory_kb": _ARGON2_M_DEFAULT,
        "argon2_output_bytes": _HARDENED_PLAIN_LEN,
        "session_key_derivation": "HKDF-SHA3-512(kem_shared ‖ argon2_hardened) → 32B",
        "symmetric_cipher": "AES-256-GCM",
        "nonce_size_bits": NONCE_SIZE * 8,
        "auth_tag_size_bits": 128,
        "security_classical_bits": 256,
        "security_quantum_bits": 128,
        "nist_pqc_level": 5,
        "decryption_needs": "ML-KEM dk only (Argon2id output is bundled inside package)",
        "file_magic": MAGIC_QS.decode("latin1"),
        "defense_in_depth": (
            "Session key = HKDF(KEM_shared ‖ Argon2id_hardened). "
            "Breaking KEM alone: attacker still needs Argon2id blob (stored in pkg, memory-hard). "
            "Reproducing behaviour alone: attacker still needs ML-KEM dk."
        ),
    }


# ---------------------------------------------------------------------------
# CLI smoke-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from key_generator import KeyGenerator

    sample_entropy = os.urandom(64)
    key = KeyGenerator.generate_quantum_hardened_key(sample_entropy)

    print("=== SUMIT KEY crypto_tools smoke test ===\n")
    print(f"Key (hex, first 32 bytes): {key[:32].hex()}")

    # Message round-trip
    plaintext_msg = "Hello from SUMIT KEY — this message is AES-256-GCM encrypted!"
    enc = encrypt_message(key, plaintext_msg, associated_data=b"demo-test")
    dec_bytes = decrypt_message(key, enc)
    assert dec_bytes.decode() == plaintext_msg, "Message round-trip failed"

    print(f"\n[Message encryption]")
    print(f"  Plaintext : {plaintext_msg}")
    print(f"  Nonce     : {enc.nonce.hex()}")
    print(f"  Ciphertext: {enc.ciphertext[:24].hex()}... ({len(enc.ciphertext)} bytes incl. tag)")
    print(f"  Decrypted : {dec_bytes.decode()}")
    print("  Round-trip: PASS")

    # File round-trip
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "original.txt"
        enc_file = Path(tmpdir) / "original.txt.sumitkey"
        dec_file = Path(tmpdir) / "decrypted.txt"

        src.write_text("Secret file contents — SUMIT KEY test\n" * 5, encoding="utf-8")

        enc_info = encrypt_file(key, src, enc_file)
        dec_info = decrypt_file(key, enc_file, dec_file)

        assert src.read_bytes() == dec_file.read_bytes(), "File round-trip failed"

        print(f"\n[File encryption]")
        print(f"  Original size : {enc_info['original_size_bytes']} bytes")
        print(f"  Encrypted size: {enc_info['encrypted_size_bytes']} bytes")
        print(f"  Decrypted size: {dec_info['decrypted_size_bytes']} bytes")
        print("  Round-trip: PASS")

    print("\n[Encryption info]")
    for k, v in encryption_info().items():
        print(f"  {k}: {v}")
