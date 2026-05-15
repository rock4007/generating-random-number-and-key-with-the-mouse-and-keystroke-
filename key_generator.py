"""Key derivation module for SUMIT KEY.

This file converts captured behavioural entropy into a 256-bit key using:
1. SHA3-256 entropy pooling.
2. HKDF (RFC 5869 structure) with HMAC-SHA3-256.

Python version target: 3.11+
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from typing import Iterable


class InsufficientEntropyError(Exception):
    """Raised when the provided entropy is below the 32-byte minimum."""


@dataclass(frozen=True)
class HKDFConfig:
    """Container for HKDF parameters.

    Why this matters cryptographically:
    - `salt` provides domain separation, so output keys are tied to this project
      and version instead of being re-usable in unrelated contexts.
    - `info` binds derived keys to a clear purpose label.
    - `length` enforces the final key size.
    """

    salt: bytes = b"SUMIT_KEY_v1"
    info: bytes = b"behavioural_entropy_key"
    length: int = 32

    @classmethod
    def quantum_hardened(cls) -> "HKDFConfig":
        """Return a quantum-hardened HKDF profile.

        Why this matters cryptographically:
        - Grover-style attacks can effectively reduce symmetric key strength.
        - A 512-bit derived key preserves a larger post-quantum security margin.
        """

        return cls(
            salt=b"SUMIT_KEY_v2_QUANTUM",
            info=b"behavioural_entropy_key_quantum_hardened",
            length=64,
        )


class KeyGenerator:
    """Derives cryptographic keys from one or more entropy chunks."""

    HASH_NAME = "sha3_256"
    HASH_LEN = hashlib.new(HASH_NAME).digest_size

    @staticmethod
    def _normalize_chunk(chunk: bytes | bytearray, index: int) -> bytes:
        """Validate a chunk and return it as immutable bytes.

        Why this matters cryptographically:
        - Strict type checking prevents accidental coercions that could change
          the exact byte stream being hashed.
        """

        if not isinstance(chunk, (bytes, bytearray)):
            raise TypeError(f"entropy chunk at index {index} must be bytes-like")
        return bytes(chunk)

    @classmethod
    def pool_entropy(cls, entropy_chunks: Iterable[bytes | bytearray]) -> bytes:
        """Mix entropy chunks into one 256-bit digest.

        Why this matters cryptographically:
        - Length-prefixing each chunk removes boundary ambiguity.
        - SHA3-256 compresses mixed input into a fixed-size digest suitable for
          HKDF extract.
        """

        if isinstance(entropy_chunks, (bytes, bytearray)):
            chunks = [bytes(entropy_chunks)]
        else:
            chunks = list(entropy_chunks)

        if not chunks:
            raise ValueError("entropy_chunks must contain at least one chunk")

        hasher = hashlib.sha3_256()
        for index, raw_chunk in enumerate(chunks):
            chunk = cls._normalize_chunk(raw_chunk, index)
            hasher.update(len(chunk).to_bytes(4, "big"))
            hasher.update(chunk)
        return hasher.digest()

    @classmethod
    def hkdf_extract(cls, ikm: bytes | bytearray, salt: bytes | bytearray) -> bytes:
        """Run HKDF-Extract and return the pseudorandom key (PRK).

        Why this matters cryptographically:
        - Extract reduces bias from imperfect input keying material (IKM).
        - Salt hardens extraction and provides domain separation.
        """

        if not isinstance(ikm, (bytes, bytearray)):
            raise TypeError("ikm must be bytes-like")
        if not isinstance(salt, (bytes, bytearray)):
            raise TypeError("salt must be bytes-like")

        normalized_salt = bytes(salt) if salt else b"\x00" * cls.HASH_LEN
        return hmac.new(normalized_salt, bytes(ikm), digestmod=cls.HASH_NAME).digest()

    @classmethod
    def hkdf_expand(
        cls,
        prk: bytes | bytearray,
        info: bytes | bytearray,
        length: int,
    ) -> bytes:
        """Run HKDF-Expand and return output key material (OKM).

        Why this matters cryptographically:
        - Expand produces deterministic, context-bound output from the PRK.
        - The RFC counter mechanism keeps blocks independent and predictable in
          structure, which is required for interoperability.
        """

        if not isinstance(prk, (bytes, bytearray)):
            raise TypeError("prk must be bytes-like")
        if not isinstance(info, (bytes, bytearray)):
            raise TypeError("info must be bytes-like")
        if length <= 0:
            raise ValueError("length must be a positive integer")

        max_length = 255 * cls.HASH_LEN
        if length > max_length:
            raise ValueError(f"length must not exceed {max_length} bytes")

        prk_bytes = bytes(prk)
        if len(prk_bytes) < cls.HASH_LEN:
            raise ValueError("prk length is shorter than hash output length")

        okm = b""
        previous_block = b""
        counter = 1

        while len(okm) < length:
            data = previous_block + bytes(info) + bytes([counter])
            previous_block = hmac.new(prk_bytes, data, digestmod=cls.HASH_NAME).digest()
            okm += previous_block
            counter += 1
        return okm[:length]

    @classmethod
    def derive_key(
        cls,
        entropy_chunks: Iterable[bytes | bytearray],
        config: HKDFConfig,
    ) -> bytes:
        """Derive a key from entropy chunks using SHA3 pooling + HKDF.

        Why this matters cryptographically:
        - Pooling and derivation are separated into explicit steps for auditability.
        - Consistent config ensures comparable outputs across experiments.
        """

        if not isinstance(config, HKDFConfig):
            raise TypeError("config must be an HKDFConfig instance")

        pooled_entropy = cls.pool_entropy(entropy_chunks)
        prk = cls.hkdf_extract(ikm=pooled_entropy, salt=config.salt)
        return cls.hkdf_expand(prk=prk, info=config.info, length=config.length)

    @classmethod
    def derive_key_hex(
        cls,
        entropy_chunks: Iterable[bytes | bytearray],
        config: HKDFConfig,
    ) -> str:
        """Derive a key and return it as lowercase hexadecimal text.

        Why this matters cryptographically:
        - Hex output makes binary key material easy to record in test reports
          without changing underlying bytes.
        """

        return cls.derive_key(entropy_chunks=entropy_chunks, config=config).hex()

    @classmethod
    def generate_key(
        cls,
        entropy_bytes: bytes | bytearray,
        config: HKDFConfig | None = None,
    ) -> bytes:
        """Generate one 256-bit key from a raw entropy byte stream.

        Why this matters cryptographically:
        - Enforcing a 32-byte minimum input prevents generating a 256-bit key
          from clearly undersized input.
        - Default domain-separated salt/info keeps keys scoped to SUMIT KEY.
        """

        if not isinstance(entropy_bytes, (bytes, bytearray)):
            raise TypeError("entropy_bytes must be bytes-like")

        normalized = bytes(entropy_bytes)
        if len(normalized) < 32:
            raise InsufficientEntropyError(
                f"Need at least 32 bytes of entropy; got {len(normalized)}"
            )

        active_config = config if config is not None else HKDFConfig()
        return cls.derive_key([normalized], active_config)

    @classmethod
    def generate_quantum_hardened_key(cls, entropy_bytes: bytes | bytearray) -> bytes:
        """Generate one 512-bit key with quantum-hardened parameters."""

        return cls.generate_key(entropy_bytes=entropy_bytes, config=HKDFConfig.quantum_hardened())

    @classmethod
    def bytes_to_bitstring(cls, data: bytes | bytearray) -> str:
        """Convert binary key material to a binary string representation."""

        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes-like")
        return "".join(f"{byte:08b}" for byte in bytes(data))

    @classmethod
    def generate_quantum_binary_string(
        cls,
        entropy_bytes: bytes | bytearray,
        bits: int = 512,
    ) -> str:
        """Generate a quantum-hardened binary string from behavioural entropy."""

        if bits <= 0 or bits > 512:
            raise ValueError("bits must be between 1 and 512")

        key_bytes = cls.generate_quantum_hardened_key(entropy_bytes)
        bit_string = cls.bytes_to_bitstring(key_bytes)
        return bit_string[:bits]


if __name__ == "__main__":
    sample_entropy = b"A" * 32
    key = KeyGenerator.generate_key(sample_entropy)
    print("Generated key (hex):", key.hex())
    print(f"Key length: {len(key) * 8} bits")
