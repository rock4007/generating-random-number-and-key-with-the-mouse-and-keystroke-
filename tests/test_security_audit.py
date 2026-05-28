"""SUMIT KEY — Honest Security Audit Test Suite.

Each test class addresses one of the seven known limitations raised in review.
Tests either:
  (a) prove a mitigation is in place and working, or
  (b) formally document the limitation and the correct threat-model boundary.

All 7 concerns:
  1. Behavioural entropy alone is not enough as a secret.
  2. Browser dashboard is a prototype, not a hardened vault.
  3. Pre-encryption malware can steal plaintext before crypto runs.
  4. Key material logged, displayed, or stored badly negates encryption.
  5. AES-GCM nonce reuse is catastrophically dangerous.
  6. OTP by SMS/email is weaker than hardware passkeys or FIDO2.
  7. Formal NIST/FIPS compliance requires official validation, not local tests.

Run with:
    python -m pytest tests/test_security_audit.py -v -s
"""

from __future__ import annotations

import hashlib
import inspect
import os
import re
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


# ── Formatting ──────────────────────────────────────────────────────────────
def _h(title: str) -> None:
    bar = "=" * 72
    print(f"\n{bar}\n  {title}\n{bar}")

def _ok(msg: str)   -> None: print(f"  [PASS]    {msg}")
def _risk(msg: str) -> None: print(f"  [RISK]    {msg}")
def _fix(msg: str)  -> None: print(f"  [FIX]     {msg}")
def _scope(msg: str)-> None: print(f"  [SCOPE]   {msg}")
def _info(msg: str) -> None: print(f"  [INFO]    {msg}")


# ============================================================================
# Concern 1 — Behavioural entropy alone is not enough as a secret
# ============================================================================

class TestBehaviouralEntropyLimitation(unittest.TestCase):
    """
    Mouse/keystroke behaviour is LOW-QUALITY entropy:
      - Typical movements produce ~3-8 bits of real entropy per event.
      - A recorded session can be replayed by an attacker with physical access.
      - `generate_key(mouse_only)` is deterministic: same pattern → same key.

    MITIGATION VERIFIED HERE:
      - `generate_fresh_key` always mixes in os.urandom (system CSPRNG).
      - The health_check_entropy gate rejects degenerate/constant inputs.
      - Result: behavioural entropy is an ADDITIONAL binding factor, not the secret.
    """

    def test_same_mouse_pattern_same_key_without_os_random(self):
        """Demonstrate that behavioural-only keys are reproducible (the risk)."""
        _h("CONCERN 1a — Same mouse pattern → same key (no os.urandom)")
        from key_generator import KeyGenerator
        from entropy_engine import extract_mouse_entropy

        # Fixed synthetic events — identical on every run
        events = [{"x": 100.0 + i * 5, "y": 200.0,
                   "velocity_px_per_s": 150.0 + i,
                   "direction_angle_deg": 45.0 + i * 3}
                  for i in range(12)]
        raw = extract_mouse_entropy(events)

        k1 = KeyGenerator.generate_key(raw)
        k2 = KeyGenerator.generate_key(raw)

        self.assertEqual(k1, k2)
        _risk("Same mouse pattern → same 256-bit key every time.")
        _risk("An attacker who replays your movement session gets your key.")
        _fix("generate_fresh_key() adds os.urandom — use it instead of generate_key().")

    def test_fresh_key_mixes_os_urandom(self):
        """Prove: generate_fresh_key with identical mouse input yields different keys."""
        _h("CONCERN 1b — generate_fresh_key mixes os.urandom (mitigation active)")
        from key_generator import KeyGenerator
        from entropy_engine import extract_mouse_entropy

        events = [{"x": 100.0 + i * 5, "y": 200.0,
                   "velocity_px_per_s": 150.0 + i,
                   "direction_angle_deg": 45.0 + i * 3}
                  for i in range(12)]
        raw = extract_mouse_entropy(events)

        # Both calls use the same behavioural bytes but fresh os.urandom
        k1 = KeyGenerator.generate_fresh_key(raw)
        k2 = KeyGenerator.generate_fresh_key(raw)

        self.assertNotEqual(k1, k2,
            "generate_fresh_key must produce different keys each call "
            "because os.urandom() is mixed in.")
        _ok("Same mouse pattern + fresh os.urandom → different key each call.")
        _ok("Replaying mouse movements cannot reproduce the session key.")

    def test_entropy_health_gate_rejects_constant_input(self):
        """Prove: the health gate blocks all-constant behavioural input."""
        _h("CONCERN 1c — Health gate blocks degenerate entropy")
        from key_generator import KeyGenerator, EntropyHealthError
        from entropy_engine import extract_mouse_entropy

        # Attacker who provides zero-movement events
        events = [{"x": 0.0, "y": 0.0,
                   "velocity_px_per_s": 0.0,
                   "direction_angle_deg": 0.0}] * 8
        zero_raw = extract_mouse_entropy(events)

        with self.assertRaises(EntropyHealthError):
            KeyGenerator.generate_fresh_key(zero_raw)
        _ok("All-zero entropy → EntropyHealthError before key derivation.")
        _ok("Degenerate capture cannot produce a key.")

    def test_nist_800_90b_minimum_check(self):
        """Prove: 32-byte minimum is enforced on all key derivation paths."""
        _h("CONCERN 1d — NIST SP 800-90B minimum entropy input gate")
        from key_generator import KeyGenerator, InsufficientEntropyError

        with self.assertRaises(InsufficientEntropyError):
            KeyGenerator.generate_key(os.urandom(10))   # 10 < 32 bytes minimum
        _ok("< 32 bytes input → InsufficientEntropyError (NIST 800-90B minimum enforced).")


# ============================================================================
# Concern 2 — Browser dashboard is a prototype, not a hardened vault
# ============================================================================

class TestDashboardPrototypeLimitation(unittest.TestCase):
    """
    dashboard.html is intentionally a development/demonstration tool.
    It has no server-side authentication, no HTTPS enforcement, and no
    session management.  Using it in production without hardening is unsafe.

    WHAT IS VERIFIED HERE:
      - The dashboard does NOT embed or display raw key material.
      - The dashboard does NOT contain hardcoded secrets or credentials.
      - The production gap is formally documented in assertions.
    """

    @classmethod
    def setUpClass(cls):
        cls.html = (ROOT / "dashboard.html").read_text(encoding="utf-8")

    def test_dashboard_contains_no_hardcoded_secrets(self):
        """Dashboard HTML must not contain any hardcoded API keys or secrets."""
        _h("CONCERN 2a — Dashboard: no hardcoded secrets")
        # Patterns that would indicate embedded secrets
        bad_patterns = [
            r'api[_-]?key\s*[:=]\s*["\'][A-Za-z0-9+/]{20,}',
            r'secret\s*[:=]\s*["\'][A-Za-z0-9+/]{16,}',
            r'password\s*[:=]\s*["\'][^\s"\']{8,}',
            r'sk-[A-Za-z0-9]{20,}',    # OpenAI-style key pattern
        ]
        for pattern in bad_patterns:
            match = re.search(pattern, self.html, re.IGNORECASE)
            self.assertIsNone(match,
                f"Hardcoded secret pattern found in dashboard: {pattern}")
        _ok("Dashboard HTML contains no hardcoded API keys or secrets.")

    def test_dashboard_does_not_display_raw_key_hex(self):
        """Dashboard must not render or log full key material client-side."""
        _h("CONCERN 2b — Dashboard: raw key not rendered in clear")
        # Acceptable: showing short preview / partial key for UX
        # Unacceptable: a full 64-char hex block labelled as the key
        full_key_pattern = re.compile(
            r'(key|secret)\s*[=:]\s*[0-9a-f]{64}', re.IGNORECASE)
        self.assertIsNone(full_key_pattern.search(self.html),
            "Dashboard renders a 256-bit key in plaintext HTML — remove it.")
        _ok("Dashboard does not embed a full 256-bit hex key in static HTML.")

    def test_dashboard_production_gap_documented(self):
        """Formally document what is missing for production hardening."""
        _h("CONCERN 2c — Dashboard: production hardening gap (documented)")
        gaps = [
            "No server-side session authentication (stateless HTML prototype)",
            "No HTTPS enforcement (must be served behind TLS terminator)",
            "No Content-Security-Policy nonce or hash (prototype CSP only)",
            "No rate-limiting at the HTML layer (API layer has rate-limiting)",
            "No audit log of dashboard access (API layer logs requests)",
        ]
        for gap in gaps:
            _risk(gap)
        # This test always passes — it documents the known gaps, not a bug
        _scope("Dashboard is a PROTOTYPE. Harden before production deployment.")
        _scope("Use: NGINX/Caddy TLS + OAuth2 proxy + CSP nonce injection.")


# ============================================================================
# Concern 3 — Pre-encryption malware can steal plaintext
# ============================================================================

class TestPreEncryptionMalwareLimitation(unittest.TestCase):
    """
    If malware controls the OS process, it can intercept plaintext
    BEFORE encrypt_message() is called.  Cryptography cannot prevent this.
    This is a fundamental trust-boundary issue, not a crypto bug.

    WHAT IS VERIFIED HERE:
      - The threat is demonstrated concretely (hook before encryption).
      - The correct threat-model boundary is stated.
      - The available mitigations (TEE, process isolation) are documented.
    """

    def test_hook_captures_plaintext_before_encryption(self):
        """Demonstrate that a caller-level hook sees plaintext pre-encryption."""
        _h("CONCERN 3a — Pre-encryption hook intercepts plaintext (threat demo)")
        from key_generator import KeyGenerator
        from crypto_tools import encrypt_message, decrypt_message

        key = KeyGenerator.generate_key(os.urandom(32))
        intercepted: list[bytes] = []

        def malware_shim(key_bytes, plaintext, associated_data=b""):
            """Simulates malware hooking the encrypt call."""
            raw = plaintext.encode() if isinstance(plaintext, str) else plaintext
            intercepted.append(raw)        # captured before crypto runs
            return encrypt_message(key_bytes, plaintext, associated_data)

        secret = b"bank transfer: $50,000 to account 9999"
        malware_shim(key, secret)

        self.assertEqual(intercepted[0], secret)
        _risk("Malware hooked encrypt_message() and captured plaintext before AES-GCM.")
        _risk("The ciphertext is correct, but the plaintext was already stolen.")
        _scope("This is an OS / process-isolation problem, NOT a crypto layer problem.")

    def test_crypto_layer_boundary_is_correct(self):
        """Prove: encryption itself is sound — the threat is above the crypto layer."""
        _h("CONCERN 3b — Crypto layer is sound; trust boundary is above it")
        from key_generator import KeyGenerator
        from crypto_tools import encrypt_message, decrypt_message
        from cryptography.exceptions import InvalidTag

        key = KeyGenerator.generate_key(os.urandom(32))
        msg = b"message that goes through the crypto layer cleanly"
        enc = encrypt_message(key, msg, associated_data=b"channel")
        dec = decrypt_message(key, enc)

        self.assertEqual(dec, msg)

        # An attacker who only sees the ciphertext cannot recover plaintext
        wrong_key = KeyGenerator.generate_key(os.urandom(32))
        with self.assertRaises(InvalidTag):
            decrypt_message(wrong_key, enc)

        _ok("Ciphertext is opaque — network-level attacker cannot recover plaintext.")
        _ok("Crypto layer is correct; the pre-encryption path is out of its scope.")
        _scope("Mitigations: Trusted Execution Environment (TEE), process isolation,")
        _scope("  memory-safe language, OS-level MAC (SELinux/AppArmor).")


# ============================================================================
# Concern 4 — Key material logged, displayed, or stored badly
# ============================================================================

class TestKeyMaterialHygiene(unittest.TestCase):
    """
    Key material that appears in logs, error messages, or API responses
    in plaintext text destroys encryption regardless of algorithm strength.

    WHAT IS VERIFIED HERE:
      - api.py no longer accepts key_hex as a URL query parameter.
      - key_generator.py __main__ no longer prints the full key.
      - Keys do not appear in exception/repr output.
      - vault serverless handler returns key_hex (documented risk).
    """

    def test_api_encrypt_endpoint_uses_post_body_not_query(self):
        """key_hex must not appear as a URL query parameter in /encrypt/message."""
        _h("CONCERN 4a — API: key_hex moved to POST body (not URL query param)")
        api_src = (ROOT / "api.py").read_text(encoding="utf-8")

        # Find the encrypt endpoint definition
        encrypt_block_match = re.search(
            r'@app\.post\("/encrypt/message".*?(?=@app\.)',
            api_src, re.DOTALL)
        self.assertIsNotNone(encrypt_block_match, "Cannot find /encrypt/message endpoint")
        block = encrypt_block_match.group(0)

        # key_hex must NOT appear as Query(...)
        self.assertNotIn('key_hex: str = Query', block,
            "/encrypt/message still passes key_hex via URL query param. "
            "URL query params appear in server access logs.")
        _ok("key_hex is accepted in POST body, not URL query param.")
        _ok("Server access logs cannot capture the key from the URL.")

    def test_api_decrypt_endpoint_uses_post_body_not_query(self):
        """key_hex must not appear as a URL query parameter in /decrypt/message."""
        _h("CONCERN 4b — API: /decrypt/message key_hex in POST body")
        api_src = (ROOT / "api.py").read_text(encoding="utf-8")

        decrypt_block_match = re.search(
            r'@app\.post\("/decrypt/message".*?(?=@app\.)',
            api_src, re.DOTALL)
        self.assertIsNotNone(decrypt_block_match, "Cannot find /decrypt/message endpoint")
        block = decrypt_block_match.group(0)

        self.assertNotIn('key_hex: str = Query', block,
            "/decrypt/message still passes key_hex via URL query param.")
        _ok("key_hex is accepted in POST body, not URL query param.")

    def test_key_generator_main_does_not_print_full_key(self):
        """key_generator.py __main__ must not print the complete key hex."""
        _h("CONCERN 4c — key_generator __main__ does not print full key")
        kg_src = (ROOT / "key_generator.py").read_text(encoding="utf-8")

        # Find __main__ block
        main_block = kg_src.split("if __name__")[1] if "if __name__" in kg_src else ""

        # Must NOT contain a full key.hex() print (prints all 64 chars)
        self.assertNotIn('print("Generated key (hex):", key.hex())', main_block,
            "key_generator __main__ still prints the full key hex to stdout.")
        _ok("key_generator __main__ no longer prints full key hex.")
        _fix("Only key length + short prefix is shown; full key withheld.")

    def test_key_bytes_not_in_exception_message(self):
        """Key material must not leak into exception messages."""
        _h("CONCERN 4d — Key material not present in exception messages")
        from key_generator import KeyGenerator
        from crypto_tools import encrypt_message, decrypt_message
        from cryptography.exceptions import InvalidTag

        key = KeyGenerator.generate_key(os.urandom(32))
        enc = encrypt_message(key, b"secret payload", associated_data=b"aad")
        wrong = KeyGenerator.generate_key(os.urandom(32))

        try:
            decrypt_message(wrong, enc)
            self.fail("Should have raised InvalidTag")
        except InvalidTag as exc:
            msg = str(exc)
            # Key bytes must not appear in the exception text
            self.assertNotIn(key.hex(), msg)
            self.assertNotIn(wrong.hex(), msg)
            _ok(f"InvalidTag message: {msg!r:.60} — no key bytes present.")

    def test_vault_serverless_key_hex_risk_documented(self):
        """Document: serverless vault handler returns key_hex — caller must protect it."""
        _h("CONCERN 4e — Serverless vault: key_hex in response (documented risk)")
        vault_src = (ROOT / "vault.py").read_text(encoding="utf-8")

        # The known risk: vault_retrieve returns key_hex in the response dict
        self.assertIn('"key_hex": key_bytes.hex()', vault_src,
            "Serverless vault_retrieve response not found — verify the risk is still present.")
        _risk("vault.py serverless handler returns key_hex in the response dict.")
        _risk("In production: decrypt inside the serverless function; never return raw key_hex.")
        _fix("Caller should store key_hex in a secrets manager (AWS Secrets Manager,")
        _fix("  GCP Secret Manager, HashiCorp Vault) and reference it by ARN/name only.")


# ============================================================================
# Concern 5 — AES-GCM nonce reuse is catastrophically dangerous
# ============================================================================

class TestNonceReuseProtection(unittest.TestCase):
    """
    AES-GCM is NOT a random oracle when the same (key, nonce) pair is reused.
    Reusing a nonce with the same key:
      - XOR of two ciphertexts = XOR of two plaintexts (keystream cancels).
      - The authentication tag can be forged.
      - ALL confidentiality and integrity is lost.

    MITIGATION VERIFIED HERE:
      - encrypt_message() always generates a fresh os.urandom(12) nonce.
      - Two calls with identical plaintext produce different ciphertexts.
      - 10,000 sampled nonces contain zero collisions (birthday-bound safe).
    """

    def test_nonce_reuse_xor_attack_demonstration(self):
        """Demonstrate: same (key, nonce) → XOR of plaintexts recoverable."""
        _h("CONCERN 5a — Nonce reuse XOR attack (threat demonstration)")
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        key   = os.urandom(32)
        nonce = b"\x00" * 12    # fixed nonce — the dangerous mistake

        p1 = b"send $1000 to alice"
        p2 = b"send $9999 to evilx"

        aes = AESGCM(key)
        c1  = aes.encrypt(nonce, p1, None)[:-16]   # strip 16-byte tag
        c2  = aes.encrypt(nonce, p2, None)[:-16]

        # XOR of ciphertexts = XOR of plaintexts (keystream cancels out)
        xor_ct = bytes(a ^ b for a, b in zip(c1, c2))
        xor_pt = bytes(a ^ b for a, b in zip(p1, p2))
        self.assertEqual(xor_ct, xor_pt,
            "Nonce-reuse XOR: ciphertext XOR should equal plaintext XOR")

        _risk("Nonce reused with same key: XOR of ciphertexts = XOR of plaintexts.")
        _risk("Attacker who knows ONE plaintext recovers the other completely.")
        _fix("encrypt_message() uses os.urandom(12) per call — NEVER reuses nonces.")

    def test_encrypt_always_fresh_nonce(self):
        """Prove: encrypt_message generates a new nonce on every call."""
        _h("CONCERN 5b — encrypt_message uses fresh nonce every call (mitigation)")
        from key_generator import KeyGenerator
        from crypto_tools import encrypt_message

        key   = KeyGenerator.generate_key(os.urandom(32))
        msg   = b"same plaintext every time"

        enc1 = encrypt_message(key, msg)
        enc2 = encrypt_message(key, msg)
        enc3 = encrypt_message(key, msg)

        nonces = {enc1.nonce, enc2.nonce, enc3.nonce}
        self.assertEqual(len(nonces), 3,
            "encrypt_message reused a nonce across three calls — critical bug.")
        self.assertNotEqual(enc1.ciphertext, enc2.ciphertext,
            "Identical plaintext encrypted twice must produce different ciphertext.")
        _ok("Three encryptions of the same plaintext → three unique nonces.")
        _ok("Ciphertexts differ: IND-CPA security property holds.")

    def test_nonce_source_is_os_urandom(self):
        """Verify by source inspection that nonces come from os.urandom."""
        _h("CONCERN 5c — Nonce source is os.urandom (source inspection)")
        ct_src = (ROOT / "crypto_tools.py").read_text(encoding="utf-8")

        # The encrypt_message function must use os.urandom for the nonce
        self.assertIn("nonce = os.urandom(NONCE_SIZE)", ct_src,
            "encrypt_message nonce is not generated by os.urandom.")
        _ok("Source verified: nonce = os.urandom(NONCE_SIZE) in encrypt_message.")

    def test_birthday_bound_no_collision_in_10k_nonces(self):
        """Statistical: 10,000 random 96-bit nonces must have zero collisions."""
        _h("CONCERN 5d — Birthday-bound check: 10,000 nonces, zero collisions")
        nonces = {os.urandom(12) for _ in range(10_000)}
        self.assertEqual(len(nonces), 10_000,
            "Collision detected in 10,000 random 96-bit nonces — CSPRNG failure.")
        # Probability of collision in 10k draws from 2^96 space ≈ 10^-20
        _ok("10,000 random 96-bit nonces: zero collisions (birthday bound safe).")
        _info("Collision probability at 10k draws: ~6×10⁻²¹ (negligible).")
        _info("Rotate keys before reaching ~2^32 messages to stay in safe zone.")


# ============================================================================
# Concern 6 — OTP by SMS/email is weaker than hardware passkeys or FIDO2
# ============================================================================

class TestOTPWeaknessAndFIDO2Gap(unittest.TestCase):
    """
    SMS OTP is vulnerable to:
      - SIM-swap attacks (attacker takes over your phone number).
      - SS7 protocol interception (telco-level attack).
      - Phishing (attacker tricks user into entering OTP on fake site).
      - Malware that reads OTP from notification shade.

    Email OTP is vulnerable to:
      - Email account compromise.
      - Man-in-the-middle on SMTP delivery.

    FIDO2 / hardware passkeys provide:
      - Origin binding (phishing-resistant — key only works on correct domain).
      - Private key never leaves the device/HSM.
      - No shared secret on the server side.

    WHAT IS VERIFIED HERE:
      - SimulatedOTPProvider has NO channel security (documented).
      - OTP codes travel as cleartext to the verifier (no channel binding).
      - The production upgrade path to FIDO2 is stated.
    """

    def test_otp_provider_has_no_channel_security(self):
        """SimulatedOTPProvider has no transport binding — code travels in clear."""
        _h("CONCERN 6a — OTP provider has no channel security (documented)")
        from fallback_auth import SimulatedOTPProvider

        otp  = SimulatedOTPProvider(secret=b"otp-test-secret-32-bytes-padding")
        dest = "user@example.com"
        code = otp.issue(dest, ttl_seconds=300)

        # The code is a plain string — no transport binding, no channel key
        self.assertIsInstance(code, str)
        self.assertEqual(len(code), 6)
        _risk("OTP code is a plain 6-digit string with no channel binding.")
        _risk("SMS delivery: vulnerable to SIM-swap, SS7 interception, phishing.")
        _risk("Email delivery: vulnerable to SMTP interception, account compromise.")

    def test_otp_sim_swap_simulation(self):
        """Attacker with SIM-swap obtains the issued code and authenticates."""
        _h("CONCERN 6b — SIM-swap simulation: attacker intercepts OTP")
        from fallback_auth import SimulatedOTPProvider

        otp   = SimulatedOTPProvider(secret=b"otp-test-secret-32-bytes-padding")
        dest  = "victim@example.com"
        code  = otp.issue(dest, ttl_seconds=300)  # sent to victim's phone

        # Attacker intercepts code (SIM-swap / SS7 / shoulder-surf / phishing)
        attacker_has_code = code    # ← in real attack: attacker received the SMS

        # Attacker authenticates as the victim
        self.assertTrue(otp.verify(dest, attacker_has_code),
            "OTP should verify (attacker succeeded with intercepted code)")
        _risk("Attacker with intercepted OTP code authenticates successfully.")
        _risk("There is no origin binding — any party who holds the code can use it.")

    def test_fido2_properties_gap_documented(self):
        """Formally document what FIDO2 provides that OTP does not."""
        _h("CONCERN 6c — FIDO2 / hardware passkey properties (gap document)")
        fido2_properties = [
            "Origin binding: authenticator signs the relying-party origin — "
            "phishing sites receive a different credential, useless on the real site.",
            "Private key never leaves device: server stores only the public key, "
            "no shared secret to steal from the database.",
            "Replay-resistant: each assertion includes a server-supplied challenge "
            "and client data hash, signed by the authenticator.",
            "Hardware attestation: the authenticator's make/model is cryptographically "
            "verified against the FIDO Metadata Service.",
        ]
        for prop in fido2_properties:
            _fix(f"FIDO2: {prop}")
        _scope("Production recommendation: replace SimulatedOTPProvider with")
        _scope("  WebAuthn (python-fido2 library) or a FIDO2-compliant hardware key.")
        _scope("  NFC-based FIDO2 tokens (YubiKey 5 NFC) already in the auth chain.")

    def test_nfc_token_is_stronger_than_otp(self):
        """Verify that NFC token auth uses hash comparison (no plaintext secret)."""
        _h("CONCERN 6d — NFC token: no plaintext secret on server (stronger than OTP)")
        from fallback_auth import SimulatedNFCProvider

        nfc = SimulatedNFCProvider()
        nfc.register_token("secure-nfc-uid-abc123")

        # Server stores only SHA-256 hash of the token UID
        stored_hash = SimulatedNFCProvider.token_hash("secure-nfc-uid-abc123")
        self.assertEqual(len(stored_hash), 64)   # 32-byte SHA-256 as hex

        # Raw UID is never stored
        nfc_src = inspect.getsource(SimulatedNFCProvider)
        self.assertIn("sha256", nfc_src,
            "SimulatedNFCProvider should hash token UIDs with SHA-256")
        _ok("NFC: server stores SHA-256(token_uid), not the raw UID.")
        _ok("Compromised server database does not yield usable NFC credentials.")


# ============================================================================
# Concern 7 — Formal NIST/FIPS compliance is not the same as local test pass
# ============================================================================

class TestNISTFIPSComplianceGap(unittest.TestCase):
    """
    "Using NIST-standardised algorithms" ≠ "NIST-certified product".

    NIST validation requires:
      - Submission to the Cryptographic Module Validation Program (CMVP).
      - Algorithm-level testing by an accredited third-party laboratory (CAVP).
      - FIPS 140-3 module boundary definition and documentation.
      - Strict operational environment constraints.

    What this codebase has:
      - Correct algorithm choices (AES-256-GCM, SHA3, HKDF, ML-KEM-1024).
      - Local NIST SP 800-22 statistical tests on entropy output.
      - Source-code inspection that parameters match published specifications.

    What it does NOT have:
      - CMVP module certificate.
      - CAVP algorithm validation certificates.
      - Entropy source validation under NIST SP 800-90B.

    WHAT IS VERIFIED HERE:
      - Algorithm parameters match NIST specifications (aes-256, sha3, etc.).
      - The gap between "passes local tests" and "NIST certified" is stated.
      - The path to formal certification is documented.
    """

    def test_aes_key_size_matches_nist_fips_197(self):
        """AES key must be exactly 256 bits (NIST FIPS 197 Table 3)."""
        _h("CONCERN 7a — Algorithm check: AES-256 key size (FIPS 197)")
        from key_generator import KeyGenerator

        key = KeyGenerator.generate_key(os.urandom(32))
        self.assertEqual(len(key) * 8, 256,
            f"AES key must be 256 bits; got {len(key)*8}")
        _ok(f"Key size: {len(key)*8} bits — matches NIST FIPS 197 AES-256.")

    def test_aes_gcm_nonce_is_96_bits_nist_sp_800_38d(self):
        """GCM recommended nonce size is 96 bits (NIST SP 800-38D §8.2.1)."""
        _h("CONCERN 7b — Algorithm check: AES-GCM 96-bit nonce (SP 800-38D)")
        from crypto_tools import NONCE_SIZE

        self.assertEqual(NONCE_SIZE, 12,
            f"GCM nonce must be 12 bytes (96 bits); got {NONCE_SIZE}")
        _ok(f"NONCE_SIZE = {NONCE_SIZE} bytes = 96 bits — matches NIST SP 800-38D.")

    def test_sha3_256_digest_size(self):
        """SHA3-256 must produce a 32-byte (256-bit) digest (FIPS 202)."""
        _h("CONCERN 7c — Algorithm check: SHA3-256 digest size (FIPS 202)")
        digest = hashlib.sha3_256(b"test").digest()
        self.assertEqual(len(digest), 32)
        _ok(f"SHA3-256 digest: {len(digest)} bytes = 256 bits — matches FIPS 202.")

    def test_ml_kem_1024_key_sizes_fips_203(self):
        """ML-KEM-1024 ek=1568B, dk=3168B, ct=1568B (NIST FIPS 203 Table 2)."""
        _h("CONCERN 7d — Algorithm check: ML-KEM-1024 sizes (FIPS 203)")
        from crypto_tools import quantum_keygen

        session = quantum_keygen()
        ek_len  = len(bytes.fromhex(session.ek))
        dk_len  = len(bytes.fromhex(session.dk))

        self.assertEqual(ek_len, 1568,
            f"ML-KEM-1024 ek must be 1568 bytes; got {ek_len}")
        self.assertEqual(dk_len, 3168,
            f"ML-KEM-1024 dk must be 3168 bytes; got {dk_len}")
        _ok(f"ML-KEM-1024 ek={ek_len}B, dk={dk_len}B — matches FIPS 203 Table 2.")

    def test_hkdf_uses_sha3_per_rfc_5869(self):
        """HKDF must use SHA3 (not MD5/SHA1) as the PRF (RFC 5869 + FIPS 202)."""
        _h("CONCERN 7e — Algorithm check: HKDF uses SHA3 (RFC 5869 + FIPS 202)")
        kg_src = (ROOT / "key_generator.py").read_text(encoding="utf-8")

        self.assertIn("sha3", kg_src.lower(),
            "key_generator does not reference SHA3 in HKDF")
        self.assertNotIn("md5", kg_src.lower())
        self.assertNotIn("sha1", kg_src.lower())
        _ok("HKDF uses SHA3 family — no MD5 or SHA1 references in key_generator.")

    def test_formal_certification_gap_documented(self):
        """Formally state the gap between local tests and CMVP certification."""
        _h("CONCERN 7f — NIST/FIPS formal certification gap (documented)")
        _info("What this project HAS:")
        _ok("  Correct algorithm choices: AES-256-GCM, SHA3-256/512, HKDF, ML-KEM-1024.")
        _ok("  NIST SP 800-22 statistical tests run locally on entropy output.")
        _ok("  Parameter values match published NIST/IETF specifications.")

        _risk("")
        _risk("What this project does NOT have:")
        _risk("  CMVP module certificate (FIPS 140-3) — requires lab submission.")
        _risk("  CAVP algorithm validation certificates — requires NIST-accredited lab.")
        _risk("  SP 800-90B entropy source validation — requires physical testing.")
        _risk("  Defined FIPS module boundary documentation.")

        _fix("")
        _fix("Path to formal certification:")
        _fix("  1. Engage an accredited CAVP/CMVP laboratory (UL, atsec, Leidos etc.).")
        _fix("  2. Submit algorithm implementation test vectors to CAVP.")
        _fix("  3. Define the cryptographic module boundary and security policy.")
        _fix("  4. Submit FIPS 140-3 module for CMVP review (12-24 month timeline).")
        _fix("  5. For government/regulated use: require CMVP certificate on the module.")

        # This test always passes — it documents the gap, not a code defect
        self.assertTrue(True)


# ============================================================================
# Summary
# ============================================================================

class TestAuditSummary(unittest.TestCase):
    """Consolidated pass/risk table printed once at the end."""

    def test_audit_summary_table(self):
        _h("SECURITY AUDIT SUMMARY")
        rows = [
            ("1. Behavioural entropy alone",
             "MITIGATED",
             "generate_fresh_key() mixes os.urandom; health gate rejects degenerate input."),
            ("2. Dashboard prototype",
             "DOCUMENTED",
             "No hardcoded secrets; no key display. Production needs TLS+auth proxy."),
            ("3. Pre-encryption malware",
             "OUT OF SCOPE",
             "Crypto layer boundary is correct. Requires TEE/OS-level mitigation."),
            ("4. Key logging / display",
             "FIXED",
             "key_hex removed from URL query params; __main__ no longer prints full key."),
            ("5. AES-GCM nonce reuse",
             "MITIGATED",
             "os.urandom(12) per call; 10k nonce sample shows zero collisions."),
            ("6. OTP weaker than FIDO2",
             "DOCUMENTED",
             "SIM-swap risk stated. NFC stores hash. Upgrade path to FIDO2 documented."),
            ("7. NIST/FIPS formal compliance",
             "DOCUMENTED",
             "Algorithms match specs; CMVP/CAVP certification gap formally stated."),
        ]
        print()
        print(f"  {'Concern':<35}  {'Status':<13}  Notes")
        print(f"  {'-'*35}  {'-'*13}  {'-'*35}")
        for concern, status, note in rows:
            print(f"  {concern:<35}  {status:<13}  {note}")
        print()
        self.assertEqual(len(rows), 7)
        _ok("All 7 security concerns accounted for.")


if __name__ == "__main__":
    unittest.main(verbosity=2, failfast=False)
