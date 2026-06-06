"""test_file_decrypt_aad.py — Tests for the filename AAD verification gap fix.

encrypt_file / quantum_encrypt_file bind the ciphertext to the original
source filename via AAD.  The gap was that decrypt_file /
quantum_decrypt_file never verified the embedded AAD against an expected
name, so renaming an encrypted file was silently ignored.

The fix adds an optional expected_name= parameter (same pattern as
MITMShield.receive(associated_data=...)):
  - If omitted  → backward-compatible; decryption succeeds regardless of name.
  - If provided  → raises ValueError when embedded AAD ≠ expected.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path


# ─── helpers ─────────────────────────────────────────────────────────────────

def _make_key():
    from key_generator import KeyGenerator
    return KeyGenerator.generate_fresh_key(os.urandom(64))


def _make_qs_session():
    from crypto_tools import quantum_keygen
    return quantum_keygen()


# ─── Classical encrypt_file / decrypt_file ───────────────────────────────────

class TestDecryptFileExpectedName(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.key = _make_key()
        from crypto_tools import encrypt_file
        self.src = self.tmp / "secret.txt"
        self.enc = self.tmp / "secret.txt.sumitkey"
        self.dec = self.tmp / "out.txt"
        self.src.write_bytes(b"confidential payload")
        encrypt_file(self.key, self.src, self.enc)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_decrypt_without_expected_name_succeeds(self):
        """Omitting expected_name is backward-compatible."""
        from crypto_tools import decrypt_file
        info = decrypt_file(self.key, self.enc, self.dec)
        self.assertEqual(self.dec.read_bytes(), b"confidential payload")
        self.assertEqual(info["aad"], "file:secret.txt")

    def test_decrypt_with_correct_expected_name_succeeds(self):
        """Passing the original filename succeeds."""
        from crypto_tools import decrypt_file
        info = decrypt_file(self.key, self.enc, self.dec, expected_name="secret.txt")
        self.assertEqual(self.dec.read_bytes(), b"confidential payload")

    def test_decrypt_with_wrong_expected_name_raises(self):
        """Passing a different name raises ValueError (rename-attack guard)."""
        from crypto_tools import decrypt_file
        with self.assertRaises(ValueError) as ctx:
            decrypt_file(self.key, self.enc, self.dec, expected_name="other.txt")
        self.assertIn("Filename mismatch", str(ctx.exception))
        self.assertIn("file:secret.txt", str(ctx.exception))
        self.assertIn("file:other.txt", str(ctx.exception))

    def test_renamed_enc_without_expected_name_still_decrypts(self):
        """Rename attack is silent if caller does not supply expected_name."""
        from crypto_tools import decrypt_file
        renamed = self.tmp / "innocent.txt.sumitkey"
        shutil.copy(self.enc, renamed)
        # No expected_name → passes (caller must opt in to the check)
        info = decrypt_file(self.key, renamed, self.dec)
        self.assertEqual(self.dec.read_bytes(), b"confidential payload")
        # But the embedded AAD reveals the original name
        self.assertEqual(info["aad"], "file:secret.txt")

    def test_renamed_enc_with_original_expected_name_succeeds(self):
        """Caller knows the original name and passes it — succeeds despite rename."""
        from crypto_tools import decrypt_file
        renamed = self.tmp / "innocent.txt.sumitkey"
        shutil.copy(self.enc, renamed)
        # Caller still knows the original was secret.txt
        info = decrypt_file(self.key, renamed, self.dec, expected_name="secret.txt")
        self.assertEqual(self.dec.read_bytes(), b"confidential payload")

    def test_renamed_enc_with_renamed_expected_name_raises(self):
        """Caller passes the *new* name as expected — detects the swap."""
        from crypto_tools import decrypt_file
        renamed = self.tmp / "innocent.txt.sumitkey"
        shutil.copy(self.enc, renamed)
        with self.assertRaises(ValueError) as ctx:
            decrypt_file(self.key, renamed, self.dec, expected_name="innocent.txt")
        self.assertIn("Filename mismatch", str(ctx.exception))

    def test_wrong_key_raises_invalid_tag_not_value_error(self):
        """Wrong key raises InvalidTag (GCM), not the filename check."""
        from crypto_tools import decrypt_file
        from cryptography.exceptions import InvalidTag
        bad_key = _make_key()
        with self.assertRaises(InvalidTag):
            decrypt_file(bad_key, self.enc, self.dec, expected_name="secret.txt")

    def test_output_not_written_when_name_check_fails(self):
        """No partial output is written when the expected_name check raises."""
        from crypto_tools import decrypt_file
        try:
            decrypt_file(self.key, self.enc, self.dec, expected_name="wrong.txt")
        except ValueError:
            pass
        self.assertFalse(self.dec.exists(), "output must not be created on mismatch")


# ─── Quantum quantum_encrypt_file / quantum_decrypt_file ─────────────────────

class TestQuantumDecryptFileExpectedName(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.session = _make_qs_session()
        self.entropy = os.urandom(64)
        from crypto_tools import quantum_encrypt_file
        self.src = self.tmp / "report.pdf"
        self.enc = self.tmp / "report.pdf.qs"
        self.dec = self.tmp / "report_out.pdf"
        self.src.write_bytes(b"quantum-safe payload " * 10)
        quantum_encrypt_file(self.session, self.src, self.enc, self.entropy)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_decrypt_without_expected_name_succeeds(self):
        from crypto_tools import quantum_decrypt_file
        info = quantum_decrypt_file(self.session, self.enc, self.dec)
        self.assertEqual(self.dec.read_bytes(), self.src.read_bytes())

    def test_decrypt_with_correct_expected_name_succeeds(self):
        from crypto_tools import quantum_decrypt_file
        quantum_decrypt_file(self.session, self.enc, self.dec, expected_name="report.pdf")
        self.assertEqual(self.dec.read_bytes(), self.src.read_bytes())

    def test_decrypt_with_wrong_expected_name_raises(self):
        from crypto_tools import quantum_decrypt_file
        with self.assertRaises(ValueError) as ctx:
            quantum_decrypt_file(self.session, self.enc, self.dec, expected_name="evil.pdf")
        self.assertIn("Filename mismatch", str(ctx.exception))
        self.assertIn("file:report.pdf", str(ctx.exception))
        self.assertIn("file:evil.pdf", str(ctx.exception))

    def test_renamed_enc_detected_when_expected_name_given(self):
        from crypto_tools import quantum_decrypt_file
        renamed = self.tmp / "public.pdf.qs"
        shutil.copy(self.enc, renamed)
        # Caller passes renamed file's stem as expected → mismatch detected
        with self.assertRaises(ValueError):
            quantum_decrypt_file(self.session, renamed, self.dec, expected_name="public.pdf")

    def test_renamed_enc_passes_when_original_name_given(self):
        from crypto_tools import quantum_decrypt_file
        renamed = self.tmp / "public.pdf.qs"
        shutil.copy(self.enc, renamed)
        # Caller knows the original name and provides it → OK
        quantum_decrypt_file(self.session, renamed, self.dec, expected_name="report.pdf")
        self.assertEqual(self.dec.read_bytes(), self.src.read_bytes())

    def test_output_not_written_on_name_mismatch(self):
        from crypto_tools import quantum_decrypt_file
        try:
            quantum_decrypt_file(self.session, self.enc, self.dec, expected_name="wrong.pdf")
        except ValueError:
            pass
        self.assertFalse(self.dec.exists())


if __name__ == "__main__":
    unittest.main()
