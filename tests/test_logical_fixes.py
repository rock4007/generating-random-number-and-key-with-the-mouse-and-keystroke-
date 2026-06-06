"""test_logical_fixes.py — Targeted tests for logical fixes in recent changes.

Covers:
  1. vault_store requires master_password (vault.py)
  2. MITMShield.receive() rejects mismatched associated_data (vault.py)
  3. /vault/serverless accepts POST body, not query params (api.py)
  4. quantum_encrypt_file reports correct original_size_bytes (crypto_tools.py)
  5. security.py: no circular import in ThreatLogger.log_threat
  6. require_api_key uses singleton and validates correctly (security.py)
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path


class TestVaultStoreMasterPasswordRequired(unittest.TestCase):
    """vault_store must require master_password; random fallback was removed."""

    def setUp(self):
        from vault import lambda_handler
        self.handler = lambda_handler
        self.key_hex = os.urandom(32).hex()

    def test_vault_store_without_password_returns_422(self):
        result = self.handler({
            "action": "vault_store",
            "payload": {"key_hex": self.key_hex},
        })
        self.assertEqual(result["statusCode"], 422)
        import json
        body = json.loads(result["body"])
        self.assertIn("master_password", body["error"])

    def test_vault_store_with_empty_password_returns_422(self):
        result = self.handler({
            "action": "vault_store",
            "payload": {"key_hex": self.key_hex, "master_password": ""},
        })
        self.assertEqual(result["statusCode"], 422)

    def test_vault_store_with_password_succeeds(self):
        result = self.handler({
            "action": "vault_store",
            "payload": {"key_hex": self.key_hex, "master_password": "strongpass"},
        })
        self.assertEqual(result["statusCode"], 200)
        import json
        body = json.loads(result["body"])
        self.assertEqual(body["status"], "ok")
        self.assertIn("vault_id", body)


class TestMITMShieldAssociatedDataCheck(unittest.TestCase):
    """MITMShield.receive() should reject mismatched associated_data."""

    def _make_session(self):
        from vault import MITMShield
        alice = MITMShield()
        bob = MITMShield()
        init = alice.begin_session()
        resp = bob.accept_session(init)
        alice.finish_session(resp)
        return alice, bob

    def test_matching_aad_succeeds(self):
        from vault import MITMShield
        alice, bob = self._make_session()
        wire = alice.send(b"payload", associated_data=b"channel-A")
        plaintext = bob.receive(wire, associated_data=b"channel-A")
        self.assertEqual(plaintext, b"payload")

    def test_mismatched_aad_raises(self):
        from vault import MITMShield, MITMShieldError
        alice, bob = self._make_session()
        wire = alice.send(b"payload", associated_data=b"channel-A")
        with self.assertRaises(MITMShieldError) as ctx:
            bob.receive(wire, associated_data=b"channel-B")
        self.assertIn("associated_data mismatch", str(ctx.exception))

    def test_empty_aad_skips_check(self):
        """Empty associated_data (default) should skip the check (backward compat)."""
        from vault import MITMShield
        alice, bob = self._make_session()
        wire = alice.send(b"payload", associated_data=b"channel-A")
        # Receiver passes no associated_data → check skipped → succeeds
        plaintext = bob.receive(wire)
        self.assertEqual(plaintext, b"payload")

    def test_aad_mismatch_rejected_before_decryption(self):
        """Mismatch is detected after HMAC (authentic packet) but before decryption."""
        from vault import MITMShield, MITMShieldError
        alice, bob = self._make_session()
        wire = alice.send(b"secret", associated_data=b"real-ctx")
        # HMAC is valid (authentic), but AAD check should fail
        with self.assertRaises(MITMShieldError):
            bob.receive(wire, associated_data=b"fake-ctx")


class TestVaultServerlessEndpointPostBody(unittest.TestCase):
    """POST /vault/serverless uses a JSON body, not query parameters."""

    def setUp(self):
        from api import _VaultServerlessBody, vault_serverless_endpoint
        self.body = _VaultServerlessBody
        self.endpoint = vault_serverless_endpoint

    def test_post_body_action_dispatched(self):
        data = self.endpoint(
            self.body(action="zkp_keygen", payload={"entropy_hex": os.urandom(64).hex()})
        )
        self.assertEqual(data["status"], "ok")
        self.assertIn("pk_hex", data)

    def test_post_body_vault_store_no_password_returns_error(self):
        data = self.endpoint(
            self.body(action="vault_store", payload={"key_hex": os.urandom(32).hex()})
        )
        # The embedded http_status should be 422
        self.assertEqual(data["http_status"], 422)
        self.assertIn("master_password", data["error"])

    def test_unknown_action_returns_error(self):
        data = self.endpoint(self.body(action="nonexistent", payload={}))
        self.assertIn("error", data)

    def test_get_query_params_rejected(self):
        """The old query-param interface no longer exists."""
        import pytest
        from pydantic import ValidationError

        # Direct construction mirrors request-body validation: action is
        # required in JSON body, so an empty body is rejected before dispatch.
        with pytest.raises(ValidationError):
            self.body()


class TestQuantumEncryptFileOriginalSize(unittest.TestCase):
    """quantum_encrypt_file must report original_size_bytes without re-reading the file."""

    def test_original_size_matches_actual_content(self):
        from crypto_tools import quantum_keygen, quantum_encrypt_file, quantum_decrypt_file
        session = quantum_keygen()
        entropy = os.urandom(64)

        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "test.bin"
            enc = Path(tmpdir) / "test.enc"
            dec = Path(tmpdir) / "test.dec"

            data = os.urandom(512)
            src.write_bytes(data)

            info = quantum_encrypt_file(session, src, enc, entropy)
            self.assertEqual(info["original_size_bytes"], len(data))

            quantum_decrypt_file(session, enc, dec)
            self.assertEqual(dec.read_bytes(), data)

    def test_original_size_correct_for_empty_file(self):
        from crypto_tools import quantum_keygen, quantum_encrypt_file, quantum_decrypt_file
        session = quantum_keygen()
        entropy = os.urandom(64)

        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "empty.bin"
            enc = Path(tmpdir) / "empty.enc"
            dec = Path(tmpdir) / "empty.dec"

            src.write_bytes(b"")
            info = quantum_encrypt_file(session, src, enc, entropy)
            self.assertEqual(info["original_size_bytes"], 0)

            quantum_decrypt_file(session, enc, dec)
            self.assertEqual(dec.read_bytes(), b"")


class TestThreatLoggerCircularImportFix(unittest.TestCase):
    """ThreatLogger.log_threat must not do circular 'from security import ...'."""

    def test_log_threat_does_not_raise_import_error(self):
        from security import ThreatLogger
        tl = ThreatLogger()
        # Should not raise ImportError or any other exception
        tl.log_threat("TEST_EVENT", "127.0.0.1", "unit test")
        self.assertEqual(len(tl.threat_events), 1)
        self.assertEqual(tl.threat_events[0]["type"], "TEST_EVENT")

    def test_get_stats_reflects_logged_threats(self):
        from security import ThreatLogger
        tl = ThreatLogger()
        for i in range(6):
            tl.log_threat("BRUTE", "10.0.0.2", str(i))
        stats = tl.get_stats()
        self.assertGreaterEqual(stats["total_threat_events"], 6)
        self.assertIn("10.0.0.2", stats["blocked_ips"])


class TestRequireApiKeySingleton(unittest.TestCase):
    """require_api_key uses the module-level singleton and returns bool."""

    def test_require_api_key_returns_true_when_auth_disabled(self):
        # Clear the env var to disable auth
        env_backup = os.environ.pop("SUMIT_API_KEY", None)
        try:
            import importlib, security
            importlib.reload(security)
            result = security.require_api_key(None)
            self.assertTrue(result)
        finally:
            if env_backup is not None:
                os.environ["SUMIT_API_KEY"] = env_backup

    def test_api_key_auth_verify_correct_key(self):
        import hashlib
        from security import APIKeyAuth
        import importlib, security

        test_key = "my-api-key-12345"
        key_hash = hashlib.sha256(test_key.encode()).hexdigest()

        auth = APIKeyAuth.__new__(APIKeyAuth)
        auth.expected_key = key_hash
        auth.enabled = True

        self.assertTrue(auth.verify(test_key))
        self.assertFalse(auth.verify("wrong-key"))
        self.assertFalse(auth.verify(None))
        self.assertFalse(auth.verify(""))


if __name__ == "__main__":
    unittest.main()
