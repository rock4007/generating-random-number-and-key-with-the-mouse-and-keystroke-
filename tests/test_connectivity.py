"""test_connectivity.py — Full cross-stack connectivity tests.

Verifies that every stack can talk to every other stack:

  Stack A  entropy_engine  →  key_generator  →  crypto_tools (classical AES-256-GCM)
  Stack B  entropy_engine  →  key_generator  →  crypto_tools (quantum ML-KEM-1024)
  Stack C  entropy_engine  →  key_generator  →  vault (ZKP + Shamir + Vault + MITM)
  Stack D  entropy_engine  →  key_generator  →  advanced_security (rotating keys)
  Stack E  entropy_engine  →  key_generator  →  sdk (lightweight layer)
  Stack F  sdk  ←→  api  (FastAPI TestClient)
  Stack G  sdk  ←→  sdk.server  (lightweight server)
  Stack H  platform integrations (WhatsApp / Telegram / Gmail / Drive / Instagram / Twitter)
  Stack X  cross-stack: key generated in one stack, used in another
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


# ── Shared synthetic events ───────────────────────────────────────────────────

def _mouse(n: int = 15) -> list[dict]:
    return [
        {"velocity_px_per_s": 120 + i * 7, "direction_angle_deg": i * 23 % 360,
         "x": i * 5, "y": i * 3, "timestamp": i * 0.05}
        for i in range(n)
    ]

def _keys(n: int = 8) -> list[dict]:
    return [
        {"key": chr(65 + i), "dwell_time_ms": 80 + i * 3,
         "flight_time_ms": 50 + i * 2, "release_timestamp": i * 0.12}
        for i in range(n)
    ]


# ── Stack A: entropy_engine → key_generator → crypto_tools classical ─────────

class TestStackA_Classical(unittest.TestCase):
    """entropy_engine → key_generator → crypto_tools AES-256-GCM round-trips."""

    def setUp(self):
        from entropy_engine import extract_mouse_entropy, extract_keystroke_entropy, pool_entropy
        from key_generator import KeyGenerator
        me = extract_mouse_entropy(_mouse())
        ke = extract_keystroke_entropy(_keys())
        pooled = pool_entropy(me, ke)
        self.key32 = KeyGenerator.generate_fresh_key(pooled)
        self.key64 = KeyGenerator.generate_fresh_quantum_hardened_key(pooled)

    def test_key_sizes(self):
        self.assertEqual(len(self.key32), 32)
        self.assertEqual(len(self.key64), 64)

    def test_message_roundtrip_256bit(self):
        from crypto_tools import encrypt_message, decrypt_message
        enc = encrypt_message(self.key32, "secret text", associated_data=b"ctx")
        self.assertEqual(decrypt_message(self.key32, enc), b"secret text")

    def test_message_roundtrip_512bit(self):
        from crypto_tools import encrypt_message, decrypt_message
        enc = encrypt_message(self.key64, "quantum key text", associated_data=b"ctx")
        self.assertEqual(decrypt_message(self.key64, enc), b"quantum key text")

    def test_file_roundtrip(self):
        from crypto_tools import encrypt_file, decrypt_file
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "doc.txt"
            enc = Path(tmp) / "doc.txt.sk"
            dec = Path(tmp) / "doc_out.txt"
            src.write_bytes(b"confidential content")
            encrypt_file(self.key32, src, enc)
            decrypt_file(self.key32, enc, dec, expected_name="doc.txt")
            self.assertEqual(dec.read_bytes(), b"confidential content")

    def test_wrong_key_rejected(self):
        from crypto_tools import encrypt_message, decrypt_message
        from cryptography.exceptions import InvalidTag
        enc = encrypt_message(self.key32, "secret", associated_data=b"ctx")
        from key_generator import KeyGenerator
        wrong = KeyGenerator.generate_fresh_key(os.urandom(32))
        with self.assertRaises(InvalidTag):
            decrypt_message(wrong, enc)

    def test_serialise_deserialise_message(self):
        from crypto_tools import encrypt_message, decrypt_message, message_to_dict, message_from_dict
        enc = encrypt_message(self.key32, "round trip", associated_data=b"aad")
        d   = message_to_dict(enc)
        enc2 = message_from_dict(d)
        self.assertEqual(decrypt_message(self.key32, enc2), b"round trip")


# ── Stack B: entropy_engine → key_generator → crypto_tools quantum ───────────

class TestStackB_QuantumSafe(unittest.TestCase):
    """entropy_engine → ML-KEM-1024 + Argon2id + AES-256-GCM round-trips."""

    def setUp(self):
        from entropy_engine import extract_mouse_entropy, extract_keystroke_entropy, pool_entropy
        from key_generator import KeyGenerator
        from crypto_tools import quantum_keygen
        me = extract_mouse_entropy(_mouse())
        ke = extract_keystroke_entropy(_keys())
        self.behaviour = pool_entropy(me, ke)
        self.session   = quantum_keygen()

    def test_kem_keygen_sizes(self):
        self.assertEqual(len(self.session.ek_bytes()), 1568)
        self.assertEqual(len(self.session.dk_bytes()), 3168)

    def test_message_roundtrip(self):
        from crypto_tools import quantum_encrypt_message, quantum_decrypt_message
        pkg  = quantum_encrypt_message(self.session, "quantum hello", self.behaviour)
        plain = quantum_decrypt_message(self.session, pkg)
        self.assertEqual(plain, b"quantum hello")

    def test_message_with_aad(self):
        from crypto_tools import quantum_encrypt_message, quantum_decrypt_message
        pkg  = quantum_encrypt_message(self.session, b"aad test",
                                       self.behaviour, associated_data=b"label")
        self.assertEqual(quantum_decrypt_message(self.session, pkg), b"aad test")

    def test_file_roundtrip(self):
        from crypto_tools import quantum_encrypt_file, quantum_decrypt_file
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "report.pdf"
            enc = Path(tmp) / "report.pdf.qs"
            dec = Path(tmp) / "report_out.pdf"
            data = b"quantum-safe document content"
            src.write_bytes(data)
            quantum_encrypt_file(self.session, src, enc, self.behaviour)
            quantum_decrypt_file(self.session, enc, dec, expected_name="report.pdf")
            self.assertEqual(dec.read_bytes(), data)

    def test_serialise_deserialise_package(self):
        from crypto_tools import (quantum_encrypt_message, quantum_decrypt_message,
                                   quantum_package_to_dict, quantum_package_from_dict)
        pkg  = quantum_encrypt_message(self.session, "serial test", self.behaviour)
        d    = quantum_package_to_dict(pkg)
        pkg2 = quantum_package_from_dict(d)
        self.assertEqual(quantum_decrypt_message(self.session, pkg2), b"serial test")

    def test_wrong_dk_rejected(self):
        from crypto_tools import quantum_encrypt_message, quantum_decrypt_message, quantum_keygen
        pkg  = quantum_encrypt_message(self.session, "secret", self.behaviour)
        wrong_session = quantum_keygen()
        with self.assertRaises(Exception):
            quantum_decrypt_message(wrong_session, pkg)


# ── Stack C: entropy_engine → key_generator → vault (ZKP + Shamir + MITM) ────

class TestStackC_Vault(unittest.TestCase):
    """entropy_engine → vault: ZKP prove/verify + Shamir SSS + HighVoltageVault + MITMShield."""

    def setUp(self):
        from entropy_engine import extract_mouse_entropy, extract_keystroke_entropy, pool_entropy
        from key_generator import KeyGenerator
        me = extract_mouse_entropy(_mouse())
        ke = extract_keystroke_entropy(_keys())
        self.pooled = pool_entropy(me, ke)
        self.key    = KeyGenerator.generate_fresh_key(self.pooled)

    def test_zkp_prove_verify(self):
        from vault import zkp_keygen, zkp_prove, zkp_verify
        kp    = zkp_keygen(self.pooled)
        proof = zkp_prove(kp, context=b"test-context")
        self.assertTrue(zkp_verify(kp.pk_hex(), proof, context=b"test-context"))
        self.assertFalse(zkp_verify(kp.pk_hex(), proof, context=b"wrong-context"))

    def test_shamir_split_combine(self):
        from vault import shamir_split, shamir_combine
        shards    = shamir_split(self.key, n_shares=5, threshold=3)
        recovered = shamir_combine(shards[:3])
        self.assertEqual(recovered, self.key)

    def test_shamir_insufficient_shards(self):
        from vault import shamir_split, shamir_combine
        shards = shamir_split(self.key, n_shares=5, threshold=3)
        # Only 2 shards — below threshold — should NOT reconstruct correctly
        wrong = shamir_combine(shards[:2])
        self.assertNotEqual(wrong, self.key)

    def test_vault_store_retrieve(self):
        from vault import HighVoltageVault
        vault = HighVoltageVault()
        vid   = vault.store(self.key, master_password=b"strongpass",
                            n_shards=3, threshold=2)
        recovered = vault.retrieve(vid, shard_xs=[1, 2], master_password=b"strongpass")
        self.assertEqual(recovered, self.key)

    def test_vault_burn_after_read(self):
        from vault import HighVoltageVault
        vault = HighVoltageVault()
        vid   = vault.store(self.key, master_password=b"pass",
                            n_shards=3, threshold=2, burn_after_read=True)
        vault.retrieve(vid, shard_xs=[1, 2], master_password=b"pass")
        with self.assertRaises(Exception):
            vault.retrieve(vid, shard_xs=[1, 2], master_password=b"pass")

    def test_mitm_shield_roundtrip(self):
        from vault import MITMShield
        alice, bob = MITMShield(), MITMShield()
        resp = bob.accept_session(alice.begin_session())
        alice.finish_session(resp)
        wire = alice.send(self.key, associated_data=b"channel-A")
        self.assertEqual(bob.receive(wire, associated_data=b"channel-A"), self.key)

    def test_mitm_shield_replay_rejected(self):
        from vault import MITMShield, MITMShieldError
        alice, bob = MITMShield(), MITMShield()
        resp = bob.accept_session(alice.begin_session())
        alice.finish_session(resp)
        wire = alice.send(b"payload")
        bob.receive(wire)
        with self.assertRaises(MITMShieldError):
            bob.receive(wire)   # replay

    def test_mitm_aad_mismatch_rejected(self):
        from vault import MITMShield, MITMShieldError
        alice, bob = MITMShield(), MITMShield()
        resp = bob.accept_session(alice.begin_session())
        alice.finish_session(resp)
        wire = alice.send(b"data", associated_data=b"real")
        with self.assertRaises(MITMShieldError):
            bob.receive(wire, associated_data=b"fake")


# ── Stack D: entropy_engine → key_generator → advanced_security ──────────────

class TestStackD_AdvancedSecurity(unittest.TestCase):
    """entropy_engine → RotatingKeyEnvelope encrypt/decrypt round-trip."""

    def setUp(self):
        from advanced_security import RotatingKeyEnvelope, SystemIdentity
        from entropy_engine import extract_mouse_entropy, extract_keystroke_entropy, pool_entropy
        me = extract_mouse_entropy(_mouse())
        ke = extract_keystroke_entropy(_keys())
        behaviour = pool_entropy(me, ke)
        self.identity = SystemIdentity.from_current_system(
            user_id="test-user",
            session_id="test-session",
            device_secret=behaviour,
        )
        self.envelope = RotatingKeyEnvelope(self.identity)

    def test_rotating_encrypt_decrypt(self):
        enc = self.envelope.encrypt("rotating secret", context="test")
        dec = self.envelope.decrypt(enc, context="test", max_clock_skew_seconds=2.0)
        self.assertEqual(dec, b"rotating secret")

    def test_wrong_context_rejected(self):
        enc = self.envelope.encrypt("secret", context="ctx-A")
        with self.assertRaises(Exception):
            self.envelope.decrypt(enc, context="ctx-B")

    def test_serialise_roundtrip(self):
        from advanced_security import RotatingEncryptedMessage
        enc  = self.envelope.encrypt("serial", context="test")
        d    = enc.to_dict()
        enc2 = RotatingEncryptedMessage.from_dict(d)
        dec  = self.envelope.decrypt(enc2, context="test", max_clock_skew_seconds=2.0)
        self.assertEqual(dec, b"serial")


# ── Stack E: entropy_engine → key_generator → sdk lightweight ────────────────

class TestStackE_SDK(unittest.TestCase):
    """entropy_engine → key_generator → sdk.core round-trips."""

    def setUp(self):
        from entropy_engine import extract_mouse_entropy, extract_keystroke_entropy, pool_entropy
        from key_generator import KeyGenerator
        from sdk.core import SumitKey
        me = extract_mouse_entropy(_mouse())
        ke = extract_keystroke_entropy(_keys())
        pooled = pool_entropy(me, ke)
        raw_key = KeyGenerator.generate_fresh_key(pooled)
        self.key_b64 = base64.urlsafe_b64encode(raw_key).decode()
        self.sk = SumitKey()

    def test_text_roundtrip(self):
        env = self.sk.encrypt_text("hello sdk", self.key_b64, context="test")
        self.assertEqual(self.sk.decrypt_text(env, self.key_b64), "hello sdk")

    def test_file_roundtrip(self):
        data = b"document content for SDK test"
        env  = self.sk.encrypt_file(data, "test.bin", self.key_b64)
        self.assertEqual(self.sk.decrypt(env, self.key_b64), data)

    def test_context_mismatch_rejected(self):
        from sdk.core import SumitKeyError
        env = self.sk.encrypt_text("secret", self.key_b64, context="ctx-A")
        pkg = json.loads(env)
        pkg["context"] = "ctx-B"
        with self.assertRaises(SumitKeyError):
            self.sk.decrypt_text(json.dumps(pkg), self.key_b64)

    def test_sdk_new_key_modes(self):
        key_rand  = self.sk.new_key()
        key_pass  = self.sk.new_key(passphrase="test-pass")
        key_behav = self.sk.new_key(mouse_events=_mouse(), keystroke_events=_keys())
        for k in (key_rand, key_pass, key_behav):
            env = self.sk.encrypt_text("check", k)
            self.assertEqual(self.sk.decrypt_text(env, k), "check")

    def test_qr_payload_roundtrip(self):
        qr  = self.sk.key_to_qr_payload(self.key_b64, "WhatsApp")
        key = self.sk.key_from_qr_payload(qr)
        self.assertEqual(key, self.key_b64)

    def test_fingerprint_stable(self):
        fp1 = self.sk.fingerprint(self.key_b64)
        fp2 = self.sk.fingerprint(self.key_b64)
        self.assertEqual(fp1, fp2)
        self.assertTrue(fp1.startswith("fp:"))


# ── Stack F: sdk ←→ main API (FastAPI TestClient) ────────────────────────────

class TestStackF_SDK_vs_MainAPI(unittest.TestCase):
    """SDK envelope accepted and decrypted by the main api.py endpoints."""

    def setUp(self):
        from sdk.core import SumitKey
        self.sk = SumitKey()
        self.request = SimpleNamespace(client=SimpleNamespace(host="testclient"))

    def test_sdk_key_used_in_main_api_encrypt(self):
        """Key generated by SDK → used in main API /encrypt/message → decrypt."""
        from api import (
            _DecryptMessageBody,
            _EncryptMessageBody,
            decrypt_message_endpoint,
            encrypt_message_endpoint,
        )

        key_b64  = self.sk.new_key()
        key_hex  = base64.urlsafe_b64decode(key_b64 + "==").hex()
        enc = encrypt_message_endpoint(
            self.request,
            _EncryptMessageBody(
                message="hello from sdk key",
                key_hex=key_hex,
                label="sdk-compat-test",
            ),
        )
        dec = decrypt_message_endpoint(
            self.request,
            _DecryptMessageBody(
                nonce_hex=enc["nonce_hex"],
                ciphertext_hex=enc["ciphertext_hex"],
                key_hex=key_hex,
                associated_data_hex=enc["associated_data_hex"],
            ),
        )
        self.assertEqual(dec["plaintext"], "hello from sdk key")

    def test_ghost_encrypt_decrypt_via_api(self):
        """Full ghost package lifecycle through the main API."""
        from api import (
            _GhostEncryptBody,
            _GhostPackageBody,
            ghost_decrypt_endpoint,
            ghost_encrypt_endpoint,
        )

        created = ghost_encrypt_endpoint(
            self.request,
            _GhostEncryptBody(
                message="ghost connectivity test",
                label="stack-F-test",
                ttl_seconds=60,
            ),
        )
        opened = ghost_decrypt_endpoint(
            self.request,
            _GhostPackageBody(**created["package"]),
        )
        self.assertEqual(opened["plaintext"], "ghost connectivity test")

    def test_vault_serverless_store_retrieve(self):
        """SDK key → vault/serverless store → vault/serverless retrieve."""
        from api import _VaultServerlessBody, vault_serverless_endpoint

        key_b64 = self.sk.new_key()
        key_hex = base64.urlsafe_b64decode(key_b64 + "==").hex()
        stored = vault_serverless_endpoint(
            _VaultServerlessBody(
                action="vault_store",
                payload={
                    "key_hex": key_hex,
                    "master_password": "test-pass",
                    "n_shards": 3,
                    "threshold": 2,
                },
            )
        )
        self.assertEqual(stored["status"], "ok")
        vid = stored["vault_id"]

        retrieved = vault_serverless_endpoint(
            _VaultServerlessBody(
                action="vault_retrieve",
                payload={
                    "vault_id": vid,
                    "shard_xs": [1, 2],
                    "master_password": "test-pass",
                },
            )
        )
        self.assertEqual(retrieved["status"], "ok")
        self.assertEqual(retrieved["key_hex"], key_hex)


# ── Stack G: sdk.core ←→ sdk.server ──────────────────────────────────────────

class TestStackG_SDK_vs_LightweightServer(unittest.TestCase):
    """sdk.core encrypt/decrypt through sdk.server REST endpoints."""

    def setUp(self):
        from sdk import server
        from sdk.core import SumitKey
        self.server = server
        self.sk = SumitKey()

    def test_health(self):
        self.assertEqual(self.server.health()["status"], "ok")

    def test_new_key(self):
        d = self.server.new_key(self.server.KeyRequest())
        self.assertIn("key_b64", d)
        self.assertIn("fingerprint", d)
        self.assertIn("qr_payload", d)
        self.assertTrue(d["qr_payload"].startswith("SUMITKEY://v1/"))

    def test_new_key_with_passphrase(self):
        data = self.server.new_key(self.server.KeyRequest(passphrase="my-secret"))
        self.assertIn("key_b64", data)

    def test_encrypt_decrypt_text(self):
        key = self.server.new_key(self.server.KeyRequest())["key_b64"]
        encrypted = self.server.encrypt_text(
            self.server.EncryptTextRequest(
                plaintext="lightweight server test",
                key_b64=key,
                context="server-test",
            )
        )
        decrypted = self.server.decrypt(
            self.server.DecryptRequest(envelope=encrypted["envelope"], key_b64=key)
        )
        self.assertEqual(decrypted["plaintext"], "lightweight server test")

    def test_encrypt_decrypt_file(self):
        key = self.server.new_key(self.server.KeyRequest())["key_b64"]
        # Use non-UTF-8 bytes so the server returns binary/data_b64 path
        file_data = bytes(range(0, 256))
        encrypted = self.server.encrypt_file(
            self.server.EncryptFileRequest(
                data_b64=base64.b64encode(file_data).decode(),
                filename="report.bin",
                key_b64=key,
                context="gdrive",
            )
        )
        body = self.server.decrypt(
            self.server.DecryptRequest(envelope=encrypted["envelope"], key_b64=key)
        )
        # Server returns binary path for non-UTF-8 content
        self.assertEqual(body["content_type"], "binary")
        self.assertEqual(base64.b64decode(body["data_b64"]), file_data)

    def test_wrong_key_returns_400(self):
        from fastapi import HTTPException

        key = self.server.new_key(self.server.KeyRequest())["key_b64"]
        wrong = self.server.new_key(self.server.KeyRequest())["key_b64"]
        env = self.server.encrypt_text(
            self.server.EncryptTextRequest(plaintext="x", key_b64=key)
        )["envelope"]
        with self.assertRaises(HTTPException) as ctx:
            self.server.decrypt(self.server.DecryptRequest(envelope=env, key_b64=wrong))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_sdk_envelope_decrypted_by_server(self):
        """Envelope created by sdk.core Python — decrypted by sdk.server."""
        key = self.server.new_key(self.server.KeyRequest())["key_b64"]
        env = self.sk.encrypt_text("cross-layer test", key, context="server-sdk")
        data = self.server.decrypt(self.server.DecryptRequest(envelope=env, key_b64=key))
        self.assertEqual(data["plaintext"], "cross-layer test")


# ── Stack H: platform integrations ───────────────────────────────────────────

class TestStackH_PlatformIntegrations(unittest.TestCase):
    """WhatsApp / Telegram / Gmail / Drive / Instagram / Twitter round-trips."""

    def setUp(self):
        from sdk.core import SumitKey
        self.sk  = SumitKey()
        self.key = self.sk.new_key()

    def test_whatsapp_text(self):
        env = self.sk.encrypt_text("WhatsApp secret", self.key, context="whatsapp")
        pkg = json.loads(env)
        self.assertEqual(pkg["context"], "whatsapp")
        self.assertEqual(self.sk.decrypt_text(env, self.key), "WhatsApp secret")

    def test_telegram_bulk(self):
        messages = ["msg one", "msg two", "msg three"]
        for msg in messages:
            env = self.sk.encrypt_text(msg, self.key, context="telegram")
            self.assertEqual(self.sk.decrypt_text(env, self.key), msg)

    def test_gmail_body(self):
        body = "Hi,\n\nThe merger is confirmed for Monday.\n\nRegards"
        env  = self.sk.encrypt_text(body, self.key, context="gmail")
        self.assertEqual(self.sk.decrypt_text(env, self.key), body)

    def test_gdrive_document(self):
        doc = b"CONFIDENTIAL: Q3 revenue = $4.2M"
        env = self.sk.encrypt_file(doc, "q3_revenue.txt", self.key, context="gdrive")
        self.assertEqual(self.sk.decrypt(env, self.key), doc)

    def test_instagram_dm(self):
        msg = "Don't post this — it's private."
        env = self.sk.encrypt_text(msg, self.key, context="instagram")
        # Simulate IG DM prefix
        dm  = f"🔒 {env}"
        raw = dm.lstrip("🔒 ")
        self.assertEqual(self.sk.decrypt_text(raw, self.key), msg)

    def test_twitter_dm(self):
        msg = "Off the record: acquisition offer is $4.2M."
        env = self.sk.encrypt_text(msg, self.key, context="twitter")
        self.assertEqual(self.sk.decrypt_text(env, self.key), msg)

    def test_wrap_unwrap_platform(self):
        from sdk.core import SumitKey
        sk  = SumitKey()
        env = sk.encrypt_text("wrapped message", self.key, context="generic")
        wrapped = sk.wrap_for_platform(env, "whatsapp") if hasattr(sk, "wrap_for_platform") else env
        self.assertIn("SUMITKEY1", wrapped)

    def test_cross_platform_context_isolation(self):
        """Envelope from WhatsApp cannot be replayed as a Telegram envelope."""
        env = self.sk.encrypt_text("secret", self.key, context="whatsapp")
        pkg = json.loads(env)
        pkg["context"] = "telegram"
        from sdk.core import SumitKeyError
        with self.assertRaises(SumitKeyError):
            self.sk.decrypt_text(json.dumps(pkg), self.key)


# ── Stack X: cross-stack key compatibility ────────────────────────────────────

class TestStackX_CrossStackCompatibility(unittest.TestCase):
    """Key generated in one stack used transparently in another stack."""

    def test_keygen_key_in_sdk(self):
        """KeyGenerator key → SDK encrypt/decrypt."""
        from key_generator import KeyGenerator
        from sdk.core import SumitKey
        raw = KeyGenerator.generate_fresh_key(os.urandom(32))
        key = base64.urlsafe_b64encode(raw).decode()
        sk  = SumitKey()
        env = sk.encrypt_text("cross-stack msg", key)
        self.assertEqual(sk.decrypt_text(env, key), "cross-stack msg")

    def test_sdk_key_in_cryptotools(self):
        """SDK key → crypto_tools AES-256-GCM."""
        from sdk.core import SumitKey
        from crypto_tools import encrypt_message, decrypt_message
        key_b64  = SumitKey().new_key()
        key_bytes = base64.urlsafe_b64decode(key_b64 + "==")
        enc = encrypt_message(key_bytes, "cross-stack crypto", associated_data=b"x")
        self.assertEqual(decrypt_message(key_bytes, enc), b"cross-stack crypto")

    def test_sdk_key_in_vault_shamir(self):
        """SDK key → Shamir split → recombine → SDK decrypt."""
        from sdk.core import SumitKey
        from vault import shamir_split, shamir_combine
        sk      = SumitKey()
        key_b64 = sk.new_key()
        raw     = base64.urlsafe_b64decode(key_b64 + "==")
        shards  = shamir_split(raw, n_shares=5, threshold=3)
        recovered = shamir_combine(shards[:3])
        recovered_b64 = base64.urlsafe_b64encode(recovered).decode()

        env = sk.encrypt_text("vault-sdk bridge", key_b64)
        self.assertEqual(sk.decrypt_text(env, recovered_b64), "vault-sdk bridge")

    def test_keygen_key_in_vault(self):
        """KeyGenerator key → HighVoltageVault store → retrieve → crypto_tools decrypt."""
        from key_generator import KeyGenerator
        from vault import HighVoltageVault
        from crypto_tools import encrypt_message, decrypt_message
        key   = KeyGenerator.generate_fresh_key(os.urandom(32))
        vault = HighVoltageVault()
        vid   = vault.store(key, master_password=b"pw", n_shards=3, threshold=2)
        recovered = vault.retrieve(vid, shard_xs=[1, 2], master_password=b"pw")
        enc = encrypt_message(key, "vault roundtrip", associated_data=b"test")
        self.assertEqual(decrypt_message(recovered, enc), b"vault roundtrip")

    def test_sdk_server_key_in_sdk_core(self):
        """Key generated by sdk.server → envelope decrypted by sdk.core directly."""
        from sdk import server
        from sdk.core import SumitKey

        key_b64 = server.new_key(server.KeyRequest())["key_b64"]
        sk = SumitKey()
        env = sk.encrypt_text("server-core bridge", key_b64)
        data = server.decrypt(server.DecryptRequest(envelope=env, key_b64=key_b64))
        self.assertEqual(data["plaintext"], "server-core bridge")

    def test_entropy_all_three_paths_same_schema(self):
        """All entropy paths produce keys with the same size and SDK-compatible format."""
        from sdk.core import SumitKey
        sk   = SumitKey()
        keys = [
            sk.new_key(),
            sk.new_key(passphrase="test"),
            sk.new_key(mouse_events=_mouse(), keystroke_events=_keys()),
        ]
        for key in keys:
            raw = base64.urlsafe_b64decode(key + "==")
            self.assertEqual(len(raw), 32, f"key length wrong for {key[:20]}")
            env = sk.encrypt_text("schema check", key)
            self.assertEqual(sk.decrypt_text(env, key), "schema check")


if __name__ == "__main__":
    unittest.main(verbosity=2)
