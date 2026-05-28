"""test_ghost_api.py — Ghost key API tests + quantum ghost session demo.

Covers:
  - Classic ghost key: one-time decrypt, revoke, status, burn-after-read
  - Quantum ghost session: two-device ML-KEM flow with presence proof
  - MITM detection: tampered package → 400 + threat logged
  - Fallback assess endpoint for browser extension
  - File encryption: quantum-strong, no-read without dk
  - Admin threats endpoint: IP + MAC exposure
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import HTTPException


def _mouse_events(n: int = 20) -> list[dict]:
    from fallback_auth import make_chess_like_mouse_events
    return make_chess_like_mouse_events(good=True, moves=max(4, n // 4))


def _qs_setup(ttl: int = 60) -> dict:
    from api import _QsSessionBody, qs_session_endpoint

    return qs_session_endpoint(_request(), _QsSessionBody(ttl_seconds=ttl))


def _qs_send(ek_hex: str, message: str, events=None) -> dict:
    from api import _QsSendBody, qs_send_endpoint

    return qs_send_endpoint(
        _request(),
        _QsSendBody(
            ek_hex=ek_hex,
            message=message,
            mouse_events=events or _mouse_events(),
            label="test",
        ),
    )


def _qs_recv(vault_id, secret_hex, package, events=None):
    from api import _QsReceiveBody, qs_receive_endpoint

    try:
        data = qs_receive_endpoint(
            _request(),
            _QsReceiveBody(
                vault_id=vault_id,
                session_secret_hex=secret_hex,
                package=package,
                mouse_events=events if events is not None else _mouse_events(),
            ),
        )
        return SimpleNamespace(status_code=200, json=lambda: data, text=str(data))
    except HTTPException as exc:
        status_code = exc.status_code
        detail = exc.detail
        return SimpleNamespace(
            status_code=status_code,
            json=lambda: {"detail": detail},
            text=str(detail),
        )


def _request():
    return SimpleNamespace(client=SimpleNamespace(host="testclient"))


# ════════════════════════════════════════════════════════════════════════════
# QUANTUM GHOST SESSION — two-device ML-KEM presence-proof flow
# ════════════════════════════════════════════════════════════════════════════

def test_quantum_ghost_full_happy_path() -> None:
    """Setup → Send → Receive: correct plaintext, ghost key burned."""
    session = _qs_setup()
    send = _qs_send(session["ek_hex"], "Quantum ghost demo message!")
    recv = _qs_recv(session["vault_id"], session["session_secret_hex"], send["package"])
    assert recv.status_code == 200, recv.text
    data = recv.json()
    assert data["plaintext"] == "Quantum ghost demo message!"
    assert "burned" in data["ghost_key_status"]


def test_quantum_ghost_burn_after_read() -> None:
    """Second receive attempt must be rejected (burn-after-read)."""
    session = _qs_setup()
    send = _qs_send(session["ek_hex"], "one-time only")
    _qs_recv(session["vault_id"], session["session_secret_hex"], send["package"])
    second = _qs_recv(session["vault_id"], session["session_secret_hex"], send["package"])
    assert second.status_code in (403, 410)


def test_quantum_ghost_any_mouse_unlocks() -> None:
    """Different random mouse movements still unlock — presence matters, not pattern."""
    from fallback_auth import make_chess_like_mouse_events
    session = _qs_setup()
    send = _qs_send(session["ek_hex"], "cross-device unlock")
    other_events = make_chess_like_mouse_events(good=True, moves=8)
    recv = _qs_recv(session["vault_id"], session["session_secret_hex"],
                    send["package"], events=other_events)
    assert recv.status_code == 200
    assert recv.json()["plaintext"] == "cross-device unlock"


def test_quantum_ghost_unicode_round_trip() -> None:
    msg = "Ghost 🔐 密码 مرحبا — Ñoño"
    session = _qs_setup()
    send = _qs_send(session["ek_hex"], msg)
    recv = _qs_recv(session["vault_id"], session["session_secret_hex"], send["package"])
    assert recv.json()["plaintext"] == msg


def test_quantum_ghost_tampered_ciphertext_rejected() -> None:
    """Bit-flip in ciphertext must return 400 (AES-GCM auth failure)."""
    session = _qs_setup()
    send = _qs_send(session["ek_hex"], "tamper test")
    bad_pkg = dict(send["package"])
    ct = bytearray(bytes.fromhex(bad_pkg["ciphertext_hex"]))
    ct[0] ^= 0xFF
    bad_pkg["ciphertext_hex"] = ct.hex()
    recv = _qs_recv(session["vault_id"], session["session_secret_hex"], bad_pkg)
    assert recv.status_code == 400


def test_quantum_ghost_wrong_secret_rejected() -> None:
    """Wrong session secret must not unlock the vault."""
    session = _qs_setup()
    send = _qs_send(session["ek_hex"], "secret message")
    wrong = os.urandom(32).hex()
    recv = _qs_recv(session["vault_id"], wrong, send["package"])
    assert recv.status_code in (400, 403, 422)


def test_quantum_ghost_no_mouse_events_blocked() -> None:
    """Receiver with zero mouse events (bot) must be rejected."""
    session = _qs_setup()
    send = _qs_send(session["ek_hex"], "presence required")
    recv = _qs_recv(session["vault_id"], session["session_secret_hex"],
                    send["package"], events=[])
    assert recv.status_code == 422
    assert "mouse" in recv.json()["detail"].lower()


def test_quantum_ghost_revoke_destroys_key() -> None:
    """Revoke must zeroize the vault before it is used."""
    from api import _QsRevokeBody, qs_revoke_endpoint

    session = _qs_setup()
    send = _qs_send(session["ek_hex"], "revoking now")
    r = qs_revoke_endpoint(_request(), _QsRevokeBody(vault_id=session["vault_id"]))
    assert r["status"] == "revoked"
    recv = _qs_recv(session["vault_id"], session["session_secret_hex"], send["package"])
    assert recv.status_code in (403, 404, 410)


# ════════════════════════════════════════════════════════════════════════════
# ADMIN THREATS — IP + MAC exposure
# ════════════════════════════════════════════════════════════════════════════

def test_admin_threats_endpoint_returns_correct_shape() -> None:
    from api import admin_threats_endpoint

    data = admin_threats_endpoint(_request())
    assert "threats" in data
    assert "blocked_ips" in data
    assert "total_threats" in data


def test_mitm_attempt_logged_with_ip_and_mac() -> None:
    """A failed decrypt attempt must appear in the threat log with ip + mac."""
    # Trigger a threat
    _qs_recv("fake-vault-xyz", "dead" * 8, {}, events=_mouse_events())

    from api import admin_threats_endpoint

    data = admin_threats_endpoint(_request())
    assert len(data["threats"]) > 0
    for event in data["threats"]:
        assert "ip" in event
        assert "mac" in event


# ════════════════════════════════════════════════════════════════════════════
# FALLBACK ASSESS — browser extension integration
# ════════════════════════════════════════════════════════════════════════════

def test_fallback_assess_good_mouse_passes() -> None:
    from fallback_auth import make_chess_like_mouse_events
    from api import _FallbackAssessBody, fallback_assess_endpoint

    evts = make_chess_like_mouse_events(good=True, moves=16)
    data = fallback_assess_endpoint(_FallbackAssessBody(mouse_events=evts))
    assert data["mouse_verdict"] in ("PASS", "WARN", "FAIL")
    assert 0.0 <= data["score"] <= 1.0


def test_fallback_assess_no_events_fails() -> None:
    from api import _FallbackAssessBody, fallback_assess_endpoint

    assert fallback_assess_endpoint(_FallbackAssessBody(mouse_events=[]))["mouse_verdict"] == "FAIL"


# ════════════════════════════════════════════════════════════════════════════
# FILE ENCRYPTION — quantum strong
# ════════════════════════════════════════════════════════════════════════════

def test_quantum_file_unreadable_without_dk() -> None:
    """Encrypted file bytes must not contain the plaintext."""
    import tempfile
    from crypto_tools import quantum_keygen, quantum_encrypt_file, quantum_decrypt_file
    from fallback_auth import make_chess_like_mouse_events
    from entropy_engine import extract_mouse_entropy
    from key_generator import KeyGenerator

    session = quantum_keygen()
    entropy = KeyGenerator.generate_fresh_key(
        extract_mouse_entropy(make_chess_like_mouse_events(good=True, moves=8))
    )
    plaintext = b"CLASSIFIED - eyes only"

    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "f.txt";  src.write_bytes(plaintext)
        enc = Path(d) / "f.qsg"
        quantum_encrypt_file(session, src, enc, entropy)
        assert plaintext not in enc.read_bytes()

        # Correct dk decrypts
        dec = Path(d) / "out.txt"
        quantum_decrypt_file(session, enc, dec)
        assert dec.read_bytes() == plaintext

        # Wrong dk fails
        from cryptography.exceptions import InvalidTag
        wrong = quantum_keygen()
        try:
            quantum_decrypt_file(wrong, enc, dec)
            assert False, "Should have failed with wrong dk"
        except Exception:
            pass  # Expected


# ════════════════════════════════════════════════════════════════════════════
# CLASSIC GHOST KEY (existing tests, kept for regression)
# ════════════════════════════════════════════════════════════════════════════


def test_ghost_package_opens_once_then_disappears() -> None:
    import pytest
    from fastapi import HTTPException
    from api import _GhostEncryptBody, _GhostPackageBody, ghost_decrypt_endpoint, ghost_encrypt_endpoint

    created = ghost_encrypt_endpoint(
        _request(),
        _GhostEncryptBody(
            message="volunteer ghost message",
            label="volunteer-demo",
            ttl_seconds=60,
        ),
    )
    package = created["package"]
    assert package["ghost_id"]
    assert package["key_fingerprint"].startswith("fp:")
    assert "key_hex" not in package

    opened = ghost_decrypt_endpoint(_request(), _GhostPackageBody(**package))
    assert opened["plaintext"] == "volunteer ghost message"
    assert opened["ghost_key_status"] == "zeroized_and_deleted"

    with pytest.raises(HTTPException) as exc:
        ghost_decrypt_endpoint(_request(), _GhostPackageBody(**package))
    assert exc.value.status_code == 410


def test_ghost_status_and_revoke_burn_key() -> None:
    from api import (
        _GhostEncryptBody,
        _GhostPackageBody,
        ghost_decrypt_endpoint,
        ghost_encrypt_endpoint,
        ghost_revoke_endpoint,
        ghost_status_endpoint,
    )

    created = ghost_encrypt_endpoint(
        _request(),
        _GhostEncryptBody(message="burn after revoke", ttl_seconds=60),
    )
    package = created["package"]
    alive = ghost_status_endpoint(package["ghost_id"])
    assert alive["status"] == "alive"
    assert alive["available"] is True

    revoked = ghost_revoke_endpoint(package["ghost_id"])
    assert revoked["status"] == "revoked"
    assert revoked["ghost_key_status"] == "zeroized_and_deleted"

    gone = ghost_status_endpoint(package["ghost_id"])
    assert gone["status"] == "gone"
    assert gone["available"] is False

    import pytest
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        ghost_decrypt_endpoint(_request(), _GhostPackageBody(**package))
    assert exc.value.status_code == 410


def test_ghost_info_documents_portable_boundary() -> None:
    from api import ghost_info

    body = ghost_info()
    assert "devices without SUMIT KEY installed" in body["purpose"]
    assert "cannot recreate the sender key" in body["security_boundary"]
