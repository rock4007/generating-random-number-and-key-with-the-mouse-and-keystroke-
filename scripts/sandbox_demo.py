"""Sandbox demos for SUMIT KEY.

These demos use synthetic mouse and keystroke events so they run on headless
machines, CI, Codespaces, or any laptop without requiring real input capture.

Examples:
    python scripts/sandbox_demo.py --demo classic
    python scripts/sandbox_demo.py --demo ghost
    python scripts/sandbox_demo.py --demo quantum-ghost
    python scripts/sandbox_demo.py --demo file
    python scripts/sandbox_demo.py --demo all
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _line() -> None:
    print("-" * 72)


def _title(text: str) -> None:
    print()
    _line()
    print(text)
    _line()


def _note(text: str) -> None:
    print(f"  SIDE NOTE: {text}")


def _ok(text: str) -> None:
    print(f"  OK: {text}")


def _request() -> SimpleNamespace:
    return SimpleNamespace(client=SimpleNamespace(host="sandbox-demo"))


def _synthetic_mouse_events(moves: int = 10) -> list[dict]:
    from fallback_auth import make_chess_like_mouse_events

    return make_chess_like_mouse_events(good=True, moves=moves)


def _synthetic_keystroke_events() -> list[dict]:
    base = 1000.0
    letters = "sumitkey"
    events: list[dict] = []
    for index, key in enumerate(letters):
        press = base + index * 0.17 + (index % 3) * 0.013
        release = press + 0.075 + (index % 2) * 0.021
        previous_release = events[-1]["release_timestamp"] if events else press
        events.append(
            {
                "key": key,
                "press_timestamp": press,
                "release_timestamp": release,
                "dwell_time_ms": (release - press) * 1000,
                "flight_time_ms": (press - previous_release) * 1000,
            }
        )
    return events


def _make_demo_key() -> bytes:
    from entropy_engine import extract_keystroke_entropy, extract_mouse_entropy, pool_entropy
    from key_generator import KeyGenerator

    mouse_entropy = extract_mouse_entropy(_synthetic_mouse_events())
    key_entropy = extract_keystroke_entropy(_synthetic_keystroke_events())
    pooled = pool_entropy(mouse_entropy, key_entropy)
    return KeyGenerator.generate_fresh_key(
        pooled,
        system_random_bytes=b"sandbox-demo-system-random-32bytes!!",
        personalization=b"sandbox-demo-classical",
    )


def demo_classic() -> None:
    """Show synthetic entropy -> AES-GCM message encryption -> tamper reject."""

    from crypto_tools import EncryptedMessage, decrypt_message, encrypt_message

    _title("SANDBOX DEMO 1: Classical AES-GCM message")
    key = _make_demo_key()
    plaintext = "Sandbox volunteer message: hidden by SUMIT KEY."
    aad = b"sandbox-classic-message"

    encrypted = encrypt_message(key, plaintext, associated_data=aad)
    decrypted = decrypt_message(key, encrypted).decode("utf-8")

    print(f"  key fingerprint: {key.hex()[:16]}...")
    print(f"  nonce: {encrypted.nonce.hex()}")
    print(f"  ciphertext bytes: {len(encrypted.ciphertext)}")
    print(f"  decrypted message: {decrypted}")
    _ok("round trip succeeded")

    tampered = EncryptedMessage(
        nonce=encrypted.nonce,
        ciphertext=encrypted.ciphertext[:-1] + bytes([encrypted.ciphertext[-1] ^ 0x01]),
        associated_data=encrypted.associated_data,
    )
    try:
        decrypt_message(key, tampered)
        raise AssertionError("tampered ciphertext decrypted unexpectedly")
    except Exception:
        _ok("tampered ciphertext was rejected")
    _note("AES-GCM protects confidentiality and detects tampering.")


def demo_file() -> None:
    """Show file encryption and filename-AAD checking."""

    from crypto_tools import decrypt_file, encrypt_file

    _title("SANDBOX DEMO 2: File encryption")
    key = _make_demo_key()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source = root / "volunteer-note.txt"
        encrypted = root / "volunteer-note.sumitkey"
        output = root / "opened-note.txt"
        source.write_text("This file was encrypted in the sandbox demo.\n", encoding="utf-8")

        enc_info = encrypt_file(key, source, encrypted)
        dec_info = decrypt_file(key, encrypted, output, expected_name=source.name)

        print(f"  source bytes: {enc_info['original_size_bytes']}")
        print(f"  encrypted bytes: {enc_info['encrypted_size_bytes']}")
        print(f"  decrypted bytes: {dec_info['decrypted_size_bytes']}")
        print(f"  decrypted text: {output.read_text(encoding='utf-8').strip()}")
        _ok("file round trip succeeded")

        try:
            decrypt_file(key, encrypted, root / "wrong.txt", expected_name="wrong-name.txt")
            raise AssertionError("filename mismatch was not rejected")
        except ValueError:
            _ok("wrong expected filename was rejected")
    _note("The filename is bound as AES-GCM associated data.")


def demo_ghost() -> None:
    """Show classic API ghost package opens once, then disappears."""

    from api import (
        _GhostEncryptBody,
        _GhostPackageBody,
        ghost_decrypt_endpoint,
        ghost_encrypt_endpoint,
        ghost_status_endpoint,
    )
    from fastapi import HTTPException

    _title("SANDBOX DEMO 3: One-time ghost package")
    created = ghost_encrypt_endpoint(
        _request(),
        _GhostEncryptBody(
            message="Ghost demo message opens once, then the key is gone.",
            label="sandbox-ghost",
            ttl_seconds=60,
        ),
    )
    package = created["package"]
    print(f"  ghost id: {package['ghost_id']}")
    print(f"  key fingerprint: {package['key_fingerprint']}")
    print(f"  status before open: {ghost_status_endpoint(package['ghost_id'])['status']}")

    opened = ghost_decrypt_endpoint(_request(), _GhostPackageBody(**package))
    print(f"  plaintext: {opened['plaintext']}")
    print(f"  ghost key status: {opened['ghost_key_status']}")
    _ok("first open succeeded")

    try:
        ghost_decrypt_endpoint(_request(), _GhostPackageBody(**package))
        raise AssertionError("ghost package opened twice")
    except HTTPException as exc:
        if exc.status_code != 410:
            raise
        _ok("second open was blocked")
    print(f"  status after open: {ghost_status_endpoint(package['ghost_id'])['status']}")
    _note("This is the server-side burn-after-read demo path.")


def demo_quantum_ghost() -> None:
    """Show ML-KEM quantum ghost session with presence proof and burn."""

    from api import (
        _QsReceiveBody,
        _QsSendBody,
        _QsSessionBody,
        qs_receive_endpoint,
        qs_send_endpoint,
        qs_session_endpoint,
    )
    from fastapi import HTTPException

    _title("SANDBOX DEMO 4: Quantum ghost handoff")
    session = qs_session_endpoint(_request(), _QsSessionBody(ttl_seconds=60))
    sent = qs_send_endpoint(
        _request(),
        _QsSendBody(
            ek_hex=session["ek_hex"],
            message="Quantum ghost message for a second device.",
            mouse_events=_synthetic_mouse_events(),
            label="sandbox-quantum-ghost",
        ),
    )

    print(f"  vault id: {session['vault_id']}")
    print(f"  package format: {sent['package']['format']}")
    print(f"  kem fingerprint: {sent['package']['kem_fingerprint']}")

    opened = qs_receive_endpoint(
        _request(),
        _QsReceiveBody(
            vault_id=session["vault_id"],
            session_secret_hex=session["session_secret_hex"],
            package=sent["package"],
            mouse_events=_synthetic_mouse_events(),
        ),
    )
    print(f"  plaintext: {opened['plaintext']}")
    print(f"  ghost key status: {opened['ghost_key_status']}")
    _ok("quantum ghost opened and burned")

    try:
        qs_receive_endpoint(
            _request(),
            _QsReceiveBody(
                vault_id=session["vault_id"],
                session_secret_hex=session["session_secret_hex"],
                package=sent["package"],
                mouse_events=_synthetic_mouse_events(),
            ),
        )
        raise AssertionError("quantum ghost opened twice")
    except HTTPException as exc:
        if exc.status_code not in {403, 410}:
            raise
        _ok("second quantum open was blocked")
    _note("Receiver mouse events prove presence; they do not recreate sender key.")


def run_all() -> None:
    demo_classic()
    demo_file()
    demo_ghost()
    demo_quantum_ghost()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SUMIT KEY sandbox demos.")
    parser.add_argument(
        "--demo",
        choices=["classic", "file", "ghost", "quantum-ghost", "all"],
        default="all",
        help="Which sandbox demo to run.",
    )
    args = parser.parse_args()

    if args.demo == "classic":
        demo_classic()
    elif args.demo == "file":
        demo_file()
    elif args.demo == "ghost":
        demo_ghost()
    elif args.demo == "quantum-ghost":
        demo_quantum_ghost()
    else:
        run_all()

    print()
    _ok("sandbox demo completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
