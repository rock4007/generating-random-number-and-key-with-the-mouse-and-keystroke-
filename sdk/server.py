"""sdk/server.py — Minimal SUMIT KEY REST server.

Run:  uvicorn sdk.server:app --port 8000

Four endpoints — no hardware, no mouse capture, no NIST tests.
Drops in front of any platform as an encryption proxy.

    POST /key/new          → generate a fresh key
    POST /encrypt          → encrypt text or file bytes
    POST /decrypt          → decrypt any SUMIT KEY envelope
    GET  /health           → liveness check
"""

from __future__ import annotations

import base64
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from sdk.core import SumitKey, SumitKeyError

app = FastAPI(
    title="SUMIT KEY",
    description="Lightweight encryption layer for any social / messaging platform.",
    version="1.0.0",
)

# Allow any origin — designed to be called from browser extensions,
# mobile apps, and third-party integrations.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

_sk = SumitKey()


# ─── Models ───────────────────────────────────────────────────────────────────

class KeyRequest(BaseModel):
    passphrase: str = ""
    label: str = ""

class EncryptTextRequest(BaseModel):
    plaintext: str
    key_b64: str
    context: str = ""

class EncryptFileRequest(BaseModel):
    data_b64: str       # base64-encoded file bytes
    filename: str
    key_b64: str
    context: str = ""

class DecryptRequest(BaseModel):
    envelope: str
    key_b64: str


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "SUMIT KEY lightweight SDK"}


@app.post("/key/new")
def new_key(body: KeyRequest) -> dict[str, Any]:
    """Generate a fresh AES-256 key.

    Share the returned key_b64 with your contact via a secure side-channel
    (QR code, ghost code, in-person). Everything else travels over the normal
    messaging platform.
    """
    key_b64 = _sk.new_key(passphrase=body.passphrase or None)
    return {
        "key_b64":     key_b64,
        "fingerprint": _sk.fingerprint(key_b64),
        "qr_payload":  _sk.key_to_qr_payload(key_b64, body.label or "SUMIT KEY"),
        "note": (
            "Keep key_b64 secret. Share it with your contact via QR code or "
            "a different channel from the one you use to send messages."
        ),
    }


@app.post("/encrypt")
def encrypt_text(body: EncryptTextRequest) -> dict[str, Any]:
    """Encrypt a text message.

    Paste the returned envelope into any messaging platform —
    WhatsApp, Telegram, iMessage, Instagram DM, Gmail, etc.
    The platform sees only an opaque JSON string; it cannot read the content.
    """
    try:
        envelope = _sk.encrypt_text(body.plaintext, body.key_b64, context=body.context)
    except SumitKeyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "envelope":     envelope,
        "hint":         "Paste this envelope into your messaging platform.",
        "platform":     body.context or "any",
        "fingerprint":  _sk.fingerprint(body.key_b64),
    }


@app.post("/encrypt-file")
def encrypt_file(body: EncryptFileRequest) -> dict[str, Any]:
    """Encrypt a document, image, or any binary file.

    Send the envelope as a .sumitkey attachment or store in cloud storage.
    Only the holder of key_b64 can decrypt it.
    """
    try:
        raw = base64.b64decode(body.data_b64)
    except Exception as exc:
        raise HTTPException(status_code=422, detail="data_b64 is not valid base64") from exc
    try:
        envelope = _sk.encrypt_file(raw, body.filename, body.key_b64, context=body.context)
    except SumitKeyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "envelope":    envelope,
        "filename":    body.filename,
        "fingerprint": _sk.fingerprint(body.key_b64),
        "hint":        f"Save as {body.filename}.sumitkey or attach to any platform.",
    }


@app.post("/decrypt")
def decrypt(body: DecryptRequest) -> dict[str, Any]:
    """Decrypt any SUMIT KEY envelope — text or file."""
    try:
        raw = _sk.decrypt(body.envelope, body.key_b64)
    except SumitKeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        text = raw.decode("utf-8")
        return {"content_type": "text", "plaintext": text}
    except UnicodeDecodeError:
        return {
            "content_type": "binary",
            "data_b64": base64.b64encode(raw).decode("ascii"),
        }
