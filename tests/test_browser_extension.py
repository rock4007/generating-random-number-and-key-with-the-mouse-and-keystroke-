from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXT = ROOT / "browser_extension"


def test_extension_registers_content_script_for_presence_capture() -> None:
    manifest = json.loads((EXT / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["manifest_version"] == 3
    assert "storage" in manifest["permissions"]
    assert manifest["background"]["service_worker"] == "background.js"
    assert manifest["content_scripts"][0]["js"] == ["content.js"]
    assert "http://*/*" in manifest["content_scripts"][0]["matches"]
    assert "https://*/*" in manifest["content_scripts"][0]["matches"]


def test_extension_uses_current_ghost_api_and_auto_unlock_gate() -> None:
    background = (EXT / "background.js").read_text(encoding="utf-8")
    popup = (EXT / "popup.js").read_text(encoding="utf-8")
    content = (EXT / "content.js").read_text(encoding="utf-8")

    assert 'apiPost("/ghost/encrypt"' in background
    assert 'apiPost("/ghost/decrypt"' in background
    assert "/ghost/quantum" not in background
    assert "/ghost/quantum" not in popup
    assert "REQUIRED_SCORE" in background
    assert "maybeAutoUnlock" in background
    assert 'sendPresence("mouse")' in content
    assert 'sendPresence("key")' in content
