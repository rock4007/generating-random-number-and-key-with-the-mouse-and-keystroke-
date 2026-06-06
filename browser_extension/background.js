"use strict";

const DEFAULT_API_BASE = "http://localhost:8000";
const REQUIRED_SCORE = 40;

let unlockInFlight = false;

function nowSeconds() {
  return Date.now() / 1000;
}

function storageGet(keys) {
  return chrome.storage.local.get(keys);
}

function storageSet(values) {
  return chrome.storage.local.set(values);
}

function storageRemove(keys) {
  return chrome.storage.local.remove(keys);
}

// ── Self-contained AES-256-GCM ghost crypto (no server required) ────────────

function b64enc(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function b64dec(s) {
  const raw = atob(s);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function generateGhostCode() {
  // 10 random hex chars split 5-5: e.g. "A3F9C-2B701"
  const b = new Uint8Array(5);
  crypto.getRandomValues(b);
  const hex = Array.from(b).map(v => v.toString(16).padStart(2, "0")).join("").toUpperCase();
  return `${hex.slice(0, 5)}-${hex.slice(5)}`;
}

async function deriveKey(ghostCode, salt, usages) {
  const raw = new TextEncoder().encode(ghostCode);
  const km = await crypto.subtle.importKey("raw", raw, { name: "PBKDF2" }, false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: 210000 },
    km,
    { name: "AES-GCM", length: 256 },
    false,
    usages,
  );
}

async function localEncrypt(message, ttlSeconds) {
  const salt  = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ghostCode = generateGhostCode();
  const key = await deriveKey(ghostCode, salt, ["encrypt"]);
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    key,
    new TextEncoder().encode(message),
  );
  const pkg = {
    mode: "local",
    ver: 1,
    cipher: b64enc(cipher),
    nonce:  b64enc(nonce),
    salt:   b64enc(salt),
    expires_at: Math.floor(Date.now() / 1000) + (ttlSeconds || 300),
  };
  return { pkg, ghostCode };
}

async function localDecrypt(pkg, ghostCode) {
  if (!pkg || pkg.mode !== "local") throw new Error("Not a local ghost package.");
  if (nowSeconds() > (pkg.expires_at || 0)) throw new Error("Package has expired.");
  const salt  = b64dec(pkg.salt);
  const nonce = b64dec(pkg.nonce);
  const cipher = b64dec(pkg.cipher);
  const key = await deriveKey(ghostCode, salt, ["decrypt"]);
  try {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, cipher);
    return new TextDecoder().decode(plain);
  } catch {
    throw new Error("Wrong ghost code, or package is tampered / expired.");
  }
}

// ── API helpers (optional, used when server is reachable) ──────────────────

async function apiBase() {
  const stored = await storageGet(["apiBase"]);
  return (stored.apiBase || DEFAULT_API_BASE).replace(/\/+$/, "");
}

async function apiGet(path) {
  const response = await fetch(`${await apiBase()}${path}`);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || body.error || response.statusText);
  return body;
}

async function apiPost(path, body) {
  const response = await fetch(`${await apiBase()}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || payload.error || response.statusText);
  return payload;
}

async function isApiOnline() {
  try {
    await apiGet("/health");
    return true;
  } catch {
    return false;
  }
}

async function notify(title, message) {
  await storageSet({ lastNotice: { title, message, at: nowSeconds() } });
}

// ── Presence tracking ──────────────────────────────────────────────────────

async function updatePresence(event) {
  const stored = await storageGet(["presence"]);
  const presence = stored.presence || { moves: 0, keys: 0, score: 0, lastAt: 0 };
  if (event.kind === "mouse") presence.moves += 1;
  if (event.kind === "key")   presence.keys  += 1;
  presence.lastAt = nowSeconds();
  presence.score = Math.min(100, Math.round((presence.moves * 1.4) + (presence.keys * 4)));
  await storageSet({ presence });
  await maybeAutoUnlock();
}

// ── Ghost package lifecycle (API mode) ─────────────────────────────────────

async function createGhostPackage({ message, label, ttlSeconds }) {
  const result = await apiPost("/ghost/encrypt", {
    message,
    label: label || "extension-ghost-message",
    ttl_seconds: ttlSeconds || 120,
  });
  await storageSet({
    lastCreatedPackage: result.package,
    activeGhostId: result.package.ghost_id,
    lastGhostCode: null,
  });
  chrome.alarms.create(`ghost_expiry_${result.package.ghost_id}`, {
    delayInMinutes: Math.max(0.1, ((result.package.expires_at * 1000) - Date.now()) / 60000),
  });
  return result;
}

async function setPendingPackage(packageData, autoUnlock = true) {
  await storageSet({ pendingGhostPackage: packageData, autoUnlock, lastUnlock: null });
  await maybeAutoUnlock();
}

async function maybeAutoUnlock() {
  if (unlockInFlight) return;
  const stored = await storageGet(["pendingGhostPackage", "presence", "autoUnlock"]);
  if (!stored.pendingGhostPackage || stored.autoUnlock === false) return;
  const presence = stored.presence || { score: 0 };
  if ((presence.score || 0) < REQUIRED_SCORE) return;
  // Local packages need the ghost code — auto-unlock only works for API packages
  if (stored.pendingGhostPackage.mode === "local") return;
  await unlockPendingPackage();
}

async function unlockPendingPackage() {
  unlockInFlight = true;
  try {
    const stored = await storageGet(["pendingGhostPackage", "presence"]);
    const packageData = stored.pendingGhostPackage;
    if (!packageData) throw new Error("No ghost package is waiting.");
    const presence = stored.presence || { score: 0 };
    if ((presence.score || 0) < REQUIRED_SCORE) {
      throw new Error("Move the mouse or type a few keys on this device first.");
    }
    const result = await apiPost("/ghost/decrypt", packageData);
    await storageSet({
      lastUnlock: {
        plaintext: result.plaintext,
        plaintextBytesHex: result.plaintext_bytes_hex,
        keyFingerprint: result.key_fingerprint,
        ghostKeyStatus: result.ghost_key_status,
        openedAt: nowSeconds(),
      },
    });
    await storageRemove(["pendingGhostPackage", "activeGhostId"]);
    await notify("SUMIT KEY: Ghost Opened", "Message opened once. Ghost key is gone.");
    return result;
  } finally {
    unlockInFlight = false;
  }
}

async function revokeGhost(ghostId) {
  const result = await apiPost(`/ghost/revoke/${encodeURIComponent(ghostId)}`, {});
  await storageRemove(["pendingGhostPackage", "activeGhostId"]);
  return result;
}

// ── Alarm handlers ─────────────────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(() => {
  storageSet({
    apiBase: DEFAULT_API_BASE,
    presence: { moves: 0, keys: 0, score: 0, lastAt: 0 },
  });
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === "presence_decay") {
    const stored = await storageGet(["presence"]);
    const presence = stored.presence || { moves: 0, keys: 0, score: 0, lastAt: 0 };
    if (nowSeconds() - (presence.lastAt || 0) > 90) {
      await storageSet({ presence: { moves: 0, keys: 0, score: 0, lastAt: 0 } });
    }
    return;
  }
  if (alarm.name.startsWith("ghost_expiry_")) {
    const ghostId = alarm.name.replace("ghost_expiry_", "");
    const stored = await storageGet(["activeGhostId"]);
    if (stored.activeGhostId === ghostId) {
      await storageRemove(["pendingGhostPackage", "activeGhostId"]);
      await notify("SUMIT KEY: Ghost Expired", "The ghost key expired before it was opened.");
    }
  }
});

chrome.alarms.create("presence_decay", { periodInMinutes: 1 });

// ── Message router ─────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  (async () => {

    if (message.type === "presence_event") {
      await updatePresence(message.event);
      return { ok: true };
    }

    if (message.type === "get_state") {
      const state = await storageGet([
        "apiBase", "presence", "pendingGhostPackage",
        "lastCreatedPackage", "lastUnlock", "activeGhostId", "lastGhostCode",
      ]);
      const apiStatus = await isApiOnline() ? "online" : "offline";
      return { ok: true, state: { ...state, apiStatus, requiredScore: REQUIRED_SCORE } };
    }

    if (message.type === "set_api_base") {
      await storageSet({ apiBase: message.apiBase || DEFAULT_API_BASE });
      return { ok: true };
    }

    // Create ghost package — tries API first, falls back to local AES-256-GCM
    if (message.type === "create_package") {
      const online = await isApiOnline();
      if (online) {
        try {
          return { ok: true, result: await createGhostPackage(message), local: false };
        } catch {
          // fall through to local
        }
      }
      const { pkg, ghostCode } = await localEncrypt(message.message, message.ttlSeconds || 120);
      await storageSet({ lastCreatedPackage: pkg, activeGhostId: null, lastGhostCode: ghostCode });
      return { ok: true, result: { package: pkg }, ghostCode, local: true };
    }

    if (message.type === "set_pending_package") {
      await setPendingPackage(message.packageData, message.autoUnlock !== false);
      return { ok: true };
    }

    // API-mode unlock
    if (message.type === "unlock_now") {
      return { ok: true, result: await unlockPendingPackage() };
    }

    // Local-mode unlock (AES-256-GCM, no server)
    if (message.type === "local_decrypt") {
      const stored = await storageGet(["pendingGhostPackage", "presence"]);
      const presence = stored.presence || { score: 0 };
      if ((presence.score || 0) < REQUIRED_SCORE) {
        throw new Error("Move the mouse or type on this device first.");
      }
      const pkg = message.packageData || stored.pendingGhostPackage;
      if (!pkg) throw new Error("No ghost package saved.");
      const plaintext = await localDecrypt(pkg, message.ghostCode);
      await storageSet({ lastUnlock: { plaintext, openedAt: nowSeconds() } });
      await storageRemove(["pendingGhostPackage"]);
      await notify("SUMIT KEY: Ghost Opened", "Message opened once. Ghost key burned.");
      return { ok: true, plaintext };
    }

    if (message.type === "status") {
      return { ok: true, result: await apiGet(`/ghost/status/${encodeURIComponent(message.ghostId)}`) };
    }

    if (message.type === "revoke") {
      return { ok: true, result: await revokeGhost(message.ghostId) };
    }

    if (message.type === "clear") {
      await storageRemove(["pendingGhostPackage", "lastCreatedPackage", "lastUnlock", "activeGhostId", "lastGhostCode"]);
      return { ok: true };
    }

    return { ok: false, error: "Unknown message type" };

  })()
    .then(sendResponse)
    .catch((error) => sendResponse({ ok: false, error: error.message }));
  return true;
});
