/**
 * SUMIT KEY — Browser SDK  v1.0.0
 *
 * Zero dependencies. Uses only the Web Crypto API (built into every browser).
 * Drop this file into any web page, extension, or PWA.
 *
 * Quick start:
 *   const key = await SumitKey.newKey();
 *   const env = await SumitKey.encryptText("hello", key);
 *   const msg = await SumitKey.decryptText(env, key);
 *
 * Platform integration pattern:
 *   1. Generate key → share via QR code / ghost code (separate channel)
 *   2. encrypt*() before posting to WhatsApp / Telegram / Gmail / Drive
 *   3. Paste the returned envelope into the platform as-is
 *   4. Recipient: decrypt*() the envelope using the shared key
 */

"use strict";

const SumitKey = (() => {

  const MAGIC   = "SUMITKEY1";
  const VERSION = 1;
  const ALGO    = { name: "AES-GCM", length: 256 };
  const PBKDF2  = { name: "PBKDF2", hash: "SHA-256", iterations: 210_000 };

  // ── Encoding helpers ────────────────────────────────────────────────────────

  const enc = new TextEncoder();
  const dec = new TextDecoder();

  function b64enc(buf) {
    const bytes = new Uint8Array(buf);
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }

  function b64dec(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const raw = atob(s);
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out.buffer;
  }

  // ── Key generation ──────────────────────────────────────────────────────────

  /**
   * Generate a fresh AES-256 key.
   * @param {string} [passphrase] - optional; strengthened via PBKDF2
   * @returns {Promise<string>} URL-safe base64 key string
   */
  async function newKey(passphrase = "") {
    if (passphrase) {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const km   = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveBits"]);
      const bits = await crypto.subtle.deriveBits({ ...PBKDF2, salt }, km, 256);
      return b64enc(bits);
    }
    const raw = crypto.getRandomValues(new Uint8Array(32));
    return b64enc(raw);
  }

  /**
   * Import a base64 key string into a CryptoKey object.
   */
  async function _importKey(keyB64, usage) {
    const raw = b64dec(keyB64);
    return crypto.subtle.importKey("raw", raw, ALGO, false, [usage]);
  }

  // ── Encryption ──────────────────────────────────────────────────────────────

  /**
   * Encrypt text.  Returns a JSON string safe to paste anywhere.
   * @param {string} plaintext
   * @param {string} keyB64
   * @param {string} [context]  - optional platform label, e.g. "whatsapp"
   */
  async function encryptText(plaintext, keyB64, context = "") {
    return _encrypt(enc.encode(plaintext), keyB64, "text", "", context);
  }

  /**
   * Encrypt a File or ArrayBuffer (document, image, etc.).
   * @param {File|ArrayBuffer} data
   * @param {string} keyB64
   * @param {string} [context]
   */
  async function encryptFile(data, keyB64, context = "") {
    const filename = data instanceof File ? data.name : "file";
    const buf      = data instanceof File ? await data.arrayBuffer() : data;
    return _encrypt(buf, keyB64, "file", filename, context);
  }

  async function _encrypt(plainBuf, keyB64, contentType, filename, context) {
    const key   = await _importKey(keyB64, "encrypt");
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const aad   = enc.encode(`${contentType}|${filename}|${context}`);
    const ct    = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, key, plainBuf);
    const fp    = b64enc(await crypto.subtle.digest("SHA-256", b64dec(keyB64))).slice(0, 16);
    return JSON.stringify({
      magic: MAGIC, version: VERSION,
      content_type: contentType, filename, context,
      nonce: b64enc(nonce), ciphertext: b64enc(ct),
      fp: "fp:" + fp,
    });
  }

  // ── Decryption ──────────────────────────────────────────────────────────────

  /**
   * Decrypt any SUMIT KEY envelope.  Returns ArrayBuffer.
   */
  async function decrypt(envelope, keyB64) {
    let pkg;
    try { pkg = JSON.parse(envelope); } catch { throw new Error("envelope is not valid JSON"); }
    if (pkg.magic !== MAGIC)       throw new Error("not a SUMIT KEY envelope");
    if (pkg.version !== VERSION)   throw new Error(`unsupported version ${pkg.version}`);

    const key = await _importKey(keyB64, "decrypt");
    const aad = enc.encode(`${pkg.content_type}|${pkg.filename || ""}|${pkg.context || ""}`);
    try {
      return await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: b64dec(pkg.nonce), additionalData: aad },
        key,
        b64dec(pkg.ciphertext),
      );
    } catch {
      throw new Error("Decryption failed — wrong key or tampered envelope");
    }
  }

  /**
   * Decrypt a text envelope.  Returns a string.
   */
  async function decryptText(envelope, keyB64) {
    return dec.decode(await decrypt(envelope, keyB64));
  }

  /**
   * Decrypt a file envelope.  Returns a Blob.
   */
  async function decryptFile(envelope, keyB64) {
    const pkg = JSON.parse(envelope);
    const buf = await decrypt(envelope, keyB64);
    return new Blob([buf], { type: "application/octet-stream" });
  }

  // ── Key utilities ───────────────────────────────────────────────────────────

  /**
   * Returns a short fingerprint — safe to display, never reveals key material.
   */
  async function fingerprint(keyB64) {
    const hash = await crypto.subtle.digest("SHA-256", b64dec(keyB64));
    return "fp:" + b64enc(hash).slice(0, 16);
  }

  /**
   * Returns a QR-code-ready string for key exchange.
   */
  function keyToQr(keyB64, label = "SUMIT KEY") {
    return `SUMITKEY://v1/${keyB64}?label=${encodeURIComponent(label)}`;
  }

  function keyFromQr(payload) {
    if (!payload.startsWith("SUMITKEY://v1/")) throw new Error("not a SUMIT KEY QR payload");
    return payload.slice("SUMITKEY://v1/".length).split("?")[0];
  }

  // ── Platform helpers ────────────────────────────────────────────────────────

  /**
   * Format an envelope for a specific platform.
   * Some platforms truncate long text — this packs it safely.
   */
  function wrapForPlatform(envelope, platform = "generic") {
    const tag = `[🔒 SUMIT KEY ${platform.toUpperCase()} — decrypt at sumitkey.app]`;
    return `${tag}\n${envelope}`;
  }

  function unwrapFromPlatform(text) {
    const lines = text.split("\n");
    return lines.find(l => {
      try { const p = JSON.parse(l); return p.magic === MAGIC; } catch { return false; }
    }) || text.trim();
  }

  // ── Copy to clipboard helper ────────────────────────────────────────────────

  async function copyToClipboard(text) {
    if (navigator.clipboard) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement("textarea");
      ta.value = text; document.body.appendChild(ta); ta.select();
      document.execCommand("copy"); document.body.removeChild(ta);
    }
  }

  // ── Public API ──────────────────────────────────────────────────────────────

  return {
    newKey, fingerprint, keyToQr, keyFromQr,
    encryptText, encryptFile,
    decrypt, decryptText, decryptFile,
    wrapForPlatform, unwrapFromPlatform,
    copyToClipboard,
  };

})();

// CommonJS / Node export
if (typeof module !== "undefined") module.exports = SumitKey;
