"use strict";

function $(id) { return document.getElementById(id); }

function send(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (!response || !response.ok) {
        reject(new Error((response && response.error) || "Extension action failed"));
        return;
      }
      resolve(response);
    });
  });
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function isLocalPackage(pkg) {
  return pkg && pkg.mode === "local";
}

function packageSummary(pkg) {
  if (!pkg) return "No package yet.";
  if (isLocalPackage(pkg)) {
    const exp = new Date(pkg.expires_at * 1000).toLocaleTimeString();
    return `local ghost package ready\nmode: AES-256-GCM (no server)\nexpires: ${exp}\n\n${JSON.stringify(pkg, null, 2)}`;
  }
  return [
    "ghost package ready",
    `ghost_id: ${pkg.ghost_id}`,
    `key fingerprint: ${pkg.key_fingerprint}`,
    `expires_at: ${new Date(pkg.expires_at * 1000).toLocaleTimeString()}`,
    "",
    JSON.stringify(pkg, null, 2),
  ].join("\n");
}

function showGhostCodeBox(code) {
  $("ghostCodeText").textContent = code;
  $("ghostCodeDisplay").style.display = "";
  $("copyCode").style.display = "";
  $("revokePackage").style.display = "none";
}

function hideGhostCodeBox() {
  $("ghostCodeDisplay").style.display = "none";
  $("copyCode").style.display = "none";
}

// Show/hide ghost code input in receive tab based on whether pasted package is local
function updateGhostCodeInput() {
  const raw = $("packageText").value.trim();
  if (!raw) { $("ghostCodeWrap").style.display = "none"; return; }
  try {
    const pkg = JSON.parse(raw);
    $("ghostCodeWrap").style.display = isLocalPackage(pkg) ? "" : "none";
  } catch {
    $("ghostCodeWrap").style.display = "none";
  }
}

// ── State refresh ───────────────────────────────────────────────────────────

async function refreshState() {
  const { state } = await send({ type: "get_state" });

  $("apiStatus").textContent = state.apiStatus === "online" ? "API online" : "local mode";
  $("apiStatus").className   = `pill ${state.apiStatus === "online" ? "good" : "warn"}`;
  $("apiBase").value = state.apiBase || "http://localhost:8000";

  const presence = state.presence || { score: 0, moves: 0, keys: 0 };
  const required = state.requiredScore || 40;
  $("presenceScore").textContent = String(presence.score || 0);
  $("requiredScore").textContent = String(required);
  $("presenceBar").style.width   = `${Math.min(100, Math.round(((presence.score || 0) / required) * 100))}%`;

  // Restore ghost code display if we have one stored
  if (state.lastGhostCode) {
    showGhostCodeBox(state.lastGhostCode);
  }

  if (state.lastCreatedPackage) {
    $("sendOutput").textContent = packageSummary(state.lastCreatedPackage);
    // Show revoke button only for API packages
    if (!isLocalPackage(state.lastCreatedPackage)) {
      $("revokePackage").style.display = "";
      $("copyCode").style.display = "none";
    }
  }

  if (state.pendingGhostPackage) {
    $("receiveOutput").textContent = [
      "package waiting",
      isLocalPackage(state.pendingGhostPackage)
        ? "Enter the ghost code and click Open Now"
        : "move/type on any webpage; it will open automatically when presence is ready",
    ].join("\n");
  }

  if (state.lastUnlock) {
    $("receiveOutput").textContent = [
      "ghost opened",
      state.lastUnlock.keyFingerprint ? `key fingerprint: ${state.lastUnlock.keyFingerprint}` : "",
      state.lastUnlock.ghostKeyStatus ? `ghost key status: ${state.lastUnlock.ghostKeyStatus}` : "",
      "",
      state.lastUnlock.plaintext || `(binary hex) ${state.lastUnlock.plaintextBytesHex}`,
    ].filter(Boolean).join("\n");
  }
}

// ── Tab navigation ──────────────────────────────────────────────────────────

document.querySelectorAll(".tab").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
    button.classList.add("active");
    $(button.dataset.tab).classList.add("active");
    refreshState().catch((err) => {
      $("apiStatus").textContent = err.message;
      $("apiStatus").className = "pill bad";
    });
  });
});

// ── Send tab ────────────────────────────────────────────────────────────────

$("createPackage").addEventListener("click", async () => {
  const message = $("message").value.trim();
  if (!message) { $("sendOutput").textContent = "Type a message first."; return; }
  $("sendOutput").textContent = "creating ghost package...";
  hideGhostCodeBox();
  try {
    const resp = await send({
      type: "create_package",
      message,
      label: $("label").value.trim() || "volunteer-demo",
      ttlSeconds: Number($("ttl").value || 120),
    });
    $("sendOutput").textContent = packageSummary(resp.result.package);
    if (resp.local && resp.ghostCode) {
      showGhostCodeBox(resp.ghostCode);
    } else if (!resp.local) {
      // API mode — show revoke button
      $("revokePackage").style.display = "";
    }
  } catch (err) {
    $("sendOutput").textContent = `error: ${err.message}`;
  }
});

$("copyPackage").addEventListener("click", async () => {
  const { state } = await send({ type: "get_state" });
  if (!state.lastCreatedPackage) { $("sendOutput").textContent = "Create a package first."; return; }
  await navigator.clipboard.writeText(JSON.stringify(state.lastCreatedPackage, null, 2));
  $("sendOutput").textContent = `${packageSummary(state.lastCreatedPackage)}\n\npackage JSON copied to clipboard`;
});

$("copyCode").addEventListener("click", async () => {
  const code = $("ghostCodeText").textContent;
  if (!code) return;
  await navigator.clipboard.writeText(code);
  const prev = $("ghostCodeText").textContent;
  $("ghostCodeText").textContent = "copied!";
  setTimeout(() => { $("ghostCodeText").textContent = prev; }, 900);
});

$("revokePackage").addEventListener("click", async () => {
  const { state } = await send({ type: "get_state" });
  const ghostId = state.activeGhostId || (state.lastCreatedPackage && state.lastCreatedPackage.ghost_id);
  if (!ghostId) { $("sendOutput").textContent = "No API ghost package to revoke."; return; }
  try {
    const { result } = await send({ type: "revoke", ghostId });
    $("sendOutput").textContent = `revoked: ${JSON.stringify(result, null, 2)}`;
    $("revokePackage").style.display = "none";
  } catch (err) {
    $("sendOutput").textContent = `revoke error: ${err.message}`;
  }
});

// ── Receive tab ─────────────────────────────────────────────────────────────

$("packageText").addEventListener("input", updateGhostCodeInput);

$("savePackage").addEventListener("click", async () => {
  try {
    const packageData = JSON.parse($("packageText").value);
    await send({ type: "set_pending_package", packageData, autoUnlock: !isLocalPackage(packageData) });
    $("receiveOutput").textContent = isLocalPackage(packageData)
      ? "package saved; enter ghost code and click Open Now"
      : "package saved; move/type on any webpage to auto open";
    await refreshState();
  } catch (err) {
    $("receiveOutput").textContent = `package error: ${err.message}`;
  }
});

$("unlockNow").addEventListener("click", async () => {
  try {
    // Determine if pending package is local or API mode
    const { state } = await send({ type: "get_state" });
    const pkg = state.pendingGhostPackage;

    if (pkg && isLocalPackage(pkg)) {
      const ghostCode = $("ghostCode").value.trim();
      if (!ghostCode) {
        $("receiveOutput").textContent = "Enter the ghost code from the sender first.";
        return;
      }
      const resp = await send({ type: "local_decrypt", packageData: pkg, ghostCode });
      $("receiveOutput").textContent = ["ghost opened", "", resp.plaintext].join("\n");
    } else {
      const { result } = await send({ type: "unlock_now" });
      $("receiveOutput").textContent = [
        "ghost opened",
        `key fingerprint: ${result.key_fingerprint}`,
        `ghost key status: ${result.ghost_key_status}`,
        "",
        result.plaintext || `(binary hex) ${result.plaintext_bytes_hex}`,
      ].join("\n");
    }

    $("ghostCode").value = "";
    $("ghostCodeWrap").style.display = "none";
    await refreshState();
  } catch (err) {
    $("receiveOutput").textContent = `open error: ${err.message}`;
  }
});

$("clearAll").addEventListener("click", async () => {
  await send({ type: "clear" });
  $("packageText").value = "";
  $("ghostCode").value = "";
  $("ghostCodeWrap").style.display = "none";
  $("receiveOutput").textContent = "local ghost data cleared";
  $("sendOutput").textContent = "No package yet.";
  hideGhostCodeBox();
  await refreshState();
});

// ── Settings tab ─────────────────────────────────────────────────────────────

$("saveApi").addEventListener("click", async () => {
  await send({ type: "set_api_base", apiBase: $("apiBase").value.trim() });
  await refreshState();
});

$("refreshState").addEventListener("click", () => {
  refreshState().catch((err) => {
    $("apiStatus").textContent = err.message;
    $("apiStatus").className = "pill bad";
  });
});

// ── Init ─────────────────────────────────────────────────────────────────────

refreshState().catch((err) => {
  $("apiStatus").textContent = err.message;
  $("apiStatus").className = "pill bad";
});
