"use strict";

let lastMouseAt = 0;
let lastKeyAt = 0;

function sendPresence(kind) {
  chrome.runtime.sendMessage({
    type: "presence_event",
    event: {
      kind,
      at: Date.now(),
      url: location.origin,
    },
  }, () => {
    if (chrome.runtime.lastError) {
      return;
    }
  });
}

document.addEventListener("mousemove", () => {
  const now = Date.now();
  if (now - lastMouseAt < 120) return;
  lastMouseAt = now;
  sendPresence("mouse");
}, { passive: true });

document.addEventListener("keydown", (event) => {
  if (event.ctrlKey || event.metaKey || event.altKey) return;
  const now = Date.now();
  if (now - lastKeyAt < 150) return;
  lastKeyAt = now;
  sendPresence("key");
}, { passive: true });
