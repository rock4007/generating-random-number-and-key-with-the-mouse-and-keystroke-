"use strict";

let active = false;
let mouseEvents = [];
let keystrokeEvents = [];
let keyDown = new Map();
let lastRelease = null;
let lastMouseSample = 0;

function resetCapture() {
  mouseEvents = [];
  keystrokeEvents = [];
  keyDown = new Map();
  lastRelease = null;
  lastMouseSample = 0;
}

function nowMs() {
  return performance.now();
}

function onMouseMove(event) {
  if (!active) return;

  const t = nowMs();

  if (t - lastMouseSample < 8) {
    return;
  }

  lastMouseSample = t;

  mouseEvents.push({
    x: event.clientX,
    y: event.clientY,
    t
  });

  if (mouseEvents.length > 5000) {
    mouseEvents.shift();
  }
}

function onKeyDown(event) {
  if (!active) return;
  if (event.repeat) return;

  keyDown.set(
    event.code,
    nowMs()
  );
}

function onKeyUp(event) {
  if (!active) return;

  const release = nowMs();
  const press = keyDown.get(event.code);

  if (press === undefined) {
    return;
  }

  keyDown.delete(event.code);

  const dwell = Math.max(
    0,
    release - press
  );

  const flight =
    lastRelease === null
      ? 0
      : Math.max(
          0,
          press - lastRelease
        );

  lastRelease = release;

  keystrokeEvents.push({
    dwell_ms: dwell,
    flight_ms: flight,
    t: release
  });

  if (keystrokeEvents.length > 2000) {
    keystrokeEvents.shift();
  }
}

document.addEventListener(
  "mousemove",
  onMouseMove,
  {
    passive: true
  }
);

document.addEventListener(
  "keydown",
  onKeyDown,
  true
);

document.addEventListener(
  "keyup",
  onKeyUp,
  true
);

chrome.runtime.onMessage.addListener(
  (
    message,
    _sender,
    sendResponse
  ) => {

    if (
      message.type ===
      "sumit_capture_start"
    ) {
      resetCapture();

      active = true;

      sendResponse({
        ok: true
      });

      return;
    }

    if (
      message.type ===
      "sumit_capture_stop"
    ) {
      active = false;

      sendResponse({
        ok: true,
        capture: {
          mouse_events:
            mouseEvents,
          keystroke_events:
            keystrokeEvents
        }
      });

      resetCapture();

      return;
    }

    if (
      message.type ===
      "sumit_capture_cancel"
    ) {
      active = false;

      resetCapture();

      sendResponse({
        ok: true
      });
    }
  }
);