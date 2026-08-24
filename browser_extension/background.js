"use strict";

const DEFAULT_API_BASE =
  "http://127.0.0.1:8000";

function sleep(ms) {
  return new Promise(
    resolve => setTimeout(
      resolve,
      ms
    )
  );
}

async function storageGet(keys) {
  return chrome.storage.local.get(
    keys
  );
}

async function storageSet(values) {
  return chrome.storage.local.set(
    values
  );
}

async function apiBase() {
  const stored = await storageGet(
    ["apiBase"]
  );

  return (
    stored.apiBase ||
    DEFAULT_API_BASE
  ).replace(
    /\/+$/,
    ""
  );
}

async function apiPost(
  path,
  body
) {
  const response = await fetch(
    `${await apiBase()}${path}`,
    {
      method: "POST",
      headers: {
        "Content-Type":
          "application/json"
      },
      body: JSON.stringify(body)
    }
  );

  const payload =
    await response
      .json()
      .catch(
        () => ({})
      );

  if (!response.ok) {
    throw new Error(
      payload.detail ||
      payload.error ||
      response.statusText
    );
  }

  return payload;
}

async function apiGet(path) {
  const response = await fetch(
    `${await apiBase()}${path}`
  );

  const payload =
    await response
      .json()
      .catch(
        () => ({})
      );

  if (!response.ok) {
    throw new Error(
      payload.detail ||
      payload.error ||
      response.statusText
    );
  }

  return payload;
}

async function activeTab() {
  const [tab] =
    await chrome.tabs.query({
      active: true,
      currentWindow: true
    });

  if (!tab || !tab.id) {
    throw new Error(
      "No active webpage tab found"
    );
  }

  return tab;
}

async function captureBehaviour(
  durationMs = 5000
) {
  const tab =
    await activeTab();

  await chrome.tabs.sendMessage(
    tab.id,
    {
      type:
        "sumit_capture_start"
    }
  );

  await sleep(
    durationMs
  );

  const result =
    await chrome.tabs.sendMessage(
      tab.id,
      {
        type:
          "sumit_capture_stop"
      }
    );

  if (
    !result ||
    !result.ok
  ) {
    throw new Error(
      "Behaviour capture failed"
    );
  }

  const stored =
    await storageGet(
      ["deviceProfile"]
    );

  const device =
    stored.deviceProfile || {
      device_id:
        "browser-device-1",
      dpi: 800,
      polling_rate_hz: 125,
      screen_width: 1920,
      screen_height: 1080,
      operating_system:
        navigator.platform ||
        "unknown",
      input_type: "mouse"
    };

  return {
    mouse_events:
      result.capture
        .mouse_events,

    keystroke_events:
      result.capture
        .keystroke_events,

    device
  };
}

async function enrolUser({
  userId,
  email,
  phone,
  durationMs = 5000
}) {
  const capture =
    await captureBehaviour(
      durationMs
    );

  return apiPost(
    "/auth/enrol",
    {
      user_id: userId,
      email:
        email || null,
      phone:
        phone || null,
      capture
    }
  );
}

async function authenticateUser(
  userId,
  purpose,
  durationMs = 5000
) {
  const challenge =
    await apiPost(
      "/auth/challenge",
      {
        user_id: userId,
        purpose
      }
    );

  const capture =
    await captureBehaviour(
      durationMs
    );

  const result =
    await apiPost(
      "/auth/verify",
      {
        user_id: userId,
        challenge_id:
          challenge.challenge_id,
        capture
      }
    );

  if (!result.authenticated) {
    throw new Error(
      "Behaviour authentication failed; use OTP/NFC fallback"
    );
  }

  return result;
}

async function encryptForRecipient({
  senderId,
  recipientId,
  plaintext,
  ttlSeconds = 120
}) {
  const auth =
    await authenticateUser(
      senderId,
      "encrypt"
    );

  return apiPost(
    "/message/encrypt",
    {
      sender_id:
        senderId,

      recipient_id:
        recipientId,

      auth_token:
        auth.auth_token,

      plaintext,

      ttl_seconds:
        ttlSeconds
    }
  );
}

async function decryptMessage({
  recipientId,
  messageId
}) {
  const auth =
    await authenticateUser(
      recipientId,
      "decrypt"
    );

  return apiPost(
    "/message/decrypt",
    {
      recipient_id:
        recipientId,

      auth_token:
        auth.auth_token,

      message_id:
        messageId
    }
  );
}

chrome.runtime.onInstalled.addListener(
  () => {
    storageSet({
      apiBase:
        DEFAULT_API_BASE
    });
  }
);

chrome.runtime.onMessage.addListener(
  (
    message,
    _sender,
    sendResponse
  ) => {

    (
      async () => {

        if (
          message.type ===
          "sumit_health"
        ) {
          return {
            ok: true,
            result:
              await apiGet(
                "/health"
              )
          };
        }

        if (
          message.type ===
          "sumit_set_api"
        ) {
          await storageSet({
            apiBase:
              message.apiBase ||
              DEFAULT_API_BASE
          });

          return {
            ok: true
          };
        }

        if (
          message.type ===
          "sumit_set_device"
        ) {
          await storageSet({
            deviceProfile:
              message.deviceProfile
          });

          return {
            ok: true
          };
        }

        if (
          message.type ===
          "sumit_enrol"
        ) {
          return {
            ok: true,
            result:
              await enrolUser(
                message
              )
          };
        }

        if (
          message.type ===
          "sumit_authenticate"
        ) {
          return {
            ok: true,
            result:
              await authenticateUser(
                message.userId,
                message.purpose ||
                  "generic",
                message.durationMs ||
                  5000
              )
          };
        }

        if (
          message.type ===
          "sumit_encrypt"
        ) {
          return {
            ok: true,
            result:
              await encryptForRecipient(
                message
              )
          };
        }

        if (
          message.type ===
          "sumit_decrypt"
        ) {
          return {
            ok: true,
            result:
              await decryptMessage(
                message
              )
          };
        }

        if (
          message.type ===
          "sumit_otp_issue"
        ) {
          return {
            ok: true,
            result:
              await apiPost(
                "/fallback/otp/issue",
                {
                  user_id:
                    message.userId,

                  channel:
                    message.channel
                }
              )
          };
        }

        if (
          message.type ===
          "sumit_otp_verify"
        ) {
          return {
            ok: true,
            result:
              await apiPost(
                "/fallback/otp/verify",
                {
                  user_id:
                    message.userId,

                  channel:
                    message.channel,

                  code:
                    message.code
                }
              )
          };
        }

        return {
          ok: false,
          error:
            "Unknown message type"
        };
      }
    )()
      .then(
        sendResponse
      )
      .catch(
        error =>
          sendResponse({
            ok: false,
            error:
              error.message
          })
      );

    return true;
  }
);