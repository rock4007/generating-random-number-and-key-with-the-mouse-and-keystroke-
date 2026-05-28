# Security Limitations And Volunteer Readiness

This project is a research and prototype implementation. Before using it with
volunteers or real user data, treat the following as non-negotiable boundaries.

## What The Behaviour Signal Is

Mouse movement and keystroke timing can add entropy and help score risk, but
they are not passwords and they are not enough as the only secret. Production
keys must mix in operating-system CSPRNG output and protected device/session
secret material.

## Dashboard Boundary

The browser dashboard is a volunteer/demo prototype, not a hardened production vault.
It should be used to demonstrate local encryption flow, packet metadata,
recovery behaviour, and threat decisions. It should not be used to collect live
secrets unless the surrounding device, browser, deployment, and operating
procedures have been hardened and reviewed.

## Device Compromise

Client-side encryption cannot protect plaintext from malware that already
controls the user's device. Malware can read the message before encryption,
change the page code, capture screenshots, or exfiltrate session material.
Volunteer use must include clean-device guidance and a clear incident path.

## Secret Handling

Raw AES keys, raw behavioural entropy, device secrets, and full system secrets
must not be printed, logged, stored in analytics, or shown in the UI. Display
only short fingerprints for debugging. If logs are collected centrally, scrub
nonce/key/context fields and never send plaintext.

## Ghost Key Demo

The ghost-key handoff is a demo of one-time message opening across devices. A
different device cannot recreate the sender's key from fresh random mouse
movement. The demo package carries the unlock key with the ciphertext, decrypts
once in the receiver dashboard, and clears the key from memory. That makes the
flow quick to demonstrate, but anyone who receives the package can open it.

The portable API version uses `/ghost/encrypt` and `/ghost/decrypt` for devices
that do not have SUMIT KEY installed. In that mode, the API server briefly holds
the one-time unlock key in process memory and zeroizes/deletes it after first
decrypt or expiry. If the API process restarts before decrypt, the ghost key is
gone and the package cannot be opened.

Operators can use `/ghost/status/{ghost_id}` to check whether a package can
still be opened and `/ghost/revoke/{ghost_id}` to burn a ghost key before use.

The browser extension can collect local mouse and keystroke presence on ordinary
web pages, but that is still a presence/risk gate. It does not magically
recreate the sender's key on the receiver device. The API-held ghost key is what
opens the message, and the API burns that key after first decrypt.

## AES-GCM Nonces

AES-GCM requires nonce uniqueness for every encryption under the same key.
This code uses fresh 96-bit random nonces for each encryption operation. Any
production service should also add monitoring or structured message IDs so
accidental replay or nonce reuse can be detected.

## Authentication Factors

SMS and email OTP are weaker fallback factors and should be treated as
restricted recovery signals. Prefer phishing-resistant passkeys, FIDO2/WebAuthn,
secure hardware tokens, or platform authenticators for real volunteer accounts.

## NIST/FIPS Claims

Local NIST SP 800-22 randomness tests are useful engineering checks, but they
are not official validation. Formal NIST/FIPS compliance requires accredited
validation for the exact cryptographic module, build, platform, configuration,
and operating procedures.

## Pre-Volunteer Checklist

- Use HTTPS, secure headers, and a reviewed static build.
- Keep raw keys and plaintext out of logs, analytics, screenshots, and support
  exports.
- Prefer passkeys or FIDO2/WebAuthn over SMS/email OTP.
- Document that behaviour is an entropy/risk signal, not a standalone secret.
- Review the threat model for malware, phishing, replay, and operator mistakes.
- Run the automated tests and record which tests are skipped due to hardware or
  display limitations.
- Do not represent local test results as official NIST/FIPS certification.
