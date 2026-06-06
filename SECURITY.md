# Security Policy

## Supported versions

| Version | Security fixes |
|---|---|
| `1.0.x` | Actively maintained |
| `< 1.0` | Not supported |

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Report security bugs by emailing **soumodeepguha22@gmail.com** with:

1. A clear description of the vulnerability
2. Steps to reproduce (proof-of-concept or test case where possible)
3. Affected version(s) and configuration
4. Suggested severity (Critical / High / Medium / Low)

You should receive an acknowledgement within **72 hours** and a triage decision within **7 days**. If the bug is confirmed, a fix will be prepared before public disclosure. We will credit you in the release notes unless you prefer to remain anonymous.

## Scope

In scope:

- Cryptographic weaknesses in `sdk/core.py`, `sdk/identity.py`, key derivation logic
- Authentication bypass (e.g. GCM tag forging, AAD bypass)
- Nonce reuse or key material leakage to disk / network logs
- Vault burn-after-read bypass
- Rate-limiting bypass in `security.py`

Out of scope:

- Social engineering attacks
- Physical access to an unlocked device
- Vulnerabilities in third-party dependencies (report those upstream)
- Pre-encryption malware (documented limitation — see [Security Limitations](README.md#security-limitations))

## Severity definitions

| Severity | Examples |
|---|---|
| **Critical** | Remote code execution, key material exfiltration without authentication |
| **High** | Authentication bypass, MITM without detection, GCM tag forgery |
| **Medium** | Entropy degradation that weakens (but does not break) key derivation |
| **Low** | Information disclosure, minor timing side-channels |

## Cryptographic expectations

SUMIT KEY makes the following explicit guarantees:

| Claim | Mechanism |
|---|---|
| 256-bit key security (classical) | AES-256-GCM + HKDF-SHA3-256 |
| ≥128-bit post-quantum security | ML-KEM-1024 (NIST FIPS 203) |
| Authentication with associated data | AES-256-GCM 128-bit tag |
| Nonce uniqueness | `os.urandom(12)` per message |
| Key isolation per platform | Platform label in HKDF context |
| Key isolation per user pair | Sorted user IDs in HKDF context |

Attacks against any of these claims are treated as **High** or **Critical** severity.

## Known limitations

The following are documented, accepted limitations and are **not** treated as vulnerabilities:

1. Pre-encryption kernel/browser malware can intercept plaintext.
2. Ghost code is ~40-bit — suitable for demos, not high-value production secrets.
3. ARP MAC resolution only works on the same LAN subnet.
4. NIST SP 800-22 results are statistical checks, not FIPS 140-3 certification.
5. Schnorr ZKP in Stack C does not resist Shor's algorithm (use Stack B for post-quantum).

See [README.md — Security Limitations](README.md#security-limitations) for the full list.
