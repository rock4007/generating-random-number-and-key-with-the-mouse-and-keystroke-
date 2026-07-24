# SUMIT KEY Research Contributions

This document defines paper-ready research directions for SUMIT KEY. The goal is
not to claim that nobody has ever studied mouse movement, keystroke dynamics,
multi-factor KDFs, or burn-after-read messages. Those areas exist. The stronger
and more defensible claim is that SUMIT KEY studies how these ideas can be
composed into a cryptographic lifecycle: entropy capture, key derivation,
message encryption, volunteer handoff, recovery, audit, and failure boundaries.

## Contribution 1: Session-Bound Behavioral Entropy As A Cryptographic Input

### Gap

Behavioral biometrics are usually used as authentication or fraud scoring
signals. They answer "does this look like the same user?" They are less often
studied as live, session-bound input to a KDF that is explicitly additive to OS
randomness and safe even when the behavioral signal is weak.

### Proposed Claim

SUMIT KEY introduces a session-bound behavioral entropy pipeline where mouse and
keystroke features are length-prefixed, conditioned, health-checked, and mixed
with CSPRNG output before cryptographic use.

### Why It Matters

The industry gap is not lack of randomness. The gap is lack of human/session
presence in key generation. A stolen device secret or leaked stored key can be
long-lived. A live behavioral capture adds a time-local signal that is harder to
replay exactly.

### What Must Be Proven

- Behavioral input never reduces security when it is weak or attacker-shaped.
- The system remains secure with zero behavioral entropy because CSPRNG input is
  always present.
- Strong behavioral captures increase replay cost and session uniqueness.
- The health gate rejects constant, repeated, dominated, or synthetic patterns.

### Project Hooks

- `behave_kdf.py`
- `entropy_engine.py`
- `key_generator.py`
- `tests/test_entropy_sources_deep.py`
- `tests/test_mouse_entropy.py`

### Paper Experiment

Compare four sources across many trials:

1. OS randomness only.
2. Mouse only plus OS randomness.
3. Keystroke only plus OS randomness.
4. Mouse plus keystroke plus OS randomness.

Report min-entropy estimates, collision behavior, avalanche distance, and
failure rate under weak/synthetic captures.

Reproducible command:

```bash
python scripts/research_evidence.py --trials 48 --output results/research_evidence.json
```

## Contribution 2: Presence-Gated Burn-After-Read Handoff For Volunteer Demos

### Gap

Burn-after-read encrypted links exist, and behavioral presence detection exists,
but volunteer research demos need a safer middle ground: quick cross-device
opening, explicit burn semantics, no false claim that another person's mouse can
recreate the sender's key, and clear logs showing what happened.

### Proposed Claim

SUMIT KEY defines a volunteer-safe ghost handoff state machine:

`created -> available -> opened_once -> zeroized_and_deleted`

The receiver's mouse movement is a presence/risk gate, while the cryptographic
unlock material is held only briefly by the local demo or API and burned after
first use.

### Why It Matters

Security demos often hide their threat model. This contribution makes the demo
honest: it is fast enough for volunteers, portable across devices, and explicit
about what it does not prove.

### What Must Be Proven

- A ghost package opens once and cannot be replayed.
- Revoked or expired packages fail closed.
- The plaintext and raw key are not logged.
- The state transition is understandable to non-expert volunteers.

### Project Hooks

- `api.py` ghost endpoints.
- `browser_extension/`
- `scripts/sandbox_demo.py`
- `scripts/research_evidence.py`
- `tests/test_ghost_api.py`
- `tests/test_sandbox_demo_script.py`

### Paper Experiment

Run a volunteer usability and security comprehension study:

- Time to create and open a package.
- Number of failed opens.
- Whether volunteers understand "presence gate" vs "cryptographic key."
- Whether replay attempts are rejected consistently.

## Contribution 3: Platform-Bound Encryption That Treats Apps As Untrusted Pipes

### Gap

End-to-end encryption is usually controlled by the platform. Users who want the
same encryption logic across WhatsApp, Telegram, Gmail, cloud drives, browser
forms, or custom apps must trust each platform's security model separately.

### Proposed Claim

SUMIT KEY treats platforms as untrusted transport pipes. The platform name,
sender identity, receiver identity, and message context are bound into key
derivation or authenticated data so ciphertext from one context cannot be
silently replayed into another.

### Why It Matters

The next long-term industry gap is not only stronger algorithms. It is user-held
encryption that follows the user across platforms without giving platforms
plaintext access.

### What Must Be Proven

- Cross-platform replay fails.
- Directional replay fails.
- Sender/receiver/channel metadata is authenticated.
- The platform sees only opaque ciphertext.

### Project Hooks

- `sdk/identity.py`
- `sdk/core.py`
- `sdk/sumitkey.js`
- `tests/test_identity.py`
- `tests/test_connectivity.py`
- `scripts/research_evidence.py`

### Paper Experiment

Construct the same message across multiple platform labels and prove that
changing platform, sender, receiver, context, or AAD prevents decryption.

## Contribution 4: Research-Grade Honesty Layer For Prototype Security Claims

### Gap

Many prototype security projects overclaim: "NIST passed," "quantum safe,"
"biometric key," or "zero knowledge" without clearly separating engineering
tests from formal validation.

### Proposed Claim

SUMIT KEY contributes a security-claim discipline for research prototypes:
every feature must name its boundary, failure mode, and validation level before
it is shown to volunteers or described in a paper.

### Why It Matters

This is a real industry gap. Future security systems will combine AI, behavior,
biometrics, post-quantum crypto, browser agents, and cloud APIs. Without claim
hygiene, users and reviewers cannot tell what is proven, tested, assumed, or
only demonstrated.

### What Must Be Proven

- Security claims are mapped to tests, threat-model entries, or limitations.
- NIST/FIPS wording is clearly separated from local statistical testing.
- Hardware compromise, malware, logging, nonce reuse, and weak OTP limits are
  documented before volunteer use.

### Project Hooks

- `SECURITY.md`
- `SECURITY_LIMITATIONS.md`
- `threat_model.py`
- `scripts/ci_check.py`
- `.github/workflows/ci.yml`
- `scripts/research_evidence.py`
- `tests/test_security_audit.py`

### Paper Experiment

Create a claim matrix:

| Claim | Code | Test | Threat Boundary | Formal Status |
|---|---|---|---|---|
| AES-GCM encrypts messages | `crypto_tools.py` | file/message tests | nonce reuse risk | engineering test |
| Ghost opens once | `api.py` | ghost tests | API memory trust | prototype |
| NIST randomness checked | validators | NIST tests | not FIPS validation | local statistical |

Then compare reviewer comprehension before and after reading the matrix.

## Recommended Paper Thesis

SUMIT KEY is best positioned as a systems-security research prototype:

> This work investigates whether live behavioral entropy, platform-bound
> encryption, and honest burn-after-read handoff can be composed into a
> practical cross-platform cryptographic lifecycle for volunteer-facing
> security tools.

This is stronger than saying "mouse movement creates a secret key." The latter
is easy to attack. The former is a real research question with measurable
experiments.

## What Not To Claim Yet

- Do not claim official NIST or FIPS validation.
- Do not claim behavioral movement alone is a secure secret.
- Do not claim malware on the user's device can be defeated.
- Do not claim no one has discussed behavioral biometrics or burn-after-read
  encryption.
- Do not claim another random person's mouse movement can recreate the sender's
  key.

## Next Implementation Milestones

1. Add a `claim_matrix.json` file mapping every public claim to tests and
   limitations.
2. Add a benchmark script that runs behavioral-source experiments and exports
   paper tables.
3. Add volunteer-study mode to the dashboard: no raw secrets, no analytics,
   consent text, and automatic result export.
4. Add replay-case tests for platform, direction, sender, receiver, context,
   nonce, expiry, and ghost state transitions.
