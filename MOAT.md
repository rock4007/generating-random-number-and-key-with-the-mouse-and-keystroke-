# SUMIT KEY Moat

This is the defensibility map for SUMIT KEY. A moat is not only an idea; it is
the combination of thesis, implementation, tests, evidence, and honest limits
that makes the work hard to dismiss or casually copy.

## Moat Thesis

SUMIT KEY's moat is human-session-owned cryptography:

`live behavior + OS randomness + user-held identity + platform context + one-time handoff + claim hygiene`

The defensible insight is that these are usually separate security topics. This
project turns them into one lifecycle with code and tests.

## Defensible Assets

| Asset | What It Proves | Project Evidence |
|---|---|---|
| Human-session KDF | Behavior is additive, never the only secret | `behave_kdf.py`, `scripts/research_evidence.py`, entropy tests |
| Ghost handoff | A message opens once, burns the key, and documents the boundary | `api.py`, `browser_extension/`, ghost tests |
| Platform-bound encryption | Apps become untrusted pipes; context replay fails | `sdk/identity.py`, `sdk/core.py`, identity/connectivity tests |
| Claim matrix | Public claims map to code, tests, limits, and validation status | `claim_matrix.json`, security audit tests |
| Reproducible evidence | Reviewers can run the proof artifacts locally | `scripts/ci_check.py`, `scripts/research_evidence.py`, `scripts/moat_report.py` |
| Volunteer boundary | The demo is honest about malware, OTP, NIST/FIPS, and ghost limits | `SECURITY_LIMITATIONS.md`, `NOVELTY_POSITIONING.md` |

## Why This Is Harder To Copy Than A Single Feature

A single feature can be copied: AES-GCM encryption, mouse collection, a browser
extension, or a burn-after-read link. The moat is the composition:

1. Behavioral input is useful without becoming an unsafe standalone secret.
2. Platform context is bound into encryption so replay across apps fails.
3. Ghost handoff works for volunteers but does not pretend to be magic key
   recreation.
4. Every claim has a boundary and a test/evidence path.
5. The pipeline exports reviewer-readable evidence, not only screenshots.

## Moat Test

Run:

```bash
python scripts/research_evidence.py --trials 48 --output results/research_evidence.json
python scripts/moat_report.py --output-md results/moat_report.md --output-json results/moat_report.json
```

The moat is healthy only when:

- claim paths exist,
- research evidence passes,
- ghost open-once passes,
- platform replay is rejected,
- behavioral KDF evidence passes,
- CI includes these checks.

## What The Moat Is Not

- It is not a claim that every component is new.
- It is not a claim that behavior alone is a secure secret.
- It is not official NIST/FIPS validation.
- It is not protection against malware controlling the user device.

The moat is the disciplined lifecycle: new composition, working code, evidence,
and honest boundaries.

