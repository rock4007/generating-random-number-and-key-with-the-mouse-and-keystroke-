# SUMIT KEY Novelty Positioning

This file gives the bold research story for SUMIT KEY while keeping the claims
credible enough for a security paper.

## One-Line Novelty Claim

To our knowledge, SUMIT KEY is the first open research prototype to treat live
human behavior, user-held cross-platform encryption, one-time volunteer handoff,
and explicit security-claim hygiene as one cryptographic lifecycle rather than
four separate features.

## The Real Problem Being Solved

The security industry has strong cryptographic algorithms, but weak lifecycle
ownership:

- Platforms own encryption UX and can limit portability.
- Users rarely understand where keys live or when they are gone.
- Behavioral biometrics are usually only risk scores, not cryptographic inputs.
- Security demos often work, but their threat model is hidden.
- Research prototypes often overclaim validation.

SUMIT KEY's research question is:

> Can a human session become part of the cryptographic lifecycle without making
> unsafe claims that behavior alone is a secret?

That is the real gap.

## The Four Strongest Novel Ideas

### 1. Human-Session Cryptography

Most systems bind keys to devices, passwords, hardware tokens, or accounts.
SUMIT KEY studies how to bind key generation to a live human session:

`device randomness + mouse dynamics + keystroke rhythm + context -> session key`

The novelty is not "mouse movement is random." The novelty is the safety rule:
behavior is additive and can never reduce the CSPRNG baseline.

### 2. Ghost Handoff As A Research Protocol

Many systems can make a link expire. SUMIT KEY frames burn-after-read as a
volunteer research protocol:

`create -> transfer -> prove presence -> open once -> zeroize -> audit`

The receiver's behavior does not recreate the key. It proves presence and gates
the open. This honest separation is part of the contribution.

### 3. Platform-Independent Personal Encryption

Current users live across many platforms. SUMIT KEY treats each platform as an
untrusted pipe and moves the encryption boundary to the user:

`same user, same secret, different platform -> different cryptographic context`

The long-term idea is a personal encryption layer that follows the user for the
next 30 years, even as apps change.

### 4. Claim Hygiene As A Security Primitive

Most prototypes only ship features. SUMIT KEY ships claims with boundaries:

`claim -> implementation -> test -> limitation -> validation status`

This can itself become a research contribution because future security systems
will combine behavior, AI, browsers, post-quantum crypto, and cloud APIs. The
industry needs a way to show what is proven, what is tested, and what is only a
demo.

## Paper Abstract Draft

Modern users communicate across many platforms, but cryptographic control often
remains bound to the platform rather than the user. Meanwhile, behavioral
biometrics are widely studied for authentication, yet rarely integrated into the
full lifecycle of key generation, message protection, one-time handoff, and
claim validation. This paper presents SUMIT KEY, a systems-security prototype
that composes live mouse and keystroke behavior with operating-system
randomness, platform-bound authenticated encryption, and burn-after-read ghost
handoff. The design treats behavior as additive entropy and a presence signal,
not as a standalone secret. We evaluate the system through entropy-source
health tests, replay and tamper tests, cross-platform isolation tests, and a
security-claim matrix that maps every public claim to implementation, tests,
limitations, and validation status. SUMIT KEY demonstrates a practical path
toward user-held, platform-independent cryptographic lifecycles while avoiding
common overclaims around biometrics, randomness testing, and prototype security.

## Research Questions

1. Can behavioral input be safely added to key derivation without weakening a
   CSPRNG-backed design?
2. Can ordinary users understand a one-time ghost handoff if the system clearly
   separates presence gating from cryptographic secrecy?
3. Can platform labels, sender identity, receiver identity, and message context
   prevent cross-platform replay in a portable user-held encryption layer?
4. Does an explicit claim matrix improve reviewer and volunteer understanding
   of what a prototype actually proves?

## Reviewer-Safe Wording

Use:

- "To our knowledge..."
- "This exact composition has not been formalized in an open prototype..."
- "We study behavior as additive entropy and presence, not as a standalone
  secret."
- "Local NIST-style testing is used as engineering evidence, not certification."

Avoid:

- "No one has ever thought of this."
- "Mouse movement alone creates an unbreakable key."
- "NIST/FIPS compliant" unless you have official validation.
- "Quantum proof" or "impossible to hack."

## The 30-Year Vision

If this research grows, SUMIT KEY becomes a personal cryptographic layer that
survives platform churn:

- A user owns their encryption identity.
- Every app is just a transport.
- Live human presence can raise or lower trust without becoming the only secret.
- Messages can be opened once, revoked, expired, or bound to context.
- Security claims are machine-checkable instead of marketing text.

That is the big idea: human-session-owned cryptography for a post-platform
internet.

## Moat Artifact

The moat is tracked as a project artifact, not only as positioning text:

```bash
python scripts/research_evidence.py --trials 48 --output results/research_evidence.json
python scripts/moat_report.py --output-md results/moat_report.md --output-json results/moat_report.json
```

Read [MOAT.md](MOAT.md) for the strategy and `results/moat_report.md` for the
generated evidence-backed report.
